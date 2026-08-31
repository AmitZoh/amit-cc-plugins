#!/usr/bin/env python3
"""
init: machine-level setup for agent-sandbox.

Runs the local-system phases ONLY:
  - Create the macOS user `claude-ro` (no login)
  - Allow-ACL on the user's $HOME for claude-ro
  - sudoers entry: user can `sudo -u claude-ro` without password
  - /Users/claude-ro/.kube/per-launch/ directory
  - Symlink claude/aws/kubectl into /usr/local/bin (so claude-ro's PATH finds them)
  - launchd plist for the daily lockdown sweep

Does NOT touch AWS or provision any provider. After init, run
`provision_account` for each provider account you want to bind to.
First-time setup: `init` then `provision_account` then `bind_cluster`.

This split exists because init is provider-agnostic (it's a one-time
machine prep) and the per-account provisioning is provider-specific.
Mashing them together coupled args from two layers and made re-running
either independently confusing.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

CLAUDE_RO_USER = "claude-ro"
CLAUDE_RO_HOME = pathlib.Path("/Users") / CLAUDE_RO_USER
CLAUDE_RO_KEYCHAIN = CLAUDE_RO_HOME / "Library" / "Keychains" / "login.keychain-db"
SUDOERS_PATH = pathlib.Path("/etc/sudoers.d/claude-ro")
LAUNCHD_PLIST_PATH = pathlib.Path(os.path.expanduser(
    "~/Library/LaunchAgents/com.claude-ro.lockdown.plist"
))


# ---------- local phases ----------

def phase_local_user_actions(*, ctx: common.Ctx) -> list[str]:
    """Predict the privileged actions phase_local_user will perform. Must
    stay in lockstep with the skip conditions in phase_local_user."""
    if ctx.dry_run or _user_exists(CLAUDE_RO_USER):
        return []
    return [
        f"Create macOS user '{CLAUDE_RO_USER}' (sysadminctl -addUser, non-admin, no login)",
        "Flush Directory Service cache (dscacheutil -flushcache)",
    ]


def phase_local_user(*, ctx: common.Ctx) -> None:
    """Create the claude-ro macOS user. Idempotent (skip if exists)."""
    if ctx.dry_run:
        common.log.info("[dry-run] would create macOS user %s", CLAUDE_RO_USER)
        return
    if _user_exists(CLAUDE_RO_USER):
        _wait_for_user_resolvable(CLAUDE_RO_USER, flush_cache=False)
        common.log.info("macOS user %s already exists", CLAUDE_RO_USER)
        return
    cfg = ctx.config.get("macos_user") or {}
    full_name = cfg.get("full_name", "Claude RO")
    shell = cfg.get("shell", "/bin/zsh")
    # `-password OFF` is NOT a valid sysadminctl idiom — it gets parsed as the
    # literal string "OFF" and the create silently no-ops because of password
    # policy. Use a strong throwaway password instead. The password is never
    # persisted anywhere; claude-ro can't log in, can't su, can't unlock FDE.
    # The launcher uses `sudo -u claude-ro env -i ... claude` which bypasses
    # the password check entirely.
    throwaway_pw = secrets.token_urlsafe(32)
    common.admin_run_a([
        "sysadminctl",
        "-addUser", CLAUDE_RO_USER,
        "-fullName", full_name,
        "-password", throwaway_pw,
        "-shell", shell,
    ])
    # Open Directory has propagation lag between sysadminctl returning and
    # downstream tools (chmod +a, dseditgroup) being able to resolve the user
    # name → UUID via the Membership API. Flush dscache and poll dscl until the
    # user record is readable; otherwise the next phase fails with
    # "Unable to translate '<user>' to a UUID".
    _wait_for_user_resolvable(CLAUDE_RO_USER, flush_cache=True)
    common.log.info("created macOS user %s", CLAUDE_RO_USER)


def _wait_for_user_resolvable(username: str, timeout: int = 15, *,
                               flush_cache: bool) -> None:
    """Poll until macOS can resolve `username` to a UUID.

    If flush_cache is True, runs dscacheutil -flushcache once first (an admin
    op declared in phase_local_user_actions). Then polls `dscl . -read
    /Users/... GeneratedUID` (authoritative for local Open Directory) until
    success or timeout. The Membership API used by chmod +a / dseditgroup
    tracks dscl closely, so once dscl can read the record the ACL operations
    work."""
    if flush_cache:
        common.admin_run_a(["dscacheutil", "-flushcache"], check=False)
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        proc = subprocess.run(
            ["dscl", ".", "-read", f"/Users/{username}", "GeneratedUID"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0 and "GeneratedUID:" in proc.stdout:
            return
        last_err = (proc.stderr or proc.stdout).strip()
        time.sleep(0.2)
    raise SystemExit(
        f"user {username} did not become resolvable within {timeout}s. "
        f"Last error: {last_err}"
    )


def phase_local_acl(username: str, *, ctx: common.Ctx) -> None:
    """Allow-ACL on the user's $HOME for claude-ro. macOS chmod +a."""
    home = f"/Users/{username}"
    if ctx.dry_run:
        common.log.info("[dry-run] would set allow-ACL on %s", home)
        return
    common.run([
        "chmod", "+a", f"{CLAUDE_RO_USER} allow read,execute,readattr", home,
    ])
    common.log.info("set allow-ACL on %s for %s", home, CLAUDE_RO_USER)


def phase_local_sudoers_actions(*, ctx: common.Ctx) -> list[str]:
    if ctx.dry_run:
        return []
    return [
        f"Validate {SUDOERS_PATH} syntax (visudo -c, read-only)",
        f"Install {SUDOERS_PATH} (mode 440, owner root:wheel)",
    ]


def phase_local_sudoers(username: str, *, ctx: common.Ctx) -> None:
    """Render the sudoers entry, validate with visudo, install at /etc/sudoers.d/claude-ro."""
    template = (SKILL_DIR / "templates" / "sudoers.tmpl").read_text()
    rendered = _render({
        "USERNAME": username,
    }, template)

    if ctx.dry_run:
        common.log.info("[dry-run] would install sudoers at %s", SUDOERS_PATH)
        return

    # Validate with visudo before installing.
    with tempfile.NamedTemporaryFile("w", suffix=".sudoers", delete=False) as f:
        f.write(rendered)
        tmp = f.name
    try:
        proc = common.admin_run_a(["visudo", "-c", "-f", tmp], check=False)
        if proc.returncode != 0:
            raise SystemExit(f"sudoers validation failed: {proc.stderr}")
        # Install with mode 440, owned by root.
        common.admin_run_a(
            ["install", "-m", "440", "-o", "root", "-g", "wheel",
             tmp, str(SUDOERS_PATH)],
        )
    finally:
        os.unlink(tmp)
    common.log.info("installed %s", SUDOERS_PATH)


def phase_local_kube_dir_actions(*, ctx: common.Ctx) -> list[str]:
    if ctx.dry_run:
        return []
    target = CLAUDE_RO_HOME / ".kube" / "per-launch"
    return [f"Create {target} (mode 700, owner {CLAUDE_RO_USER}:staff)"]


def phase_local_kube_dir(*, ctx: common.Ctx) -> None:
    """Ensure /Users/claude-ro/.kube/per-launch/ exists, mode 700, owned by claude-ro."""
    target = CLAUDE_RO_HOME / ".kube" / "per-launch"
    if ctx.dry_run:
        common.log.info("[dry-run] would mkdir -m 700 %s", target)
        return
    common.admin_run_a([
        "install", "-d", "-m", "700",
        "-o", CLAUDE_RO_USER, "-g", "staff",
        str(target),
    ])
    common.log.info("ensured %s", target)


def phase_local_stable_skill_link_actions(*, ctx: common.Ctx) -> list[str]:
    return [f"create symlink {common.SKILLS_LINK} → {common.SKILL_DIR.parent}"]


def phase_local_stable_skill_link(*, ctx: common.Ctx) -> None:
    """Point the stable /usr/local/claude-ro-skills link at the plugin's skills dir,
    and link cred-sweep into ~/.claude/skills so the sandbox user can see it.

    Distinct from phase_local_skill_symlink below, which makes the user's skills
    dir discoverable from claude-ro's HOME. This one exists so that no installed
    artifact has to name the skill's real path: brokers, the tunnel helper and
    the lockdown plist all reach the code through this link. Must run before
    phase_local_launchd and before any bind-* renders a broker."""
    common.ensure_skill_symlink(ctx=ctx)
    common.ensure_cred_sweep_discoverable(ctx=ctx)


def phase_local_skill_symlink_actions(username: str, *, ctx: common.Ctx) -> list[str]:
    if ctx.dry_run:
        return []
    target = pathlib.Path("/Users") / username / ".claude" / "skills"
    link = CLAUDE_RO_HOME / ".claude" / "skills"
    return [
        f"Ensure {link.parent} exists (mode 755, owner {CLAUDE_RO_USER}:staff)",
        f"Symlink {link} → {target} (replaces any existing entry)",
    ]


def phase_local_skill_symlink(username: str, *, ctx: common.Ctx) -> None:
    """Create /Users/claude-ro/.claude/skills symlinked to the user's skills dir.

    Without this, Claude Code inside claude-ro looks at $HOME/.claude/skills/
    (where HOME=/Users/claude-ro) and finds no user-scoped skills. Discovery
    then falls back to PWD walk-up gated by project-root markers — fragile and
    surprising (skills appear from cwds without `.git/`, vanish from cwds with
    one). The symlink makes HOME-based discovery resolve to the user's actual
    skills dir, so /cred-sweep and friends are reachable inside the
    sandbox regardless of cwd.

    No security expansion: claude-ro could already read those files via the
    direct path (mode 644). The symlink just makes them HOME-discoverable.
    Writes through the symlink fail because claude-ro doesn't own the user's
    skills/ dir (correct behavior).

    Idempotent: ln -sfn replaces any existing entry (file, dir, or wrong
    symlink) with the right symlink."""
    target = pathlib.Path("/Users") / username / ".claude" / "skills"
    link = CLAUDE_RO_HOME / ".claude" / "skills"

    if ctx.dry_run:
        common.log.info("[dry-run] would ensure %s and symlink %s → %s",
                        link.parent, link, target)
        return

    # Ensure /Users/claude-ro/.claude exists. Idempotent: install -d is a no-op
    # if the dir already exists with the right mode/owner. claude-ro's CC may
    # have already created it for credentials.
    common.admin_run_a([
        "install", "-d", "-m", "755",
        "-o", CLAUDE_RO_USER, "-g", "staff",
        str(link.parent),
    ])
    # Create / replace the symlink as claude-ro so the symlink itself is owned
    # by claude-ro. ln -sfn: -s symbolic, -f remove any existing, -n don't
    # dereference if existing is a symlink-to-dir (so we replace, not follow).
    common.admin_run_a([
        "-u", CLAUDE_RO_USER,
        "ln", "-sfn", str(target), str(link),
    ])
    common.log.info("symlinked %s → %s", link, target)


def phase_local_keychain_actions(*, ctx: common.Ctx) -> list[str]:
    if ctx.dry_run:
        return []
    return [
        f"Ensure {CLAUDE_RO_KEYCHAIN.parent} exists (owner {CLAUDE_RO_USER})",
        f"Create empty-password login keychain {CLAUDE_RO_KEYCHAIN} for "
        f"{CLAUDE_RO_USER} (if absent)",
        f"Set it as {CLAUDE_RO_USER}'s default + login keychain, disable "
        "auto-lock, and unlock it",
    ]


def phase_local_keychain(*, ctx: common.Ctx) -> None:
    """Provision an empty-password login keychain for claude-ro so Claude Code
    can store its Anthropic OAuth token without a GUI prompt.

    claude-ro is created with a throwaway password that init discards (see
    phase_local_user), so the account's stock login keychain can never be
    unlocked — every token write would otherwise pop a Keychain dialog that
    can't be satisfied (claude-ro has no GUI session), and CC re-prompts for
    /login on the next launch. We replace it with a fresh keychain whose
    password is empty, set it as default + login, and disable auto-lock. The
    launcher unlocks it (-p "") per invocation, because a no-GUI security
    session re-locks on its own between launches.

    Empty password is acceptable under this skill's threat model: claude-ro
    already holds the same token on disk, so a keychain only claude-ro can read
    adds no exposure.

    Idempotent: create-keychain runs only if the file is absent; the
    settings/default/login/unlock steps are safe to re-apply."""
    kc = str(CLAUDE_RO_KEYCHAIN)
    if ctx.dry_run:
        common.log.info("[dry-run] would provision empty-password login keychain %s", kc)
        return
    common.admin_run_a(["-u", CLAUDE_RO_USER, "mkdir", "-p", str(CLAUDE_RO_KEYCHAIN.parent)])
    exists = common.admin_run_a(
        ["-u", CLAUDE_RO_USER, "test", "-f", kc], check=False,
    ).returncode == 0
    if not exists:
        common.admin_run_a(["-u", CLAUDE_RO_USER, "security", "create-keychain", "-p", "", kc])
        common.log.info("created login keychain %s", kc)
    else:
        common.log.info("login keychain %s already exists", kc)
    # No -t / -l → no auto-lock timeout, no lock-on-sleep.
    common.admin_run_a(["-u", CLAUDE_RO_USER, "security", "set-keychain-settings", kc])
    common.admin_run_a(["-u", CLAUDE_RO_USER, "security", "default-keychain", "-s", kc])
    common.admin_run_a(["-u", CLAUDE_RO_USER, "security", "login-keychain", "-s", kc])
    common.admin_run_a(["-u", CLAUDE_RO_USER, "security", "unlock-keychain", "-p", "", kc])
    common.log.info("configured %s as claude-ro default+login keychain (auto-lock off)", kc)


def _binary_symlink_target(binary: str) -> str | None:
    """Compute the canonical real path that /usr/local/bin/<binary> should
    point at, or None if no symlink work is needed (real file present, or
    existing symlink already points at canonical).

    For each binary, find its canonical real path on the user's PATH (resolving
    every symlink with os.path.realpath) and ensure /usr/local/bin/<binary>
    points DIRECTLY at that real file. This avoids fragile multi-hop
    indirection — e.g. stock /usr/local/bin/kubectl is often a symlink into
    Docker Desktop's bundle, and uninstalling Docker would leave it dangling.
    We replace such indirect symlinks with direct ones at init time.

    If /usr/local/bin/<binary> already exists AS A REAL FILE (not a symlink),
    we leave it alone — the user put it there deliberately and we're not in
    the business of overwriting their binaries."""
    ulb_path = f"/usr/local/bin/{binary}"
    if os.path.exists(ulb_path) and not os.path.islink(ulb_path):
        return None
    user_path = shutil.which(binary)
    if not user_path:
        raise SystemExit(
            f"{binary} not found on the user's PATH. Install it system-wide "
            f"or place it at {ulb_path} before running init."
        )
    canonical = os.path.realpath(user_path)
    if not os.path.exists(canonical):
        # `which` returned a broken symlink chain. Drop /usr/local/bin/<binary>
        # from PATH and search again.
        saved_path = os.environ.get("PATH", "")
        try:
            filtered = ":".join(p for p in saved_path.split(":") if p != "/usr/local/bin")
            os.environ["PATH"] = filtered
            user_path = shutil.which(binary)
        finally:
            os.environ["PATH"] = saved_path
        if not user_path:
            raise SystemExit(
                f"{binary} resolved to a broken symlink ({canonical}); "
                "no alternative found on the user's PATH after dropping /usr/local/bin. "
                "Reinstall the binary."
            )
        canonical = os.path.realpath(user_path)
        if not os.path.exists(canonical):
            raise SystemExit(
                f"{binary} still resolves to a non-existent path ({canonical}). Reinstall."
            )
    if os.path.islink(ulb_path):
        try:
            if os.path.realpath(ulb_path) == canonical:
                return None
        except OSError:
            pass
    return canonical


def phase_local_binaries_actions(*, ctx: common.Ctx) -> list[str]:
    if ctx.dry_run:
        return []
    out: list[str] = []
    for binary in ("claude", "aws", "kubectl"):
        target = _binary_symlink_target(binary)
        if target is not None:
            out.append(f"Symlink /usr/local/bin/{binary} → {target}")
    return out


def phase_local_binaries(*, ctx: common.Ctx) -> None:
    """Symlink claude/aws/kubectl into /usr/local/bin so claude-ro's PATH finds them."""
    for binary in ("claude", "aws", "kubectl"):
        target = _binary_symlink_target(binary)
        if target is None:
            continue
        ulb_path = f"/usr/local/bin/{binary}"
        if ctx.dry_run:
            common.log.info("[dry-run] would symlink %s -> %s", ulb_path, target)
            continue
        common.admin_run_a(["ln", "-sf", target, ulb_path])
        common.log.info("symlinked %s -> %s", ulb_path, target)


def phase_local_launchd(username: str, *, ctx: common.Ctx) -> None:
    """Render and bootstrap the lockdown launchd plist. Note: invoking `claude -p`
    from launchd is unverified — see the template comment."""
    template = (SKILL_DIR / "templates" / "lockdown.launchd.plist.tmpl").read_text()
    cfg = ctx.config.get("launchd") or {}
    rendered = _render({
        "HOME": f"/Users/{username}",
        "USERNAME": username,
        "SKILL_SCRIPTS_DIR": str(common.SKILL_SCRIPTS_LINK),
        "HOUR": str(int(cfg.get("hour", 3))),
        "MINUTE": str(int(cfg.get("minute", 0))),
    }, template)

    if ctx.dry_run:
        common.log.info("[dry-run] would install %s and bootstrap it", LAUNCHD_PLIST_PATH)
        return

    LAUNCHD_PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    LAUNCHD_PLIST_PATH.write_text(rendered)
    LAUNCHD_PLIST_PATH.chmod(0o644)

    uid = os.getuid()
    # bootstrap is the modern launchctl verb. bootout is the inverse. We try
    # bootout first to clear any stale registration, then bootstrap.
    subprocess.run(
        ["launchctl", "bootout", f"gui/{uid}/com.claude-ro.lockdown"],
        check=False, capture_output=True,
    )
    subprocess.run(
        ["launchctl", "bootstrap", f"gui/{uid}", str(LAUNCHD_PLIST_PATH)],
        check=False, capture_output=True,
    )
    common.log.info("installed and bootstrapped %s", LAUNCHD_PLIST_PATH)


# ---------- helpers ----------

def _user_exists(username: str) -> bool:
    proc = subprocess.run(["id", "-u", username], capture_output=True, check=False)
    return proc.returncode == 0


def _render(vars: dict[str, str], template: str) -> str:
    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in vars:
            raise KeyError(f"template variable {key!r} not provided")
        return str(vars[key])
    return re.sub(r"\{\{(\w+)\}\}", sub, template)


# ---------- main ----------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Machine-level setup for agent-sandbox (no AWS/cloud "
                    "work — run provision_account afterwards).",
    )
    ap.add_argument("--yes", action="store_true",
                    help="Auto-confirm the top-level prompt.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="Resume a previously interrupted init from state.json's "
                         "last_completed_phase.")
    args = ap.parse_args()

    ctx = common.Ctx.from_args(args)
    username = os.environ.get("USER") or os.environ.get("LOGNAME")
    if not username:
        raise SystemExit("could not determine username from $USER")

    # Top-level description. TTY mode shows it through an inline "Continue?"
    # prompt. Non-TTY mode (e.g. Claude Code) prints it to the transcript and
    # the actual approval moment is the single admin_session password dialog
    # opened below — that dialog enumerates every privileged action.
    if not args.resume:
        description = (
            f"About to set up this machine for agent-sandbox (user "
            f"{username}).\n"
            "  - Create macOS user 'claude-ro' (no password, non-admin)\n"
            f"  - Allow-ACL on /Users/{username} for claude-ro\n"
            f"  - Install /etc/sudoers.d/claude-ro\n"
            f"  - Symlink {common.SKILLS_LINK} at the plugin's skills (stable path for "
            f"brokers), and link cred-sweep into ~/.claude/skills for the sandbox\n"
            "  - Symlink claude/aws/kubectl into /usr/local/bin (if missing)\n"
            "  - Provision an empty-password login keychain for claude-ro (CC token storage)\n"
            "  - Install ~/Library/LaunchAgents/com.claude-ro.lockdown.plist\n"
            "\nThis is provider-agnostic. After init, run provision_account for each "
            "cloud account you want claude-ro to read."
        )
        if args.yes:
            print(description, file=sys.stderr)
            common.log.info("[--yes] proceeding without confirmation")
        elif sys.stdin.isatty():
            if not common.prompt_yes_no(description + "\nContinue?", default=False, ctx=ctx):
                print("aborted", file=sys.stderr)
                sys.exit(1)
        else:
            print(description, file=sys.stderr)

    # Initialize state with the user's username (skipped in dry-run).
    if not ctx.dry_run and not common.STATE_PATH.exists():
        with common.update_state() as s:
            s["user"]["username"] = username

    # Begin operation (skipped in dry-run).
    target = {"user": username}
    if not ctx.dry_run:
        with common.update_state() as s:
            if not args.resume or s.get("pending_operation") is None:
                common.begin_operation(s, "init", target)

    # Phases: (name, run_fn, actions_fn). actions_fn returns the privileged
    # actions the phase will perform — collected up front so admin_session can
    # show the user every action behind a single password prompt. Phases that
    # do no privileged work (local_acl, local_launchd) return [].
    phases = [
        ("local_user",
         lambda: phase_local_user(ctx=ctx),
         lambda: phase_local_user_actions(ctx=ctx)),
        ("local_acl",
         lambda: phase_local_acl(username, ctx=ctx),
         lambda: []),
        ("local_stable_skill_link",
         lambda: phase_local_stable_skill_link(ctx=ctx),
         lambda: phase_local_stable_skill_link_actions(ctx=ctx)),
        ("local_sudoers",
         lambda: phase_local_sudoers(username, ctx=ctx),
         lambda: phase_local_sudoers_actions(ctx=ctx)),
        ("local_kube_dir",
         lambda: phase_local_kube_dir(ctx=ctx),
         lambda: phase_local_kube_dir_actions(ctx=ctx)),
        ("local_skill_symlink",
         lambda: phase_local_skill_symlink(username, ctx=ctx),
         lambda: phase_local_skill_symlink_actions(username, ctx=ctx)),
        ("local_keychain",
         lambda: phase_local_keychain(ctx=ctx),
         lambda: phase_local_keychain_actions(ctx=ctx)),
        ("local_binaries",
         lambda: phase_local_binaries(ctx=ctx),
         lambda: phase_local_binaries_actions(ctx=ctx)),
        ("local_launchd",
         lambda: phase_local_launchd(username, ctx=ctx),
         lambda: []),
    ]
    if ctx.dry_run:
        start = 0
    else:
        state = common.state_read()
        start = common.resume_phase_index(state, [p[0] for p in phases], "init", target)
        if start > 0:
            common.log.info("resuming from phase %s",
                            phases[start][0] if start < len(phases) else "(post-local)")

    # Compute every privileged action that the remaining phases will perform.
    remaining_actions: list[str] = []
    for _, _, actions_fn in phases[start:]:
        remaining_actions.extend(actions_fn())

    def _run_phases() -> None:
        for name, fn, _ in phases[start:]:
            common.log.info("phase: %s", name)
            fn()
            if not ctx.dry_run:
                with common.update_state() as s:
                    common.mark_phase(s, name)

    if remaining_actions and not ctx.dry_run:
        with common.admin_session(
            title="agent-sandbox: machine setup (init)",
            actions=remaining_actions,
        ):
            _run_phases()
    else:
        # A dry run performs no privileged action — every phase returns early on
        # ctx.dry_run — so it must not pop the authorization dialog. Escalating
        # to do nothing trains the user to approve prompts without reading them.
        # No privileged work to do (resume past all admin phases, or all
        # idempotent skip-conditions met). Skip the dialog entirely.
        _run_phases()

    # End the init operation.
    if not ctx.dry_run:
        with common.update_state() as s:
            common.end_operation(s)

    if ctx.dry_run:
        common.log.info("[dry-run] init complete (no state changes)")
        return

    common.log.info(
        "init complete. Next: provision_account --provider aws "
        "--aws-profile <p> --aws-account-id <id> --aws-region <r>"
    )


if __name__ == "__main__":
    main()
