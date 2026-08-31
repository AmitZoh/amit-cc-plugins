#!/usr/bin/env python3
"""
bind_github: grant claude-ro read-only GitHub access — one read-only GitHub App OWNED BY
each account (an org OR your personal user account) and installed on it. Owner == install
target means the App stays PRIVATE (no public App). The account type is auto-detected.
Additive and idempotent:

    bind_github.py --orgs my-org            # org: create my-org's App, install on my-org
    bind_github.py --orgs my-user           # personal user: same, on your own account

Per account there are two browser steps (Create, then Install + approve). claude-ro reaches
EVERY bound account at once through a single argument-less mint broker that writes a per-
account ~1h token FILE under the runtime dir (never through the model's context).

Secrets never pass through argv or the model: each App private key is delivered by GitHub
straight into its 600 file via the manifest exchange.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

CLAUDE_RO_USER = "claude-ro"
GH_SHIM_PATH = pathlib.Path("/usr/local/bin/gh")
GIT_CRED_HELPER_PATH = pathlib.Path("/usr/local/bin/claude-ro-git-credential")
# Explicit path (not --global): the wiring runs as claude-ro via sudo, but HOME is the
# invoking user's home, so --global would target the wrong ~/.gitconfig. Inside the
# sandbox HOME=/Users/claude-ro, so --file <this> == --global there.
CLAUDE_RO_GITCONFIG = "/Users/claude-ro/.gitconfig"
_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")  # GitHub login charset


def _validate_org(org: str) -> str:
    if not _ORG_RE.match(org):
        raise SystemExit(f"invalid GitHub org login: {org!r}")
    return org


# ---------- claude-ro git + gh wiring (App-agnostic; installed once, idempotent) ----------

def _git_credential_helper(user: str) -> str:
    """A git credential helper for github.com that returns the PRE-MINTED per-org token
    from the runtime dir. The org comes from the repo path (git passes it because
    useHttpPath=true). If the token file is missing or stale it re-runs the pinned mint
    broker (which repopulates all orgs) — so `git` stays transparent."""
    return f"""#!/bin/sh
# claude-ro git credential helper (agent-sandbox). Do NOT edit by hand.
set -eu
[ "$1" = "get" ] || exit 0
ORG=""
while IFS='=' read -r k v; do
  case "$k" in
    path) ORG="${{v%%/*}}" ;;
    "") break ;;
  esac
done
[ -n "$ORG" ] || exit 0
F="{common.RUNTIME_DIR}/github/$ORG.token"
if [ ! -f "$F" ] || [ "$(( $(date +%s) - $(stat -f %m "$F") ))" -ge 3000 ]; then
  sudo -u {user} /usr/local/bin/claude-ro-mint-github >/dev/null 2>&1 || true
fi
[ -f "$F" ] || exit 0
printf 'username=x-access-token\\n'
printf 'password=%s\\n' "$(cat "$F")"
"""


def install_git_wiring(user: str, *, ctx: common.Ctx) -> None:
    """Install the git credential helper script + point claude-ro's github.com config
    at it with useHttpPath=true. Idempotent. Requires an active admin_session."""
    key = "credential.https://github.com.helper"
    if ctx.dry_run:
        common.log.info("[dry-run] would install %s and set claude-ro git %s + useHttpPath",
                        GIT_CRED_HELPER_PATH, key)
        return
    common.admin_run_a(["tee", str(GIT_CRED_HELPER_PATH)], input_text=_git_credential_helper(user))
    common.admin_run_a(["chmod", "755", str(GIT_CRED_HELPER_PATH)])
    common.admin_run_a(["chown", "root:wheel", str(GIT_CRED_HELPER_PATH)])
    common.admin_run_a(["-u", CLAUDE_RO_USER, "git", "config", "--file",
                        CLAUDE_RO_GITCONFIG, "--unset-all", key], check=False)
    common.admin_run_a(["-u", CLAUDE_RO_USER, "git", "config", "--file",
                        CLAUDE_RO_GITCONFIG, "--add", key, str(GIT_CRED_HELPER_PATH)])
    common.admin_run_a(["-u", CLAUDE_RO_USER, "git", "config", "--file",
                        CLAUDE_RO_GITCONFIG, "credential.https://github.com.useHttpPath", "true"])
    common.log.info("configured claude-ro git credential helper for github.com (%s)",
                    GIT_CRED_HELPER_PATH)


def _gh_shim(real_gh: str, user: str) -> str:
    """gh shim: if gh is unauthenticated, nudge CC toward the per-org token files (CC
    knows which org its task is on). Does not guess the org."""
    return f"""#!/bin/sh
# claude-ro gh shim (agent-sandbox). Do NOT edit by hand.
set -eu
REAL_GH="{real_gh}"
if [ -z "${{GH_TOKEN:-}}" ] && [ -z "${{GITHUB_TOKEN:-}}" ]; then
  echo "claude-ro: gh is unauthenticated. Read-only GitHub tokens are per-org files." >&2
  echo "  For org <ORG>:  GH_TOKEN=\\$(cat {common.RUNTIME_DIR}/github/<ORG>.token) gh ..." >&2
  echo "  (run  sudo -u {user} /usr/local/bin/claude-ro-mint-github  first if the file is missing)" >&2
fi
exec "$REAL_GH" "$@"
"""


def install_gh_shim(user: str, *, ctx: common.Ctx) -> None:
    """Install /usr/local/bin/gh as a nudge shim. Skipped (with a warning) if no real
    gh is found or if the real gh IS /usr/local/bin/gh. Requires an admin_session."""
    real_gh = shutil.which("gh")
    if not real_gh:
        common.log.warning("no `gh` on PATH — skipping gh shim (git access still works)")
        return
    if pathlib.Path(real_gh).resolve() == GH_SHIM_PATH.resolve():
        common.log.warning("real gh is at %s — cannot install a shim there (git still works)",
                           GH_SHIM_PATH)
        return
    if ctx.dry_run:
        common.log.info("[dry-run] would install gh shim %s -> %s", GH_SHIM_PATH, real_gh)
        return
    common.admin_run_a(["tee", str(GH_SHIM_PATH)], input_text=_gh_shim(real_gh, user))
    common.admin_run_a(["chmod", "755", str(GH_SHIM_PATH)])
    common.admin_run_a(["chown", "root:wheel", str(GH_SHIM_PATH)])
    common.log.info("installed gh shim %s -> %s", GH_SHIM_PATH, real_gh)


def _install_broker_and_wiring(user: str, *, ctx: common.Ctx) -> None:
    """Install the single argless mint broker + its sudoers, plus the git/gh wiring.
    All idempotent, so safe on create, add-org, and resume."""
    helper = common.render_github_broker()
    common.install_broker_helper("github", None, helper, ctx=ctx)
    common.install_broker_sudoers("github", None, ctx=ctx)
    install_git_wiring(user, ctx=ctx)
    install_gh_shim(user, ctx=ctx)
    common.install_capability_note(ctx=ctx)


def _install_actions(orgs: list[str]) -> list[str]:
    return [
        f"Create secrets dir {common.SECRETS_DIR} + runtime dir {common.RUNTIME_DIR} (once)",
        f"For each org ({', '.join(orgs)}): store its App key + commit the org to state.json",
        f"Install mint broker {common.broker_helper_path('github')} + sudoers drop-in",
        f"Install git credential helper {GIT_CRED_HELPER_PATH} + claude-ro gh shim",
        "Install claude-ro capability note + SessionStart hook",
    ]


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Bind claude-ro to GitHub: one org-owned read-only App per org, installed on that org.")
    ap.add_argument("--orgs", required=True,
                    help="Comma-separated logins — orgs and/or your personal account "
                         "(e.g. my-org,my-user); type auto-detected. Additive across runs.")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    orgs = [_validate_org(o.strip()) for o in args.orgs.split(",") if o.strip()]
    if not orgs:
        ap.error("--orgs must list at least one org login")

    ctx = common.Ctx.from_args(args)
    user = common.current_username()
    provider = common.load_provider("github")
    state = common.state_read(validate=True)
    bound = {r["login"].lower() for r in (state.get("github") or [])}
    new_orgs = [o for o in orgs if o.lower() not in bound]

    if not new_orgs:
        common.log.info("all requested accounts already bound (%s) — nothing to do.", ", ".join(orgs))
        return

    # Detect org-vs-user per account (fail-fast, unauthenticated — safe under --dry-run).
    # Each becomes a PRIVATE App owned by that account (org or personal) and installed on it.
    targets = [(login, provider.detect_account_type(login, ctx=ctx)) for login in new_orgs]

    if ctx.dry_run:
        desc = ", ".join(f"{login} ({atype})" for login, atype in targets)
        common.log.info("[dry-run] would create a private App per account + install on: %s "
                        "(already bound, skipped: %s)", desc, ", ".join(sorted(bound)) or "none")
        return

    if not common.prompt_yes_no(
            f"Bind claude-ro to GitHub for {', '.join(new_orgs)} (one private read-only App "
            f"per account — two browser steps each: Create, then Install)?",
            default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    with common.update_state() as s:
        common.begin_operation(s, "bind-github", {"kind": "github", "orgs": new_orgs})

    # ONE admin dialog wraps the whole run. It appears BEFORE any App is created
    # (dismiss → nothing happens). Each account's key is stored + its record committed
    # the instant GitHub returns it, so a failure part-way leaves earlier ones bound and
    # a re-run resumes (already-bound accounts are skipped up front).
    with common.admin_session(
        title=f"agent-sandbox: bind GitHub ({', '.join(new_orgs)})",
        actions=_install_actions(new_orgs),
    ):
        common.ensure_secrets_dir(ctx=ctx)
        common.ensure_runtime_dir(ctx=ctx)
        for login, atype in targets:
            info = provider.create_account_app(login, atype, ctx=ctx)
            secret_ref = f"github-{login}.pem"
            common.secret_store(secret_ref, info["pem"], ctx=ctx)
            record = {
                "login": info["login"],
                "account_type": atype,
                "app_id": common.validate_github_app_id(info["app_id"]),
                "app_slug": info["app_slug"],
                "installation_id": common.validate_github_app_id(info["installation_id"]),
                "secret_ref": secret_ref,
                "granted_at": common.now_iso(),
            }
            with common.update_state() as s:
                if not any(g["login"].lower() == login.lower() for g in s.get("github") or []):
                    s.setdefault("github", []).append(record)
                common.mark_phase(s, "state_commit")
            common.log.info("bound %s (%s; app %s, installation %s)",
                            login, atype, record["app_id"], record["installation_id"])
        _install_broker_and_wiring(user, ctx=ctx)
        with common.update_state() as s:
            common.mark_phase(s, "broker_installed")

    with common.update_state() as s:
        common.end_operation(s)

    common.log.info("GitHub bound for: %s. In claude-ro, run "
                    "`sudo -u %s /usr/local/bin/claude-ro-mint-github` to write per-org "
                    "token files under %s/github/.", ", ".join(new_orgs), user, common.RUNTIME_DIR)


if __name__ == "__main__":
    main()
