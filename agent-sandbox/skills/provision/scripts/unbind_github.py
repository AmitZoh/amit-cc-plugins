#!/usr/bin/env python3
"""
unbind_github: reverse bind_github, per org.

    unbind_github.py --orgs my-org      # uninstall + remove just that org's App
    unbind_github.py                    # FULL: remove every bound org, plus the shared
                                        # broker/wiring/state

Each org has its own org-owned App. `revoke` uninstalls the installation; the App itself
can't be deleted via the API, so this prints the org's settings URL to delete it by hand.
"""

from __future__ import annotations

import argparse
import contextlib
import pathlib
import re
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

CLAUDE_RO_USER = "claude-ro"
GH_SHIM_PATH = pathlib.Path("/usr/local/bin/gh")
GIT_CRED_HELPER_PATH = pathlib.Path("/usr/local/bin/claude-ro-git-credential")
CLAUDE_RO_GITCONFIG = "/Users/claude-ro/.gitconfig"
_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")


def _remove_token_file(login: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        (common.RUNTIME_DIR / "github" / f"{login}.token").unlink()


def _settings_url(rec: dict) -> str:
    """The settings page that owns this App — org vs personal user."""
    if rec.get("account_type") == "user":
        return "https://github.com/settings/apps"
    return f"https://github.com/organizations/{rec['login']}/settings/apps"


def main() -> None:
    ap = argparse.ArgumentParser(description="Unbind claude-ro GitHub (one org, or fully).")
    ap.add_argument("--orgs", help="Comma-separated org logins to remove. Omit for a FULL unbind.")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)
    github = state.get("github") or []
    if not github:
        print("no GitHub orgs bound in state.json", file=sys.stderr)
        sys.exit(2)
    by_login = {r["login"].lower(): r for r in github}

    if args.orgs:
        targets = []
        for o in args.orgs.split(","):
            o = o.strip()
            if not o:
                continue
            if not _ORG_RE.match(o):
                ap.error(f"invalid org login: {o!r}")
            rec = by_login.get(o.lower())
            if rec is None:
                common.log.warning("org %s is not bound — skipping", o)
                continue
            targets.append(rec)
        if not targets:
            print("none of the requested orgs are bound", file=sys.stderr)
            sys.exit(2)
    else:
        targets = list(github)  # full unbind

    target_logins = [r["login"] for r in targets]
    if not common.prompt_yes_no(
            f"Unbind GitHub for {', '.join(target_logins)}? Uninstalls each App + deletes its "
            f"stored key. The Apps themselves must then be deleted by hand (URLs printed).",
            default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)
    if ctx.dry_run:
        common.log.info("[dry-run] would unbind: %s", ", ".join(target_logins))
        return

    with common.update_state() as s:
        common.begin_operation(s, "unbind-github", {"kind": "github", "orgs": target_logins})

    provider = common.load_provider("github")
    for rec in targets:
        try:
            secret = common.secret_read(rec["secret_ref"])
            provider.revoke(rec, secret)  # uninstall the installation while the key exists
        except SystemExit as exc:
            common.log.warning("could not uninstall %s (continuing): %s", rec["login"], exc)
        common.secret_delete(rec["secret_ref"], ctx=ctx)
        _remove_token_file(rec["login"])
        common.log.info("unbound org %s (installation %s)", rec["login"], rec["installation_id"])

    removed = {r["login"].lower() for r in targets}
    with common.update_state() as s:
        s["github"] = [g for g in (s.get("github") or []) if g["login"].lower() not in removed]
        last = not s["github"]

    if last:
        with common.admin_session(
            title="agent-sandbox: remove the shared GitHub broker + wiring",
            actions=[
                f"Remove mint broker {common.broker_helper_path('github')} + sudoers drop-in",
                f"Remove git credential helper {GIT_CRED_HELPER_PATH} + gh shim + gitconfig entries",
            ],
        ):
            common.remove_broker_sudoers("github", None, ctx=ctx)
            common.remove_broker_helper("github", None, ctx=ctx)
            common.admin_run_a(["rm", "-f", str(GIT_CRED_HELPER_PATH)])
            common.admin_run_a(["rm", "-f", str(GH_SHIM_PATH)])
            common.admin_run_a(["-u", CLAUDE_RO_USER, "git", "config", "--file",
                                CLAUDE_RO_GITCONFIG, "--unset-all",
                                "credential.https://github.com.helper"], check=False)
            common.admin_run_a(["-u", CLAUDE_RO_USER, "git", "config", "--file",
                                CLAUDE_RO_GITCONFIG, "--unset",
                                "credential.https://github.com.useHttpPath"], check=False)

    with common.update_state() as s:
        common.end_operation(s)

    common.log.info("GitHub unbound for: %s%s. Each App can't be removed via API — delete "
                    "it by hand:", ", ".join(target_logins),
                    " (shared broker/wiring removed — no orgs remain)" if last else "")
    for rec in targets:
        common.log.info("  %s → %s", rec["login"], _settings_url(rec))


if __name__ == "__main__":
    main()
