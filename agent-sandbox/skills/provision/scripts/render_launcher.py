#!/usr/bin/env python3
"""
Re-render /usr/local/bin/claude-ro from state.json.

Installs templates/launcher.sh.tmpl to /usr/local/bin/claude-ro (mode 755, root).
The launcher is fully static now — AWS, k8s, GitHub, Mongo, and the Mongo tunnels
are all broker-on-demand inside the sandbox, so nothing is rendered from state.
Called from init.py and any sub-command that (re)installs the launcher.

Idempotent: same template → same output. Never edits the file in place.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

# SKILL_DIR derived from this file's location, NOT ~. Robust against running
# under a different effective user.
SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

LAUNCHER_PATH = pathlib.Path("/usr/local/bin/claude-ro")
TEMPLATE_PATH = SKILL_DIR / "templates" / "launcher.sh.tmpl"


def render(state: dict) -> str:
    # The launcher is now fully static: AWS, k8s, GitHub, Mongo, and the Mongo tunnels
    # are all broker-on-demand inside the sandbox. The launcher only tags the session
    # (CLAUDE_RO_SESSION = its PID) and tears down that session's tunnels on exit — no
    # per-account or per-cluster rendering. `state` is unused but kept for the callers'
    # render(state) signature. Accounts are NOT required (GitHub/Mongo-only setups valid).
    return TEMPLATE_PATH.read_text()


def write_launcher(rendered: str, *, dry_run: bool = False) -> None:
    if dry_run:
        print(rendered)
        return

    def _write() -> None:
        common.admin_run_a(["tee", str(LAUNCHER_PATH)], input_text=rendered)
        common.admin_run_a(["chmod", "755", str(LAUNCHER_PATH)])
        common.admin_run_a(["chown", "root:wheel", str(LAUNCHER_PATH)])

    # Callers split two ways: most (provision_account, unbind_cluster,
    # deprovision_account) call this OUTSIDE any session and want their own dialog;
    # refresh_settings calls it INSIDE one, where opening a second would raise —
    # admin_session is deliberately not re-entrant. Join the caller's session when there
    # is one. That caller must already declare the launcher write in its own `actions`,
    # so nothing is hidden from the approval dialog.
    if common.admin_session_active():
        _write()
        return
    with common.admin_session(
        title=f"Install {LAUNCHER_PATH}",
        actions=[
            f"Write rendered launcher script to {LAUNCHER_PATH}",
            f"chmod 755 {LAUNCHER_PATH}",
            f"chown root:wheel {LAUNCHER_PATH}",
        ],
    ):
        _write()


def main() -> None:
    ap = argparse.ArgumentParser(description="Re-render /usr/local/bin/claude-ro from state.json.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print to stdout; don't write the file.")
    args = ap.parse_args()

    state = common.state_read()
    rendered = render(state)
    write_launcher(rendered, dry_run=args.dry_run)
    if not args.dry_run:
        common.log.info("wrote %s", LAUNCHER_PATH)


if __name__ == "__main__":
    main()
