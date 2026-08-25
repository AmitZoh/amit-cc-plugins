#!/usr/bin/env python3
"""
unbind_mongodb: reverse bind_mongodb for one MongoDB database.

Deletes the stored password and the state entry. The mint helper is SHARED across
all bound DBs, so its helper + sudoers drop-in are removed only when this is the
last DB. The remote DB user `claude-ro-<engineer>` is owner-managed — this never
touches it (the laptop has no admin credential). Ask your DB owner to drop the user
when retiring access.

Usage:
    unbind_mongodb.py --name <id>
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402
from bind_mongodb import _rerender_launcher  # noqa: E402 — shared launcher re-render


def main() -> None:
    ap = argparse.ArgumentParser(description="Unbind one claude-ro MongoDB identity.")
    ap.add_argument("--name", required=True, help="MongoDB identity to remove.")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    name = common.validate_identifier(args.name)
    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)
    record = next((m for m in (state.get("mongodb") or []) if m["name"] == name), None)
    if record is None:
        print(f"no mongodb identity named {name!r} in state.json", file=sys.stderr)
        sys.exit(2)

    # The mint broker is shared across all bound DBs, so it's removed only when this
    # is the last one.
    is_last = len([m for m in (state.get("mongodb") or [])]) == 1
    broker_note = ("  - Remove the shared mint helper + sudoers drop-in (last DB)\n"
                   if is_last else
                   "  - Leave the shared mint helper in place (other DBs still bound)\n")
    if record.get("auth") == "aws_iam":
        cred_note = (f"  - No stored secret to delete (AWS IAM auth via RO role "
                     f"{record.get('iam_role_arn', '?')})\n"
                     f"  - The Atlas IAM DB user is owner-managed — remove that ARN in "
                     f"Atlas yourself if you want to fully revoke\n")
    else:
        cred_note = (f"  - Delete the stored password {common.SECRETS_DIR}/{record['secret_ref']}\n"
                     f"  - The remote DB user {record['username']} is left intact (owner-managed)\n")
    confirm = (
        f"About to unbind MongoDB {name!r}:\n"
        f"{cred_note}"
        f"{broker_note}"
        f"Continue?"
    )
    if not common.prompt_yes_no(confirm, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    if ctx.dry_run:
        common.log.info("[dry-run] would remove mongodb %s", name)
        return

    with common.update_state() as s:
        common.begin_operation(s, "unbind-mongodb", {"kind": "mongodb", "name": name})

    via = record.get("via_cluster")
    if record.get("secret_ref"):  # aws_iam records have no stored secret
        common.secret_delete(record["secret_ref"], ctx=ctx)
    with common.update_state() as s:
        s["mongodb"] = [m for m in (s.get("mongodb") or []) if m["name"] != name]
        last = not s["mongodb"]
        cluster_still_used = bool(via) and any(
            m.get("via_cluster") == via for m in s["mongodb"])
    # Remove this cluster's on-demand tunnel broker only when no remaining DB needs it.
    remove_tunnel = bool(via) and not cluster_still_used
    tunnel_label = common.tunnel_cluster_label(via) if remove_tunnel else None

    # One admin session: re-render the launcher (drop this cluster from the tunnel-cleanup
    # list if unused), remove this cluster's tunnel broker if unused, and — when no DBs
    # remain at all — also remove the shared mint broker.
    actions = ["Re-render /usr/local/bin/claude-ro (tunnel-cleanup context list)"]
    if remove_tunnel:
        actions.append(f"Remove SOCKS tunnel broker for cluster {via}")
    if last:
        actions += [
            f"Remove mint helper {common.broker_helper_path('mongodb')}",
            f"Remove sudoers drop-in {common.broker_sudoers_path('mongodb')}",
        ]
    with common.admin_session(
        title=f"agent-sandbox-provision: unbind MongoDB {name}",
        actions=actions,
    ):
        if remove_tunnel:
            common.remove_broker_sudoers("tunnel", tunnel_label, ctx=ctx)
            common.remove_broker_helper("tunnel", tunnel_label, ctx=ctx)
        if last:
            common.remove_broker_sudoers("mongodb", None, ctx=ctx)
            common.remove_broker_helper("mongodb", None, ctx=ctx)
        _rerender_launcher(ctx=ctx)

    with common.update_state() as s:
        common.end_operation(s)

    identity = record.get("username") or record.get("iam_role_arn") or "(owner-managed)"
    common.log.info("unbound MongoDB %s (remote identity %s left intact)%s",
                    name, identity,
                    "; removed the shared mint broker (no DBs remain)" if last else "")


if __name__ == "__main__":
    main()
