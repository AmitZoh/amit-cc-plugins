#!/usr/bin/env python3
"""
unbind_snowflake: reverse bind_snowflake for one Snowflake account.

Deletes the stored RSA private key and the state entry. The mint helper is SHARED
across all bound accounts, so its helper + sudoers drop-in are removed only when
this is the last one.

Deleting the private key is what actually ends this machine's access — without it
no JWT can be signed. The Snowflake service user itself is owner-managed and is
never touched here (the laptop holds no credential able to drop it), so this
prints the DROP USER statement for the owner to run when retiring access for good.

Usage:
    unbind_snowflake.py --name <id>
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="Unbind one claude-ro Snowflake identity.")
    ap.add_argument("--name", required=True, help="Snowflake identity to remove.")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    name = common.validate_identifier(args.name)
    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)
    record = next((s for s in (state.get("snowflake") or []) if s["name"] == name), None)
    if record is None:
        print(f"no snowflake identity named {name!r} in state.json", file=sys.stderr)
        sys.exit(2)

    # The mint broker is shared across all bound accounts, so it's removed only when
    # this is the last one.
    is_last = len(state.get("snowflake") or []) == 1
    # A bind that never reached Phase B installed no broker, so don't promise to
    # remove one — the confirmation has to describe what will actually happen.
    broker_present = (common.broker_helper_path("snowflake").exists()
                      or common.broker_sudoers_path("snowflake").exists())
    if is_last and broker_present:
        broker_note = "  - Remove the shared mint helper + sudoers drop-in (last account)\n"
    elif is_last:
        broker_note = "  - No mint helper to remove (this bind never completed)\n"
    else:
        broker_note = "  - Leave the shared mint helper in place (other accounts still bound)\n"
    confirm = (
        f"About to unbind Snowflake {name!r}:\n"
        f"  - Delete the stored private key {common.SECRETS_DIR}/{record['secret_ref']}\n"
        f"  - The service user {record['service_user']} is left intact (owner-managed)\n"
        f"{broker_note}"
        f"Continue?"
    )
    if not common.prompt_yes_no(confirm, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    if ctx.dry_run:
        common.log.info("[dry-run] would remove snowflake %s", name)
        return

    with common.update_state() as s:
        common.begin_operation(s, "unbind-snowflake", {"kind": "snowflake", "name": name})

    # revoke() before secret_delete, per the contract — snowflake's is a no-op (the
    # service user is owner-managed), but the ordering is the one unbind_github relies
    # on and keeping it uniform means a future remote teardown needs no re-think.
    snow = common.load_provider("snowflake")
    snow.revoke(record, common.secret_read(record["secret_ref"]))

    common.secret_delete(record["secret_ref"], ctx=ctx)
    with common.update_state() as s:
        s["snowflake"] = [x for x in (s.get("snowflake") or []) if x["name"] != name]
        last = not s["snowflake"]

    # Only escalate if the broker is actually on disk. An unbind that never reached
    # Phase B has nothing installed to remove, and asking for a password to delete
    # files that don't exist is noise.
    installed = (common.broker_helper_path("snowflake").exists()
                 or common.broker_sudoers_path("snowflake").exists())
    if last and installed:
        with common.admin_session(
            title=f"agent-sandbox: unbind Snowflake {name}",
            actions=[
                f"Remove mint helper {common.broker_helper_path('snowflake')}",
                f"Remove sudoers drop-in {common.broker_sudoers_path('snowflake')}",
            ],
        ):
            # Sudoers first: drop the permission before the thing it points at, so no
            # window exists where the rule names a path that could be recreated.
            common.remove_broker_sudoers("snowflake", None, ctx=ctx)
            common.remove_broker_helper("snowflake", None, ctx=ctx)

    with common.update_state() as s:
        common.end_operation(s)

    message = snow.owner_teardown_request(record)
    print("\n" + "=" * 78, file=sys.stderr)
    print("The private key is gone, so this machine can no longer authenticate. To retire\n"
          "the account in Snowflake itself, send this to whoever administers it:",
          file=sys.stderr)
    print("=" * 78 + "\n", file=sys.stderr)
    print(message, file=sys.stderr)
    print("=" * 78, file=sys.stderr)
    try:
        subprocess.run(["pbcopy"], input=message, text=True, check=True, timeout=5)
        print("This message is now on your clipboard.", file=sys.stderr)
    except (OSError, subprocess.SubprocessError):
        pass  # non-fatal: the message is printed above regardless
    common.log.info("unbound Snowflake %s (service user %s left intact)%s",
                    name, record["service_user"],
                    "; removed the shared mint broker (no accounts remain)"
                    if last and installed else "")


if __name__ == "__main__":
    main()
