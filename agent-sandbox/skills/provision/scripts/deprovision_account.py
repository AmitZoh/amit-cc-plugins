#!/usr/bin/env python3
"""
deprovision_account: remove THIS user's binding to a provider account.

Reverses provision_account for the named account. Deletes the per-user RO
IAM role and detaches its policies. Drops every cluster binding for this
user on this account too (per-user EKS access entries).

Does NOT touch the org-shared verify fixtures (S3 bucket, KMS key, Secrets
Manager / DynamoDB / CloudWatch Logs entries) or the supplemental
ClusterRoles — other engineers may still be using them. Those are deleted
only by `purge_org_fixtures` (Skill 3, not yet implemented).

Idempotent (NotFound is success at every step).

Usage:
    deprovision_account.py --provider aws --aws-account-id <12-digit>

Profile and region are read from state.json (recorded at provision time).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Remove this user's binding to a provider account "
                    "(deletes per-user RO role + cluster access entries).",
    )
    ap.add_argument("--provider", required=True, choices=["aws"])
    ap.add_argument("--aws-account-id", required=True,
                    help="12-digit AWS account ID.")
    ap.add_argument("--yes", action="store_true",
                    help="Skip the destructive-action confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.provider != "aws":
        print(f"provider {args.provider!r} not yet implemented", file=sys.stderr)
        sys.exit(2)

    common.validate_aws_account_id(args.aws_account_id)
    ctx = common.Ctx.from_args(args)
    aws = common.load_provider("aws")

    state = common.state_read()
    account = next((a for a in state["accounts"]
                    if a["account_id"] == args.aws_account_id), None)
    if account is None:
        print(f"no binding to account {args.aws_account_id} in state.json",
              file=sys.stderr)
        sys.exit(2)

    # Guard: refuse if a bound Mongo DB is reached through a cluster in THIS account —
    # deprovisioning removes the assumer_profile the tunnel broker needs, so the DB would
    # silently lose its tunnel. Make the operator unbind those DBs first.
    dependent = []
    for m in state.get("mongodb") or []:
        via = m.get("via_cluster")
        if not via:
            continue
        try:
            acct, _r, _n = common.parse_eks_arn(via)
        except SystemExit:
            continue
        if acct == args.aws_account_id:
            dependent.append(m["name"])
    if dependent:
        print(f"cannot deprovision account {args.aws_account_id}: these MongoDB DBs route "
              f"through a cluster in it and depend on its tunnel broker: "
              f"{', '.join(dependent)}.\nUnbind them first: "
              f"unbind_mongodb --name <name>.", file=sys.stderr)
        sys.exit(1)

    principal = account.get("trust_principal_arn") or "(unknown principal)"
    clusters = account.get("clusters") or []
    bullet_clusters = (
        f"  - Drop {len(clusters)} cluster binding(s) "
        f"(per-user EKS access entries; supplemental ClusterRoles stay)\n"
        if clusters else ""
    )
    confirm_q = (
        f"About to remove the binding between {principal} and "
        f"account {args.aws_account_id}.\n"
        f"  - Delete RO role {account['ro_role_name']}\n"
        f"{bullet_clusters}"
        f"  - Org-shared verify fixtures and supplemental ClusterRoles are "
        f"NOT deleted (purge_org_fixtures handles those — Skill 3, deferred)\n"
        f"Continue?"
    )
    if not common.prompt_yes_no(confirm_q, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    aws.teardown_delete(
        account["ro_role_name"], account["ro_role_arn"], clusters,
        profile=account["assumer_profile"],
        region=account["default_region"],
        account_ref=account["account_id"],
        dry_run=ctx.dry_run,
    )

    if ctx.dry_run:
        common.log.info("[dry-run] would drop account %s from state.json",
                        args.aws_account_id)
        return

    with common.update_state() as s:
        s["accounts"] = [a for a in s["accounts"]
                         if a["account_id"] != args.aws_account_id]
        if s.get("default_account_id") == args.aws_account_id:
            s["default_account_id"] = (
                s["accounts"][0]["account_id"] if s["accounts"] else ""
            )

    # Remove this account's on-demand AWS minter + its sudoers drop-in. The capability
    # note self-cleans (it globs installed brokers at SessionStart), so no re-render is
    # needed there. The runtime dir's aws/ files for this account are stale but harmless;
    # they're overwritten on the next mint and hold only already-expired RO creds.
    with common.admin_session(
        title=f"Remove AWS minter for account {args.aws_account_id}",
        actions=[
            f"Remove broker {common.broker_helper_path('aws', args.aws_account_id)}",
            f"Remove sudoers {common.broker_sudoers_path('aws', args.aws_account_id)}",
        ],
    ):
        common.remove_broker_helper("aws", args.aws_account_id, ctx=ctx)
        common.remove_broker_sudoers("aws", args.aws_account_id, ctx=ctx)

    state_after = common.state_read()
    if state_after["accounts"]:
        import render_launcher
        render_launcher.write_launcher(render_launcher.render(state_after))
    else:
        common.log.warning(
            "no accounts left in state.json. Re-run provision_account or "
            "delete /usr/local/bin/claude-ro to clean up the launcher."
        )

    common.log.info(
        "removed binding between %s and account %s",
        principal, args.aws_account_id,
    )


if __name__ == "__main__":
    main()
