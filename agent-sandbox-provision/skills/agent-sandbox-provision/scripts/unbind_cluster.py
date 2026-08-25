#!/usr/bin/env python3
"""
unbind_cluster: remove THIS user's binding to a k8s cluster.

Reverses bind_cluster for one cluster on one provider account. Disassociates
the per-user EKS access policy and deletes the per-user EKS access entry
for this user's RO role.

Does NOT delete the supplemental ClusterRole (org-shared, used by every
engineer's RO role on this cluster) or the verify pod (org-shared, same
reason). Those are deleted only by `purge_org_fixtures` (Skill 3, deferred).

Idempotent (NotFound is success at every step).

Usage:
    unbind_cluster.py --provider aws --aws-account-id <12-digit> --cluster-name <name>

Region and profile are read from state.json (recorded at bind_cluster time).
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
        description="Remove this user's binding to a k8s cluster (per-user EKS "
                    "access entry; org-shared ClusterRole stays).",
    )
    ap.add_argument("--provider", required=True, choices=["aws"])
    ap.add_argument("--aws-account-id", required=True,
                    help="12-digit AWS account ID.")
    ap.add_argument("--cluster-name", required=True,
                    help="k8s cluster name as registered in state.json.")
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
    principal = account.get("trust_principal_arn") or "(unknown principal)"
    cluster = next((c for c in account.get("clusters") or []
                    if c["cluster_name"] == args.cluster_name), None)
    if cluster is None:
        print(f"cluster {args.cluster_name} is not bound to account "
              f"{args.aws_account_id} for {principal}", file=sys.stderr)
        sys.exit(2)

    confirm_q = (
        f"About to remove the binding between {principal} and "
        f"cluster {args.cluster_name} on account {args.aws_account_id}.\n"
        f"  - Disassociate EKS view policy from {account['ro_role_arn']}\n"
        f"  - Delete EKS access entry for that role on the cluster\n"
        f"  - Org-shared supplemental ClusterRole on this cluster is NOT "
        f"deleted (other engineers may still need it)\n"
        f"Continue?"
    )
    if not common.prompt_yes_no(confirm_q, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    aws.unbind_cluster(
        account["ro_role_arn"], cluster["cluster_name"], cluster,
        profile=account["assumer_profile"],
        region=cluster.get("region", account["default_region"]),
        account_ref=account["account_id"],
        dry_run=ctx.dry_run,
    )

    if ctx.dry_run:
        common.log.info("[dry-run] would drop %s from state.json",
                        args.cluster_name)
        return

    with common.update_state() as s:
        target = next((a for a in s["accounts"]
                       if a["account_id"] == args.aws_account_id), None)
        if target is None:
            return
        target["clusters"] = [c for c in target.get("clusters") or []
                              if c["cluster_name"] != args.cluster_name]

    # Re-render the launcher (the kubeconfig case-arms include this cluster).
    import render_launcher
    render_launcher.write_launcher(render_launcher.render(common.state_read()))

    common.log.info(
        "removed binding between %s and cluster %s on account %s",
        principal, args.cluster_name, args.aws_account_id,
    )


if __name__ == "__main__":
    main()
