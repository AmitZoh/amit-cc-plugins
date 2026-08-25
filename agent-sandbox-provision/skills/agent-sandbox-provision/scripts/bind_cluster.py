#!/usr/bin/env python3
"""
bind_cluster: bind THIS user's RO role on a provider account to one k8s cluster.

Reuses the per-user RO role created by `provision_account`. Adds the
per-user EKS access entry, ensures the org-shared supplemental ClusterRole
exists on the cluster (idempotent — kubectl apply overwrites with the same
content), and ensures the org-shared verify pod / CRD-kind sentinel exist.

One cluster per call. No implicit "current kubectl context" semantics — you
name the cluster explicitly and bind_cluster prints the full coordinates
(user, account, cluster, region, kube-context) for confirmation before any
write lands.

Usage:
    bind_cluster.py --provider aws \\
        --aws-account-id <12-digit> \\
        --cluster-name <name> \\
        --aws-region <region>

Profile is read from state.json (recorded at provision_account time).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


def bind_one(account: dict, cluster_name: str, region: str, *,
             ctx: common.Ctx) -> dict:
    """Bind one cluster to `account`'s RO role. Returns {bind_record, fixtures}."""
    aws = common.load_provider("aws")

    bind_record = aws.bind_cluster(
        account["account_id"], cluster_name, account["ro_role_arn"],
        ctx=ctx, profile=account["assumer_profile"], region=region,
    )

    # Per-cluster org-shared fixtures (verify pod + CRD-kind sentinel).
    fixtures = aws.ensure_verify_fixtures(
        account["account_id"], region,
        ctx=ctx, profile=account["assumer_profile"],
        clusters=[bind_record],
    )

    return {"bind_record": bind_record, "fixtures": fixtures}


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Bind this user's RO role to one k8s cluster.",
    )
    ap.add_argument("--provider", required=True, choices=["aws"])
    ap.add_argument("--aws-account-id", required=True,
                    help="12-digit AWS account ID (must already be provisioned).")
    ap.add_argument("--cluster-name", required=True,
                    help="k8s cluster name as registered with the provider (EKS clusterName).")
    ap.add_argument("--aws-region", required=True,
                    help="Region the cluster lives in (may differ from the account "
                         "default region recorded by provision_account).")
    ap.add_argument("--yes", action="store_true",
                    help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.provider != "aws":
        print(f"provider {args.provider!r} not yet implemented", file=sys.stderr)
        sys.exit(2)

    common.validate_aws_account_id(args.aws_account_id)
    common.validate_aws_region(args.aws_region)

    ctx = common.Ctx.from_args(args)
    state = common.state_read()
    account = next((a for a in state["accounts"]
                    if a["account_id"] == args.aws_account_id), None)
    if account is None:
        print(
            f"no binding to account {args.aws_account_id} — run "
            f"provision_account first.",
            file=sys.stderr,
        )
        sys.exit(2)
    principal = account.get("trust_principal_arn") or "(unknown principal)"

    # Idempotency check.
    existing = next((c for c in account.get("clusters") or []
                     if c["cluster_name"] == args.cluster_name), None)
    aws = common.load_provider("aws")
    kctx_name = aws.kube_context_for_cluster(
        args.aws_account_id, args.aws_region, args.cluster_name,
    )
    if existing is not None:
        decision = common.resolve_idempotency_conflict(
            f"binding between {principal} and cluster "
            f"{args.cluster_name} on account {args.aws_account_id}", ctx,
        )
        if decision == "stop":
            print("aborted (cluster already bound)", file=sys.stderr)
            sys.exit(1)
        if decision == "overwrite":
            common.log.info("overwriting existing binding for cluster %s",
                            args.cluster_name)
            aws.unbind_cluster(
                account["ro_role_arn"], args.cluster_name, existing,
                profile=account["assumer_profile"],
                region=existing.get("region", account["default_region"]),
                account_ref=account["account_id"], dry_run=ctx.dry_run,
            )
            if not ctx.dry_run:
                with common.update_state() as s:
                    tgt = next(a for a in s["accounts"]
                               if a["account_id"] == args.aws_account_id)
                    tgt["clusters"] = [c for c in tgt.get("clusters") or []
                                       if c["cluster_name"] != args.cluster_name]
        else:
            common.log.info("custom intent recorded: %s", decision)

    # Confirmation gate. Print full coordinates so the user can sanity-check
    # before any IAM / EKS / k8s call lands. No implicit "current context".
    confirm_q = (
        f"About to bind {principal} to k8s cluster "
        f"{args.cluster_name} (account {args.aws_account_id}, region "
        f"{args.aws_region}, kube-context {kctx_name}).\n"
        f"  - Add per-user EKS access entry with AmazonEKSViewPolicy\n"
        f"  - Ensure org-shared supplemental ClusterRole "
        f"claude-ro-crd-read-{_safe_label(args.cluster_name)} exists "
        f"(applied via kubectl from your current admin credentials)\n"
        f"  - Ensure org-shared verify pod + CRD-kind sentinel exist on "
        f"the cluster\n"
        f"Continue?"
    )
    if not common.prompt_yes_no(confirm_q, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    # Begin operation.
    target = {"account_id": args.aws_account_id,
              "cluster_name": args.cluster_name, "region": args.aws_region}
    if not ctx.dry_run:
        with common.update_state() as s:
            common.begin_operation(s, "bind-cluster", target)

    out = bind_one(account, args.cluster_name, args.aws_region, ctx=ctx)
    bind_record = out["bind_record"]
    fixtures = out["fixtures"]

    if ctx.dry_run:
        common.log.info("[dry-run] would record cluster %s in state.json",
                        args.cluster_name)
        return

    with common.update_state() as s:
        tgt = next(a for a in s["accounts"]
                   if a["account_id"] == args.aws_account_id)
        tgt.setdefault("clusters", []).append(bind_record)
        existing_fix = tgt.setdefault("verify_fixtures", {})
        for k, v in fixtures.items():
            if isinstance(v, dict) and isinstance(existing_fix.get(k), dict):
                existing_fix[k].update(v)
            else:
                existing_fix.setdefault(k, v)
        common.mark_phase(s, "k8s_supplemental_role")
        common.end_operation(s)

    # Smoke-check the bind.
    ok, detail = common.kubectl_smoke_check(kctx_name)
    if ok:
        common.log.info("smoke check passed for kube-context %s", kctx_name)
    else:
        common.log.warning("smoke check failed for kube-context %s: %s",
                           kctx_name, detail)

    common.log.info(
        "bound %s to cluster %s on account %s",
        principal, args.cluster_name, args.aws_account_id,
    )


def _safe_label(s: str) -> str:
    import re
    s = s.lower()
    s = re.sub(r"[^a-z0-9-]", "-", s).strip("-")
    return s[:63] or "unnamed"


if __name__ == "__main__":
    main()
