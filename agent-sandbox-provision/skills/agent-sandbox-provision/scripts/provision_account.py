#!/usr/bin/env python3
"""
provision_account: bind THIS user to a provider account.

Per engineer, per account. Creates the per-user RO IAM role and ensures the
org-shared verify fixtures exist (idempotent on existing-resource exceptions).
Does NOT bind any clusters — run `bind_cluster` for each cluster you want
this user's role to read.

Each engineer in your org runs this for themselves on every account they
need read access to. The org-shared fixtures (S3 bucket, KMS key, Secrets
Manager / DynamoDB / CloudWatch Logs entries) are created the first time,
then reused by every subsequent engineer's role for verify checks.

Usage:
    provision_account.py --provider aws \\
        --aws-profile <profile> \\
        --aws-account-id <12-digit-account-id> \\
        --aws-region <region>

All flags mandatory; no defaults. Future GCP/Azure variants will declare
their own provider-specific flag set (--gcp-project-id, etc.).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

_IAM_USER_ARN_RE = re.compile(r"^arn:aws:iam::([0-9]{12}):user/")


def resolve_user_principal(profile: str, expected_account_id: str) -> str:
    """Return the IAM-user ARN for `profile`. Fail if profile doesn't resolve to
    an IAM user, or if the resolved account doesn't match `expected_account_id`
    (catches "wrong profile for this account" mistakes early)."""
    common.log.info("verifying assumer profile %r", profile)
    try:
        ident = common.aws_caller_identity(profile)
    except common.AssumeRoleError as exc:
        print(f"could not authenticate as profile {profile}: {exc}", file=sys.stderr)
        print(exc.hint(), file=sys.stderr)
        sys.exit(2)
    except Exception as exc:  # noqa: BLE001
        print(f"could not run sts:get-caller-identity for profile {profile}: {exc}",
              file=sys.stderr)
        sys.exit(2)

    arn = ident["Arn"]
    actual_account = ident["Account"]
    if actual_account != expected_account_id:
        print(
            f"profile {profile!r} resolves to account {actual_account}, but "
            f"--aws-account-id is {expected_account_id}. Fix the flags or use a "
            f"different profile.",
            file=sys.stderr,
        )
        sys.exit(2)
    if not _IAM_USER_ARN_RE.match(arn):
        print(
            f"profile {profile} resolves to {arn!r} — v1 supports IAM-user "
            "principals only.\nSSO/federated principals are deferred to Phase 2.",
            file=sys.stderr,
        )
        sys.exit(2)
    return arn


def provision_account_phases(profile: str, region: str, *,
                             ctx: common.Ctx,
                             account_id: str,
                             user_principal_arn: str) -> dict:
    """Run the provider-side phases for one account. Returns an account record
    suitable for appending to state.accounts[]. Does NOT touch clusters."""
    aws = common.load_provider("aws")

    # Phase: aws_role + aws_role_policies.
    role_info = aws.provision_identity(account_id, user_principal_arn,
                                       ctx=ctx, profile=profile)
    # Existing s3_decrypt_grants must be re-supplied: put-role-policy REPLACES the
    # inline document, so a re-run that omitted them would silently revoke them.
    existing = next((a for a in (common.state_read().get("accounts") or [])
                     if a.get("account_id") == account_id), {})
    aws.attach_role_policies(account_id, role_info["role_name"],
                             ctx=ctx, profile=profile,
                             grants=existing.get("s3_decrypt_grants") or [])
    if not ctx.dry_run:
        with common.update_state() as s:
            common.mark_phase(s, "aws_role_policies")

    # Phase: account-level verify fixtures (org-shared; idempotent).
    fixtures = aws.ensure_verify_fixtures(
        account_id, region, ctx=ctx, profile=profile,
        clusters=[],  # provision_account does not touch clusters.
    )
    if not ctx.dry_run:
        with common.update_state() as s:
            common.mark_phase(s, "verify_fixtures")

    return {
        "account_id": account_id,
        "ro_role_name": role_info["role_name"],
        "ro_role_arn": role_info["role_arn"],
        "default_region": region,
        "assumer_profile": profile,
        "trust_principal_arn": user_principal_arn,
        "trust_principal_kind": "iam_user",
        "clusters": [],
        "verify_fixtures": fixtures,
    }


def commit_account_record(record: dict) -> None:
    with common.update_state() as s:
        s.setdefault("accounts", []).append(record)
        if not s.get("default_account_id"):
            s["default_account_id"] = record["account_id"]
        common.mark_phase(s, "state_commit")


def render_launcher_now() -> None:
    import render_launcher
    render_launcher.write_launcher(render_launcher.render(common.state_read()))


def install_aws_broker(record: dict, *, ctx: common.Ctx) -> None:
    """Install this account's on-demand AWS mint broker: the per-account helper, its
    pinned sudoers drop-in (with the bounded region-argument rule), the runtime dir,
    and the capability note. Idempotent, so safe on create and on reconcile. Requires
    no active admin_session — opens its own."""
    if ctx.dry_run:
        common.log.info("[dry-run] would install AWS minter for account %s",
                        record["account_id"])
        return
    with common.admin_session(
        title=f"Install AWS minter for account {record['account_id']}",
        actions=[
            f"Ensure runtime dir {common.RUNTIME_DIR}",
            f"Install broker {common.broker_helper_path('aws', record['account_id'])}",
            f"Install sudoers {common.broker_sudoers_path('aws', record['account_id'])}",
            "Install/refresh the claude-ro capability note",
        ],
    ):
        common.ensure_runtime_dir(ctx=ctx)
        helper = common.render_aws_broker(record)
        common.install_broker_helper("aws", record["account_id"], helper, ctx=ctx)
        common.install_broker_sudoers("aws", record["account_id"],
                                      ctx=ctx, allow_arg=True)
        common.install_capability_note(ctx=ctx)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Bind THIS user to a provider account: create per-user RO "
                    "role and ensure org-shared verify fixtures.",
    )
    ap.add_argument("--provider", required=True, choices=["aws"],
                    help="Cloud provider.")
    ap.add_argument("--aws-profile", required=True,
                    help="The user's AWS CLI profile that has working creds in "
                         "this account.")
    ap.add_argument("--aws-account-id", required=True,
                    help="12-digit AWS account ID.")
    ap.add_argument("--aws-region", required=True,
                    help="Default AWS region for org-shared fixtures in this account.")
    ap.add_argument("--yes", action="store_true",
                    help="Auto-answer interactive prompts.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.provider != "aws":
        print(f"provider {args.provider!r} not yet implemented", file=sys.stderr)
        sys.exit(2)

    common.validate_aws_profile(args.aws_profile)
    common.validate_aws_account_id(args.aws_account_id)
    common.validate_aws_region(args.aws_region)

    ctx = common.Ctx.from_args(args)
    state = common.state_read()

    # Authenticate, validate principal, validate account match.
    arn = resolve_user_principal(args.aws_profile, args.aws_account_id)

    # Reconcile-on-rerun: if this account is already bound to the SAME principal,
    # skip the AWS work (already done) and just (re)render the launcher. Recovers
    # the partial-failure case where state.json was committed but the launcher
    # write didn't land.
    existing = next(
        (a for a in state.get("accounts") or []
         if a["account_id"] == args.aws_account_id),
        None,
    )
    if existing is not None and existing.get("trust_principal_arn") == arn:
        if ctx.dry_run:
            common.log.info(
                "[dry-run] binding for %s already recorded; would reconcile launcher",
                args.aws_account_id,
            )
            return
        common.log.info(
            "binding for %s already recorded; reconciling launcher + AWS minter",
            args.aws_account_id,
        )
        render_launcher_now()
        install_aws_broker(existing, ctx=ctx)
        common.log.info(
            "reconciled %s -> RO role %s", args.aws_account_id, existing["ro_role_name"],
        )
        return

    # Idempotency check (different principal binding the same account = real conflict).
    if any(a["account_id"] == args.aws_account_id
           for a in state.get("accounts") or []):
        decision = common.resolve_idempotency_conflict(
            f"binding between {arn} and account "
            f"{args.aws_account_id}", ctx,
        )
        if decision == "stop":
            print("aborted (binding already exists)", file=sys.stderr)
            sys.exit(1)
        if decision == "overwrite":
            print(
                f"to overwrite, run: deprovision_account --provider aws "
                f"--aws-account-id {args.aws_account_id} --yes",
                file=sys.stderr,
            )
            sys.exit(1)
        common.log.info("custom intent recorded: %s", decision)

    # Begin operation.
    target = {"account_id": args.aws_account_id, "profile": args.aws_profile,
              "region": args.aws_region}
    if not ctx.dry_run:
        with common.update_state() as s:
            common.begin_operation(s, "provision-account", target)

    record = provision_account_phases(
        args.aws_profile, args.aws_region,
        ctx=ctx, account_id=args.aws_account_id, user_principal_arn=arn,
    )

    if ctx.dry_run:
        common.log.info("[dry-run] would record binding for %s to account %s",
                        arn, args.aws_account_id)
        return

    commit_account_record(record)
    with common.update_state() as s:
        common.end_operation(s)
    render_launcher_now()
    install_aws_broker(record, ctx=ctx)

    common.log.info(
        "bound %s to account %s as RO role %s",
        arn, args.aws_account_id, record["ro_role_name"],
    )


if __name__ == "__main__":
    main()
