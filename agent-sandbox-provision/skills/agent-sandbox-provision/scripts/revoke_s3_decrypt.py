#!/usr/bin/env python3
"""
revoke_s3_decrypt: reverse grant_s3_decrypt. Drops one bucket's decrypt grants (or
all of them) and re-puts the guardrails, so kms:Decrypt goes back to being denied
for that scope.

Both halves come back together: the grant's Allow statement disappears AND its
exclusion from the DenyKmsDecrypt condition disappears. With no grants left, the
deny is unconditional again — byte-identical to what provision-account writes.

Usage:
    revoke_s3_decrypt.py --provider aws (--bucket <name> [--prefix <p>] | --all)
                         [--aws-account-id <12-digit>]
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

from grant_s3_decrypt import resolve_account  # noqa: E402


def _label(g: dict) -> str:
    return g["bucket"] + (f"/{g['prefix']}*" if g.get("prefix") else " (whole bucket)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Revoke RO-role decrypt grants on S3 buckets.",
    )
    ap.add_argument("--provider", required=True, choices=["aws"])
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--bucket", help="revoke this bucket's grant(s)")
    group.add_argument("--all", action="store_true",
                       help="revoke every S3 decrypt grant on the account")
    ap.add_argument("--prefix", default=None,
                    help="with --bucket: revoke only this prefix grant. Omit to "
                         "revoke every grant on the bucket.")
    ap.add_argument("--aws-account-id", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    if args.prefix and not args.bucket:
        ap.error("--prefix requires --bucket")

    ctx = common.Ctx.from_args(args)
    aws = common.load_provider("aws")

    state = common.state_read()
    account = resolve_account(state, args.aws_account_id)
    account_id = account["account_id"]
    grants = list(account.get("s3_decrypt_grants") or [])

    if not grants:
        print(f"account {account_id} has no S3 decrypt grants — nothing to revoke.")
        return

    if args.all:
        doomed, keep = grants, []
    else:
        bucket = aws.validate_bucket_name(args.bucket.strip())
        prefix = args.prefix.strip() if args.prefix else None
        doomed = [g for g in grants
                  if g["bucket"] == bucket
                  and (prefix is None or (g.get("prefix") or None) == prefix)]
        keep = [g for g in grants if g not in doomed]

    if not doomed:
        listing = ", ".join(_label(g) for g in grants)
        print(f"no matching grant on account {account_id}. Granted: {listing}",
              file=sys.stderr)
        sys.exit(2)

    confirm_q = (
        f"Revoke decrypt access on account {account_id} "
        f"(role {account['ro_role_name']}):\n"
        + "".join(f"  - {_label(g)}\n" for g in doomed)
        + f"\n{len(keep)} grant(s) stay. kms:Decrypt goes back to denied for the "
          f"revoked scope(s).\nContinue?"
    )
    if not common.prompt_yes_no(confirm_q, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    if ctx.dry_run:
        common.log.info("[dry-run] would revoke %d grant(s) and re-put the inline "
                        "guardrails with %d remaining", len(doomed), len(keep))
        return

    target = {"account_id": account_id,
              "bucket": args.bucket if not args.all else "*",
              "prefix": args.prefix}
    with common.update_state() as s:
        common.begin_operation(s, "revoke-s3-decrypt", target)

    aws.attach_role_policies(account_id, account["ro_role_name"],
                             ctx=ctx, profile=account["assumer_profile"],
                             grants=keep)

    with common.update_state() as s:
        tgt = next(a for a in s["accounts"] if a["account_id"] == account_id)
        if keep:
            tgt["s3_decrypt_grants"] = keep
        else:
            tgt.pop("s3_decrypt_grants", None)
        common.mark_phase(s, "aws_role_policies")
        common.end_operation(s)

    common.log.info("revoked %d grant(s) on account %s; %d remaining",
                    len(doomed), account_id, len(keep))


if __name__ == "__main__":
    main()
