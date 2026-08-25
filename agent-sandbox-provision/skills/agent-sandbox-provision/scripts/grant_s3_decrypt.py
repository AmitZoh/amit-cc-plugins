#!/usr/bin/env python3
"""
grant_s3_decrypt: let the RO role decrypt SSE-KMS objects in ONE S3 bucket
(optionally one prefix of it), by punching a scoped hole in the guardrails.

Why two policy changes and not one: the guardrails deny kms:Decrypt outright, and
in IAM an explicit deny beats any allow — so an allow on its own changes nothing.
But `ReadOnlyAccess` carries no kms:Decrypt either, so narrowing the deny on its own
grants nothing. Both halves are written together, from the same grant record:

  Deny  kms:Decrypt  *   unless kms:EncryptionContext:aws:s3:arn matches a grant
  Allow kms:Decrypt  <key arn>  when ViaService=s3.<region> and the context matches

Prefix scoping depends on the bucket. S3 puts the OBJECT arn in the encryption
context normally, but the BUCKET arn when the bucket has S3 Bucket Keys enabled —
one data key per bucket, so nothing object-specific exists to match on. On a
bucket-key bucket a prefix grant is therefore unwritable, and this command stops to
ask rather than quietly widening or writing a grant that would fail every GetObject.

Usage:
    grant_s3_decrypt.py --provider aws --bucket <name> [--prefix <key-prefix>]
                        [--aws-account-id <12-digit>]

Profile and role are read from state.json (recorded at provision_account time).
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


def resolve_account(state: dict, account_id: str | None) -> dict:
    """Pick the accounts[] record to grant on. Explicit flag wins; otherwise the
    default account; otherwise the sole one. Never guesses among several."""
    accounts = state.get("accounts") or []
    if not accounts:
        raise SystemExit("no provisioned AWS account — run provision-account first.")
    if account_id:
        rec = next((a for a in accounts if a["account_id"] == account_id), None)
        if rec is None:
            raise SystemExit(
                f"account {account_id} is not provisioned. Bound: "
                f"{', '.join(a['account_id'] for a in accounts)}")
        return rec
    if len(accounts) == 1:
        return accounts[0]
    default = state.get("default_account_id")
    rec = next((a for a in accounts if a["account_id"] == default), None)
    if rec is None:
        raise SystemExit(
            f"{len(accounts)} accounts are provisioned and none is the default — "
            f"pass --aws-account-id. Bound: "
            f"{', '.join(a['account_id'] for a in accounts)}")
    return rec


def resolve_bucket_key_conflict(bucket: str, prefix: str, ctx: common.Ctx) -> str:
    """The bucket has BucketKeyEnabled=true and a --prefix was asked for, which
    cannot be expressed. Returns "widen", "abort", or "custom:<text>".

    Fail-closed everywhere: --yes, a dismissed dialog, and EOF all mean abort. The
    widening is a real broadening of what the sandbox can read, so it is never the
    silent default."""
    explain = (
        f"s3://{bucket} has BucketKeyEnabled=true, so S3 puts the BUCKET arn in the "
        f"KMS encryption context — never the object arn. A grant scoped to "
        f"'{prefix}' cannot be written: every GetObject would still be denied.\n\n"
        f"  • Grant whole bucket — decrypt anything in s3://{bucket}\n"
        f"  • Abort — write nothing"
    )
    if ctx.yes:
        common.log.warning(
            "[--yes] %s has bucket keys on; a --prefix grant is unwritable. Aborting "
            "(re-run without --yes to choose, or drop --prefix to grant the bucket).",
            bucket)
        return "abort"
    if not sys.stdin.isatty():
        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')
        osa_line = (
            f'display dialog "{_esc(explain)}" '
            f'buttons {{"Abort", "Grant whole bucket"}} '
            f'with icon caution with title "agent-sandbox-provision"'
        )
        proc = subprocess.run(
            ["osascript", "-e", osa_line, "-e", "button returned of result"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            common.log.info("dialog dismissed; aborting")
            return "abort"
        return "widen" if proc.stdout.strip() == "Grant whole bucket" else "abort"

    print(explain, file=sys.stderr)
    print("  1. widen  — grant the whole bucket\n"
          "  2. abort  — write nothing (default)\n"
          "  3. custom — describe a different intent in free text",
          file=sys.stderr)
    while True:
        try:
            resp = input("> ").strip().lower()
        except EOFError:
            return "abort"
        if resp in ("", "2", "abort", "a"):
            return "abort"
        if resp in ("1", "widen", "w"):
            return "widen"
        if resp in ("3", "custom", "c"):
            try:
                detail = input("describe: ").strip()
            except EOFError:
                return "abort"
            return f"custom:{detail}"
        print("Please answer 1, 2, or 3.", file=sys.stderr)


def merge_grant(grants: list[dict], new: dict) -> tuple[list[dict], list[str]]:
    """Fold `new` into `grants`. Returns (grants, notes).

    Same (bucket, prefix) → replaced in place, so a re-run refreshes a key or region
    that changed on the bucket. A new bucket-wide grant supersedes that bucket's
    prefix grants, which would otherwise sit in the policy granting nothing extra."""
    notes: list[str] = []
    out = []
    for g in grants:
        if g["bucket"] == new["bucket"] and (g.get("prefix") or None) == new["prefix"]:
            notes.append(f"replaced the existing grant for {new['bucket']}"
                         + (f"/{new['prefix']}" if new["prefix"] else ""))
            continue
        if g["bucket"] == new["bucket"] and new["prefix"] is None and g.get("prefix"):
            notes.append(f"dropped the now-redundant prefix grant "
                         f"{g['bucket']}/{g['prefix']} (superseded by bucket-wide)")
            continue
        if (g["bucket"] == new["bucket"] and g.get("prefix") is None
                and new["prefix"] is not None):
            notes.append(f"{new['bucket']} is already granted bucket-wide; the new "
                         f"prefix grant adds nothing")
        out.append(g)
    out.append(new)
    return out, notes


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Let the RO role decrypt SSE-KMS objects in one S3 bucket.",
    )
    ap.add_argument("--provider", required=True, choices=["aws"])
    ap.add_argument("--bucket", required=True, help="S3 bucket name (not an ARN, not a URI)")
    ap.add_argument("--prefix", default=None,
                    help="object-key prefix; only possible when the bucket has "
                         "BucketKeyEnabled=false")
    ap.add_argument("--aws-account-id", default=None,
                    help="which provisioned account's RO role; defaults to the sole "
                         "or default account")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", action="store_true")
    args = ap.parse_args()

    ctx = common.Ctx.from_args(args)
    aws = common.load_provider("aws")

    bucket = aws.validate_bucket_name(args.bucket.strip())
    prefix = aws.validate_object_prefix(args.prefix.strip()) if args.prefix else None

    state = common.state_read()
    account = resolve_account(state, args.aws_account_id)
    account_id = account["account_id"]
    profile = account["assumer_profile"]
    grants = list(account.get("s3_decrypt_grants") or [])

    info = aws.inspect_bucket_encryption(bucket, profile=profile,
                                         role_account_id=account_id)
    for note in info["notes"]:
        common.log.warning("%s", note)

    if not info["kms_key_arn"]:
        algo = info["sse_algorithm"] or "none"
        print(
            f"s3://{bucket} has default encryption {algo!r} — no KMS key is involved, "
            f"so there is nothing to grant. The RO role's ReadOnlyAccess already "
            f"covers s3:GetObject there; if reads are failing, the cause is the "
            f"bucket policy or the object's own SSE settings, not kms:Decrypt.",
            file=sys.stderr,
        )
        sys.exit(2)

    if prefix and info["bucket_key_enabled"]:
        decision = resolve_bucket_key_conflict(bucket, prefix, ctx)
        if decision == "abort":
            print("aborted — nothing written", file=sys.stderr)
            sys.exit(1)
        if decision.startswith("custom:"):
            common.log.info("custom intent recorded: %s", decision[len("custom:"):])
            print("aborted — nothing written; custom intent needs a different command",
                  file=sys.stderr)
            sys.exit(3)
        common.log.warning("widening %s/%s to the whole bucket", bucket, prefix)
        prefix = None

    grant = aws.build_grant(bucket, prefix, info)
    merged, notes = merge_grant(grants, grant)
    for note in notes:
        common.log.info("%s", note)

    # Assemble the document now, before anything is stamped or written: an
    # over-limit policy must fail with nothing half-done.
    try:
        aws.deny_policy(merged)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)

    scope = f"s3://{bucket}/{prefix}*" if prefix else f"s3://{bucket} (whole bucket)"
    managed = " (AWS-managed)" if info.get("key_manager") == "AWS" else ""
    confirm_q = (
        f"Grant claude-ro decrypt access:\n"
        f"  account:  {account_id}\n"
        f"  role:     {account['ro_role_name']}\n"
        f"  scope:    {scope}\n"
        f"  key:      {info['kms_key_arn']}{managed}\n"
        f"  context:  {grant['encryption_context']} ({grant['context_match']})\n"
        f"  via:      s3.{info['region']}.amazonaws.com only\n\n"
        f"Anything readable in that scope becomes readable by the sandboxed agent, "
        f"including credentials stored there. kms:Decrypt stays denied everywhere "
        f"else.\nContinue?"
    )
    if not common.prompt_yes_no(confirm_q, default=False, ctx=ctx):
        print("aborted", file=sys.stderr)
        sys.exit(1)

    if ctx.dry_run:
        common.log.info("[dry-run] would grant %s on account %s and re-put the "
                        "inline guardrails with %d grant(s)",
                        scope, account_id, len(merged))
        return

    target = {"account_id": account_id, "bucket": bucket, "prefix": prefix}
    with common.update_state() as s:
        common.begin_operation(s, "grant-s3-decrypt", target)

    aws.attach_role_policies(account_id, account["ro_role_name"],
                             ctx=ctx, profile=profile, grants=merged)

    with common.update_state() as s:
        tgt = next(a for a in s["accounts"] if a["account_id"] == account_id)
        tgt["s3_decrypt_grants"] = merged
        common.mark_phase(s, "aws_role_policies")
        common.end_operation(s)

    common.log.info("granted kms:Decrypt for %s to %s on account %s",
                    scope, account["ro_role_name"], account_id)
    print(
        f"\nGranted. Verify end-to-end with:\n"
        f"  python3 {SKILL_DIR}/scripts/verify.py --provider aws "
        f"--aws-account-id {account_id}\n"
        f"Existing claude-ro sessions keep their old policy evaluation only until "
        f"their next call — IAM changes take effect immediately, no relaunch needed.",
    )


if __name__ == "__main__":
    main()
