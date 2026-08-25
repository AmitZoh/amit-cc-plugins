#!/usr/bin/env python3
"""
Run the verify suite.

Two invocation modes:

  verify --provider aws --aws-account-id <id>   # one account
  verify --all                                   # sweep all bound providers/accounts

`--provider` is mandatory in single-account mode (no defaults). `--all` and
`--provider` are mutually exclusive.

Returns non-zero if any check fails. Prints a per-check breakdown.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import time

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


def _per_launch_kubeconfig_for(account_id: str) -> str:
    pid = os.getpid()
    epoch = int(time.time())
    proc = subprocess.run(
        [sys.executable,
         str(SKILL_DIR / "scripts" / "render_per_launch_kubeconfig.py"),
         "--account", account_id,
         "--launcher-pid", str(pid),
         "--start-epoch", str(epoch)],
        capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def verify_account(account: dict, *, ctx: common.Ctx) -> tuple[int, int]:
    """Run verify for one account. Returns (passed, total)."""
    aws = common.load_provider("aws")  # v1: AWS only. Future: route on a per-account 'provider' field.
    fixtures = account.get("verify_fixtures") or {}
    clusters = account.get("clusters") or []
    region = account["default_region"]
    profile = account["assumer_profile"]
    role_arn = account["ro_role_arn"]
    account_id = account["account_id"]

    kubeconfig = None
    if clusters:
        try:
            kubeconfig = _per_launch_kubeconfig_for(account_id)
        except subprocess.CalledProcessError as exc:
            common.log.error("could not render per-launch kubeconfig: %s", exc.stderr)
            return (0, 1)

    try:
        results = aws.verify(
            account_id, role_arn, fixtures,
            ctx=ctx, profile=profile, region=region,
            clusters=clusters, grants=account.get("s3_decrypt_grants") or [],
            kubeconfig=kubeconfig,
        )
    except common.AssumeRoleError as exc:
        print(f"\n[ {account_id} ] could not assume RO role:", file=sys.stderr)
        print(f"  {exc}", file=sys.stderr)
        print(f"  underlying: {exc.underlying}", file=sys.stderr)
        print(f"  hint: {exc.hint()}", file=sys.stderr)
        return (0, 1)

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"\n[ {account_id} ]  {passed}/{total} checks passed")
    for r in results:
        mark = "✓" if r["passed"] else "✗"
        print(f"  {mark} {r['name']}  (expected {r['expected']}, got {r['actual']})")
        if not r["passed"] and r.get("detail"):
            print(f"      detail: {r['detail']}")
    return (passed, total)


def _print_results(label: str, results: list[dict]) -> tuple[int, int]:
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"\n[ {label} ]  {passed}/{total} checks passed")
    for r in results:
        mark = "✓" if r["passed"] else "✗"
        print(f"  {mark} {r['name']}  (expected {r['expected']}, got {r['actual']})")
        if not r["passed"] and r.get("detail"):
            print(f"      detail: {r['detail']}")
    return (passed, total)


def verify_credential_source(kind: str, record: dict, *, ctx: common.Ctx) -> tuple[int, int]:
    """Verify one github[] (per-org) / mongodb[] / snowflake[] identity: mint a real credential, then
    run the provider's read-works + write-denied checks."""
    provider = common.load_provider(kind)
    label = record.get("name") or record.get("login") or "?"
    try:
        secret = common.secret_read(record["secret_ref"])
        env = provider.mint(record, secret)
    except SystemExit as exc:
        print(f"\n[ {kind}:{label} ]  could not mint credential: {exc}", file=sys.stderr)
        return (0, 1)
    try:
        results = provider.verify(record, env, ctx=ctx)
    except SystemExit as exc:
        print(f"\n[ {kind}:{label} ]  verify error: {exc}", file=sys.stderr)
        return (0, 1)
    return _print_results(f"{kind}:{label}", results)


def verify_all_github(state: dict, *, ctx: common.Ctx) -> tuple[int, int]:
    """Verify every bound org's App: mint its token, run read-works + write-denied."""
    tp = t = 0
    for record in (state.get("github") or []):
        p, tot = verify_credential_source("github", record, ctx=ctx)
        tp += p
        t += tot
    return tp, t


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the verify suite for a bound account.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all", action="store_true",
                      help="Sweep every bound account + github/mongodb/snowflake identity in state.json.")
    mode.add_argument("--provider", choices=["aws"],
                      help="Run for a single provider account. Requires --aws-account-id.")
    mode.add_argument("--github", action="store_true",
                      help="Verify every bound GitHub org.")
    mode.add_argument("--mongodb", action="store_true",
                      help="Verify all bound MongoDB databases.")
    mode.add_argument("--snowflake", action="store_true",
                      help="Verify all bound Snowflake accounts.")
    ap.add_argument("--aws-account-id",
                    help="Required when --provider=aws. 12-digit AWS account ID.")
    ap.add_argument("--yes", action="store_true",
                    help="No effect on verify; included for argparse parity.")
    ap.add_argument("--dry-run", action="store_true",
                    help="No effect on verify (verify is read-only); for parity.")
    args = ap.parse_args()

    if args.provider == "aws" and not args.aws_account_id:
        ap.error("--provider aws requires --aws-account-id")
    if args.provider and args.provider != "aws":
        ap.error(f"provider {args.provider!r} not yet implemented")

    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)

    total_passed = 0
    total = 0

    # --- targeted github (all orgs) / mongodb (all DBs) / snowflake (all accounts) modes ---
    if args.github:
        if not state.get("github"):
            print("no GitHub orgs bound to verify", file=sys.stderr)
            sys.exit(2)
        total_passed, total = verify_all_github(state, ctx=ctx)
        print(f"\noverall: {total_passed}/{total} checks passed")
        sys.exit(0 if total_passed == total else 1)

    if args.mongodb:
        records = state.get("mongodb") or []
        if not records:
            print("no MongoDB databases bound to verify", file=sys.stderr)
            sys.exit(2)
        for record in records:
            p, t = verify_credential_source("mongodb", record, ctx=ctx)
            total_passed += p
            total += t
        print(f"\noverall: {total_passed}/{total} checks passed")
        sys.exit(0 if total_passed == total else 1)

    if args.snowflake:
        records = state.get("snowflake") or []
        if not records:
            print("no Snowflake accounts bound to verify", file=sys.stderr)
            sys.exit(2)
        for record in records:
            p, t = verify_credential_source("snowflake", record, ctx=ctx)
            total_passed += p
            total += t
        print(f"\noverall: {total_passed}/{total} checks passed")
        sys.exit(0 if total_passed == total else 1)

    # --- account modes (aws single / --all sweep) ---
    accounts = state.get("accounts") or []
    if args.provider:
        common.validate_aws_account_id(args.aws_account_id)
        target = next((a for a in accounts if a["account_id"] == args.aws_account_id), None)
        if target is None:
            print(f"unknown account: {args.aws_account_id}", file=sys.stderr)
            sys.exit(2)
        accounts = [target]

    swept = 0
    for a in accounts:
        p, t = verify_account(a, ctx=ctx)
        total_passed += p
        total += t
        swept += 1

    # --all also sweeps every bound GitHub org + every MongoDB DB + every Snowflake account.
    if args.all:
        for record in (state.get("github") or []):
            p, t = verify_credential_source("github", record, ctx=ctx)
            total_passed += p
            total += t
            swept += 1
        for record in (state.get("mongodb") or []):
            p, t = verify_credential_source("mongodb", record, ctx=ctx)
            total_passed += p
            total += t
            swept += 1
        for record in (state.get("snowflake") or []):
            p, t = verify_credential_source("snowflake", record, ctx=ctx)
            total_passed += p
            total += t
            swept += 1

    if swept == 0:
        print("nothing bound to verify in state.json", file=sys.stderr)
        sys.exit(2)

    print(f"\noverall: {total_passed}/{total} checks passed")
    sys.exit(0 if total_passed == total else 1)


if __name__ == "__main__":
    main()
