#!/usr/bin/env python3
"""
scan.py — sweep AWS surfaces reachable from the read-only sandbox identity for
plaintext credentials. Reports LOCATION ONLY; never values.

Runs INSIDE the agent-sandbox sandbox (claude-ro), and only there.
The launcher hands in assumed RO credentials via AWS_* env vars; scan.py uses
them directly, learns the account/role/region from the assumed identity and
the launcher-set env, and scans that account.

To scan a different account: relaunch claude-ro with `--account <other>`.

Usage (inside claude-ro):
    python3 scan.py [--dry-run]

No --provider, no --aws-account-id, no --all. The runtime context is the spec:
whatever account claude-ro was launched against is the account that gets
scanned. A safety net refuses to run if the assumed role doesn't look like a
claude-ro RO role (catches accidental SSO/SAML env-var leakage).

Cross-imports Skill 1's _common helpers + AWS provider (surface_list + error
helpers) from the sibling agent-sandbox skill under this same
plugin's skills/ directory. Skill 1 is canonical for shared bundle code.

Exit codes:
  0  scan completed successfully
  1  scan failed
  2  not running with assumed claude-ro creds; preflight failure
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import pathlib
import pwd
import sys
import typing as t

# ---------- cross-skill bootstrap ----------

# Both skills now ship as sibling skills/ under the same plugin, so Skill 1 is
# located relative to this file rather than via a fixed ~/.claude/skills/...
# path: parent -> scripts, parent.parent -> cred-sweep, parent.parent.parent
# -> skills/, then across to agent-sandbox.
SKILL1 = pathlib.Path(__file__).resolve().parent.parent.parent / "provision"
SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent

# (1) Skill 1's _common via sys.path. Idempotent on re-import.
sys.path.insert(0, str(SKILL1 / "scripts"))
import _common as common  # noqa: E402


def _bail(msg: str, code: int = 2) -> "t.NoReturn":
    """SystemExit with an int argument so the exit code is honored."""
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def _load_skill1_aws() -> t.Any:
    """Load Skill 1's providers/aws.py under a unique sys.modules name. Standard
    `import aws` would clash with this skill's own providers/aws.py."""
    spec = importlib.util.spec_from_file_location(
        "agent_sandbox_provision_aws", SKILL1 / "providers" / "aws.py"
    )
    if spec is None or spec.loader is None:
        _bail(f"could not load Skill 1 provider at {SKILL1 / 'providers' / 'aws.py'}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_skill2_aws() -> t.Any:
    """Load THIS skill's providers/aws.py under a unique sys.modules name."""
    path = SKILL_DIR / "providers" / "aws.py"
    spec = importlib.util.spec_from_file_location("sandbox_cred_sweep_aws", path)
    if spec is None or spec.loader is None:
        _bail(f"could not load Skill 2 provider at {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------- identity discovery ----------
#
# scan.py is designed to run inside claude-ro, but does NOT preflight on env
# vars. Whatever boto3's default credential chain finds — env vars (the
# claude-ro launcher's path), shared credentials file, SSO session, instance
# profile, etc. — is fine to attempt. The actual enforcement is the role-name
# check after sts:GetCallerIdentity: the assumed identity must match
# `claude-ro-*`. Anything else (a profile to your admin account, an SSO
# session, etc.) gets a clean refusal and a pointer back to claude-ro.


def _discover_identity(session: t.Any) -> tuple[str, str]:
    """Call sts:GetCallerIdentity on `session`, parse account_id and role_name
    from the assumed-role ARN, sanity-check the role looks like a claude-ro RO
    role. Returns (account_id, role_name).

    Raises botocore.exceptions.NoCredentialsError if boto3 found no usable
    creds in the default chain — main() catches and reports."""
    botocore_config = common._ensure_pkg("botocore.config")
    sts = session.client(
        "sts",
        config=botocore_config.Config(retries={"mode": "adaptive", "max_attempts": 10}),
    )
    ident = sts.get_caller_identity()
    arn = ident["Arn"]  # arn:aws:sts::<account>:assumed-role/<role-name>/<session>

    parts = arn.split(":assumed-role/", 1)
    if len(parts) != 2:
        _bail(
            f"refusing to run: caller is not an assumed-role session ({arn!r}). "
            f"scan.py is only intended for the agent-sandbox sandbox "
            f"identity. Launch via claude-ro and try again."
        )
    role_name = parts[1].split("/", 1)[0]
    account_id = ident["Account"]

    if not role_name.startswith("claude-ro-"):
        _bail(
            f"refusing to run: assumed role {role_name!r} does not look like a "
            f"claude-ro RO role. scan.py is only intended for the "
            f"agent-sandbox sandbox identity — running it under your "
            f"regular admin/SSO identity would mis-state the threat-model "
            f"answer. Launch via claude-ro and try again."
        )

    return account_id, role_name


# ---------- output rendering ----------

def render_findings(findings: list) -> str:
    high = [f for f in findings if f.confidence == "high"]
    advisory = [f for f in findings if f.confidence != "high"]
    parts: list[str] = []
    if high:
        parts.append("# high-confidence findings")
        for f in high:
            parts.append(f.render())
    if advisory:
        if parts:
            parts.append("# ---")
        parts.append("# advisory findings")
        for f in advisory:
            parts.append(f.render())
    return "\n".join(parts)


def _emit_account_diagnostics(summary: dict) -> None:
    skipped: list[str] = []
    throttled: list[str] = []
    denied: list[str] = []
    for name, s in summary.items():
        for ent in s.get("skipped", []):
            skipped.append(f"{name}: {ent}")
        for ent in s.get("throttled", []):
            throttled.append(f"{name}: {ent}")
        for ent in s.get("denied", []):
            denied.append(f"{name}: {ent}")
    if skipped:
        print("# skipped:")
        for s in skipped:
            print(f"  - {s}")
    if throttled:
        print("# throttled:")
        for s in throttled:
            print(f"  - {s}")
    if denied:
        print("# denied:")
        for s in denied:
            print(f"  - {s}")


# ---------- main ----------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Sweep AWS surfaces for plaintext credentials. "
                    "Run inside claude-ro.",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="List the surfaces that would be swept; make no boto calls "
             "beyond the post-assume identity check.",
    )
    ap.add_argument(
        "--yes", action="store_true",
        help="No-op for argparse parity with other bundle skills.",
    )
    args = ap.parse_args()

    boto3 = common._ensure_boto3()
    botocore_exc = common._ensure_pkg("botocore.exceptions")

    # Build a session via the default boto3 credential chain. Whatever it
    # finds — env vars (the claude-ro launcher's path), shared credentials
    # file, SSO session, instance profile — is fine to attempt. The role-name
    # check inside _discover_identity is the actual enforcement.
    session = boto3.Session()
    region = session.region_name
    if not region:
        _bail(
            "no AWS region configured. boto3 found credentials but no region "
            "in the default chain (env vars, ~/.aws/config, instance metadata). "
            "Set AWS_DEFAULT_REGION, configure a default region in your profile, "
            "or run inside claude-ro (which sets AWS_DEFAULT_REGION via the launcher)."
        )
    common.validate_aws_region(region)

    try:
        account_id, role_name = _discover_identity(session)
    except botocore_exc.NoCredentialsError:
        _bail(
            "no AWS credentials found in the default chain. scan.py expects to run "
            "inside claude-ro, where the launcher provides assumed RO creds. "
            "Launch with: claude-ro --account <ID>"
        )
    except botocore_exc.ClientError as exc:
        # ExpiredToken / InvalidClientTokenId / etc. — treat as "creds present
        # but unusable." Hand the underlying error to the user.
        _bail(f"AWS credentials present but rejected by STS: {exc}")

    ctx = common.Ctx(config={}, dry_run=args.dry_run, yes=args.yes)
    skill2_aws = _load_skill2_aws()
    # Eagerly load Skill 1's provider too — validates the cross-import path
    # and pre-registers it so providers/aws.py picks it up consistently.
    _load_skill1_aws()

    print(f"# cred-sweep run at {common.now_iso()}")
    print(f"# account: {account_id}")
    print(f"# region:  {region}")
    print(f"# role:    {role_name}")

    try:
        findings, summary = skill2_aws.scan_account(session, account_id, region, ctx)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"scan failed: {exc!r}", file=sys.stderr)
        sys.exit(1)

    n_high = sum(1 for f in findings if f.confidence == "high")
    n_adv = sum(1 for f in findings if f.confidence != "high")

    rendered = render_findings(findings)
    if rendered:
        print(rendered)

    _emit_account_diagnostics(summary)
    print(f"# total: {n_high} high, {n_adv} advisory")
    sys.exit(0)


if __name__ == "__main__":
    main()
