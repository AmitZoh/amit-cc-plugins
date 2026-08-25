# Skill 2 provider interface

Skill-2-specific contract. NOT a copy of Skill 1's `providers/_interface.md` —
the skills serve different purposes (provision vs. scan) and the per-skill
contract reflects that. Each cloud provider for `sandbox-cred-sweep` exports
the symbols below from `providers/<name>.py`. v1 ships AWS only.

## Conventions

- **`session`** is the boto3 (or provider-equivalent) session bound to assumed
  read-only creds. The orchestrator (`scripts/scan.py`) does the assume-role
  + env-clearing dance via Skill 1's `_common.aws_assume_role_clean_env`. The
  provider does NOT clear env vars again — by the time it sees `session`, the
  identity is already correct.
- **`ctx.dry_run`** skips all boto calls. The provider logs
  `[dry-run] would sweep <surface>` and continues to the next surface.
- **No `state.json` writes.** Skill 2 is stateless; the provider must NOT
  import or call `_common.update_state` / `_common.state_write_atomic`.
- **Cross-skill imports.** The provider cross-imports Skill 1's `_common` and
  Skill 1's `aws.py:surface_list` / `_client_error_code` / `_is_one_of`.
  Single source of truth for shared helpers and the surface list. Skill 1 is
  canonical; Skill 2 picks up new surfaces by re-reading `surface_list()`.

## `Finding` dataclass

```python
@dataclasses.dataclass
class Finding:
    account: str           # 12-digit AWS account ID
    surface: str           # "s3://bucket/key", "lambda:fn:env:VAR", "ssm:/path/param"
    kind: str              # canonical pattern name (aws_access_key_id, ...)
    context: str           # locator within surface (line N, env var name, ...)
    recommendation: str    # short remediation hint per kind
    confidence: str        # "high" | "advisory"

    def render(self) -> str: ...
```

**Hard rule: no `value` field.** The privacy posture of this skill is "report
locations, never values." Adding a `value` field defeats it. Do not add one
even for debugging — read the original surface yourself.

## Required functions

```python
def scan_account(session, account_id: str, region: str,
                 ctx: common.Ctx) -> tuple[list[Finding], dict]
```
Iterate `skill1_aws.surface_list()` (priority-sorted), dispatch to the
provider's `sweep_<surface>` function for each name. Returns
`(findings, run_summary)` where `run_summary` is keyed by surface name with
per-surface `{findings: int, skipped: list[str], throttled: list[str],
denied: list[str]}`. The orchestrator turns the summary into a footer so
partial coverage is never silent.

```python
def sweep_<surface>(session, *, account_id: str, region: str,
                    ctx: common.Ctx, summary: dict) -> list[Finding]
```
One per implemented surface in `surface_list()`. Reads only — never mutates
AWS state. Caps coverage where the surface is unbounded (e.g. Lambda zip
download capped at 10 MB per function). When a cap is hit, the function
appends to `summary["skipped"]` AND prints a `[skipped] <where> (<reason>)`
line so the operator sees partial coverage even before reading the footer.

S3 specifically: each bucket goes through `_read_inventory_keys` first. If
the bucket has S3 Inventory configured (Parquet or CSV format), the manifest
+ shards are read for the full key list (caps: 50 shards / 100MB per shard /
500MB total). Successful Inventory pulls emit `[inventory] s3://<bucket>
(format=..., shards=N, keys=M)`. ORC manifests fall through to bounded LIST
(declared gap). Non-Inventory buckets fall through to bounded LIST: 20×1000
keys per bucket; over-cap buckets emit `[skipped]`.

## Pattern sets

Two registries:

- **`PATTERNS_HIGH_CONFIDENCE`** (high-precision: AWS access keys, AWS secret
  field assignments, PEM private keys, URLs with embedded credentials, GitHub
  PATs, Slack tokens). Applied on every surface.
- **`PATTERNS_ENV_VAR_ADVISORY`** (e.g. `(api_key|secret|token|password)
  \s*[:=]\s*VAL`). Used ONLY on env-var-shaped surfaces (Lambda env, ECS
  containerDefinitions[].environment[], CodeBuild env, SSM parameters). Off in
  S3 — would FP-storm on JS/YAML/JSON Schema/Markdown bodies.

Helpers `_scan_text_high_confidence` (high only) and `_scan_text_with_advisory`
(high + env-var advisory) are the two entry points each `sweep_<surface>`
calls. Confidence is set on the Finding to drive output grouping.

## Per-resource error isolation

Inside each `sweep_<surface>`, the per-resource loop catches
`botocore.exceptions.ClientError` and uses `skill1_aws._is_one_of(...)` to
classify:

- `AccessDenied / AccessDeniedException / NotAuthorized / UnauthorizedOperation`
  → record under `summary["denied"]`, log `[denied] ...`, continue.
- `Throttling / ThrottlingException / RequestLimitExceeded /
  TooManyRequestsException` → record under `summary["throttled"]`, log
  `[throttled] ...`, continue. boto3 clients are constructed with
  `Config(retries={"mode": "adaptive", "max_attempts": 10})`; the per-resource
  catch is for the case where retries are exhausted.
- Any other `ClientError` → record under `summary["skipped"]`, log warning,
  continue.

Each `sweep_<surface>` call from `scan_account` is also wrapped in a generic
`try/except` that records the surface as skipped — partial-success contract.
One broken surface does not abort the run.

## What the contract does NOT include

- **Identity provisioning, role lifecycle, k8s binding, fixture creation.**
  Those are Skill 1's job. Skill 2 only consumes the role.
- **`teardown_*`, `purge_*`.** Skill 2 mutates nothing.
- **A `format=json` output mode.** Phase 2.
- **Audit logging.** Phase 2 across the bundle.
