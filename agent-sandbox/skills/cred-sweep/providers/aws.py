"""
AWS provider for cred-sweep.

Sweeps a fixed set of read-reachable surfaces in one AWS account and reports
findings as Finding records. Each Finding reports LOCATION ONLY — never the
matched value. There is no `value` field on Finding by design; do NOT add one
even for debugging. Reporting locations means a leaked secret stays where it
already is; reporting values would put the secret into the operator's terminal,
shell history, ticket system, etc.

Cross-skill imports: this provider does NOT duplicate Skill 1's _common helpers
or surface_list. Skill 1 is canonical for both. The bootstrap below registers
Skill 1's `aws.py` under a unique sys.modules name (avoiding the clash with
this file's own `aws.py` name) and imports `_common` via sys.path insertion.
Skill 1 is the sibling agent-sandbox skill under this same plugin's
skills/ directory.

Surface coverage (8 total, 7 implemented + 1 declared gap):
    s3-objects, lambda, cloudformation, ec2-userdata, ecs-taskdef, codebuild,
    glue (declared gap — minimal Glue use in-org), ssm-params.
"""

from __future__ import annotations

import base64
import dataclasses
import fnmatch
import gzip
import importlib.util
import io
import json
import pathlib
import re
import sys
import typing as t
import urllib.error
import urllib.request
import zipfile

# ---------- cross-skill bootstrap ----------

# Both skills now ship as sibling skills/ under the same plugin, so Skill 1 is
# located relative to this file rather than via a fixed ~/.claude/skills/...
# path: parent -> providers, parent.parent -> cred-sweep, parent.parent.parent
# -> skills/, then across to agent-sandbox.
SKILL1 = pathlib.Path(__file__).resolve().parent.parent.parent / "provision"

# (1) Skill 1's _common via sys.path. Idempotent if already on path; the import
# system caches the module under "_common" in sys.modules.
sys.path.insert(0, str(SKILL1 / "scripts"))
import _common as common  # noqa: E402


def _load_skill1_aws() -> t.Any:
    """Load Skill 1's providers/aws.py under a unique sys.modules name so it
    doesn't clash with THIS file (also `aws.py`). Both modules then coexist."""
    spec = importlib.util.spec_from_file_location(
        "agent_sandbox_provision_aws", SKILL1 / "providers" / "aws.py"
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load Skill 1 provider at {SKILL1 / 'providers' / 'aws.py'}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


skill1_aws = _load_skill1_aws()

log = common.get_logger("cred-sweep.aws")


# ---------- Finding ----------

@dataclasses.dataclass
class Finding:
    """Reports LOCATION ONLY. No `value` field by design — adding one defeats
    the privacy posture of this skill. Do not add one even for debugging."""
    account: str
    surface: str
    kind: str
    context: str
    recommendation: str
    confidence: str  # "high" | "advisory"

    def render(self) -> str:
        return (
            f"[finding]\n"
            f"  account: {self.account}\n"
            f"  surface: {self.surface}\n"
            f"  kind: {self.kind}\n"
            f"  context: {self.context}\n"
            f"  confidence: {self.confidence}\n"
            f"  recommendation: {self.recommendation}\n"
        )


# ---------- pattern sets ----------

# High-precision patterns. Used everywhere — including S3 object bodies, where
# false-positive density is highest.
PATTERNS_HIGH_CONFIDENCE: list[tuple[str, "re.Pattern[str]", str]] = [
    ("aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        "rotate, move to Secrets Manager"),
    ("aws_secret_access_key_field",
        re.compile(
            r'(?i)\b(aws[_-]?secret[_-]?access[_-]?key|aws_secret)\b'
            r'\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
        ),
        "rotate, move to Secrets Manager"),
    ("private_key_pem",
        re.compile(r"-----BEGIN (RSA |OPENSSH |EC |PGP |DSA )?PRIVATE KEY-----"),
        "rotate, store in Secrets Manager or KMS"),
    ("url_with_credentials",
        re.compile(r"\b[a-z][a-z0-9+\-.]*://[^\s/:@]+:[^\s/@]+@[a-zA-Z0-9.-]+"),
        "remove embedded creds; use IAM auth or Secrets Manager"),
    ("github_token",
        re.compile(r"\b(ghp_|ghs_|gho_|ghu_|github_pat_)[A-Za-z0-9_]{20,}"),
        "revoke at github.com/settings/tokens; rotate"),
    ("slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
        "revoke at api.slack.com; rotate"),
]

# Env-var-shaped surfaces only (Lambda env, ECS containerDefinitions[].environment[],
# CodeBuild env, SSM params). NOT applied in sweep_s3 — would FP-storm on object
# bodies (JS/YAML/JSON Schema/Markdown/test fixtures).
PATTERNS_ENV_VAR_ADVISORY: list[tuple[str, "re.Pattern[str]", str]] = [
    ("generic_secret_assignment",
        re.compile(
            r'(?i)\b(api[_-]?key|secret|password|token)\b'
            r'\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?'
        ),
        "review and rotate if real"),
]


def _scan_with_patterns(text: str,
                        patterns: list[tuple[str, "re.Pattern[str]", str]],
                        confidence: str,
                        *,
                        account_id: str,
                        surface: str,
                        context: str) -> list[Finding]:
    """Run each pattern against `text`. NEVER stores m.group(0) in the Finding —
    only line numbers and the kind name. Line numbers are 1-based."""
    out: list[Finding] = []
    if not text:
        return out
    for kind, pattern, recommendation in patterns:
        for m in pattern.finditer(text):
            line_num = text.count("\n", 0, m.start()) + 1
            ctx = f"{context} (line {line_num})" if context else f"line {line_num}"
            out.append(Finding(
                account=account_id, surface=surface, kind=kind,
                context=ctx, recommendation=recommendation,
                confidence=confidence,
            ))
    return out


def _scan_text_high_confidence(text: str, *,
                               account_id: str, surface: str,
                               context: str = "") -> list[Finding]:
    """High-confidence patterns only. Use on S3 object bodies and any other
    surface where the field IS NOT inherently the value."""
    return _scan_with_patterns(
        text, PATTERNS_HIGH_CONFIDENCE, "high",
        account_id=account_id, surface=surface, context=context,
    )


def _scan_text_with_advisory(text: str, *,
                             account_id: str, surface: str,
                             context: str = "") -> list[Finding]:
    """High-confidence + env-var advisory. Use only inside env-var-shaped
    surfaces (Lambda env, ECS env, CodeBuild env, SSM)."""
    return (
        _scan_with_patterns(
            text, PATTERNS_HIGH_CONFIDENCE, "high",
            account_id=account_id, surface=surface, context=context)
        + _scan_with_patterns(
            text, PATTERNS_ENV_VAR_ADVISORY, "advisory",
            account_id=account_id, surface=surface, context=context)
    )


# ---------- shared client + error helpers ----------

def _adaptive_config() -> t.Any:
    """botocore Config with adaptive retries. Without this, busy production
    accounts will throw ThrottlingException / RequestLimitExceeded mid-sweep
    and silently drop coverage."""
    botocore_config = common._ensure_pkg("botocore.config")
    return botocore_config.Config(retries={"mode": "adaptive", "max_attempts": 10})


def _client(session: t.Any, service: str, *, region: str | None = None) -> t.Any:
    kwargs: dict[str, t.Any] = {"config": _adaptive_config()}
    if region is not None:
        kwargs["region_name"] = region
    return session.client(service, **kwargs)


def _is_denied(exc: BaseException) -> bool:
    return skill1_aws._is_one_of(exc, (
        "AccessDenied", "AccessDeniedException", "NotAuthorized",
        "UnauthorizedOperation",
    ))


def _is_throttled(exc: BaseException) -> bool:
    return skill1_aws._is_one_of(exc, (
        "Throttling", "ThrottlingException",
        "RequestLimitExceeded", "TooManyRequestsException",
    ))


def _record_resource_error(summary: dict, key: str, exc: BaseException, action: str) -> None:
    """Per-resource error isolation: classify, record, log+skip. The caller
    `continue`s after this — no exception propagates."""
    code = skill1_aws._client_error_code(exc) or type(exc).__name__
    if _is_denied(exc):
        summary["denied"].append(f"{key}: {code}")
        log.info("[denied] %s (%s)", key, code)
        return
    if _is_throttled(exc):
        summary["throttled"].append(f"{key}: {code}")
        log.info("[throttled] %s (%s)", key, code)
        return
    summary["skipped"].append(f"{key}: {code}")
    log.warning("%s failed for %s: %s", action, key, code)


def _new_summary() -> dict:
    return {"findings": 0, "skipped": [], "throttled": [], "denied": []}


# ---------- pivot helpers (used by the agent playbook) ----------
#
# These are not used by scan.py / scan_account. They support the agent-driven
# playbook in SKILL.md, where the agent — after surfacing a candidate
# credential — needs to (a) learn what identity it resolves to and (b) compare
# that identity's permissions against claude-ro's. The "delta" is the chain.
#
# Neither helper logs or stores the matched credential value. whoami_with_creds
# uses the value to construct an isolated boto3.Session and immediately drops
# the reference; simulate_principal_policy never sees it.


def simulate_principal_policy(session: t.Any, principal_arn: str,
                              actions: list[str],
                              resources: list[str] | None = None) -> dict:
    """Wrap iam:SimulatePrincipalPolicy. Returns a dict mapping each action
    name to one of: 'allowed', 'explicitDeny', 'implicitDeny'.

    `session` is the existing claude-ro session — IAM simulation runs against
    arbitrary principals from any caller permitted to call SimulatePrincipalPolicy.
    `resources` defaults to None, which IAM treats as the wildcard `*`.

    Raises botocore.exceptions.ClientError if the caller is not permitted to
    call iam:SimulatePrincipalPolicy in this account, or if principal_arn is
    malformed. Caller decides whether to log+continue or treat as a hard error.
    """
    iam = _client(session, "iam")
    kwargs: dict[str, t.Any] = {
        "PolicySourceArn": principal_arn,
        "ActionNames": list(actions),
    }
    if resources is not None:
        kwargs["ResourceArns"] = list(resources)
    out: dict[str, str] = {}
    paginator = iam.get_paginator("simulate_principal_policy")
    for page in paginator.paginate(**kwargs):
        for r in page.get("EvaluationResults", []) or []:
            action = r.get("EvalActionName") or "?"
            decision = r.get("EvalDecision") or "implicitDeny"
            out[action] = decision
    return out


def whoami_with_creds(access_key: str, secret_key: str,
                      session_token: str | None = None,
                      region: str | None = None) -> dict:
    """Build an isolated boto3.Session with the supplied override credentials
    and call sts:GetCallerIdentity. Returns {'arn', 'account', 'user_id'}.

    Does NOT modify any environment variable in the parent process — the
    Session is constructed with explicit kwargs and goes out of scope after
    this call.

    Raises botocore.exceptions.NoCredentialsError / ClientError on bad or
    expired credentials. Caller logs the surface location as advisory and
    moves on.
    """
    boto3 = common._ensure_boto3()
    kwargs: dict[str, t.Any] = {
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
    }
    if session_token is not None:
        kwargs["aws_session_token"] = session_token
    if region is not None:
        kwargs["region_name"] = region
    new_session = boto3.Session(**kwargs)
    sts = new_session.client("sts", config=_adaptive_config())
    ident = sts.get_caller_identity()
    return {
        "arn": ident.get("Arn", ""),
        "account": ident.get("Account", ""),
        "user_id": ident.get("UserId", ""),
    }


# ---------- S3 ----------

S3_NAME_PATTERNS = (
    "terraform.tfstate", "terraform.tfstate.backup",
    ".env", ".env.local", ".env.production",
    "credentials", "credentials.json", "credentials.yaml",
)
S3_NAME_GLOBS = ("*.config", "*credentials*", "*secret*")
S3_MAX_PAGES_PER_BUCKET = 20
S3_MAX_OBJECT_BYTES = 5_000_000
S3_RANGE_BYTES = 65_536


def _matches_s3_name(key: str) -> bool:
    base = key.rsplit("/", 1)[-1]
    if base in S3_NAME_PATTERNS:
        return True
    return any(fnmatch.fnmatch(base, g) for g in S3_NAME_GLOBS)


def _bucket_region(default_s3: t.Any, bucket: str, default_region: str) -> str:
    """get_bucket_location is on ReadOnlyAccess. Returns "" or None for us-east-1."""
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    try:
        loc = default_s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    except botocore_exc.ClientError:
        return default_region
    if not loc or loc == "EU":  # legacy: "EU" == eu-west-1
        return "us-east-1" if not loc else "eu-west-1"
    return loc


# S3 Inventory caps. Inventory shards can be huge for million-object buckets;
# we bound total bytes read per bucket so a single Inventory pull can't burn
# arbitrary memory / time. Numbers tuned for "reads keys in a few seconds even
# on a 10M-object bucket" — typical Parquet shard ~50MB compressed.
INVENTORY_MAX_SHARDS = 50
INVENTORY_SHARD_BYTES_CAP = 100_000_000
INVENTORY_TOTAL_BYTES_CAP = 500_000_000
_INVENTORY_FOLDER_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}Z$")


def _read_inventory_keys(session: t.Any, bucket: str,
                         default_region: str) -> tuple[list[str] | None, dict]:
    """Try to read the bucket's S3 Inventory manifest and shards; return
    (keys, info). `keys=None` means Inventory was unusable for any reason
    (no configs, ORC format, dest-bucket access denied, caps exceeded, ...);
    caller falls back to bounded LIST. `info["reason"]` always names why on
    failure; on success info has source/format/shards.

    Recon (pre-implementation) on a test account: 2/142 buckets
    have Inventory configured, both Parquet. ORC support is a declared gap
    because no ORC configs exist in this account and ORC requires another
    heavyweight dep (pyorc / pyarrow.orc). CSV is implemented for free
    (stdlib only) so any account that uses CSV is covered without code change.
    """
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    src_s3 = _client(session, "s3", region=default_region)
    try:
        inv = src_s3.list_bucket_inventory_configurations(Bucket=bucket)
    except botocore_exc.ClientError as exc:
        code = skill1_aws._client_error_code(exc) or "unknown"
        return None, {"reason": f"list-inventory-configs: {code}"}

    configs = inv.get("InventoryConfigurationList") or []
    if not configs:
        return None, {"reason": "no inventory configs"}

    cfg = next((c for c in configs if c.get("IsEnabled")), configs[0])
    cfg_id = cfg.get("Id") or "?"
    dest = (cfg.get("Destination") or {}).get("S3BucketDestination") or {}
    dest_arn = dest.get("Bucket") or ""
    dest_bucket = dest_arn.rsplit(":", 1)[-1] if dest_arn else ""
    dest_prefix = dest.get("Prefix") or ""
    fmt = dest.get("Format") or "?"

    if not dest_bucket:
        return None, {"reason": "manifest dest bucket missing in config"}
    if fmt == "ORC":
        return None, {"reason": "ORC format (declared gap — pyorc dep not bundled)"}
    if fmt not in ("Parquet", "CSV"):
        return None, {"reason": f"unsupported format {fmt!r}"}

    dest_region = _bucket_region(src_s3, dest_bucket, default_region)
    dest_s3 = _client(session, "s3", region=dest_region)

    # Find latest date-stamped delivery folder under
    # <prefix>/<src-bucket>/<config-id>/.
    base = ""
    if dest_prefix:
        base = dest_prefix.rstrip("/") + "/"
    base += f"{bucket}/{cfg_id}/"
    folders: list[str] = []
    try:
        paginator = dest_s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=dest_bucket, Prefix=base, Delimiter="/"):
            for cp in page.get("CommonPrefixes", []) or []:
                p = cp.get("Prefix") or ""
                tail = p[len(base):].rstrip("/")
                if _INVENTORY_FOLDER_RE.match(tail):
                    folders.append(p)
    except botocore_exc.ClientError as exc:
        code = skill1_aws._client_error_code(exc) or "unknown"
        return None, {"reason": f"list dest folders: {code}"}
    if not folders:
        return None, {"reason": f"no delivery folders under s3://{dest_bucket}/{base}"}
    folders.sort()
    latest = folders[-1]
    manifest_key = f"{latest}manifest.json"

    try:
        body = dest_s3.get_object(Bucket=dest_bucket, Key=manifest_key)["Body"].read()
        manifest = json.loads(body)
    except botocore_exc.ClientError as exc:
        code = skill1_aws._client_error_code(exc) or "unknown"
        return None, {"reason": f"get manifest.json: {code}"}
    except json.JSONDecodeError as exc:
        return None, {"reason": f"manifest parse: {exc}"}

    files = manifest.get("files") or []
    actual_fmt = manifest.get("fileFormat") or fmt
    if not files:
        return [], {"source": "inventory", "format": actual_fmt, "shards": 0}

    total_bytes = sum(int(f.get("size") or 0) for f in files)
    if len(files) > INVENTORY_MAX_SHARDS:
        return None, {"reason": f"too many shards ({len(files)} > {INVENTORY_MAX_SHARDS})"}
    if total_bytes > INVENTORY_TOTAL_BYTES_CAP:
        return None, {"reason": f"total shard bytes {total_bytes} > "
                                f"{INVENTORY_TOTAL_BYTES_CAP} cap"}

    keys: list[str] = []
    if actual_fmt == "Parquet":
        try:
            pq = common._ensure_pkg("pyarrow.parquet", "pyarrow")
        except SystemExit:
            return None, {"reason": "pyarrow auto-install failed"}
        for f in files:
            shard_key = f.get("key") or ""
            sz = int(f.get("size") or 0)
            if not shard_key:
                continue
            if sz > INVENTORY_SHARD_BYTES_CAP:
                return None, {"reason": f"shard {shard_key} too large ({sz}B)"}
            try:
                blob = dest_s3.get_object(
                    Bucket=dest_bucket, Key=shard_key)["Body"].read()
            except botocore_exc.ClientError as exc:
                code = skill1_aws._client_error_code(exc) or "unknown"
                return None, {"reason": f"get shard {shard_key}: {code}"}
            try:
                tbl = pq.read_table(io.BytesIO(blob))
            except Exception as exc:  # pyarrow throws bare Exception subclasses
                return None, {"reason": f"parquet parse {shard_key}: {exc!s}"}
            # S3 Inventory Parquet uses lowercase 'key'; older AWS docs show
            # capitalized 'Key'. Be case-tolerant.
            cols = list(tbl.column_names)
            key_col = next((c for c in cols if c.lower() == "key"), None)
            if key_col is None:
                return None, {"reason": f"parquet schema lacks key column "
                                        f"(cols={cols})"}
            keys.extend(tbl.column(key_col).to_pylist())
    elif actual_fmt == "CSV":
        # CSV inventory: fileSchema names the columns. Stdlib csv + gzip.
        import csv
        schema = manifest.get("fileSchema") or "Bucket, Key"
        cols = [c.strip() for c in schema.split(",")]
        try:
            key_idx = cols.index("Key")
        except ValueError:
            return None, {"reason": f"CSV fileSchema lacks Key column ({cols})"}
        for f in files:
            shard_key = f.get("key") or ""
            sz = int(f.get("size") or 0)
            if not shard_key:
                continue
            if sz > INVENTORY_SHARD_BYTES_CAP:
                return None, {"reason": f"shard {shard_key} too large ({sz}B)"}
            try:
                blob = dest_s3.get_object(
                    Bucket=dest_bucket, Key=shard_key)["Body"].read()
            except botocore_exc.ClientError as exc:
                code = skill1_aws._client_error_code(exc) or "unknown"
                return None, {"reason": f"get shard {shard_key}: {code}"}
            if shard_key.endswith(".gz"):
                try:
                    blob = gzip.decompress(blob)
                except (OSError, EOFError) as exc:
                    return None, {"reason": f"gunzip {shard_key}: {exc!s}"}
            try:
                text = blob.decode("utf-8")
            except UnicodeDecodeError as exc:
                return None, {"reason": f"decode {shard_key}: {exc!s}"}
            for row in csv.reader(io.StringIO(text)):
                if len(row) > key_idx:
                    keys.append(row[key_idx])

    return keys, {"source": "inventory", "format": actual_fmt, "shards": len(files)}


def _list_bucket_keys(session: t.Any, s3: t.Any, bucket: str,
                      region: str) -> tuple[list[str], dict]:
    """Return (keys, info). Tries Inventory first (full coverage, cheap), falls
    back to bounded ListObjectsV2 if Inventory is unavailable for any reason.

    `info` has:
      - `source`: "inventory" | "list" | "list-capped"
      - `format`: format name when source=inventory
      - `shards`: shard count when source=inventory
      - `fallback_reason`: why Inventory was skipped (when source != inventory)
    """
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    inv_keys, inv_info = _read_inventory_keys(session, bucket, region)
    if inv_keys is not None:
        return inv_keys, inv_info

    keys: list[str] = []
    capped = False
    pages = 0
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, MaxKeys=1000):
            pages += 1
            for obj in page.get("Contents", []) or []:
                keys.append(obj["Key"])
            if pages >= S3_MAX_PAGES_PER_BUCKET:
                capped = True
                break
    except botocore_exc.ClientError:
        # Caller catches and records; preserve original semantics.
        raise
    return keys, {
        "source": "list-capped" if capped else "list",
        "fallback_reason": inv_info.get("reason"),
    }


def sweep_s3(session: t.Any, *, account_id: str, region: str,
             ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    s3 = _client(session, "s3", region=region)
    findings: list[Finding] = []
    try:
        buckets = s3.list_buckets().get("Buckets", []) or []
    except botocore_exc.ClientError as exc:
        _record_resource_error(summary, "s3:ListBuckets", exc, "ListBuckets")
        return findings

    for b in buckets:
        bucket = b["Name"]
        try:
            br = _bucket_region(s3, bucket, region)
            bs3 = _client(session, "s3", region=br)
            keys, info = _list_bucket_keys(session, bs3, bucket, br)
        except botocore_exc.ClientError as exc:
            _record_resource_error(summary, f"s3://{bucket}", exc, "ListObjects")
            continue

        src = info.get("source", "list")
        if src == "inventory":
            print(f"[inventory] s3://{bucket} (format={info.get('format')}, "
                  f"shards={info.get('shards')}, keys={len(keys)})")
        elif src == "list-capped":
            why = info.get("fallback_reason") or "no inventory"
            msg = (f"[skipped] s3://{bucket} (object list truncated at "
                   f"{S3_MAX_PAGES_PER_BUCKET * 1000} keys; "
                   f"configure S3 Inventory for full coverage; "
                   f"inventory not used: {why})")
            print(msg)
            summary["skipped"].append(
                f"s3://{bucket}: list capped at "
                f"{S3_MAX_PAGES_PER_BUCKET * 1000} keys"
            )

        for key in keys:
            if not _matches_s3_name(key):
                continue
            # Always flag the matched key NAME — even if HEAD/GET later fails.
            findings.append(Finding(
                account=account_id,
                surface=f"s3://{bucket}/{key}",
                kind="likely_credential_filename",
                context="key name matches credential pattern",
                recommendation="confirm contents and rotate if real",
                confidence="advisory",
            ))
            try:
                head = bs3.head_object(Bucket=bucket, Key=key)
            except botocore_exc.ClientError as exc:
                _record_resource_error(summary, f"s3://{bucket}/{key}", exc, "HeadObject")
                continue
            size = int(head.get("ContentLength") or 0)
            if size > S3_MAX_OBJECT_BYTES:
                msg = (f"[skipped] s3://{bucket}/{key} (size {size}B > "
                       f"{S3_MAX_OBJECT_BYTES}B cap)")
                print(msg)
                summary["skipped"].append(f"s3://{bucket}/{key}: too large ({size}B)")
                continue
            try:
                obj = bs3.get_object(
                    Bucket=bucket, Key=key,
                    Range=f"bytes=0-{S3_RANGE_BYTES - 1}",
                )
                body = obj["Body"].read()
            except botocore_exc.ClientError as exc:
                _record_resource_error(summary, f"s3://{bucket}/{key}", exc, "GetObject")
                continue
            try:
                text = body.decode("utf-8")
            except UnicodeDecodeError:
                # Treat as binary; key-name finding above is the record.
                continue
            findings.extend(_scan_text_high_confidence(
                text, account_id=account_id,
                surface=f"s3://{bucket}/{key}", context=""
            ))
    return findings


# ---------- Lambda (zip-only path, per step-0 recon) ----------

LAMBDA_MAX_ZIP_BYTES = 10_000_000   # 10 MB cap per function
LAMBDA_MAX_ENTRY_BYTES = 1_000_000  # 1 MB cap per zip entry


def sweep_lambda(session: t.Any, *, account_id: str, region: str,
                 ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    lam = _client(session, "lambda", region=region)
    findings: list[Finding] = []
    try:
        paginator = lam.get_paginator("list_functions")
        funcs = []
        for page in paginator.paginate():
            funcs.extend(page.get("Functions", []) or [])
    except botocore_exc.ClientError as exc:
        _record_resource_error(summary, "lambda:ListFunctions", exc, "ListFunctions")
        return findings

    for fn in funcs:
        name = fn.get("FunctionName") or "?"
        pkg = fn.get("PackageType") or "Zip"
        if pkg != "Zip":
            # Recon (step 0 of plan) found 16 Zip / 0 Image in the test account.
            # Container-image is a declared gap; flag as skipped if encountered.
            summary["skipped"].append(
                f"lambda:{name}: PackageType={pkg} (Image scanning not in v1)"
            )
            continue

        # Env vars (advisory + high-confidence).
        env = (fn.get("Environment") or {}).get("Variables") or {}
        for k, v in env.items():
            if not isinstance(v, str):
                continue
            findings.extend(_scan_text_with_advisory(
                f"{k}={v}",
                account_id=account_id,
                surface=f"lambda:{name}:env:{k}",
                context=f"env var {k}",
            ))

        # Zip download.
        try:
            detail = lam.get_function(FunctionName=name)
        except botocore_exc.ClientError as exc:
            _record_resource_error(summary, f"lambda:{name}", exc, "GetFunction")
            continue
        url = (detail.get("Code") or {}).get("Location")
        if not url:
            continue
        try:
            head_req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(head_req, timeout=30) as resp:
                cl = int(resp.headers.get("Content-Length") or 0)
        except (urllib.error.URLError, ValueError) as exc:
            log.warning("lambda HEAD %s failed: %s", name, exc)
            summary["skipped"].append(f"lambda:{name}: HEAD failed ({exc!s})")
            continue
        if cl > LAMBDA_MAX_ZIP_BYTES:
            msg = f"[skipped] lambda:{name} (zip {cl}B exceeds {LAMBDA_MAX_ZIP_BYTES}B cap)"
            print(msg)
            summary["skipped"].append(f"lambda:{name}: zip too large ({cl}B)")
            continue
        try:
            with urllib.request.urlopen(url, timeout=120) as resp:
                blob = resp.read()
        except urllib.error.URLError as exc:
            log.warning("lambda GET %s failed: %s", name, exc)
            summary["skipped"].append(f"lambda:{name}: GET failed ({exc!s})")
            continue
        try:
            zf = zipfile.ZipFile(io.BytesIO(blob))
        except zipfile.BadZipFile as exc:
            log.warning("lambda %s zip is invalid: %s", name, exc)
            summary["skipped"].append(f"lambda:{name}: bad zip")
            continue
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.file_size > LAMBDA_MAX_ENTRY_BYTES:
                summary["skipped"].append(
                    f"lambda:{name}:zip:{info.filename}: entry too large "
                    f"({info.file_size}B)"
                )
                continue
            try:
                raw = zf.read(info)
                text = raw.decode("utf-8")
            except (UnicodeDecodeError, zipfile.BadZipFile):
                continue  # binary entry, skip
            findings.extend(_scan_text_high_confidence(
                text, account_id=account_id,
                surface=f"lambda:{name}:zip:{info.filename}",
                context="archive entry",
            ))
    return findings


# ---------- CloudFormation ----------

_CFN_OK_STATUSES = (
    "CREATE_COMPLETE", "UPDATE_COMPLETE",
    "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
)


def sweep_cloudformation(session: t.Any, *, account_id: str, region: str,
                         ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    cfn = _client(session, "cloudformation", region=region)
    findings: list[Finding] = []
    stack_names: list[str] = []
    try:
        paginator = cfn.get_paginator("list_stacks")
        for page in paginator.paginate(StackStatusFilter=list(_CFN_OK_STATUSES)):
            for s in page.get("StackSummaries", []) or []:
                stack_names.append(s["StackName"])
    except botocore_exc.ClientError as exc:
        _record_resource_error(summary, "cfn:ListStacks", exc, "ListStacks")
        return findings

    for name in stack_names:
        # Template body.
        try:
            tmpl_resp = cfn.get_template(StackName=name)
        except botocore_exc.ClientError as exc:
            _record_resource_error(summary, f"cfn:{name}", exc, "GetTemplate")
            continue
        tmpl = tmpl_resp.get("TemplateBody")
        if isinstance(tmpl, dict):
            tmpl_text = json.dumps(tmpl, indent=2, default=str)
        else:
            tmpl_text = "" if tmpl is None else str(tmpl)
        findings.extend(_scan_text_high_confidence(
            tmpl_text, account_id=account_id,
            surface=f"cloudformation:{name}:template",
            context="template body",
        ))

        # Outputs + Parameters (NoEcho parameters are auto-masked by CFN to ****).
        try:
            stacks = cfn.describe_stacks(StackName=name).get("Stacks", []) or []
        except botocore_exc.ClientError as exc:
            _record_resource_error(summary, f"cfn:{name}", exc, "DescribeStacks")
            continue
        if not stacks:
            continue
        stack = stacks[0]
        for o in stack.get("Outputs", []) or []:
            okey = o.get("OutputKey") or "?"
            val = str(o.get("OutputValue") or "")
            findings.extend(_scan_text_high_confidence(
                val, account_id=account_id,
                surface=f"cloudformation:{name}:output:{okey}",
                context=f"output {okey}",
            ))
        for p in stack.get("Parameters", []) or []:
            pkey = p.get("ParameterKey") or "?"
            val = str(p.get("ParameterValue") or "")
            if val == "****":
                continue
            findings.extend(_scan_text_high_confidence(
                val, account_id=account_id,
                surface=f"cloudformation:{name}:param:{pkey}",
                context=f"parameter {pkey}",
            ))
    return findings


# ---------- EC2 user-data ----------

def sweep_ec2_userdata(session: t.Any, *, account_id: str, region: str,
                       ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    ec2 = _client(session, "ec2", region=region)
    findings: list[Finding] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        instance_ids: list[str] = []
        for page in paginator.paginate():
            for r in page.get("Reservations", []) or []:
                for inst in r.get("Instances", []) or []:
                    instance_ids.append(inst["InstanceId"])
    except botocore_exc.ClientError as exc:
        _record_resource_error(summary, "ec2:DescribeInstances", exc, "DescribeInstances")
        return findings

    for iid in instance_ids:
        try:
            attr = ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")
        except botocore_exc.ClientError as exc:
            _record_resource_error(summary, f"ec2:{iid}", exc, "DescribeInstanceAttribute")
            continue
        ud_b64 = (attr.get("UserData") or {}).get("Value")
        if not ud_b64:
            continue
        try:
            raw = base64.b64decode(ud_b64)
        except (ValueError, base64.binascii.Error):
            summary["skipped"].append(f"ec2:{iid}: user-data not base64")
            continue
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                summary["skipped"].append(f"ec2:{iid}: user-data gzip decompress failed")
                continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            summary["skipped"].append(f"ec2:{iid}: user-data not utf-8")
            continue
        findings.extend(_scan_text_high_confidence(
            text, account_id=account_id,
            surface=f"ec2:{iid}:userdata",
            context="user-data",
        ))
    return findings


# ---------- ECS task definitions ----------

def sweep_ecs_taskdef(session: t.Any, *, account_id: str, region: str,
                      ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    ecs = _client(session, "ecs", region=region)
    findings: list[Finding] = []
    families: list[str] = []
    try:
        paginator = ecs.get_paginator("list_task_definition_families")
        for page in paginator.paginate(status="ACTIVE"):
            families.extend(page.get("families", []) or [])
    except botocore_exc.ClientError as exc:
        _record_resource_error(
            summary, "ecs:ListTaskDefinitionFamilies", exc,
            "ListTaskDefinitionFamilies",
        )
        return findings

    for family in families:
        try:
            td = ecs.describe_task_definition(taskDefinition=family)
        except botocore_exc.ClientError as exc:
            _record_resource_error(summary, f"ecs:{family}", exc, "DescribeTaskDefinition")
            continue
        cdefs = (td.get("taskDefinition") or {}).get("containerDefinitions", []) or []
        for c in cdefs:
            cname = c.get("name") or "?"
            for env in c.get("environment", []) or []:
                k = env.get("name") or "?"
                v = env.get("value") or ""
                findings.extend(_scan_text_with_advisory(
                    f"{k}={v}",
                    account_id=account_id,
                    surface=f"ecs:taskdef:{family}:{cname}:env:{k}",
                    context=f"container env {k}",
                ))
    return findings


# ---------- CodeBuild ----------

def sweep_codebuild(session: t.Any, *, account_id: str, region: str,
                    ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    cb = _client(session, "codebuild", region=region)
    findings: list[Finding] = []
    project_names: list[str] = []
    try:
        paginator = cb.get_paginator("list_projects")
        for page in paginator.paginate():
            project_names.extend(page.get("projects", []) or [])
    except botocore_exc.ClientError as exc:
        _record_resource_error(summary, "codebuild:ListProjects", exc, "ListProjects")
        return findings

    # BatchGetProjects accepts up to 100 names per call.
    for i in range(0, len(project_names), 100):
        chunk = project_names[i:i + 100]
        try:
            resp = cb.batch_get_projects(names=chunk)
        except botocore_exc.ClientError as exc:
            _record_resource_error(
                summary, f"codebuild:BatchGetProjects[{i}]", exc, "BatchGetProjects",
            )
            continue
        for proj in resp.get("projects", []) or []:
            pname = proj.get("name") or "?"
            env = proj.get("environment") or {}
            for v in env.get("environmentVariables", []) or []:
                vtype = v.get("type") or "PLAINTEXT"
                if vtype != "PLAINTEXT":
                    # PARAMETER_STORE / SECRETS_MANAGER — references, not values.
                    continue
                k = v.get("name") or "?"
                val = str(v.get("value") or "")
                findings.extend(_scan_text_with_advisory(
                    f"{k}={val}",
                    account_id=account_id,
                    surface=f"codebuild:{pname}:env:{k}",
                    context=f"env {k}",
                ))
            src = proj.get("source") or {}
            loc = src.get("location") or ""
            if loc:
                findings.extend(_scan_text_high_confidence(
                    loc, account_id=account_id,
                    surface=f"codebuild:{pname}:source",
                    context="source location",
                ))
            bs = src.get("buildspec") or ""
            if bs:
                findings.extend(_scan_text_high_confidence(
                    bs, account_id=account_id,
                    surface=f"codebuild:{pname}:buildspec",
                    context="buildspec",
                ))
    return findings


# ---------- Glue (declared gap) ----------

def sweep_glue(session: t.Any, *, account_id: str, region: str,
               ctx: common.Ctx, summary: dict) -> list[Finding]:
    """Declared gap (org makes minimal use of Glue). See SKILL.md "What this
    skill does NOT do." Always prints `[skipped] glue (declared gap)` so the
    operator never assumes silent coverage."""
    print("[skipped] glue (declared gap)")
    summary["skipped"].append("glue: declared gap (org makes minimal use of Glue)")
    return []


# ---------- SSM Parameter Store ----------

SSM_NAME_SUSPICIOUS_RE = re.compile(r"(?i)(api[_-]?key|token|password|secret)")


def sweep_ssm_params(session: t.Any, *, account_id: str, region: str,
                     ctx: common.Ctx, summary: dict) -> list[Finding]:
    botocore_exc = common._ensure_pkg("botocore.exceptions")
    ssm = _client(session, "ssm", region=region)
    findings: list[Finding] = []
    names: list[str] = []
    try:
        paginator = ssm.get_paginator("describe_parameters")
        filters = [{"Key": "Type", "Option": "Equals", "Values": ["String", "StringList"]}]
        for page in paginator.paginate(ParameterFilters=filters):
            for p in page.get("Parameters", []) or []:
                n = p.get("Name")
                if n:
                    names.append(n)
    except botocore_exc.ClientError as exc:
        _record_resource_error(summary, "ssm:DescribeParameters", exc, "DescribeParameters")
        return findings

    # GetParameters accepts up to 10 names per call.
    for i in range(0, len(names), 10):
        batch = names[i:i + 10]
        try:
            resp = ssm.get_parameters(Names=batch, WithDecryption=False)
        except botocore_exc.ClientError as exc:
            _record_resource_error(
                summary, f"ssm:GetParameters[{i}]", exc, "GetParameters",
            )
            continue
        for p in resp.get("Parameters", []) or []:
            n = p.get("Name") or "?"
            v = str(p.get("Value") or "")
            if SSM_NAME_SUSPICIOUS_RE.search(n):
                findings.append(Finding(
                    account=account_id,
                    surface=f"ssm:{n}",
                    kind="suspicious_parameter_name",
                    context="parameter name matches credential pattern",
                    recommendation="confirm value and migrate to SecureString",
                    confidence="advisory",
                ))
            findings.extend(_scan_text_with_advisory(
                f"{n}={v}",
                account_id=account_id,
                surface=f"ssm:{n}",
                context=f"parameter {n}",
            ))
    return findings


# ---------- dispatch + scan_account ----------

SURFACE_DISPATCH: dict[str, t.Callable[..., list[Finding]]] = {
    "s3-objects": sweep_s3,
    "lambda": sweep_lambda,
    "cloudformation": sweep_cloudformation,
    "ec2-userdata": sweep_ec2_userdata,
    "ecs-taskdef": sweep_ecs_taskdef,
    "codebuild": sweep_codebuild,
    "glue": sweep_glue,
    "ssm-params": sweep_ssm_params,
}


def scan_account(session: t.Any, account_id: str, region: str,
                 ctx: common.Ctx) -> tuple[list[Finding], dict]:
    """Iterate Skill 1's surface_list (priority-sorted), dispatch to sweep_<name>.
    ctx.dry_run -> log '[dry-run] would sweep <name>' and skip dispatch. Returns
    (findings, run_summary) where run_summary keys each surface to its
    findings/skipped/throttled/denied buckets — used by scan.py for the footer.
    """
    surfaces = sorted(skill1_aws.surface_list(), key=lambda s: s["priority"])
    findings: list[Finding] = []
    summary: dict[str, dict] = {}

    for surface in surfaces:
        name = surface["name"]
        summary[name] = _new_summary()
        annotation = " (declared gap)" if name == "glue" else ""

        if ctx.dry_run:
            print(f"[dry-run] would sweep {name}{annotation}")
            continue

        fn = SURFACE_DISPATCH.get(name)
        if fn is None:
            log.warning("no implementation for surface %r; skipping", name)
            summary[name]["skipped"].append("no implementation")
            continue

        try:
            sf = fn(session, account_id=account_id, region=region,
                    ctx=ctx, summary=summary[name])
            findings.extend(sf)
            summary[name]["findings"] = len(sf)
        except Exception as exc:
            # Per-surface error isolation — partial-success contract.
            log.error("sweep %s raised: %s", name, exc)
            summary[name]["skipped"].append(f"sweep raised: {type(exc).__name__}")

    return findings, summary
