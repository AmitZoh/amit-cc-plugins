"""
AWS provider for agent-sandbox-provision (boto3 backend).

Implements the contract documented in providers/_interface.md. boto3 is
auto-installed via _common._ensure_boto3() on first call. kubectl is shelled
out — kube-side ops don't have a Python SDK on the bundled-deps allowlist.

Idempotency: every create/destroy method is idempotent at the level of
"the named entity now exists / no longer exists". Provider exceptions that
mean "already created" or "already gone" are caught and treated as success.

Org-shared verify fixtures: ensure_verify_fixtures uses deterministic names
(see state.schema.json description). Existing-resource errors → success.
purge_org_fixtures is the destructive counterpart called only by sandbox-revoke.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import typing as t

# _common is in scripts/, this file is in providers/. Add scripts/ to path.
_HERE = pathlib.Path(__file__).resolve().parent
_SCRIPTS = _HERE.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import _common as common  # noqa: E402

log = common.get_logger("agent-sandbox.aws")


# ---------- boto3 lazy bootstrap ----------

def _client(profile: str, service: str, region: str | None = None) -> t.Any:
    """boto3 client bound to `profile`, optionally region-scoped. Ambient AWS_*
    are cleared during session construction so the profile actually wins."""
    session = common.boto3_session(profile)
    if region:
        return session.client(service, region_name=region)
    return session.client(service)


def _client_error_code(exc: BaseException) -> str | None:
    """Pull the ClientError code out of a botocore exception."""
    err = getattr(exc, "response", None)
    if not err:
        return None
    return (err.get("Error") or {}).get("Code")


def _is_one_of(exc: BaseException, codes: tuple[str, ...]) -> bool:
    code = _client_error_code(exc)
    return code is not None and code in codes


# ---------- IAM: role + policies ----------

ROLE_NAME_PREFIX = "claude-ro-"

# The S3 encryption-context key. S3 sets it on every SSE-KMS Decrypt it makes on a
# caller's behalf: the OBJECT arn normally, the BUCKET arn when the bucket has S3
# Bucket Keys enabled (one data key per bucket, so there is nothing object-specific
# to put in the context). That is why prefix-scoped grants are only possible on
# buckets with BucketKeyEnabled=false.
S3_CTX_KEY = "kms:EncryptionContext:aws:s3:arn"

# IAM caps an inline role policy at 10,240 characters.
_INLINE_POLICY_MAX_CHARS = 10240

# Inline guardrails: deny secret reads + cost-trap operations.
#
# kms:Decrypt sits on its OWN statement so grant_s3_decrypt can punch per-bucket
# holes in it without weakening the secretsmanager deny. The hole is a NEGATED
# condition carrying exactly ONE condition key. Keys inside a Condition block are
# ANDed, so adding kms:ViaService here would read "deny when it is not-S3 AND
# not-that-bucket" — the deny would stop biting on direct KMS calls the moment the
# context matched. ViaService pinning belongs on the Allow, which is the thing that
# actually grants access. A request carrying no S3 encryption context (a raw
# kms:Decrypt of a ciphertext blob, or a decrypt on Secrets Manager's behalf) has
# the key absent, and negated string operators evaluate TRUE on an absent key — so
# the deny still applies. Fail-closed by construction.
_DENY_SECRET_READS = {
    "Sid": "DenySecretReads",
    "Effect": "Deny",
    "Action": ["secretsmanager:GetSecretValue"],
    "Resource": "*",
}

_DENY_COST_TRAPS = {
    "Sid": "DenyCostTraps",
    "Effect": "Deny",
    "Action": ["s3:RestoreObject", "dynamodb:Scan", "logs:StartQuery"],
    "Resource": "*",
}


def grant_context(bucket: str, prefix: str | None, *,
                  bucket_key_enabled: bool) -> tuple[str, str]:
    """Return (encryption_context_value, match_op) for one grant.

    match_op is "equals" (bucket-wide) or "like" (prefix-scoped). A prefix grant is
    only meaningful when bucket keys are off — the caller is responsible for
    refusing/widening before getting here."""
    if prefix and not bucket_key_enabled:
        return f"arn:aws:s3:::{bucket}/{prefix.lstrip('/')}*", "like"
    return f"arn:aws:s3:::{bucket}", "equals"


def grant_sid(grant: dict) -> str:
    """Deterministic, IAM-legal Sid ([A-Za-z0-9] only) for one grant statement."""
    import hashlib
    label = re.sub(r"[^A-Za-z0-9]", "", grant["bucket"])[:40]
    digest = hashlib.sha1(grant["encryption_context"].encode()).hexdigest()[:8]
    return f"AllowS3Decrypt{label}{digest}"


def _grant_statement(grant: dict) -> dict:
    """One Allow per grant. Never merged: merging two grants into one statement
    would AND their conditions together and grant neither bucket."""
    via = {"kms:ViaService": f"s3.{grant['region']}.amazonaws.com"}
    ctx = grant["encryption_context"]
    if grant.get("context_match", "equals") == "like":
        condition = {"StringEquals": via, "StringLike": {S3_CTX_KEY: ctx}}
    else:
        condition = {"StringEquals": {**via, S3_CTX_KEY: ctx}}
    return {
        "Sid": grant_sid(grant),
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": grant["kms_key_arn"],
        "Condition": condition,
    }


def deny_policy(grants: list[dict] | None = None) -> dict:
    """Return the inline-policy document the caller attaches to the RO role.

    `grants` are accounts[].s3_decrypt_grants records. With none, kms:Decrypt is
    denied unconditionally (the v1 document). With grants, the deny statement grows
    a negated condition excluding each grant's encryption context, and each grant
    gets its own scoped Allow — BOTH are required: an explicit deny beats any allow,
    and ReadOnlyAccess does not carry kms:Decrypt, so narrowing the deny alone
    leaves nothing to fall back on."""
    grants = list(grants or [])
    equals = [g["encryption_context"] for g in grants
              if g.get("context_match", "equals") == "equals"]
    likes = [g["encryption_context"] for g in grants
             if g.get("context_match") == "like"]

    deny_kms: dict = {
        "Sid": "DenyKmsDecrypt",
        "Effect": "Deny",
        "Action": ["kms:Decrypt"],
        "Resource": "*",
    }
    condition: dict = {}
    if equals:
        condition["StringNotEquals"] = {S3_CTX_KEY: equals}
    if likes:
        condition["StringNotLike"] = {S3_CTX_KEY: likes}
    if condition:
        deny_kms["Condition"] = condition

    statements = [_DENY_SECRET_READS, deny_kms, _DENY_COST_TRAPS]
    statements.extend(_grant_statement(g) for g in grants)
    doc = {"Version": "2012-10-17", "Statement": statements}

    size = len(json.dumps(doc, separators=(",", ":")))
    if size > _INLINE_POLICY_MAX_CHARS:
        raise ValueError(
            f"guardrails policy would be {size} chars, over IAM's "
            f"{_INLINE_POLICY_MAX_CHARS}-char inline limit ({len(grants)} grants). "
            f"Revoke a grant, or widen prefix grants to bucket-wide ones."
        )
    return doc


def provision_identity(account_ref: str, user_principal_arn: str, *,
                       ctx: common.Ctx,
                       profile: str,
                       existing_role_name: str | None = None) -> dict:
    """Create the RO IAM role in `account_ref`.

    `existing_role_name`: if set (resume case), look up that role; create only if absent.
    Otherwise generate `claude-ro-<short_uuid>` and create.

    Returns {role_name, role_arn} ready to be merged into state.accounts[].
    Idempotent: if the role already exists, returns its details without re-creating
    and bumps MaxSessionDuration if the configured value exceeds the current one."""
    botocore = common._ensure_pkg("botocore.exceptions")
    iam = _client(profile, "iam")
    cfg = ctx.config.get("aws", {})
    max_session = int(cfg.get("ro_role_max_session_duration", 43200))

    role_name = existing_role_name or f"{ROLE_NAME_PREFIX}{common.short_uuid8()}"

    try:
        existing = iam.get_role(RoleName=role_name)["Role"]
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "NoSuchEntity":
            raise
        existing = None

    if existing is None:
        if ctx.dry_run:
            log.info("[dry-run] would create role %s in account %s", role_name, account_ref)
        else:
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "AllowUserIamUserToAssume",
                    "Effect": "Allow",
                    "Principal": {"AWS": user_principal_arn},
                    "Action": "sts:AssumeRole",
                }],
            }
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Read-only sandbox identity for Claude Code "
                            "(managed by agent-sandbox-provision).",
                MaxSessionDuration=max_session,
            )
            log.info("created role %s", role_name)
    else:
        log.info("role %s already exists; reusing", role_name)
        if existing.get("MaxSessionDuration", 0) < max_session and not ctx.dry_run:
            iam.update_role(RoleName=role_name, MaxSessionDuration=max_session)
            log.info("raised %s MaxSessionDuration to %ds", role_name, max_session)

    role_arn = f"arn:aws:iam::{account_ref}:role/{role_name}"
    return {"role_name": role_name, "role_arn": role_arn}


def attach_role_policies(account_ref: str, role_name: str, *,
                         ctx: common.Ctx, profile: str,
                         grants: list[dict] | None = None) -> None:
    """Attach managed ReadOnlyAccess and put the inline guardrails. Idempotent
    (attach-role-policy is a no-op for already-attached, put-role-policy overwrites).

    `grants` are the account's s3_decrypt_grants records. put-role-policy REPLACES
    the document, so every caller must pass the account's full grant list or it
    silently revokes the ones it left out."""
    cfg = ctx.config.get("aws", {})
    managed_arn = cfg.get("managed_policy_arn", "arn:aws:iam::aws:policy/ReadOnlyAccess")
    inline_name = cfg.get("guardrails_inline_policy_name", "claude-ro-guardrails")
    document = deny_policy(grants)

    if ctx.dry_run:
        log.info("[dry-run] would attach %s and put inline %s on %s (%d s3 decrypt grant(s))",
                 managed_arn, inline_name, role_name, len(grants or []))
        return

    iam = _client(profile, "iam")
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_name,
        PolicyDocument=json.dumps(document),
    )
    log.info("attached ReadOnlyAccess + inline %s on %s (%d s3 decrypt grant(s))",
             inline_name, role_name, len(grants or []))


def detach_role_policies(role_name: str, *, profile: str) -> None:
    """Detach all managed policies and delete all inline policies. Idempotent."""
    botocore = common._ensure_pkg("botocore.exceptions")
    iam = _client(profile, "iam")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)
    except botocore.ClientError as exc:
        if _client_error_code(exc) == "NoSuchEntity":
            return
        raise
    for p in attached.get("AttachedPolicies", []):
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        except botocore.ClientError as exc:
            if _client_error_code(exc) != "NoSuchEntity":
                raise
    inline = iam.list_role_policies(RoleName=role_name)
    for name in inline.get("PolicyNames", []):
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=name)
        except botocore.ClientError as exc:
            if _client_error_code(exc) != "NoSuchEntity":
                raise


def delete_role(role_name: str, *, profile: str) -> None:
    """Delete the IAM role. Caller must detach policies first. Idempotent."""
    botocore = common._ensure_pkg("botocore.exceptions")
    iam = _client(profile, "iam")
    try:
        iam.delete_role(RoleName=role_name)
        log.info("deleted role %s", role_name)
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "NoSuchEntity":
            raise


# ---------- S3 KMS decrypt grants ----------

_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")

# get_bucket_location's legacy answers.
_LOCATION_ALIASES = {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}


def validate_bucket_name(bucket: str) -> str:
    if not _BUCKET_NAME_RE.match(bucket or ""):
        raise SystemExit(f"invalid S3 bucket name: {bucket!r}")
    return bucket


def validate_object_prefix(prefix: str) -> str:
    """A prefix is interpolated into an IAM StringLike pattern, so wildcards in it
    would silently widen the grant. Reject them."""
    if any(ch in prefix for ch in "*?"):
        raise SystemExit(
            f"invalid prefix {prefix!r}: * and ? are IAM wildcards and would widen "
            f"the grant beyond what you typed. Pass a literal prefix.")
    if prefix.startswith("/"):
        raise SystemExit(f"invalid prefix {prefix!r}: S3 keys do not start with '/'.")
    if "\n" in prefix or "\r" in prefix:
        raise SystemExit(f"invalid prefix {prefix!r}: contains a newline.")
    return prefix


def inspect_bucket_encryption(bucket: str, *, profile: str,
                              role_account_id: str | None = None) -> dict:
    """Read what a bucket's default encryption implies for a decrypt grant.

    Returns {bucket, region, sse_algorithm, kms_key_arn, kms_key_alias, key_manager,
    key_account_id, bucket_key_enabled, notes}. sse_algorithm is None when the bucket
    has no default encryption; kms_key_arn is None whenever no KMS key is involved
    (SSE-S3/AES256 or unencrypted), which means there is nothing to grant."""
    botocore = common._ensure_pkg("botocore.exceptions")
    notes: list[str] = []
    s3 = _client(profile, "s3")

    def _header_region(payload: dict | None) -> str | None:
        headers = ((payload or {}).get("ResponseMetadata") or {}).get("HTTPHeaders") or {}
        return headers.get("x-amz-bucket-region")

    # head_bucket answers existence AND region in one call: S3 returns
    # x-amz-bucket-region on the success response and on the 301/403 error alike,
    # which is the only region source that survives a cross-region client.
    region = None
    try:
        region = _header_region(s3.head_bucket(Bucket=bucket))
    except botocore.ClientError as exc:
        code = _client_error_code(exc) or ""
        region = _header_region(getattr(exc, "response", None))
        if code in ("404", "NoSuchBucket"):
            raise SystemExit(f"bucket {bucket!r} does not exist (or is not visible "
                             f"to profile {profile!r}).")
        if code in ("301", "PermanentRedirect"):
            pass  # wrong-region client; the header above carries the right one
        elif code in ("403", "AccessDenied"):
            notes.append(f"head_bucket returned AccessDenied for profile {profile!r} — "
                         f"the bucket may be owned by another account.")
        else:
            raise

    if not region:
        loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        region = _LOCATION_ALIASES.get(loc, loc)

    s3r = _client(profile, "s3", region=region)
    algorithm = key_id = None
    bucket_key = False
    try:
        rules = (s3r.get_bucket_encryption(Bucket=bucket)
                 .get("ServerSideEncryptionConfiguration", {}).get("Rules") or [])
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "ServerSideEncryptionConfigurationNotFoundError":
            raise
        rules = []
    if rules:
        rule = rules[0]
        default = rule.get("ApplyServerSideEncryptionByDefault") or {}
        algorithm = default.get("SSEAlgorithm")
        key_id = default.get("KMSMasterKeyID")
        bucket_key = bool(rule.get("BucketKeyEnabled", False))
        if len(rules) > 1:
            notes.append(f"bucket has {len(rules)} encryption rules; read the first.")

    key_arn = alias = manager = key_account = None
    if algorithm in ("aws:kms", "aws:kms:dsse"):
        lookup = key_id or "alias/aws/s3"
        if lookup.startswith("arn:") and ":alias/" in lookup:
            alias = lookup.split(":alias/")[-1]
            alias = f"alias/{alias}"
        elif lookup.startswith("alias/"):
            alias = lookup
        try:
            meta = _client(profile, "kms", region=region).describe_key(
                KeyId=lookup)["KeyMetadata"]
            key_arn = meta["Arn"]
            manager = meta.get("KeyManager")
            key_account = meta.get("AWSAccountId")
        except botocore.ClientError as exc:
            if lookup.startswith("arn:aws:kms:") and ":key/" in lookup:
                key_arn = lookup
                notes.append(f"could not describe {lookup} with profile {profile!r} "
                             f"({_client_error_code(exc)}); using the ARN as written.")
            else:
                raise SystemExit(
                    f"cannot resolve the bucket's KMS key {lookup!r} in {region}: {exc}")

    if key_account and role_account_id and key_account != role_account_id:
        notes.append(
            f"the key lives in account {key_account}, the RO role in {role_account_id}. "
            f"An IAM allow is necessary but not sufficient cross-account — that key's "
            f"policy must also allow the role, and an AWS-managed key's policy cannot "
            f"be edited.")

    return {
        "bucket": bucket,
        "region": region,
        "sse_algorithm": algorithm,
        "kms_key_arn": key_arn,
        "kms_key_alias": alias,
        "key_manager": manager,
        "key_account_id": key_account,
        "bucket_key_enabled": bucket_key,
        "notes": notes,
    }


def build_grant(bucket: str, prefix: str | None, info: dict) -> dict:
    """Assemble the state record for one grant from an inspect_bucket_encryption()."""
    ctx_value, match = grant_context(bucket, prefix,
                                     bucket_key_enabled=info["bucket_key_enabled"])
    return {
        "bucket": bucket,
        "prefix": prefix or None,
        "region": info["region"],
        "kms_key_arn": info["kms_key_arn"],
        "kms_key_alias": info.get("kms_key_alias"),
        "bucket_key_enabled": info["bucket_key_enabled"],
        "encryption_context": ctx_value,
        "context_match": match,
        "granted_at": common.now_iso(),
    }


# ---------- EKS: access entries + kubeconfig context naming ----------

def kube_context_for_cluster(account_ref: str, region: str, cluster_name: str) -> str:
    """The kubectl context name `aws eks update-kubeconfig` writes by default:
    arn:aws:eks:<region>:<account>:cluster/<name>. Used for both the user's
    kubeconfig (sample CRDs, apply ClusterRole, fixture pod) and the per-launch
    kubeconfig (verify suite)."""
    return f"arn:aws:eks:{region}:{account_ref}:cluster/{cluster_name}"


def bind_cluster(account_ref: str, cluster_ref: str, role_arn: str, *,
                 ctx: common.Ctx, profile: str, region: str,
                 user_kubectl_context: str | None = None) -> dict:
    """Wire `role_arn` into `cluster_ref`'s authorization layer.

    EKS-specific:
      1. Create access entry (type=STANDARD).
      2. Associate AmazonEKSViewPolicy at cluster scope.
      3. Enumerate the cluster's CRDs (as the user, super-admin) and apply the
         supplemental claude-ro-crd-read-<cluster> ClusterRole.

    `user_kubectl_context` is the context the user uses to talk to this cluster.
    Defaults to the EKS-style ARN. Caller can override if their kubeconfig uses
    a different name (some teams alias).

    Returns a dict suitable for state.accounts[].clusters[]:
        {cluster_name, region, endpoint, ca_data, access_entry_principal_arn,
         supplemental_cluster_role}"""
    botocore = common._ensure_pkg("botocore.exceptions")
    cluster_role_name = f"claude-ro-crd-read-{_safe_label(cluster_ref)}"
    user_ctx = user_kubectl_context or kube_context_for_cluster(account_ref, region, cluster_ref)

    if ctx.dry_run:
        log.info("[dry-run] would bind %s to cluster %s in %s",
                 role_arn, cluster_ref, account_ref)
        return {
            "cluster_name": cluster_ref,
            "region": region,
            "endpoint": "",
            "ca_data": "",
            "access_entry_principal_arn": role_arn,
            "supplemental_cluster_role": cluster_role_name,
        }

    eks = _client(profile, "eks", region=region)

    # 0. Preflight: cluster metadata + auth-mode check. EKS rejects access-entry
    #    operations unless authenticationMode is API or API_AND_CONFIG_MAP.
    #    Legacy CONFIG_MAP-only clusters need a one-time, non-destructive flip.
    desc = eks.describe_cluster(name=cluster_ref)["cluster"]
    endpoint = desc.get("endpoint", "")
    ca_data = (desc.get("certificateAuthority") or {}).get("data", "")
    auth_mode = ((desc.get("accessConfig") or {}).get("authenticationMode") or "")
    if auth_mode == "CONFIG_MAP":
        raise SystemExit(
            f"cluster {cluster_ref!r} authenticationMode is CONFIG_MAP; access "
            f"entries require API or API_AND_CONFIG_MAP.\n"
            f"Flip is additive (existing aws-auth ConfigMap keeps working).\n"
            f"\n"
            f"If the cluster is IaC-managed (Terraform / Pulumi / CDK):\n"
            f"  - Terraform: set aws_eks_cluster.access_config.authentication_mode "
            f"to \"API_AND_CONFIG_MAP\" and apply.\n"
            f"  - Otherwise: change the equivalent field in your IaC and apply.\n"
            f"  Don't use the AWS CLI — the next apply will revert it.\n"
            f"\n"
            f"If the cluster is hand-managed:\n"
            f"  aws --profile {profile} eks update-cluster-config "
            f"--region {region} --name {cluster_ref} "
            f"--access-config authenticationMode=API_AND_CONFIG_MAP\n"
            f"\n"
            f"Either way, wait for the update to reach ACTIVE (a few minutes), "
            f"then re-run bind_cluster."
        )

    # 0b. Preflight: a working kubectl context for this cluster must already
    #     exist. bind-cluster talks to the cluster AS THE USER (super-admin) to
    #     read CRDs and apply the supplemental ClusterRole, so it needs a
    #     reachable context — but it must VERIFY that BEFORE any AWS mutation, or
    #     a missing context leaves a dangling access entry (steps 1-2 below). The
    #     skill does NOT create the context: the user's kubeconfig is theirs.
    try:
        _kubectl(["--context", user_ctx, "get", "--raw", "/version"])
    except RuntimeError as exc:
        raise SystemExit(
            f"no working kubectl context {user_ctx!r} for cluster {cluster_ref!r}.\n"
            f"bind-cluster needs to reach the cluster as you to read CRDs and apply "
            f"the supplemental ClusterRole, and it verifies this BEFORE touching AWS "
            f"so nothing is half-created. It will not modify your kubeconfig.\n"
            f"\n"
            f"Create the context yourself, then re-run bind-cluster:\n"
            f"  aws --profile {profile} eks update-kubeconfig "
            f"--region {region} --name {cluster_ref}\n"
            f"\n"
            f"No changes were made to AWS or the cluster."
        ) from exc

    # 1. Access entry — create-only-if-absent.
    try:
        eks.create_access_entry(
            clusterName=cluster_ref,
            principalArn=role_arn,
            type="STANDARD",
        )
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "ResourceInUseException":
            raise

    # 2. Associate the view policy at cluster scope.
    try:
        eks.associate_access_policy(
            clusterName=cluster_ref,
            principalArn=role_arn,
            policyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
            accessScope={"type": "cluster"},
        )
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "ResourceInUseException":
            raise

    # 4. CRD ClusterRole — applied as the user, against the user's context.
    apply_supplemental_crd_clusterrole(cluster_ref, cluster_role_name, ctx=ctx,
                                       kubectl_context=user_ctx)

    log.info("bound %s to cluster %s", role_arn, cluster_ref)
    return {
        "cluster_name": cluster_ref,
        "region": region,
        "endpoint": endpoint,
        "ca_data": ca_data,
        "access_entry_principal_arn": role_arn,
        "supplemental_cluster_role": cluster_role_name,
    }


def unbind_cluster(role_arn: str, cluster_ref: str, bind_record: dict, *,
                   profile: str, region: str,
                   user_kubectl_context: str | None = None,
                   account_ref: str | None = None,
                   dry_run: bool = False) -> None:
    """Per-user cluster unbind. Disassociates the EKS access policy and deletes
    the access entry — both per-user resources (the access entry's
    principal ARN is the user's RO role).

    Does NOT delete the supplemental ClusterRole `claude-ro-crd-read-<cluster>`
    — that's an org-shared resource (its name is per-cluster, not per-user;
    every engineer binding the same cluster shares the same ClusterRole, so
    deleting it on one user's unbind would break every other engineer's RO
    role on this cluster). The ClusterRole is deleted only by
    purge_org_fixtures, which is the explicit org-wide cleanup operation.

    Idempotent (NotFound is success at every step)."""
    botocore = common._ensure_pkg("botocore.exceptions")

    if dry_run:
        log.info("[dry-run] would disassociate access policy + delete access entry "
                 "for %s on %s (org-shared ClusterRole left intact)",
                 role_arn, cluster_ref)
        return

    # 1. Disassociate the access policy.
    eks = _client(profile, "eks", region=region)
    try:
        eks.disassociate_access_policy(
            clusterName=cluster_ref,
            principalArn=role_arn,
            policyArn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy",
        )
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "ResourceNotFoundException":
            raise

    # 2. Delete the access entry.
    try:
        eks.delete_access_entry(clusterName=cluster_ref, principalArn=role_arn)
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "ResourceNotFoundException":
            raise


def apply_supplemental_crd_clusterrole(cluster_ref: str, cluster_role_name: str, *,
                                       ctx: common.Ctx,
                                       kubectl_context: str) -> None:
    """Enumerate CRDs (as the user) and apply the per-cluster supplemental
    ClusterRole. Aggregated to `view`. resources[] is the explicit CRD list — we
    deliberately do not use resources: ["*"] because aggregation into view
    would re-grant secrets reads."""
    raw = _kubectl([
        "--context", kubectl_context,
        "get", "crds",
        "-o", "jsonpath={range .items[*]}{.spec.group}/{.spec.names.plural}{\"\\n\"}{end}",
    ])

    groups: dict[str, list[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "/" not in line:
            continue
        group, _, plural = line.partition("/")
        groups.setdefault(group, []).append(plural)

    if not groups:
        log.info("cluster %s has no CRDs; applying empty supplemental ClusterRole", cluster_ref)
        rules_yaml = "  []"
    else:
        chunks = []
        for group in sorted(groups.keys()):
            plurals = sorted(set(groups[group]))
            plurals_yaml = "[" + ", ".join(f"\"{p}\"" for p in plurals) + "]"
            chunks.append(
                f"  - apiGroups: [\"{group}\"]\n"
                f"    resources: {plurals_yaml}\n"
                f"    verbs: [\"get\", \"list\", \"watch\"]"
            )
        rules_yaml = "\n".join(chunks)

    template = (common.SKILL_DIR / "templates" / "crd-read-clusterrole.yaml.tmpl").read_text()
    rendered = _render_template(template, {
        "CLUSTER_ROLE_NAME": cluster_role_name,
        "CLUSTER_NAME_LABEL": _safe_label(cluster_ref),
        "RULES": rules_yaml,
    })

    if ctx.dry_run:
        log.info("[dry-run] would apply ClusterRole %s with %d apiGroups",
                 cluster_role_name, len(groups))
        return

    _kubectl(["--context", kubectl_context, "apply", "-f", "-"], input_text=rendered)
    log.info("applied ClusterRole %s on cluster %s (%d apiGroups)",
             cluster_role_name, cluster_ref, len(groups))


def sample_crd_kind(*, kubectl_context: str) -> str | None:
    """Return one CRD kind name from the named context, alphabetically first.
    None if the cluster has no CRDs. Caller passes the full context (typically
    the EKS ARN). Used per cluster — not against whatever the user's default is."""
    raw = _kubectl([
        "--context", kubectl_context,
        "get", "crds",
        "-o", "jsonpath={range .items[*]}{.spec.names.kind}{\"\\n\"}{end}",
    ], check=False)
    kinds = sorted({k.strip() for k in raw.splitlines() if k.strip()})
    return kinds[0] if kinds else None


# ---------- assume_creds (used by Skill 2 sweep) ----------

def assume_creds(role_arn: str, assumer_profile: str, *,
                 ctx: common.Ctx,
                 duration_seconds: int = 43200) -> common.AssumedCreds:
    """Wrapper for boto3 assume-role with env-clearing. The launcher itself uses
    bash + aws CLI for the same logic — this is for Python callers (Skill 2)."""
    return common.aws_assume_role_clean_env(
        role_arn, assumer_profile, duration_seconds=duration_seconds,
    )


# ---------- engineer admin kubeconfig (for the per-cluster tunnel broker) ----------

def mint_admin_kubeconfig(account_ref: str, region: str, cluster_name: str,
                          profile: str) -> str:
    """Build a SELF-CONTAINED kubeconfig (endpoint + CA + a static EKS bearer token)
    for `cluster_name`, signed as `profile`'s identity — the engineer's per-account
    assumer profile, which is cluster-admin. Returned as YAML.

    Used by the per-cluster SOCKS tunnel broker, which runs under `sudo -u <engineer>`
    with a stripped environment: it has neither the engineer's KUBECONFIG (a set of
    per-cluster files referenced via an env var sudo won't pass through) nor the `aws`
    CLI on PATH for the usual exec-plugin. Minting the token here via boto3 removes all
    of that: no KUBECONFIG env, no aws CLI, no exec plugin. Per-ACCOUNT profile keying
    makes it correct across multiple accounts. STDLIB + boto3; runs as the engineer."""
    session = common.boto3_session(profile)
    eks = session.client("eks", region_name=region)
    desc = eks.describe_cluster(name=cluster_name)["cluster"]
    endpoint = desc.get("endpoint", "")
    ca = (desc.get("certificateAuthority") or {}).get("data", "")
    token = _eks_bearer_token(session, cluster_name, region)

    yaml = common._ensure_pyyaml()
    ctx = kube_context_for_cluster(account_ref, region, cluster_name)
    cfg = {
        "apiVersion": "v1", "kind": "Config", "preferences": {},
        "clusters": [{"name": ctx,
                      "cluster": {"server": endpoint, "certificate-authority-data": ca}}],
        "contexts": [{"name": ctx, "context": {"cluster": ctx, "user": ctx}}],
        "current-context": ctx,
        "users": [{"name": ctx, "user": {"token": token}}],
    }
    return yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False)


def _eks_bearer_token(session: t.Any, cluster_name: str, region: str) -> str:
    """The EKS presigned-STS bearer token — the exact value `aws eks get-token` yields
    (a presigned sts:GetCallerIdentity URL carrying the x-k8s-aws-id header)."""
    from botocore.signers import RequestSigner  # botocore ships with boto3
    sts = session.client("sts", region_name=region)
    signer = RequestSigner(
        sts.meta.service_model.service_id, region, "sts", "v4",
        session.get_credentials(), sts.meta.events,
    )
    url = signer.generate_presigned_url(
        {"method": "GET",
         "url": f"https://sts.{region}.amazonaws.com/"
                "?Action=GetCallerIdentity&Version=2011-06-15",
         "body": {}, "headers": {"x-k8s-aws-id": cluster_name}, "context": {}},
        region_name=region, expires_in=60, operation_name="",
    )
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


# ---------- on-demand mint (per-account broker) ----------

def mint(record: dict, credentials_file_path: str, *,
         region: str | None = None) -> dict:
    """On-demand mint for ONE AWS account, called by the per-account broker as the
    real user.

    Assumes the account's RO role via the engineer's profile, then returns:
      - credentials_ini: a shared-credentials file body ([default] section) with the
        short-lived RO session creds,
      - kubeconfig_yaml: a kubeconfig for the account's EKS clusters, DISCOVERED LIVE
        with those creds (list_clusters + describe_cluster). Each cluster's
        `aws eks get-token` exec entry carries AWS_SHARED_CREDENTIALS_FILE pointing at
        `credentials_file_path`, so kubectl reads the same refreshed creds — no env-var
        creds anywhere.

    `region` defaults to record["default_region"]; the broker has already validated any
    caller-supplied value against the real EKS region set."""
    boto3 = common._ensure_boto3()
    reg = common.validate_aws_region(region or record["default_region"])
    creds = common.aws_assume_role_clean_env(record["ro_role_arn"], record["assumer_profile"])

    credentials_ini = (
        "[default]\n"
        f"aws_access_key_id = {creds.access_key}\n"
        f"aws_secret_access_key = {creds.secret_key}\n"
        f"aws_session_token = {creds.session_token}\n"
    )

    ro_session = boto3.Session(
        aws_access_key_id=creds.access_key,
        aws_secret_access_key=creds.secret_key,
        aws_session_token=creds.session_token,
        region_name=reg,
    )
    eks = ro_session.client("eks")
    names: list[str] = []
    for page in eks.get_paginator("list_clusters").paginate():
        names.extend(page.get("clusters", []))

    clusters: list[dict] = []
    for name in names:
        desc = eks.describe_cluster(name=name)["cluster"]
        clusters.append({
            "name": name,
            "endpoint": desc.get("endpoint", ""),
            "ca_data": (desc.get("certificateAuthority") or {}).get("data", ""),
        })

    kubeconfig_yaml = _render_kubeconfig(
        record["account_id"], reg, clusters, credentials_file_path)

    return {
        "credentials_ini": credentials_ini,
        "kubeconfig_yaml": kubeconfig_yaml,
        "region": reg,
        "clusters": [c["name"] for c in clusters],
        "expiration": creds.expiration,
    }


def _render_kubeconfig(account_id: str, region: str, clusters: list[dict],
                       credentials_file_path: str) -> str:
    """Build a kubeconfig (YAML) for the discovered clusters. Each user is an exec
    credential plugin running `aws eks get-token`, with AWS_SHARED_CREDENTIALS_FILE
    pinned to `credentials_file_path` so kubectl always reads the account's freshly
    minted RO creds. Context names match kube_context_for_cluster (the EKS ARN), the
    same names verify expects."""
    yaml = common._ensure_pyyaml()
    cfg: dict = {
        "apiVersion": "v1",
        "kind": "Config",
        "preferences": {},
        "clusters": [],
        "contexts": [],
        "users": [],
    }
    for c in clusters:
        ctx = kube_context_for_cluster(account_id, region, c["name"])
        cfg["clusters"].append({
            "name": ctx,
            "cluster": {
                "server": c["endpoint"],
                "certificate-authority-data": c["ca_data"],
            },
        })
        cfg["contexts"].append({
            "name": ctx,
            "context": {"cluster": ctx, "user": ctx},
        })
        cfg["users"].append({
            "name": ctx,
            "user": {
                "exec": {
                    "apiVersion": "client.authentication.k8s.io/v1beta1",
                    "command": "aws",
                    "args": ["eks", "get-token",
                             "--cluster-name", c["name"],
                             "--region", region],
                    "env": [
                        {"name": "AWS_SHARED_CREDENTIALS_FILE",
                         "value": credentials_file_path},
                        {"name": "AWS_PROFILE", "value": "default"},
                    ],
                },
            },
        })
    # NO current-context, deliberately. One account commonly holds several clusters, and a
    # default would be whichever happened to come first — on the reference install that was
    # prod-cluster-1, sitting alongside two staging clusters. A bare `kubectl get pods`
    # then silently read PRODUCTION, and an agent that "checked the current context"
    # believed it had chosen something. Omitting the key makes kubectl refuse any command
    # without --context ("error: no context specified"), turning a silent wrong-cluster
    # read into an immediate, obvious failure. Do not add it back for convenience.
    return yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False)


# ---------- surface_list (Skill 2) ----------

def surface_list() -> list[dict]:
    """Per-account read surfaces for sandbox-cred-sweep. Each entry has a
    `name`, `kind`, and `priority` (1=highest). Skill 2 walks the list in
    priority order, calling boto3 per service."""
    return [
        {"name": "s3-objects", "kind": "object_contents", "priority": 1},
        {"name": "lambda", "kind": "function_env", "priority": 2},
        {"name": "cloudformation", "kind": "stack_outputs_and_templates", "priority": 2},
        {"name": "ec2-userdata", "kind": "instance_user_data", "priority": 3},
        {"name": "ecs-taskdef", "kind": "container_env", "priority": 3},
        {"name": "codebuild", "kind": "project_env_and_source", "priority": 3},
        {"name": "glue", "kind": "job_script_and_params", "priority": 4},
        {"name": "ssm-params", "kind": "string_and_stringlist", "priority": 4},
    ]


# ---------- ensure_verify_fixtures (org-shared) ----------

@dataclasses.dataclass
class VerifyFixtures:
    verify_bucket: str
    verify_secret_id: str
    verify_table: str
    verify_log_group: str
    verify_kms_key_id: str
    verify_glacier_key: str
    verify_pods: dict[str, str]
    verify_crd_kind: dict[str, str]

    def to_state(self) -> dict:
        return dataclasses.asdict(self)


def ensure_verify_fixtures(account_ref: str, region: str, *,
                           ctx: common.Ctx, profile: str,
                           clusters: list[dict] | None = None) -> dict:
    """Create org-shared verify fixtures (idempotent on existing-resource errors).

    Names are deterministic — see state.schema.json. Per-cluster fixtures (pod,
    CRD-kind sentinel) are sampled per cluster using the cluster's own kubectl
    context, NOT whatever the user's default is.

    Returns a dict matching state.accounts[].verify_fixtures."""
    botocore = common._ensure_pkg("botocore.exceptions")

    bucket = f"claude-ro-verify-{account_ref}"
    secret = "claude-ro-verify-deny"
    table = "claude-ro-verify-deny"
    log_group = "/aws/claude-ro-verify-deny"
    kms_alias = "alias/claude-ro-verify"
    glacier_key = "claude-ro-verify-glacier.txt"

    if ctx.dry_run:
        log.info("[dry-run] would ensure fixtures in account %s region %s", account_ref, region)
        kms_key_id = ""
    else:
        s3 = _client(profile, "s3", region=region)
        # 1. S3 bucket — region quirk: us-east-1 doesn't take LocationConstraint.
        try:
            if region == "us-east-1":
                s3.create_bucket(Bucket=bucket)
            else:
                s3.create_bucket(
                    Bucket=bucket,
                    CreateBucketConfiguration={"LocationConstraint": region},
                )
        except botocore.ClientError as exc:
            if not _is_one_of(exc, ("BucketAlreadyOwnedByYou", "BucketAlreadyExists")):
                raise
        # Block public access.
        try:
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                },
            )
        except botocore.ClientError:
            pass

        # 2. Glacier object — Body is required, even for empty content.
        try:
            s3.put_object(
                Bucket=bucket, Key=glacier_key,
                Body=b"verify-fixture-do-not-use",
                StorageClass="GLACIER",
            )
        except botocore.ClientError:
            pass

        # 3. Secrets Manager.
        sm = _client(profile, "secretsmanager", region=region)
        try:
            sm.create_secret(
                Name=secret,
                Description="Sentinel for claude-ro deny-policy verification.",
                SecretString="verify-fixture-do-not-use",
            )
        except botocore.ClientError as exc:
            if _client_error_code(exc) != "ResourceExistsException":
                raise

        # 4. DynamoDB table.
        ddb = _client(profile, "dynamodb", region=region)
        try:
            ddb.create_table(
                TableName=table,
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )
        except botocore.ClientError as exc:
            if _client_error_code(exc) != "ResourceInUseException":
                raise

        # 5. CloudWatch Logs group.
        logs = _client(profile, "logs", region=region)
        try:
            logs.create_log_group(logGroupName=log_group)
        except botocore.ClientError as exc:
            if _client_error_code(exc) != "ResourceAlreadyExistsException":
                raise

        # 6. KMS key + alias.
        kms_key_id = _ensure_kms_key(kms_alias, region=region, profile=profile)

    # Per-cluster fixtures: pod + CRD kind sentinel. Use the per-cluster kubectl
    # context so multi-cluster binds get correct values.
    pods: dict[str, str] = {}
    crd_kinds: dict[str, str] = {}
    for c in (clusters or []):
        cname = c["cluster_name"]
        creg = c.get("region", region)
        kctx = kube_context_for_cluster(account_ref, creg, cname)
        pod_name = "claude-ro-verify-deny"
        if not ctx.dry_run:
            _kubectl([
                "--context", kctx,
                "run", pod_name,
                "--image", "public.ecr.aws/docker/library/busybox:stable",
                "--restart", "Never",
                "--command", "--", "sleep", "infinity",
            ], check=False)
        pods[cname] = pod_name
        if not ctx.dry_run:
            kind = sample_crd_kind(kubectl_context=kctx)
            if kind:
                crd_kinds[cname] = kind

    return VerifyFixtures(
        verify_bucket=bucket,
        verify_secret_id=secret,
        verify_table=table,
        verify_log_group=log_group,
        verify_kms_key_id=kms_key_id or "",
        verify_glacier_key=glacier_key,
        verify_pods=pods,
        verify_crd_kind=crd_kinds,
    ).to_state()


def _ensure_kms_key(alias: str, *, region: str, profile: str) -> str:
    """Return the KeyId behind `alias`. Create both if absent. Idempotent."""
    botocore = common._ensure_pkg("botocore.exceptions")
    kms = _client(profile, "kms", region=region)
    try:
        return kms.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "NotFoundException":
            raise

    created = kms.create_key(
        Description="Sentinel for claude-ro deny-policy verification.",
        KeyUsage="ENCRYPT_DECRYPT",
    )
    key_id = created["KeyMetadata"]["KeyId"]
    try:
        kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    except botocore.ClientError as exc:
        if _client_error_code(exc) != "AlreadyExistsException":
            raise
    return key_id


# ---------- verify ----------

def verify(account_ref: str, role_arn: str, fixtures: dict, *,
           ctx: common.Ctx,
           profile: str, region: str,
           clusters: list[dict],
           grants: list[dict] | None = None,
           kubeconfig: str | None = None) -> list[dict]:
    """Run the verify suite as the assumed RO role.

    Returns one record per check: {name, expected, actual, passed, detail}.
    """
    botocore = common._ensure_pkg("botocore.exceptions")
    boto3 = common._ensure_boto3()

    creds = common.aws_assume_role_clean_env(role_arn, profile)

    # Build a session from the assumed creds (bypasses any ambient profile).
    ro_session = boto3.Session(
        aws_access_key_id=creds.access_key,
        aws_secret_access_key=creds.secret_key,
        aws_session_token=creds.session_token,
        region_name=region,
    )

    results: list[dict] = []

    def call(client_name: str, op: str, *, expect_pass: bool, **kwargs) -> dict:
        client = ro_session.client(client_name)
        method = getattr(client, op)
        try:
            method(**kwargs)
            return _result(expect_pass=expect_pass, succeeded=True, code="ok", detail="")
        except botocore.ClientError as exc:
            code = _client_error_code(exc) or "unknown"
            denied = code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")
            return _result(expect_pass=expect_pass, succeeded=False,
                           code=code, denied=denied,
                           detail=str(exc)[:200])
        except Exception as exc:  # pragma: no cover
            return _result(expect_pass=expect_pass, succeeded=False,
                           code="unknown", denied=False, detail=str(exc)[:200])

    def named(name: str, r: dict) -> dict:
        r["name"] = name
        return r

    # Identity check
    results.append(named("sts:GetCallerIdentity returns RO role",
                         call("sts", "get_caller_identity", expect_pass=True)))

    # Reads should pass
    results.append(named("s3:ListBuckets",
                         call("s3", "list_buckets", expect_pass=True)))
    results.append(named("ec2:DescribeInstances",
                         call("ec2", "describe_instances", expect_pass=True, MaxResults=5)))

    # Mutations / cost-trap reads should be denied
    bucket = fixtures.get("verify_bucket", "")
    secret = fixtures.get("verify_secret_id", "")
    table = fixtures.get("verify_table", "")
    log_group = fixtures.get("verify_log_group", "")
    kms_id = fixtures.get("verify_kms_key_id", "")
    glacier_key = fixtures.get("verify_glacier_key", "")
    nonce = f"{int(time.time())}-{os.getpid()}"

    if bucket:
        results.append(named("s3:DeleteBucket denied",
                             call("s3", "delete_bucket", expect_pass=False, Bucket=bucket)))
    results.append(named("iam:CreateUser denied",
                         call("iam", "create_user", expect_pass=False,
                              UserName=f"claude-ro-verify-deny-{nonce}")))
    if secret:
        results.append(named("secretsmanager:GetSecretValue denied",
                             call("secretsmanager", "get_secret_value",
                                  expect_pass=False, SecretId=secret)))
    if bucket and glacier_key:
        results.append(named("s3:RestoreObject denied",
                             call("s3", "restore_object", expect_pass=False,
                                  Bucket=bucket, Key=glacier_key,
                                  RestoreRequest={"Days": 1})))
    if table:
        results.append(named("dynamodb:Scan denied",
                             call("dynamodb", "scan", expect_pass=False, TableName=table)))
    if log_group:
        results.append(named("logs:StartQuery denied",
                             call("logs", "start_query", expect_pass=False,
                                  logGroupName=log_group, startTime=0, endTime=1,
                                  queryString="fields @message")))

    # KMS decrypt — encrypt with the user's profile, decrypt as RO role.
    if kms_id:
        try:
            user_kms = _client(profile, "kms", region=region)
            enc = user_kms.encrypt(KeyId=kms_id, Plaintext=b"verify-deny")
            blob = enc["CiphertextBlob"]
            try:
                ro_session.client("kms").decrypt(CiphertextBlob=blob)
                results.append({
                    "name": "kms:Decrypt denied",
                    "expected": "AccessDenied", "actual": "succeeded (FAIL)",
                    "passed": False, "detail": "decrypt unexpectedly returned success",
                })
            except botocore.ClientError as exc:
                code = _client_error_code(exc) or "unknown"
                denied = code == "AccessDeniedException" or "Deny" in str(exc)
                results.append({
                    "name": "kms:Decrypt denied",
                    "expected": "AccessDenied", "actual": code,
                    "passed": denied, "detail": str(exc)[:200],
                })
        except Exception as exc:  # pragma: no cover
            results.append({
                "name": "kms:Decrypt denied",
                "expected": "AccessDenied",
                "actual": f"setup error: {exc}",
                "passed": False, "detail": str(exc)[:200],
            })

    # S3 decrypt grants — each one should now READ end-to-end as the RO role.
    for g in (grants or []):
        gname = g["bucket"] + (f"/{g['prefix']}" if g.get("prefix") else "")
        label = f"s3:GetObject decrypts {gname}"
        try:
            s3 = ro_session.client("s3", region_name=g.get("region", region))
            listing = s3.list_objects_v2(
                Bucket=g["bucket"], Prefix=g.get("prefix") or "", MaxKeys=1)
            contents = listing.get("Contents") or []
            if not contents:
                results.append({
                    "name": label, "expected": "decrypts",
                    "actual": "skipped (no object under that prefix)",
                    "passed": True, "detail": "nothing to read; grant not exercised",
                })
                continue
            key = contents[0]["Key"]
            # Range-limited: proves the decrypt without pulling the whole object.
            s3.get_object(Bucket=g["bucket"], Key=key, Range="bytes=0-0")
            results.append({
                "name": label, "expected": "decrypts", "actual": "ok",
                "passed": True, "detail": f"read 1 byte of {key}",
            })
        except botocore.ClientError as exc:
            code = _client_error_code(exc) or "unknown"
            results.append({
                "name": label, "expected": "decrypts", "actual": code,
                "passed": False, "detail": str(exc)[:200],
            })
        except Exception as exc:  # pragma: no cover
            results.append({
                "name": label, "expected": "decrypts",
                "actual": f"setup error: {exc}",
                "passed": False, "detail": str(exc)[:200],
            })

    # k8s checks per cluster — use the per-launch kubeconfig's context (same name
    # as the EKS ARN, written by render_per_launch_kubeconfig).
    for c in clusters:
        cname = c["cluster_name"]
        creg = c.get("region", region)
        kctx = kube_context_for_cluster(account_ref, creg, cname)

        results.append(_kubectl_check(kctx, ["get", "pods", "-A"],
                                      expect_pass=True, kubeconfig=kubeconfig,
                                      name=f"{cname}: kubectl get pods (success)"))
        results.append(_kubectl_check(kctx, ["get", "secrets", "-A"],
                                      expect_pass=False, kubeconfig=kubeconfig,
                                      name=f"{cname}: kubectl get secrets (Forbidden)"))
        pod_name = (fixtures.get("verify_pods") or {}).get(cname)
        if pod_name:
            results.append(_kubectl_check(kctx, ["delete", "pod", pod_name],
                                          expect_pass=False, kubeconfig=kubeconfig,
                                          name=f"{cname}: kubectl delete pod (Forbidden)"))
            results.append(_kubectl_check(kctx, ["exec", pod_name, "--", "echo", "hi"],
                                          expect_pass=False, kubeconfig=kubeconfig,
                                          name=f"{cname}: kubectl exec (Forbidden)"))
        crd_kind = (fixtures.get("verify_crd_kind") or {}).get(cname)
        if crd_kind:
            results.append(_kubectl_check(kctx, ["get", crd_kind, "-A"],
                                          expect_pass=True, kubeconfig=kubeconfig,
                                          name=f"{cname}: kubectl get {crd_kind} "
                                               "(CRD ClusterRole landed)"))

    return results


def _result(*, expect_pass: bool, succeeded: bool, code: str,
            denied: bool = False, detail: str = "") -> dict:
    """Translate (expect_pass, succeeded, denied, code) into a verify record."""
    if expect_pass:
        passed = succeeded
        return {
            "expected": "success",
            "actual": "success" if succeeded else code,
            "passed": passed,
            "detail": detail,
        }
    # expect_pass=False → we expected AccessDenied
    if succeeded:
        return {"expected": "AccessDenied", "actual": "succeeded (FAIL)",
                "passed": False, "detail": detail}
    return {"expected": "AccessDenied", "actual": code,
            "passed": denied, "detail": detail}


def _kubectl_check(context: str, args: list[str], *, expect_pass: bool,
                   kubeconfig: str | None, name: str) -> dict:
    cmd = ["kubectl", "--context", context, *args]
    env = dict(os.environ)
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    ok_pass = proc.returncode == 0
    forbidden = "Forbidden" in (proc.stderr or "") or "forbidden" in (proc.stderr or "")
    passed = ok_pass if expect_pass else forbidden
    return {
        "name": name,
        "expected": "success" if expect_pass else "Forbidden",
        "actual": "success" if ok_pass else ("Forbidden" if forbidden else "error"),
        "passed": passed,
        "detail": (proc.stderr or proc.stdout or "").strip()[:200],
    }


# ---------- teardown ----------

def teardown_delete(role_name: str, role_arn: str, clusters: list[dict], *,
                    profile: str, region: str,
                    account_ref: str | None = None,
                    user_kubectl_context_for: t.Callable[[str], str] | None = None,
                    dry_run: bool = False) -> None:
    """Per cluster: unbind (per-user resources only — access entry + view policy).
    Then detach + delete the per-user RO role. Org-shared resources (supplemental
    ClusterRole, verify fixtures) are NOT removed here; that's `purge_org_fixtures`.

    `user_kubectl_context_for(cluster_name) -> context` lets the caller override
    the default ARN-based context (some teams alias). Defaults to the EKS ARN."""
    for c in clusters:
        creg = c.get("region", region)
        cname = c["cluster_name"]
        ctx_name = (user_kubectl_context_for(cname) if user_kubectl_context_for
                    else (kube_context_for_cluster(account_ref, creg, cname)
                          if account_ref else cname))
        unbind_cluster(role_arn, cname, c,
                       profile=profile, region=creg,
                       user_kubectl_context=ctx_name,
                       account_ref=account_ref,
                       dry_run=dry_run)
    if dry_run:
        log.info("[dry-run] would detach policies and delete role %s", role_name)
        return
    detach_role_policies(role_name, profile=profile)
    delete_role(role_name, profile=profile)


# ---------- purge_org_fixtures ----------

def purge_org_fixtures(account_ref: str, region: str, *,
                       profile: str, fixtures: dict,
                       clusters: list[dict],
                       dry_run: bool = False) -> list[dict]:
    """Destructively delete the org-shared verify fixtures. Idempotent.

    Returns a list of {name, ok, detail} records for the caller to report."""
    botocore = common._ensure_pkg("botocore.exceptions")
    results: list[dict] = []

    bucket = fixtures.get("verify_bucket")
    secret = fixtures.get("verify_secret_id")
    table = fixtures.get("verify_table")
    log_group = fixtures.get("verify_log_group")
    kms_id = fixtures.get("verify_kms_key_id")
    kms_alias = "alias/claude-ro-verify"

    def step(name: str, fn: t.Callable[[], None]) -> None:
        if dry_run:
            log.info("[dry-run] would purge: %s", name)
            results.append({"name": name, "ok": True, "detail": "dry-run"})
            return
        try:
            fn()
            results.append({"name": name, "ok": True, "detail": ""})
        except Exception as exc:
            results.append({"name": name, "ok": False, "detail": str(exc)[:200]})

    if bucket:
        s3 = _client(profile, "s3", region=region)

        def _empty_and_delete_bucket(b: str = bucket) -> None:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=b):
                to_delete = []
                for v in (page.get("Versions") or []) + (page.get("DeleteMarkers") or []):
                    to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
                if to_delete:
                    s3.delete_objects(Bucket=b, Delete={"Objects": to_delete})
            try:
                s3.delete_bucket(Bucket=b)
            except botocore.ClientError as exc:
                if _client_error_code(exc) != "NoSuchBucket":
                    raise

        step(f"delete s3://{bucket} (recursive)", _empty_and_delete_bucket)

    if secret:
        def _del_secret(s: str = secret, r: str = region) -> None:
            sm = _client(profile, "secretsmanager", region=r)
            try:
                sm.delete_secret(SecretId=s, ForceDeleteWithoutRecovery=True)
            except botocore.ClientError as exc:
                if _client_error_code(exc) != "ResourceNotFoundException":
                    raise
        step(f"delete secret {secret}", _del_secret)

    if table:
        def _del_table(t: str = table, r: str = region) -> None:
            ddb = _client(profile, "dynamodb", region=r)
            try:
                ddb.delete_table(TableName=t)
            except botocore.ClientError as exc:
                if _client_error_code(exc) != "ResourceNotFoundException":
                    raise
        step(f"delete dynamodb table {table}", _del_table)

    if log_group:
        def _del_lg(lg: str = log_group, r: str = region) -> None:
            logs = _client(profile, "logs", region=r)
            try:
                logs.delete_log_group(logGroupName=lg)
            except botocore.ClientError as exc:
                if _client_error_code(exc) != "ResourceNotFoundException":
                    raise
        step(f"delete log group {log_group}", _del_lg)

    if kms_id:
        def _del_alias(a: str = kms_alias, r: str = region) -> None:
            kms = _client(profile, "kms", region=r)
            try:
                kms.delete_alias(AliasName=a)
            except botocore.ClientError as exc:
                if _client_error_code(exc) != "NotFoundException":
                    raise
        step(f"delete KMS alias {kms_alias}", _del_alias)

        def _sched_key(k: str = kms_id, r: str = region) -> None:
            kms = _client(profile, "kms", region=r)
            try:
                kms.schedule_key_deletion(KeyId=k, PendingWindowInDays=7)
            except botocore.ClientError as exc:
                if _client_error_code(exc) != "NotFoundException":
                    raise
        step(f"schedule KMS key {kms_id} for deletion (7 days)", _sched_key)

    # Per-cluster org-shared resources: verify pod and supplemental ClusterRole.
    # Both have deterministic per-cluster names (no per-user UUID), so they're
    # shared across every engineer who's bound this cluster — purge_org_fixtures
    # is the single owner of their lifecycle.
    pods = fixtures.get("verify_pods") or {}
    for c in clusters:
        cname = c["cluster_name"]
        creg = c.get("region", region)
        kctx = kube_context_for_cluster(account_ref, creg, cname)
        cluster_role_name = c.get("supplemental_cluster_role") or \
            f"claude-ro-crd-read-{_safe_label(cname)}"

        step(f"delete supplemental ClusterRole {cluster_role_name} on {cname}",
             lambda kctx=kctx, crn=cluster_role_name: _kubectl([
                 "--context", kctx,
                 "delete", "clusterrole", crn,
                 "--ignore-not-found=true",
             ], check=False))

        pod_name = pods.get(cname)
        if pod_name:
            step(f"delete verify pod {pod_name} on {cname}",
                 lambda kctx=kctx, pn=pod_name: _kubectl([
                     "--context", kctx,
                     "delete", "pod", pn,
                     "--ignore-not-found=true",
                 ], check=False))

    return results


# ---------- helpers ----------

def _kubectl(args: list[str], *, kubeconfig: str | None = None,
             input_text: str | None = None, capture: bool = True,
             check: bool = True) -> str:
    env = dict(os.environ)
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    proc = subprocess.run(
        ["kubectl", *args], env=env, capture_output=capture, text=True,
        input=input_text, check=False,
    )
    if proc.returncode != 0 and check:
        raise RuntimeError(
            f"kubectl {' '.join(args)} failed: {proc.stderr or proc.stdout}"
        )
    return proc.stdout


def _safe_label(s: str) -> str:
    s = s.lower()
    s = re.sub(r"[^a-z0-9-]", "-", s).strip("-")
    return s[:63] or "unnamed"


def _render_template(template: str, vars: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in vars:
            raise KeyError(f"template variable {key!r} not provided")
        return str(vars[key])
    return re.sub(r"\{\{(\w+)\}\}", sub, template)
