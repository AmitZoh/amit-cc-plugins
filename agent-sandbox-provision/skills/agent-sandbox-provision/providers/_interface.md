# Provider interface contract

Every cloud/platform provider implements this contract by exporting the
functions listed below from a Python module at `providers/<name>.py`.
Sub-commands import the active provider via `_common.load_provider(name)`.
v1 ships AWS only (`providers/aws.py`); GCP / Azure / Datadog land in Phase 2
by implementing the same contract. **`providers/aws.py` is the source of
truth — the surface below mirrors what it actually exposes.**

The contract is intentionally provider-shaped, not EKS-shaped. `bind_cluster`
is "wire the identity into a managed compute platform's authorization layer."
`account_ref`, `cluster_ref`, and `user_principal_arn` are opaque to the
orchestrator — their format is provider-specific.

## Conventions

- **Idempotency.** Every create/destroy method is idempotent at the level of
  "the named entity now exists / no longer exists." Provider exceptions that
  mean "already created" or "already gone" are caught and treated as success.
- **`ctx`.** A `_common.Ctx` carrying parsed config, dry-run flag, logger, and
  the `--yes` flag. Providers must NOT mutate `state.json` directly — the
  orchestrator owns the lock and writes after the provider call returns.
- **`profile`.** The user's AWS CLI profile (or the equivalent in another
  cloud). Providers use it to authenticate as the user; ambient `AWS_*` env
  vars are cleared inside the provider so the profile actually wins.
- **`dry_run`.** When set on `ctx` (or via the `dry_run` kwarg on teardown
  helpers), provider methods log what they would do and skip side effects.

## Required methods

```python
def deny_policy(grants: list[dict] | None = None) -> dict
```
The whole inline guardrails document: provider-specific deny statements
(secrets + cost-trap operations) plus, for each entry in `grants`, both halves
of an S3 decrypt exception. Returned as a JSON-serialisable dict the caller
attaches as an inline policy.

`grants` are `accounts[].s3_decrypt_grants` records. Each one narrows the
`kms:Decrypt` deny (a negated condition on the S3 encryption context) *and*
adds its own scoped `Allow` — both are required, since an explicit deny beats
any allow while `ReadOnlyAccess` itself carries no `kms:Decrypt`. With no
grants the deny is unconditional, which is the v1 document.

Raises `ValueError` when the assembled document would exceed IAM's
10,240-character inline-policy limit.

```python
def provision_identity(account_ref: str, user_principal_arn: str, *,
                       ctx: Ctx, profile: str,
                       existing_role_name: str | None = None) -> dict
```
Create the RO identity in `account_ref`. Trust policy authorises
`user_principal_arn`. If `existing_role_name` is set (resume case), look up
that role and reuse it instead of generating a fresh `claude-ro-<short_uuid>`.

Returns `{"role_name": str, "role_arn": str}`. Idempotent: existing role is
reused; MaxSessionDuration is bumped if config exceeds the current value.

```python
def attach_role_policies(account_ref: str, role_name: str, *,
                         ctx: Ctx, profile: str,
                         grants: list[dict] | None = None) -> None
```
Attach the managed read-only policy and put the inline guardrails. Idempotent.
`put_role_policy` REPLACES the document, so every caller passes the account's
FULL grant list — omitting grants silently revokes them.

```python
def inspect_bucket_encryption(bucket: str, *, profile: str,
                              role_account_id: str | None = None) -> dict
def build_grant(bucket: str, prefix: str | None, info: dict) -> dict
def grant_context(bucket: str, prefix: str | None, *,
                  bucket_key_enabled: bool) -> tuple[str, str]
```
Support for `grant_s3_decrypt` / `revoke_s3_decrypt`.
`inspect_bucket_encryption` reads the bucket's region and default encryption
and returns `{bucket, region, sse_algorithm, kms_key_arn, kms_key_alias,
key_manager, key_account_id, bucket_key_enabled, notes}`; `kms_key_arn` is
None whenever no KMS key is involved, meaning there is nothing to grant.
`grant_context` decides the encryption-context value and match operator:
`("arn:aws:s3:::b/prefix*", "like")` only when bucket keys are OFF, otherwise
`("arn:aws:s3:::b", "equals")`, because S3 Bucket Keys put the bucket ARN in
the encryption context and leave nothing sub-bucket to match.

```python
def detach_role_policies(role_name: str, *, profile: str) -> None
```
Detach all managed and delete all inline policies on `role_name`. Idempotent.

```python
def delete_role(role_name: str, *, profile: str) -> None
```
Delete the IAM role. Caller must `detach_role_policies` first. Idempotent.

```python
def kube_context_for_cluster(account_ref: str, region: str,
                             cluster_name: str) -> str
```
The kubectl context name the canonical kubeconfig writer uses for this
cluster. For AWS/EKS: `arn:aws:eks:<region>:<account>:cluster/<name>`. Used
by both the user's kubeconfig and the per-launch kubeconfig generator.

```python
def bind_cluster(account_ref: str, cluster_ref: str, role_arn: str, *,
                 ctx: Ctx, profile: str, region: str,
                 user_kubectl_context: str | None = None) -> dict
```
Wire `role_arn` into `cluster_ref`'s authorization layer. AWS: access entry +
view policy + supplemental CRD ClusterRole.

`user_kubectl_context` defaults to `kube_context_for_cluster(...)`. Override
when the user's kubeconfig uses an alias. Idempotent.

Returns:
```python
{
    "cluster_name": str,
    "region": str,
    "endpoint": str,
    "ca_data": str,         # base64-encoded PEM
    "access_entry_principal_arn": str,
    "supplemental_cluster_role": str,
}
```

```python
def unbind_cluster(role_arn: str, cluster_ref: str, bind_record: dict, *,
                   profile: str, region: str,
                   user_kubectl_context: str | None = None,
                   account_ref: str | None = None,
                   dry_run: bool = False) -> None
```
Reverse of `bind_cluster`. Idempotent (NotFound is success). Deletes the
supplemental ClusterRole, disassociates the access policy, deletes the
access entry.

```python
def apply_supplemental_crd_clusterrole(cluster_ref: str,
                                       cluster_role_name: str, *,
                                       ctx: Ctx,
                                       kubectl_context: str) -> None
```
Enumerate CRDs in `cluster_ref` and apply a per-cluster ClusterRole that
aggregates into `view`. The rule list uses explicit `apiGroups` / `resources`
— not `*` — because `*` aggregated into `view` would re-grant secrets reads.

```python
def sample_crd_kind(*, kubectl_context: str) -> str | None
```
Return one CRD kind from the named context (alphabetically first). None if
none. Used per cluster to pick a verify-suite sentinel — pass each cluster's
own context, not the user's default.

```python
def assume_creds(role_arn: str, assumer_profile: str, *,
                 ctx: Ctx,
                 duration_seconds: int = 43200) -> common.AssumedCreds
```
Short-lived creds via boto3 (env-cleared). Used by Skill 2 to sweep multiple
accounts as the user. The launcher itself uses bash + aws CLI for the same
logic — this is the Python entrypoint.

```python
def surface_list() -> list[dict]
```
Per-account read surfaces for Skill 2's cred-scan. Each entry:
`{"name": str, "kind": str, "priority": int}`. Sorted client-side by
priority (1 = highest).

```python
def ensure_verify_fixtures(account_ref: str, region: str, *,
                           ctx: Ctx, profile: str,
                           clusters: list[dict] | None = None) -> dict
```
Create org-shared verify fixtures with deterministic names. Idempotent on
existing-resource exceptions (`BucketAlreadyOwnedByYou`,
`ResourceExistsException`, `ResourceInUseException`,
`ResourceAlreadyExistsException`, etc.).

Returns a dict matching `state.accounts[].verify_fixtures` per
`state.schema.json`:
```python
{
    "verify_bucket": str,             # claude-ro-verify-<account_id>
    "verify_secret_id": str,          # claude-ro-verify-deny
    "verify_table": str,              # claude-ro-verify-deny
    "verify_log_group": str,          # /aws/claude-ro-verify-deny
    "verify_kms_key_id": str,
    "verify_glacier_key": str,        # claude-ro-verify-glacier.txt
    "verify_pods": dict[str, str],    # cluster_name -> pod
    "verify_crd_kind": dict[str, str] # cluster_name -> CRD kind
}
```

Per-cluster fixtures (pod, CRD-kind sentinel) are sampled per cluster using
the cluster's own kubectl context, not the user's default.

```python
def verify(account_ref: str, role_arn: str, fixtures: dict, *,
           ctx: Ctx,
           profile: str, region: str,
           clusters: list[dict],
           kubeconfig: str | None = None) -> list[dict]
```
Run the verify suite as the assumed RO role. Returns one record per check:
```python
{"name": str, "expected": str, "actual": str, "passed": bool, "detail": str}
```

`kubeconfig` is the per-launch kubeconfig path (so kubectl checks run with
the right account active). When None, kubectl uses the user's default.

```python
def teardown_delete(role_name: str, role_arn: str, clusters: list[dict], *,
                    profile: str, region: str,
                    account_ref: str | None = None,
                    user_kubectl_context_for: t.Callable[[str], str] | None = None,
                    dry_run: bool = False) -> None
```
Per cluster: `unbind_cluster`. Then `detach_role_policies` + `delete_role`.
Idempotent. `user_kubectl_context_for(cluster_name) -> context` lets the
caller override the default ARN-based context (for kubeconfig aliases).

Note: `teardown_delete` does NOT delete the org-shared verify fixtures —
those are kept (other engineers in the org may still be using them) and only
removed by the explicit `purge_org_fixtures` call below.

```python
def purge_org_fixtures(account_ref: str, region: str, *,
                       profile: str, fixtures: dict,
                       clusters: list[dict],
                       dry_run: bool = False) -> list[dict]
```
Destructively delete the org-shared verify fixtures: S3 bucket + contents,
KMS alias + scheduled key deletion, Secrets Manager secret, DynamoDB table,
CloudWatch Logs group, per-cluster pods. Idempotent (NotFound is success).

Returns a list of `{"name": str, "ok": bool, "detail": str}` records the
caller prints. Called only by `sandbox-revoke purge-org-fixtures`.

## What the contract does NOT include

- `teardown_disable` — Skill 3 is delete-only. There is no disable mode.
- `discover_crd_gaps` — superseded by `apply_supplemental_crd_clusterrole`,
  which enumerates the cluster's CRDs and produces an explicit allow-list in
  one shot rather than a per-resource discovery loop.
- A `principal_id` opaque-string return — `provision_identity` returns
  `{role_name, role_arn}`. Other providers may model identities differently;
  the dict shape is provider-specific.

---

# Credential-source provider contract (github, mongodb, snowflake)

A SECOND, lighter archetype for platforms that are not "a cloud account + a
managed compute layer" but standalone credentialed services. `providers/github.py`,
`providers/mongodb.py` and `providers/snowflake.py` implement it. Loaded via the same
`common.load_provider(name)`. These are **top-level** arrays in `state.json` —
`github[]` (one org-owned App per bound org), `mongodb[]` and `snowflake[]` — independent
of `accounts[]`. All three are **all-at-once**: every bound GitHub org, every bound Mongo
DB and every bound Snowflake account is reachable in one session (no per-launch selection).

The durable secret (App private key / RO password / RSA private key) never lives in
`claude-ro`'s reach: it sits in a mode-600 file under
`common.SECRETS_DIR` (outside the sandbox-ACL'd home), read only by the real user.
`claude-ro` obtains fresh read-only credentials by invoking a **single argument-less**
mint helper per platform through a pinned `sudo -u <user>` rule; each **writes** its
minted credential to a mode-600 file under `common.RUNTIME_DIR` (claude-ro-readable via
an inherited allow-ACE) and prints only `<name> <path>` lines — values never hit stdout:
- GitHub: `/usr/local/bin/claude-ro-mint-github` → `runtime/github/<org>.token` per bound org.
- MongoDB: `/usr/local/bin/claude-ro-mint-mongodb` → `runtime/mongodb/<name>.uri` per bound DB.
- Snowflake: `/usr/local/bin/claude-ro-mint-snowflake` → `runtime/snowflake/<name>.json` per
  bound account. The broker signs a short-lived **key-pair JWT** from the stored private
  key, locally and with no network call — the JWT is what the sandbox gets. It is scoped
  because the *key* is registered on the service account as a named key pair carrying
  `ROLE_RESTRICTION`, which the requested role must match.

## Required functions (module-level)

```python
def provision(record_in: dict, secret: str, *, ctx) -> dict
```
Probe the platform with the just-captured `secret` and return the enriched state
record (`github[]` / `mongodb[]` item shape per `state.schema.json`). MUST NOT
return the secret — the orchestrator has already stored it in the 600 file. Raise
`SystemExit` with an actionable message on auth failure.

```python
def mint(record: dict, secret: str) -> dict
```
Return the credential to hand to consumers. **STDLIB ONLY** — this runs in the
launcher / broker hot path (no `_ensure_pkg`).
- github → `{"password": "<installation token>"}` (the git credential wiring adds
  the required `username=x-access-token`).
- mongodb → `{"MONGODB_URI": "<connection string>"}`.
- snowflake → `{"SNOWFLAKE_JSON": "<json blob>"}` — the blob carries a freshly signed
  **key-pair JWT** as `token` with `token_type` `KEYPAIR_JWT`, **plus** the non-secret
  connection values (account, host, user, role, warehouse, expires_at),
  because the sandbox cannot read `state.json` and a bare token would leave it guessing.
  Consumers hit the SQL REST API with `Authorization: Bearer <token>`,
  `X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT`, and a body carrying
  `"role": "<the bound role>"` — the key's `ROLE_RESTRICTION` requires the requested role
  to match. `snowflake-connector-python` cannot be used: it derives its own JWT from a
  private key the sandbox does not hold.

```python
def revoke(record: dict, secret: str) -> None
```
Best-effort teardown of durable remote artifacts, called by `unbind-*` WHILE the
secret is still present.
- github → `DELETE /app/installations/{installation_id}` (uninstall the App).
- mongodb → no-op (the DB owner owns `claude-ro-<engineer>`; the laptop has no
  admin credential).
- snowflake → no-op. The `TYPE = SERVICE_AGENT` account is owner-managed, created by
  whoever holds USERADMIN, and the laptop has no admin credential — so the skill holds
  no privilege to remove the key registration either. `unbind-snowflake` deletes the
  local private key and prints `DROP USER IF EXISTS <user>;` for the owner to run.

```python
def verify(record: dict, env: dict, *, ctx) -> list[dict]
```
Prove read works and a write is denied. Returns the same record shape as the AWS
`verify`: `{"name","expected","actual","passed","detail"}`. May `_ensure_pkg`
(verify is not the hot path).

## Notes

- No `gc_stale` — there are no self-minted expiring artifacts left lying around (GitHub
  tokens self-expire and are re-minted on demand; each Snowflake JWT is signed locally,
  expires in under an hour and leaves nothing behind remotely; the Mongo RO user is
  static and owner-managed).
- No org-shared fixtures. Teardown is local: `unbind-*` deletes the secret file, the
  broker helper, and the sudoers drop-in — after `revoke` has had its turn with the
  secret. The only remote object `revoke` handles is the GitHub App installation; the
  identities behind the others (the Mongo DB user, the Snowflake service account and its
  registered key pair) are left to the owner.
