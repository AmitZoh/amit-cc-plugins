---
name: cred-sweep
description: Sweep AWS surfaces (S3, Lambda, CFN, EC2 user-data, ECS, CodeBuild, Glue, SSM Parameter Store) for plaintext credentials reachable from the read-only sandbox identity. Reports locations only — never values. Runs INSIDE the agent-sandbox sandbox (claude-ro); scans whatever account claude-ro was launched against.
user-invocable: true
argument-hint: "[--dry-run]"
---

# Sandbox Credential Sweep

## Threat model

The bundle's threat model is a reasoning agent that decides on a destructive action it considers reasonable (Replit-style: "fastest fix is to clear the DB"). Skill 1's IAM identity blocks direct mutation. The remaining escalation path: a reasoning agent could discover plaintext credentials in tfstate, env vars, user-data, or SSM parameters, then *escalate* via those creds to bypass the deny.

This skill turns that threat into an audit. It runs *as* claude-ro — the same identity the agent inhabits — and looks for chains of the form:

> claude-ro reads X → recovers credential Y → Y has wider permissions than claude-ro

A finding is a **chain**, not a regex match. "AKIA matched in `s3://acme-deploy/build.log`" is evidence; the chain is "AKIA matched, the access-key-id resolves to identity P, P has `iam:CreateUser` which claude-ro does not." Only the second is reportable as a finding.

Running from claude-ro's vantage (vs. the operator's broader admin creds) is load-bearing: bucket policies that deny `claude-ro` specifically would produce false positives from admin creds, and surfaces claude-ro can reach but the operator cannot would be missed.

## What this skill does

When invoked as `/cred-sweep` from inside a `claude-ro` session, this skill drives **Claude itself** (the agent currently running as claude-ro) through a credential-leak hunt. The skill body below is the agent's playbook — it is not a wrapper around a script. The agent decides which surfaces to investigate, in what order, and when to stop.

For a deterministic regex-only baseline that walks the same surfaces without agent reasoning, see the `Complementary deterministic mode` section below.

## How to invoke

Drop into the sandbox first:

```bash
claude-ro --account 123456789012
```

Then inside the sandbox session:

```
/cred-sweep
/cred-sweep --dry-run
```

The agent reads this SKILL.md and follows the playbook. `--dry-run` means **describe the plan, list which surfaces would be investigated and why, but make no AWS calls beyond `sts:GetCallerIdentity`**.

The playbook investigates **whatever account `claude-ro` was launched against**. To investigate a different account, exit and relaunch with `--account <other>`.

## Playbook

### Goal

Find an *escalation chain* from claude-ro's read-only identity to wider permissions, using only credentials reachable from claude-ro itself. The deliverable is a written narrative naming the chain, not a list of regex hits.

A complete chain has all four:

1. A specific surface claude-ro can read (e.g. `s3://acme-deploy/terraform.tfstate`).
2. A specific credential found in that surface (location only — never the value).
3. The identity that credential resolves to (via `whoami_with_creds`).
4. A specific permission that identity has and claude-ro does not (via `simulate_principal_policy`, comparing both).

If no chain is found end-to-end, **that is itself a valid outcome** — report it explicitly with a summary of what was inspected. Do not fabricate chains.

### Tools available

The agent calls these directly via Python (`python3 -c "..."` or interactive Python). None require argparse / a CLI entry — they're library functions in `${CLAUDE_PLUGIN_ROOT}/skills/cred-sweep/providers/aws.py`.

**Pivot helpers (specifically built for this playbook):**

- `simulate_principal_policy(session, principal_arn, actions, resources=None) -> dict` — wraps `iam:SimulatePrincipalPolicy`. Returns `{action: 'allowed' | 'explicitDeny' | 'implicitDeny'}`. Pagination handled.
- `whoami_with_creds(access_key, secret_key, session_token=None, region=None) -> dict` — builds an isolated boto3.Session with override creds and calls `sts:GetCallerIdentity`. Returns `{'arn', 'account', 'user_id'}`. Does **not** touch parent-process environment.

**Per-surface sweepers (cheap pattern pre-screen for any surface the agent decides is worth a look):**

- `sweep_s3`, `sweep_lambda`, `sweep_cloudformation`, `sweep_ec2_userdata`, `sweep_ecs_taskdef`, `sweep_codebuild`, `sweep_ssm_params` — each takes `(session, *, account_id, region, ctx, summary)` and returns `list[Finding]`. The Findings are **evidence the agent reasons over**, not the deliverable.
- `sweep_glue` — declared gap; returns empty list.

**Ad-hoc text scanning (when the agent has fetched something itself):**

- `_scan_text_high_confidence(text, *, account_id, surface, context)` — apply the high-precision pattern catalogue (AWS keys, PEM keys, GitHub/Slack tokens, embedded URL creds).
- `_scan_text_with_advisory(text, *, account_id, surface, context)` — same plus the env-var advisory pattern. Use only on env-var-shaped surfaces.

**Boto plumbing:**

- `_client(session, service, *, region=None)` — boto3 client factory with adaptive retries.
- `_adaptive_config()` — botocore Config when constructing clients directly.
- `_is_denied(exc)`, `_is_throttled(exc)` — error classification.

**From Skill 1 (the sibling `${CLAUDE_PLUGIN_ROOT}/skills/provision/` skill in this same plugin):**

- `_common._ensure_boto3()`, `_common._ensure_pkg(name, pip_name=None)` — lazy install.
- `_common.Ctx`, `_common.now_iso`, `_common.get_logger`, `_common.validate_aws_region`.
- `providers/aws.surface_list()` — priority-sorted `[{name, kind, priority}, …]`. A starting checklist; the agent is free to re-prioritize.
- `providers/aws._client_error_code(exc)`, `providers/aws._is_one_of(exc, codes)`.

**General-purpose:**

- Raw `aws` CLI for anything not covered above.
- Subagents (the `Agent` tool) — *suggested* for parallelism across independent surfaces (e.g. one subagent per region or per surface family). Not required; the agent decides.

### Triage

The agent picks exploration order. Heuristics that usually pay off:

- **Recency.** Recently-modified resources are more likely to contain credentials a human in a hurry pasted in. `LastModified` on S3 objects, `LastModified` on Lambda functions, `LastUpdatedTime` on CFN stacks.
- **Name patterns.** Resources named `*deploy*`, `*ci*`, `*cd*`, `*terraform*`, `*infra*`, `*bootstrap*` are usually pipeline-adjacent and frequently carry deployment creds.
- **IAM-adjacency.** Anything that touches roles, policies, trust relationships, or assume-role chains. Lambdas with `iam:*` in env vars, CFN templates with `AWS::IAM::*`, SSM params named `*role*` / `*assume*`.
- **Privilege-asymmetry hints.** Cross-account S3 buckets and third-party-owned Lambdas often have looser access patterns than first-party ones.

These are heuristics, not a checklist. The agent should reason about *this* account's shape (e.g. heavy Lambda use vs. heavy ECS use) and bias accordingly.

### Pivot rule

When a candidate credential surfaces, **do not declare it a finding yet**. Pivot:

1. **Parse what kind of credential it is.** AWS access-key pair? GitHub PAT? Slack token? Generic API key?
2. **AWS access-key pair.** Call `whoami_with_creds(access_key, secret_key, session_token)` to learn the identity. If the call fails (invalid creds, expired session), log the location as advisory and move on — this isn't a chain, it's noise.
3. **What does that identity unlock?** Call `simulate_principal_policy(session, identity_arn, actions=[...])`. Pick a small set of high-signal actions to probe — e.g. `iam:CreateUser`, `iam:AttachUserPolicy`, `iam:PassRole`, `s3:DeleteBucket`, `kms:Decrypt`, `secretsmanager:GetSecretValue`, `sts:AssumeRole`, `lambda:UpdateFunctionCode`.
4. **Compare against claude-ro's own permissions.** Call `simulate_principal_policy` on claude-ro's own ARN with the same action list (the agent learned its own ARN at startup via `sts:GetCallerIdentity`). The **delta** — actions allowed for the discovered identity but denied for claude-ro — is the chain.
5. **Non-AWS creds (GitHub PAT, Slack token, generic).** Flag the location, mark "non-AWS pivot not available from inside claude-ro." The playbook stops there for non-AWS — pivoting requires the operator's broader access.

If the discovered identity is *narrower* than claude-ro (or equal), it's not an escalation. Note it briefly and move on.

### Stop conditions

Stop and write the report when **any** of:

- A complete escalation chain is documented end-to-end (a finding satisfying all four chain criteria above).
- Wall-clock soft budget of ~30 minutes is reached.
- The agent has worked through `surface_list()` (or its own re-prioritized order) and found no candidates worth a pivot.
- The agent encounters a hard error it cannot classify or work around — stop and report the failure rather than retry indefinitely.

The first chain found is enough. The skill is an *audit*, not exhaustive enumeration. Multiple chains in the same run are fine if they fall out naturally; do not extend the run to hunt for more after the first.

### Output format

A written narrative. Suggested shape:

```
# cred-sweep — <ISO timestamp>
# account: <account_id>  region: <region>  identity: <claude-ro arn>

## Result
<one of: "Escalation chain found" | "No viable chain found">

## Chain (if found)
1. Surface: s3://acme-deploy/terraform.tfstate
2. Credential: aws_access_key_id (location only — value not captured)
3. Identity: arn:aws:iam::<account>:user/build-bot
4. Delta vs. claude-ro:
   - build-bot:  iam:CreateUser=allowed, iam:AttachUserPolicy=allowed
   - claude-ro:  iam:CreateUser=implicitDeny, iam:AttachUserPolicy=implicitDeny

## Inspected
- s3-objects: <N> buckets walked, <M> objects pre-screened
- lambda: <N> functions enumerated, <M> env-var sets pre-screened
- ...

## Skipped / denied / throttled
- s3://huge-bucket: list capped at 20000 keys (configure S3 Inventory)
- ...

## Recommendation
<concrete action: rotate the credential at <location>, restrict IAM trust on <role>, ...>
```

Locations only — **never include the matched value** in the report. The agent should reject any temptation to embed the secret "for clarity"; the privacy posture is non-negotiable (see `Privacy` below).

## Complementary deterministic mode

For a cheap regex-only baseline, run:

```bash
python3 ${CLAUDE_PLUGIN_ROOT}/skills/cred-sweep/scripts/scan.py [--dry-run]
```

`scan.py` walks Skill 1's `surface_list()` deterministically and emits a hit-list of `Finding` blocks. Same library underneath (`providers/aws.py`); the difference is that the agent's playbook *reasons about chains*, while `scan.py` reports raw matches.

When to use which:

- **Playbook (`/cred-sweep`)**: when the question is "is there an escalation path?" Slower, costs tokens, non-deterministic, can find chains regex never can.
- **`scan.py`**: when the question is "is there an obvious credential string?" Fast, cheap, repeatable, exhaustive across the surface list, but blind to anything outside the regex catalogue.

The two are not mutually exclusive — running `scan.py` first is a reasonable opening move if the agent decides to.

## Privacy

Findings — and the playbook's narrative — report **location only**. The `Finding` dataclass has no `value` field by design; do not add one even for debugging. The narrative report must not embed matched strings.

This is enforced by code review and a planted-canary verification (the AWS-published example AKID `AKIAIOSFODNN7EXAMPLE` against any output from this skill: must be 0 matches).

Reporting locations means a leaked secret stays where it already is. Reporting values would put the secret into the operator's terminal scrollback, shell history, ticket system, or wherever the report gets pasted.

## What this skill does NOT do

- **Does NOT exfiltrate** matched values. The playbook narrative carries locations, never contents.
- **Does NOT rotate** discovered credentials. Rotation is the operator's job — the playbook recommends, does not act.
- **Does NOT read or write any state file.** Stateless across runs; account/role/region are the runtime context.
- **Does NOT read `SecureString` parameters.** Skill 1's base policy denies `kms:Decrypt`, which both blocks `secretsmanager:GetSecretValue` and prevents SSM `SecureString` decryption (those return KMS-wrapped ciphertext that needs `Decrypt` to unwrap).
- **Does NOT scan Glue jobs / `ScriptLocation` contents.** Declared coverage gap (org makes minimal use of Glue). Every run that consults `surface_list()` will see Glue listed; the playbook should report it as a known gap, not silently ignore it.
- **Does NOT read ORC-format S3 Inventory manifests.** Pre-implementation recon found 0 ORC configs in the test account; Parquet and CSV are supported.
- **Does NOT scan Lambda container-image packages.** Test account is 100% Zip; container-image Lambdas are flagged but not unpacked.
- **Does NOT defend against an active attacker.** Same scope as Skill 1: the threat is the agent's own reasoning.
- **Is non-deterministic by design.** Re-runs may explore different surfaces in different orders. For deterministic auditing, use `scan.py`.

## Dependencies

- **Skill 1 (`agent-sandbox`)** — the sibling skill under this same plugin — must be provisioned (i.e., `init` and `provision-account` for at least the account claude-ro is launched against; both skills install together via `/plugin install agent-sandbox@amit-cc-plugins`, so nothing further to install separately). The playbook cross-imports Skill 1's `_common.py` and `providers/aws.py` (`surface_list`, `_client_error_code`, `_is_one_of`).
- **`boto3`** is auto-installed via `_common._ensure_boto3()` on first call.
- **`pyarrow`** is auto-installed (~80MB) on the first sweep against an account that has Parquet-format S3 Inventory. Lazy via `_common._ensure_pkg("pyarrow.parquet", "pyarrow")`. CSV-format Inventory uses stdlib only.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Playbook reports `iam:SimulatePrincipalPolicy` denied | claude-ro's base policy permits SimulatePrincipalPolicy against same-account principals, but a target account's SCP or a custom permission boundary may deny it. | Note the inability to pivot in the report; treat the candidate as advisory. |
| `iam:Get*` failures during a pivot | The discovered identity's permissions are not introspectable from claude-ro's vantage. | Report the chain as partial: surface + identity ARN, but `delta unknown`. Operator can run a fuller simulate from admin creds. |
| `[throttled]` lines during a sweep | Heavy traffic in the target account exhausted adaptive retries (`mode=adaptive, max_attempts=10`). | Re-run during quieter hours, or have the agent fall back to a narrower surface set. |
| `no AWS region configured` | claude-ro launcher always sets `AWS_DEFAULT_REGION`. If reached, the launcher invariant is broken. | Re-launch via `claude-ro --account <ID>`. |
| S3 bucket emits `[skipped] ... (object list truncated at 20000 keys ...)` | Bucket has > 20k keys and no Inventory configuration. | Configure S3 Inventory on the bucket; the next run will read it for full coverage. |
| `whoami_with_creds` raises `InvalidClientTokenId` / `SignatureDoesNotMatch` | The candidate "credential" is not a real AWS access-key pair (e.g. matched the AKIA regex but the secret-key the agent paired it with was unrelated text). | Drop as advisory; not a chain. |
