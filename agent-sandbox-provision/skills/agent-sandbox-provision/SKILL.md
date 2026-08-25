---
name: agent-sandbox-provision
description: Provision a read-only AWS+Kubernetes+GitHub+MongoDB+Snowflake sandbox for Claude Code. Creates a non-admin macOS user, a per-user IAM role with ReadOnlyAccess + targeted denies, k8s cluster access entries with view-only RBAC, read-only GitHub App / MongoDB DB-user / Snowflake role-restricted-key-pair service-account access reached through pinned argless mint brokers that write short-lived creds to files, so creds never live in the sandbox or pass through the model. Sub-commands init / provision-account / deprovision-account / bind-cluster / unbind-cluster / grant-s3-decrypt / revoke-s3-decrypt / bind-github / unbind-github / bind-mongodb / unbind-mongodb / bind-snowflake / unbind-snowflake / refresh-settings / verify / lockdown. Defends against a deliberate-but-misguided agent — the sandbox identity has no mutation capability; the one exception is the optional per-cluster SOCKS tunnel broker, which creates a single pinned proxy Deployment. Also emits auto-mode classifier rules so Claude Code does not block the brokers.
user-invocable: true
argument-hint: "[init|provision-account|deprovision-account|bind-cluster|unbind-cluster|grant-s3-decrypt|revoke-s3-decrypt|bind-github|unbind-github|bind-mongodb|unbind-mongodb|bind-snowflake|unbind-snowflake|refresh-settings|verify|lockdown|help]"
---

# Agent Sandbox — Provision

## Threat model

A reasoning agent that decides on a destructive action it considers reasonable (Replit-style: "fastest fix is to clear the DB"). Not typos. Not external attackers. Not data exfiltration. The defense is structural: the agent's identity has no mutation capability.

One deliberate exception, and it is the thing to understand before trusting this skill. The per-cluster SOCKS tunnel broker (`claude-ro-tunnel-<cluster>`) runs as the *engineer*, with cluster-admin, because standing up the tunnel requires a cluster write that `claude-ro` by design cannot perform. So the sandboxed agent can cause exactly one mutation: a Deployment named `claude-ro-socks-<port>`, running a SOCKS5 proxy with authentication disabled, in the bound cluster's default namespace. It cannot choose the cluster (compiled into the broker at bind time), the namespace, the image, or the workload shape — but the pod is real, it runs in whatever cluster you bound, and anything in-cluster that can reach port 1080 can proxy through it. If that is not acceptable in your environment, do not run `bind-mongodb --via-cluster`; every other broker is genuinely read-only.

## What this skill does

Provisions and maintains a read-only sandbox identity for Claude Code on a cloud provider + its managed k8s clusters. The sandbox is real, not advisory: the agent runs as a separate macOS user (`claude-ro`) with its own filesystem view, and cloud calls happen through a per-user IAM role whose policies forbid mutation, secret reads, and cost-trap operations.

v1 implements the **AWS** provider (RO role + EKS access entries). The script CLIs accept `--provider aws` so future GCP / Azure providers slot in without changing the per-user binding model.

**Cross-cutting properties:**

- **Zero cloud creds on disk** in `claude-ro`'s home. The launcher assumes the RO role per invocation; session creds live only in the spawned process's environment.
- **Per-launch kubeconfig** containing only the active account's clusters. Cross-account misroute via `kubectl config use-context` is structurally impossible.
- **Bash 3.2 launcher** (macOS default). Sub-commands are Python 3 and run as the user.
- **Idempotent + resumable**. Every mutating sub-command splits into named phases recorded in `state.json`; a partial-failure resume picks up at the next phase.
- **Per-user vs org-shared resources are explicit.** The per-user RO role and EKS access entries are torn down by `deprovision_account` / `unbind_cluster`. Org-shared resources (verify fixtures, supplemental ClusterRoles) are NEVER touched by per-user teardown — they're deleted only by `purge_org_fixtures` (Skill 3, deferred).

## Sub-commands

| Sub-command | Required flags | When to use |
| --- | --- | --- |
| `init` | (none) | One-time machine setup: macOS user, ACL, sudoers, launcher template, launchd plist, binary symlinks, claude-ro login keychain. Provider-agnostic. |
| `provision-account` | `--provider aws --aws-profile P --aws-account-id ID --aws-region R` | Bind THIS user to a provider account: per-user RO role + ensure org-shared verify fixtures. Run once per engineer per account. |
| `deprovision-account` | `--provider aws --aws-account-id ID` | Reverse `provision-account`. Deletes the user's per-user RO role and any cluster access entries. Org-shared fixtures stay. |
| `bind-cluster` | `--provider aws --aws-account-id ID --cluster-name N --aws-region R` | Bind this user's RO role to one k8s cluster on a bound account. Prints full coordinates and confirms before any write. |
| `unbind-cluster` | `--provider aws --aws-account-id ID --cluster-name N` | Reverse `bind-cluster`. Drops only the per-user EKS access entry; the supplemental ClusterRole stays (org-shared). |
| `grant-s3-decrypt` | `--provider aws --bucket B [--prefix P] [--aws-account-id ID]` | Let the RO role read SSE-KMS objects in ONE bucket. The guardrails deny `kms:Decrypt` outright, so a bucket encrypted with KMS returns AccessDenied on GetObject until it is granted. Writes BOTH halves at once — the deny statement grows an exclusion for that bucket's encryption context AND a scoped `Allow` on the resolved key (`ViaService` pinned to S3 in the bucket's region) — because an explicit deny beats any allow while `ReadOnlyAccess` carries no `kms:Decrypt`. Reads the bucket to resolve its region, key ARN (`alias/aws/s3` included) and `BucketKeyEnabled`. `--prefix` works only when bucket keys are OFF; see "S3 objects encrypted with KMS". Refuses buckets with no KMS key — nothing to grant there. Additive + idempotent. |
| `revoke-s3-decrypt` | `--provider aws (--bucket B [--prefix P] \| --all) [--aws-account-id ID]` | Reverse `grant-s3-decrypt`. Drops one bucket's grants (`--prefix` narrows to a single one) or every grant on the account, then re-puts the guardrails. With nothing granted, the deny is unconditional again — identical to what `provision-account` writes. |
| `bind-github` | `--orgs a,b,…` | Grant read-only GitHub access — one **private** read-only App per account (an org **or** your personal user; type auto-detected; owner == install target). Additive + idempotent. Two browser steps per account: *Create*, then *Install* + approve. Installs the shared argless mint broker + git/gh wiring. |
| `unbind-github` | `[--orgs a,b]` | With `--orgs`: remove just those orgs (uninstall + delete their key/state). Without: **FULL** unbind — every org, plus the shared broker/wiring. Each App can't be deleted via API; the command prints each org's settings URL to delete it by hand. |
| `bind-mongodb` | `--name N --kind atlas\|self_hosted (--srv-host H \| --hosts H) --default-db D [--auth password\|aws-iam] [--iam-account ID] [--via-cluster ARN]` | Grant read-only access to one MongoDB deployment. **`--auth password` (default):** prints a create-user command for the DB owner (`claude-ro-<engineer>`, readAnyDatabase@admin), registers pending, then on re-run captures the password and (re)installs the shared all-DBs mint broker. **`--auth aws-iam` (Atlas only):** no password and nothing stored — the Atlas DB user is claude-ro's **per-account RO role** and connections use MONGODB-AWS with claude-ro's minted RO creds; single-phase, it prints the RO role ARN for the DB owner to add in Atlas (IAM Role, readAnyDatabase) and commits. `--iam-account` picks which provisioned account's RO role (defaults to the sole one). Re-running an already-bound DB **updates its settings in place**. `--via-cluster` (password/self-hosted only) = an EKS cluster (its kubectl-context ARN; account must be provisioned) that claude-ro reaches via a **per-session** on-demand `claude-ro-tunnel-<cluster>` broker; no port is stored. |
| `unbind-mongodb` | `--name N` | Reverse `bind-mongodb`. Removes the password + state entry (and the shared broker when the last DB is unbound); the owner-managed DB user is left intact. |
| `bind-snowflake` | (none) | Grant read-only access to one Snowflake account. What the sandbox ends up holding is a short-lived **key-pair JWT**, signed locally from an RSA private key generated with `openssl`; its public half is registered on a dedicated `TYPE = SERVICE_AGENT` account as a **named key pair** carrying `ROLE_RESTRICTION`, which is what scopes the JWT to the read-only role. **Two-phase + resumable, like `bind-mongodb`.** *Phase A* needs no admin, no SSO and no connector on your Mac: it prints one query for you to run in a Snowflake worksheet and paste the single-cell result back, screens the roles that result reports for privileges beyond SELECT/USAGE/REFERENCES/MONITOR, has you pick from the read-only survivors — printing a `CREATE ROLE` block for the admin too if none qualify — and asks you for a friendly **name** for the account (the formal identifier like `kpsovyc-ta51714` is recorded but is never the handle); it then generates the key pair, prints a **fully-substituted** copy-paste SQL block (no placeholders — three statements: `CREATE USER`, `GRANT ROLE <that role> TO USER`, `ALTER USER … ADD KEY PAIR … ROLE_RESTRICTION`) for whoever holds USERADMIN to create the service account + grant that role + register the key, and stops. *Phase B* (re-run, after the admin has run the SQL) probes the connection and commits the record. It takes **no flags at all** — the name and the role are settled inside the flow, not on the command line (role names are account-specific; `READ_ALL` is no Snowflake built-in). Multiple accounts can be bound at once, keyed by their name, all reachable simultaneously. Installs the shared argless mint broker. |
| `unbind-snowflake` | `--name N` | Reverse `bind-snowflake`. Deletes the local private key + state entry (and the shared broker when the LAST account is unbound). Nothing remote is touched: the account is owner-managed and the skill holds no privilege to remove the key registration, so the command prints `DROP USER IF EXISTS <user>;` for the owner to run. |
| `verify` | `--provider aws --aws-account-id ID` *or* `--github` *or* `--mongodb` *or* `--snowflake` *or* `--all` | Run the verification suite. `--all` sweeps every bound account + every bound GitHub org + every MongoDB DB + every Snowflake account; `--github` checks all bound orgs, `--mongodb` runs all bound DBs, `--snowflake` runs all bound accounts. |
| `refresh-settings` | (none) | Re-render every template-rendered LOCAL artifact from state: `/etc/sudoers.d/claude-ro` + the lockdown launchd plist + the secrets/runtime dir ACLs, the broker helpers (github / mongodb / snowflake / per-cluster tunnel) + their pinned sudoers, the git credential helper + gh shim, the launcher, the capability note, and claude-ro's `settings.json` (auto-mode classifier rules). Does NOT re-run `init`-only setup (macOS user, keychain, symlinks). Touches no cloud provider, does not re-bind, and does not create the per-session SOCKS proxy. Run it after UPDATING the skill — a template fix reaches nothing until the thing it renders is re-rendered, and re-running a bind just to pick one up means re-supplying flags for a setup that hasn't changed. |
| `lockdown` | (subcommand: `scan` or `apply`) | Three-tier sensitive-file lockdown over `~`. CC-orchestrated; see "Lockdown maintenance". |

The skill is invoked as a Python entrypoint: `python3 ${CLAUDE_PLUGIN_ROOT}/skills/agent-sandbox-provision/scripts/<subcommand>.py [args]`, where `${CLAUDE_PLUGIN_ROOT}` is set by Claude Code to this plugin's installed location (each script also resolves its own directory via `Path(__file__)`, so there is no fixed literal path to hardcode). All flags are mandatory where listed; no defaults — explicit is better than implicit when the operation has a non-trivial blast radius.

**Every subcommand also accepts `--dry-run` and `--yes`** (omitted from the table's Required-flags column). `--dry-run` validates inputs and prints the plan without side effects — it never mutates state, escalates, opens a browser, or calls a cloud API that writes; `bind-github` additionally verifies the org/user login exists on github.com. `--yes` skips confirmation prompts. It stays **fail-closed on destructive overwrites**: re-running `provision-account` / `bind-cluster` on an existing entity *declines* rather than tears down. `bind-snowflake` cannot overwrite anything, because it takes no name to collide on: re-running it while a bind is *pending* resumes Phase B, and re-running it with nothing pending starts binding an **additional** account (it lists what's already bound first, and rejects a name already in use at the naming step). To change a bound account's role or key, `unbind-snowflake` first — its identity is the key pair, so there is no settings-only update to make. But re-running `bind-mongodb` on an already-bound DB is a **non-destructive in-place update** (refresh hosts/db/options/tunnel, keep the stored password), and `bind-github --orgs` just adds any new accounts — both of those `--yes` proceeds through. Do NOT read the script to confirm these two flags exist — they are universal.

## Args dispatch (when invoked via slash command)

When invoked with `args` (e.g., the user typed `/agent-sandbox-provision verify`), follow this protocol before running anything:

**Flag scoping — read first.** `bind-github` / `unbind-github` / `bind-mongodb` / `unbind-mongodb` / `bind-snowflake` / `unbind-snowflake`, and `verify --github`/`--mongodb`/`--snowflake`, are **top-level identity commands**: they take ONLY the flags in their table row (plus `--yes`/`--dry-run`) and **NEVER** take `--provider` or any `--aws-*` flag. `bind-snowflake`'s row is empty — it takes **no** flags beyond `--yes`/`--dry-run`, not even `--name`. Only `provision-account` / `deprovision-account` / `bind-cluster` / `unbind-cluster` / `grant-s3-decrypt` / `revoke-s3-decrypt` / `verify --provider aws` are AWS/provider-scoped. Do not pattern-match `--provider` onto a GitHub/Mongo command.

0. **Help token — intercept before anything else.** A `help` / `--help` / `-h` token anywhere in `args` makes this a help request, never a run request. If it appears **alone**, print the full Sub-commands table (each sub-command with its one-line description and required flags) and stop — run nothing. If it appears **alongside a sub-command name**, in either order (`bind-cluster help` or `help bind-cluster`), print **only that sub-command's** entry — what it does, when to use it, its required flags plus the universal `--dry-run`/`--yes` — and the rendered `python3 …/scripts/<subcommand>.py …` example, then stop **without executing**. Do not fall through to the flag interview or step 4.
1. **Empty args** → use `AskUserQuestion` to pick a subcommand from the Sub-commands table above. Show every subcommand with a one-line description each.
2. **Unknown subcommand** → use `AskUserQuestion` to confirm which valid subcommand the user meant. Do not guess.
3. **Identify required flags** from the table's "Required flags" column for the chosen subcommand. For each flag the user did NOT supply in `args`:

   a. **Gather candidates from `state.json`**:
      - `--aws-account-id`: every entry in `accounts[]`.
      - `--aws-region`: distinct regions across `accounts[]`.
      - `--aws-profile`: `accounts[].assumer_profile` for the selected account.
      - `--cluster-name`: every cluster under the selected account.
      - `--orgs` (bind-github / unbind-github): org logins (e.g. `my-org`). The installed
        set is discovered live from the GitHub App, not stored — don't gather it from state.
      - `--name` (unbind-mongodb): every entry in `mongodb[]`. (`verify --mongodb` and
        `verify --github` take no name — they check all bound DBs / all installed orgs.)
      - `--name` (unbind-snowflake): every entry in `snowflake[]`. (`verify --snowflake`
        takes no name — it runs all bound accounts.)
      - `--bucket` / `--prefix` (revoke-s3-decrypt): every entry in the selected
        account's `s3_decrypt_grants[]`, labeled with its scope (bucket-wide vs
        prefix). `grant-s3-decrypt` takes a NEW `--bucket` — ask for it, never
        gather it from state; its `--prefix` is optional and stays unset unless the
        user asked for one.
      - `bind-github` takes `--orgs`; `bind-mongodb` takes a NEW `--name` (not from
        `state.json`) and captures its own secret (manifest exchange / secure dialog) —
        never solicit or pass a secret via `args`.
      - `bind-snowflake` takes **no flags at all**, so there is nothing to interview for:
        the account's name, its formal identifier and the role are all gathered inside
        Phase A (the worksheet paste + the picks), and its key pair is generated locally,
        so there is no secret to solicit either. Run it as-is.

   b. **Always ask via `AskUserQuestion`**, even when only one candidate exists. The user must confirm — never substitute silently. Structure the options as:
      1. **"Use the value inferred from `state.json` — `<actual value>`"** — the most directly implied candidate (e.g., the only bound account, the region all accounts share). If there are no candidates at all, omit this option.
      2..N. Other valid candidates, each labeled with source (e.g., `"123456789012 — additional bound account"`).
      *(then alternative modes — see (c))*
      Last. **"Type a different value"** (always present).

   c. **Meaningful alternative modes** (e.g., `verify --all`, `lockdown scan` without `apply`) appear as additional options between the inferred candidates and "Type a different value", each with a one-line explanation of behavior.

4. Once flags are settled, print the rendered `python3 …/scripts/<subcommand>.py …` command on one line and execute it immediately. The slash-command invocation IS the user's confirmation. Do NOT re-confirm, print an "ASSUMPTIONS" block, summarize side effects, or ask "want me to execute it?". Applies to mutating and read-only subcommands alike — running the skill means running the skill.

   **`bind-github` / `bind-mongodb` / `bind-snowflake` are interactive and long-running — run them in the Bash tool's background mode and append `--yes`.** The slash invocation is the confirmation, so `--yes` skips the redundant "Continue?" dialog; the *real* authorization happens inside the flow (GitHub's "Create App"/"Install" browser clicks for github; the DB-owner create-user step + secure password dialog for mongodb; the worksheet query you run and paste back, the role and name picks, then the USERADMIN holder running the printed SQL, for snowflake) plus the admin dialog for the local install. These steps take human time and will blow past the ~2min foreground timeout, so start them backgrounded and narrate from the output file rather than blocking. `bind-github` opens your browser twice (Create, then Install); `bind-mongodb` prints a create-user command for your DB owner and waits (resumably) for the password — if it's interrupted, just re-run the same command and it resumes; `bind-snowflake` prints a query for you to run in a Snowflake worksheet and waits for the pasted result, then for the role and name picks, then prints the admin SQL block and **stops** — re-running the same command is Phase B.

   When describing admin escalation: `init` (and other mutating subcommands) escalate via `_common.admin_run`, which routes through `osascript -e 'do shell script ... with administrator privileges'` (a macOS Authorization Services GUI dialog) when stdin is non-TTY — the CC case. Do NOT call it a "sudo prompt" or say "you'll be asked for sudo". The sudoers file at `/etc/sudoers.d/claude-ro` is still installed as part of `init`'s output (it lets the launcher do passwordless `sudo -u claude-ro` later), but that is content, not the escalation channel.

   When the Bash tool reports "Command running in background with ID: …" for a subcommand that pops a confirmation dialog (`bind-cluster`, `unbind-cluster`, `deprovision-account`, `grant-s3-decrypt`, `revoke-s3-decrypt`, idempotency-conflict path on `provision-account`/`bind-cluster`), do NOT then tell the user "a dialog should be popping up, click Continue". Background mode means the command has already exceeded its ~2min foreground timeout — the dialog was shown and dismissed long ago. Instead, read the output file (`/private/tmp/claude-*/.../tasks/<id>.output`) first and narrate from the state it's actually in (still inside a long AWS/kubectl call, failed past the gate, etc.). Only describe a pending dialog if the foreground call clearly aborted at the confirmation gate or is still in its first few seconds.

   `bind-github` / `bind-mongodb` / `bind-snowflake` are the exception: they are *expected* to be backgrounded because they legitimately wait on the user (browser clicks / the DB-owner step / the Snowflake worksheet paste + admin step). When they're in background, read the output file to see which step it's on (waiting for the manifest callback, waiting for the installation, awaiting the DB-user password, awaiting the pasted worksheet result or the role/name pick, stopped after printing the admin SQL block, running the admin install) and tell the user exactly what to do next — here a "go click X" prompt IS correct, because the flow really is blocked on their action.

   **`bind-snowflake` Phase A and `unbind-snowflake` both end by printing a message addressed to the user's Snowflake admin, between `====` banners. Relay that message to the user IN FULL and VERBATIM.** It is the deliverable of the whole phase — the user has to forward it to another human, so a summary is useless to them, and pointing them at the output-file path is worse. Do NOT extract just the SQL, do NOT paraphrase the explanation around it, and do NOT tell them to go read the file. (The script also copies it to the clipboard; say so.)
5. **If `args` already contains all required flags**, skip the interview and proceed straight to step 4.

Never silently drop a required flag. Never invent a value that the Sub-commands table or `state.json` doesn't justify. If a flag has no inferred candidate and the user can't supply one, stop and surface the gap rather than guessing.

## Per-engineer setup workflow

This is a per-user skill: every engineer runs `init` and `provision-account` for themselves on every account they need read access to, even if a teammate has already provisioned the same account. This is by design — the per-user RO IAM role is what carries the engineer's identity through to AWS audit logs / CloudTrail, and `state.json` is per-machine, so `bind-cluster` reads from a per-user record.

The org-shared verify fixtures (S3 bucket `claude-ro-verify-<account_id>`, KMS alias `alias/claude-ro-verify`, Secrets Manager / DynamoDB / CloudWatch Logs entries with fixed `claude-ro-verify-deny` names) are created the first time anyone in the org runs `provision-account` against a given account. Subsequent engineers' `provision-account` calls hit `BucketAlreadyOwnedByYou` / `ResourceExistsException` and treat those as success — the fixtures are reused. Same idea for the per-cluster supplemental ClusterRole and verify pod: `kubectl apply` is idempotent, and the names are deterministic per cluster.

**Concrete first-time-setup flow** (one engineer, one account, one cluster):

```bash
# 1. Machine prep (provider-agnostic; once per laptop).
python3 ${CLAUDE_PLUGIN_ROOT}/skills/agent-sandbox-provision/scripts/init.py

# 2. Provider account provisioning (once per (engineer, account) pair).
python3 .../scripts/provision_account.py \
    --provider aws \
    --aws-profile my-aws-profile \
    --aws-account-id 123456789012 \
    --aws-region us-east-1

# 3. Cluster binding (once per (engineer, account, cluster) triple).
python3 .../scripts/bind_cluster.py \
    --provider aws \
    --aws-account-id 123456789012 \
    --cluster-name my-eks-cluster \
    --aws-region us-east-1

# 4. Optionally verify.
python3 .../scripts/verify.py --provider aws --aws-account-id 123456789012
```

## How the launcher works

1. The user runs `claude-ro [--account ID] [--profile NAME] [--region NAME] [--context NAME] [-- claude args...]`.
   GitHub, MongoDB and Snowflake are **launcher-independent** — no flags, nothing injected. Inside the sandbox, **all** installed GitHub orgs, **all** bound Mongo DBs and **all** bound Snowflake accounts are reachable via the `claude-ro-mint-github` / `claude-ro-mint-mongodb` / `claude-ro-mint-snowflake` brokers, which write per-org token files, per-DB URI files and per-account JSON files under `/usr/local/claude-ro-runtime`. All of this is independent of the AWS account.
2. Launcher (running as the user) parses flags, looks up the account's RO role + assumer profile, calls `sts:AssumeRole` with the env-var-cleared profile, and obtains short-lived creds.
3. Launcher renders a per-launch kubeconfig containing only the active account's clusters into `/Users/claude-ro/.kube/per-launch/<pid>.<epoch>.kubeconfig`, GCs stale ones from prior launches.
4. Launcher `sudo`'s into `claude-ro` with `env -i`, injecting the assumed creds + `KUBECONFIG=`.
5. Inside Claude Code, `kubectl config use-context X` is constrained to the active account's clusters.
6. Session creds expire in 12h (or sooner — see "Source-cred lifetime" below). When they expire, the next AWS call returns `ExpiredToken`; relaunch is the fix.

## GitHub, MongoDB and Snowflake access (credential broker)

GitHub (a single App), MongoDB (`mongodb[]`) and Snowflake (`snowflake[]`) are
**top-level**, independent of AWS accounts, and all three are **all-at-once**: every
installed GitHub org, every bound Mongo DB and every bound Snowflake account is reachable
in one session, no per-launch selection. Each is reached through an
argless broker that keeps the durable secret out of the sandbox AND out of the model.

- The durable secret (GitHub App private key / Mongo RO password / Snowflake RSA
  private key) lives in a
  mode-600 file under `/usr/local/claude-ro-secrets/` — **outside** the sandbox-ACL'd
  home, so ownership+mode is the enforcing control. `claude-ro` cannot read it. Each
  broker is a single **argument-less** helper in `/usr/local/bin` pinned by one
  `sudo -u <user>` rule — no arguments ⇒ no injection surface — and it **writes** the
  minted credential to a mode-600 file under `/usr/local/claude-ro-runtime/` (readable
  by claude-ro via an inherited allow-ACE), printing only names+paths. The credential
  value never hits stdout or the model's context.
- **GitHub** (one **private** App per account — org or personal user — all reachable at
  once): `bind-github --orgs …` auto-detects each account's type and creates a read-only
  App *owned by that account*, installed on it (private is fine — owner == install target). The argless
  `claude-ro-mint-github` broker mints a ~1h **read-only** token for each bound org and
  writes each to `/usr/local/claude-ro-runtime/github/<org>.token`. `git` is transparent
  — its credential helper reads the token file for the org in the repo path (re-running
  the broker if stale). For `gh`/REST, CC sets `GH_TOKEN=$(cat …/<org>.token)` for the
  org its task is on. No token ever sits in the launcher env.
- **MongoDB** (all bound DBs reachable at once — no per-launch selection): a **single
  shared** helper `claude-ro-mint-mongodb`. The read-only user `claude-ro-<engineer>`
  (`readAnyDatabase@admin`) is created by the **DB owner** out of band — `bind-mongodb`
  prints the exact command and waits resumably for the password. No admin/provisioning
  credential ever touches the laptop. **Nothing is injected at launch, and the URI never
  hits stdout.** claude-ro runs the pinned `sudo … claude-ro-mint-mongodb`, which **writes**
  each DB's connection string to a mode-600 file `/usr/local/claude-ro-runtime/mongodb/<name>.uri`
  (claude-ro-readable) and prints only `<name> <path>` lines. Consumers read the file directly,
  e.g. `mongosh "$(cat /usr/local/claude-ro-runtime/mongodb/<name>.uri)"` — so the password never
  enters the model's context.
- **VPC-only MongoDB (SOCKS tunnel)**: a DB bound with `--via-cluster <eks-arn>` (whose
  account must be provisioned) is reached through a **per-session, on-demand SOCKS5
  tunnel** — nothing is created at launch. When claude-ro needs the DB it runs the pinned
  `sudo … claude-ro-tunnel-<cluster> <session> [port]` broker, which — as the ENGINEER,
  never claude-ro's read-only creds — mints its own admin kubeconfig via boto3 keyed off
  the cluster account's `assumer_profile` (so it works under sudo's stripped env, with no
  KUBECONFIG or `aws` CLI), creates one SOCKS5 proxy **Deployment** (image override
  `CLAUDE_RO_SOCKS_IMAGE`) and a background port-forward on a **free local port it picks
  and prints**. The agent passes that port to `claude-ro-mint-mongodb <port>`, which bakes
  `proxyHost=127.0.0.1&proxyPort=<port>` into the DB's URI, so mongosh routes every
  connection — including replica members it discovers — through the proxy, with hostnames
  resolving inside the cluster. Each session gets its **own** port and Deployment; the
  launcher tears down only its own session's tunnels on exit, and if the tunnel drops
  claude-ro just re-runs the broker with the same port. `verify` reaches tunneled DBs via
  PySocks at the socket layer (needs a session's tunnel up; otherwise a best-effort skip).
  The sandbox's no-mutation invariant is untouched: pod create/delete happens
  engineer-side only.
- **Snowflake** (all bound accounts reachable at once, keyed by their name): what the
  sandbox gets is a short-lived **key-pair JWT**, signed locally by the broker from the
  stored RSA private key. `bind-snowflake` generates the pair locally; the public half is
  registered on a dedicated `TYPE = SERVICE_AGENT` account as a **named key pair** —
  `ALTER USER <u> ADD KEY PAIR <name> PUBLIC_KEY='…' ROLE_RESTRICTION='<role>'` — by
  whoever holds USERADMIN, pasting the fully-substituted SQL block the bind prints (three
  statements: create the account, grant it an **existing** read-only role, add the key
  pair; no role is created). Named key pairs, which Snowflake shipped on 2026-07-15, are
  the point of the design: unlike the legacy `RSA_PUBLIC_KEY` property, a named key pair
  can carry a role restriction — "When ROLE_RESTRICTION is set, the key pair can only be
  used to authenticate if the role requested in the JWT matches this role." The shared
  argless `claude-ro-mint-snowflake` broker signs the JWT from the stored private key with
  **zero network calls**, and **writes** it, alongside the non-secret connection values, to
  `/usr/local/claude-ro-runtime/snowflake/<name>.json` (mode 600, `token_type` =
  `KEYPAIR_JWT`), printing only `<name> <path>`. The JWT expires in under an hour; the
  agent re-runs the broker rather than caching it. Consumption is the **SQL REST API**:
  POST `https://<host>/api/v2/statements` with `Authorization: Bearer <token>` and
  `X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT`, and a body that MUST include
  `"role": "<the bound role>"`, because the key's `ROLE_RESTRICTION` requires the requested
  role to match. `snowflake-connector-python` will **not** work — it derives its own JWT
  from a private key the sandbox does not have.

  **Containment is narrower than "confined to the read-only role", and the gap is real.**
  `ROLE_RESTRICTION` pins the primary role and suppresses secondary roles: the credential
  cannot select another role — verified live, a credential restricted to `READ_ALL` asking
  for `PUBLIC` is refused (`Role 'PUBLIC' … is not permitted for the credentials being
  used`). What it does **not** do is exclude inherited privileges. `PUBLIC` is
  "automatically granted to every user and every role in your account", and "the privileges
  associated with a role are inherited by any roles above that role in the hierarchy" — so
  a session pinned to `READ_ALL` **also holds whatever PUBLIC holds account-wide**. The
  only remedy is `REVOKE <privilege> ON ACCOUNT FROM ROLE PUBLIC`, which is account-wide
  and the org's decision, not this skill's. `DEFAULT_SECONDARY_ROLES = ()` on the account
  is defence-in-depth only.

**Secrets never pass through the model.** The GitHub key arrives via the manifest
exchange; the Mongo password is captured in a macOS secure-input dialog; the Snowflake
private key is generated locally by `openssl` and written straight to its 600 file —
only the *public* half is ever printed, inside the admin SQL block, and what Phase A
asks you to paste back is a query result, never a credential. The JWT the broker signs
with that key is written to its runtime file and never printed either. When
orchestrating `bind-github` / `bind-mongodb` / `bind-snowflake`, do NOT solicit, echo,
or pass secrets in `args` — run the command and let it capture the secret itself.

## Source-cred lifetime

The 12h session is **capped further by the assumer's own session lifetime**. If the user's source creds are an SSO session valid for 1h, AWS clamps the assumed RO-role session to that 1h regardless of `--duration-seconds 43200`. When the source expires, the next AWS call from inside Claude Code returns `ExpiredToken` / "security token included in the request is expired"; relaunch resolves it.

## macOS TCC interaction

TCC (Transparency, Consent, Control) gates `~/Documents`, `~/Desktop`, `~/Downloads`, `~/Pictures` independently of POSIX modes. The allow-ACL on `~` is not enough — TCC keys on the binary + the responsible parent process, and the grant inherits down `terminal → sudo → claude`. Practical rule: **run the launcher from a terminal that has Full Disk Access**. If you can read `~/Documents` as yourself, the agent can too. If launching from Terminal/iTerm without FDA, the agent will see ACL-allowed but TCC-denied folders as empty.

## Claude Code token storage (login keychain)

`init` provisions an **empty-password login keychain** for `claude-ro` at `/Users/claude-ro/Library/Keychains/login.keychain-db`, makes it claude-ro's default + login keychain, and disables auto-lock (`phase_local_keychain`). This is where Claude Code stores its Anthropic OAuth token — the same path CC uses for your own token.

Why a dedicated empty-password keychain: `claude-ro` is created with a throwaway password that `init` discards, so the account's stock login keychain can never be unlocked. Without this, every token write pops a Keychain dialog that can't be satisfied (claude-ro has no GUI session), and CC re-prompts for `/login` on the next launch. Empty password is acceptable — claude-ro already holds the same token on disk, so a keychain only claude-ro can read adds no exposure under the "misguided agent / no mutation" threat model.

The launcher unlocks the keychain (`security unlock-keychain -p ""`) on **every** invocation, right before exec'ing `claude`, because a no-GUI security session re-locks on its own between launches. The unlock lives in the launcher — not in `~/.zshrc` — because the launcher exec's `claude` directly under `env -i`, so no shell rc file is ever sourced. If the keychain is absent (an install predating this phase), the unlock fails silently and CC falls back to its prior behavior.

After `init`, run `/login` once inside `claude-ro`; the token then persists across launches with no further prompts.

## Multi-region within one account

`kubectl` is fine — each context's region is baked into kubeconfig. Non-kubectl AWS calls inside Claude Code use `AWS_DEFAULT_REGION` from the launcher. If a single account spans multiple regions, those calls need a per-call `--region` override or `AWS_REGION=` prefix. To switch the launcher's default region, relaunch with `--region <other>`.

## S3 objects encrypted with KMS

`ReadOnlyAccess` grants `s3:GetObject`, but the guardrails deny `kms:Decrypt`, so an object encrypted with SSE-KMS comes back `AccessDenied` — the S3 permission is there and the decrypt behind it is not. `grant-s3-decrypt` opens exactly one bucket at a time.

Both halves are written from one grant record, and neither works alone. An explicit deny beats any allow, so the `DenyKmsDecrypt` statement has to stop covering the request; `ReadOnlyAccess` contains no `kms:Decrypt`, so something has to allow it:

```
Deny  kms:Decrypt  *            unless kms:EncryptionContext:aws:s3:arn matches a grant
Allow kms:Decrypt  <key arn>    when ViaService = s3.<bucket region> AND the context matches
```

The exclusion on the deny carries exactly **one** condition key. Keys inside a `Condition` block are ANDed, so a second key there (`kms:ViaService`, say) would read "deny when it is not-S3 **and** not-that-bucket" and stop denying direct KMS calls the moment the context matched. `ViaService` belongs on the `Allow`, which is the half that actually grants. A request with no S3 encryption context — a raw `kms:Decrypt` of a ciphertext blob, or a decrypt on Secrets Manager's behalf — has the key absent, and negated string operators evaluate true on an absent key, so the deny still bites. `verify`'s "kms:Decrypt denied" probe keeps passing unchanged with grants in place.

**Prefix scoping depends on the bucket, not on the flag.** S3 puts the object ARN in the encryption context normally, so `--prefix raw/` becomes `StringLike arn:aws:s3:::bucket/raw/*`. With **S3 Bucket Keys enabled** there is one data key per bucket, the context is the bucket ARN, and nothing sub-bucket exists to match — a prefix grant would look correctly narrow and deny every GetObject. `grant-s3-decrypt` reads `BucketKeyEnabled` and stops to ask: grant the whole bucket, abort, or describe something else. Non-interactive runs (`--yes`) abort; widening is never silent.

**What a grant costs you.** It does not add any mutation capability — the sandbox identity still cannot write. It does widen reading: everything in the granted scope is readable by the agent, credentials included, which is what the blanket `kms:Decrypt` deny was buying. Grant per bucket, prefer prefixes where bucket keys allow them, and `revoke-s3-decrypt` when the work is done. Grants live in `state.json` under `accounts[].s3_decrypt_grants` and are re-applied by `provision-account`, so a re-provision does not drop them; `verify` reads one byte of one object under each granted scope to prove the decrypt end-to-end.

## Lockdown maintenance

`lockdown.py` runs as the user and chmods sensitive files in `~` to mode 600 so `claude-ro` can't read them. Three-tier pipeline, **two-phase invocation** orchestrated by Claude Code:

- **Tier 1** (definite block, no LLM): SSH keys, PEMs/p12/JKS, `.env*`, `.netrc`, `credentials.json`, `*service-account*.json`, `*.kdbx`. `chmod 600` directly during `scan`.
- **Tier 2** (possible block, classification by CC): `*secret*` / `*credential*` / `*token*` / `*password*` / `*encrypt*` / narrow `*key*` / `*.crt`, gated by a path prefilter (`~/.config`, `~/.local`, `~/Library/Application Support`, project roots, dotfiles in `~`). The script collects candidates; CC classifies; the script applies. Verdicts are **two-state only**: `sensitive` or `not_sensitive`. Anything malformed gets coerced to `sensitive` (fail-safe).
- **Tier 3** (excluded subtrees, never scanned): `node_modules/`, `.git/`, `vendor/`, `.venv/`, `dist/`, `build/`, `target/`, `.next/`.

**Two-phase invocation pattern (CC orchestrates):**

```bash
# Phase 1: emit candidates as JSON.
python3 ${CLAUDE_PLUGIN_ROOT}/skills/agent-sandbox-provision/scripts/lockdown.py scan

# Phase 2: pipe verdicts to apply.
echo '{"verdicts": {"/path/to/file.key": "sensitive", "/other/keymap.json": "not_sensitive"}}' \
  | python3 ${CLAUDE_PLUGIN_ROOT}/skills/agent-sandbox-provision/scripts/lockdown.py apply
```

CC reads the scan JSON, reasons over filename + path for each Tier-2 candidate, and pipes the verdicts to `apply`. There is no `ANTHROPIC_API_KEY`, no review queue, no interactive y/N during a sweep — Tier-2 classification is a CC-internal operation.

**Privacy disclosure:** the script sends nothing to Anthropic directly. CC's main loop reads filenames + paths during scan and uses its normal reasoning to produce verdicts. The data that crosses the wire is whatever CC normally sends as part of its operation — same consent model as every other CC skill.

**Filename-only scope (deliberate non-goal):** Tier 2 candidacy requires both a Tier-2 name pattern and a likely-secrets path. Generic filenames like `config.json` or `app.yaml` are **out of scope** — not classified, not in any queue. Storing credentials in non-credential-shaped filenames is a user error this skill explicitly does not protect against. Filename-only is privacy-preserving and cheap; content scanning would either miss most of the value or burn a lot of tokens chasing false positives.

**Cadence:** scheduled daily via launchd (plist installed at `~/Library/LaunchAgents/com.claude-ro.lockdown.plist`) which invokes `claude -p "..."` to enter CC headless. ⚠ `claude -p` from launchd is **unverified** — spike-test with a trivial plist before relying on it; see the template comment for tuning knobs (HOME/PATH/USER env, GUI session bootstrap). If headless mode doesn't work, run `lockdown.py scan` manually under interactive CC. Re-runnable; cache-driven; only new files (no cache hit) are re-classified.

**First-run `--dry-run`:** `lockdown.py scan --dry-run` performs Tier 1/2 classification but does not chmod and does not update `state.json`. It writes proposed changes to `/tmp/lockdown-dryrun-<ISO8601>.log` (mode 600). Recommended for the first-ever sweep.

**Runtime deps:** `pip3 install --user pyyaml boto3` runs automatically the first time `init` (or any sub-command) needs them. No manual setup.

## Emergency procedures

If the agent goes rogue (or you suspect it has):

1. **Kill the process.** Session creds die with the spawned `claude` process — quitting the agent immediately invalidates whatever session keys are in its env.
2. **Run `sandbox-revoke delete` (or `delete-account`).** Removes the RO role; new `assume-role` calls fail. Existing session keys remain valid until they expire (capped at 12h, often less per Source-cred lifetime).
3. **For total certainty over in-flight sessions**, attach an explicit deny-all session policy via `aws iam put-role-policy` *before* deleting. Documented in the runbook.

## What this skill explicitly does NOT do

- Does NOT defend against an active attacker who's compromised the agent. The agent's IAM identity having no mutation capability is the defense; an attacker with arbitrary code-execution as `claude-ro` can still read everything `claude-ro` can read.
- Does NOT prevent data exfiltration. The threat model is mutation, not read-out.
- Does NOT support SSO / federated principals in v1. Provisioning fails clearly when the assumer is an `arn:aws:sts::*:assumed-role/*` ARN.
- Does NOT track binary symlinks placed at `/usr/local/bin/{claude,aws,kubectl}`. They're left in place on `sandbox-revoke delete`.
