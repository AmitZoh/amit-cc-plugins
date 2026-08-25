# agent-sandbox-provision

A Claude Code plugin bundling three skills that give an agent a read-only cloud sandbox instead of your real credentials.

- **`agent-sandbox-provision`** — provisions the sandbox: a non-admin macOS user (`claude-ro`), a per-user AWS IAM role (ReadOnlyAccess + targeted denies), read-only Kubernetes access entries, and credential-broker access to GitHub, MongoDB and Snowflake. Every credential is minted by a pinned, argument-less broker that writes it straight to a file — never to stdout, never through the model.
- **`sandbox-cred-sweep`** — runs *inside* the sandbox and audits it: hunts for plaintext credentials reachable from the read-only identity across S3, Lambda, CloudFormation, EC2 user-data, ECS, CodeBuild and SSM Parameter Store, and pivots any it finds into an escalation-chain narrative. Reports locations only, never values.
- **`sandbox-revoke`** — deletes the sandbox (full teardown or single-account). Delete-only, no disable. *Not yet implemented.*

## Threat model

A reasoning agent that decides on a destructive action it considers reasonable — not a typo, not an external attacker. The defense is structural: `claude-ro`'s cloud identity has no mutation capability. One deliberate exception exists (an optional per-cluster SOCKS tunnel broker); see `skills/agent-sandbox-provision/SKILL.md` for the full model before trusting this in your environment.

## Install

From a local clone (fastest for iterating):

```
/plugin marketplace add /path/to/this/repo
/plugin install agent-sandbox-provision@amit-cc-plugins
```

Or test in a single session without installing:

```
claude --plugin-dir /path/to/this/repo/agent-sandbox-provision
```

For team distribution, push this repo to GitHub and teammates run:

```
/plugin marketplace add your-org/this-repo
/plugin install agent-sandbox-provision@amit-cc-plugins
```

Scripts locate their own code via `Path(__file__)`, and slash-command instructions reference `${CLAUDE_PLUGIN_ROOT}` — there's no fixed literal path to type. All three skills install together; `sandbox-cred-sweep` cross-imports `agent-sandbox-provision`'s `_common.py` and AWS provider as a sibling under this plugin's `skills/` directory.

## State

`state.json` (+ `.bak`, `.lock`) lives at `~/.claude/plugins/data/agent-sandbox-provision/` (mode 700, not under this plugin's own installed directory), so it survives a plugin version bump — a plugin install lives under a version-numbered cache path that would otherwise orphan it. It holds account IDs, ARNs and cluster names; nothing more sensitive than that ever touches disk in the sandbox.

## Details

Each skill's `SKILL.md` under `skills/` is the source of truth for its sub-commands, playbook and troubleshooting — this README only orients. Start with `skills/agent-sandbox-provision/SKILL.md`.
