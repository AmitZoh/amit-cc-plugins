# agent-sandbox

A Claude Code plugin bundling three skills that give an agent a read-only cloud sandbox instead of your real credentials.

- **`provision`** (`/agent-sandbox:provision`) — provisions the sandbox: a non-admin macOS user (`claude-ro`), a per-user AWS IAM role (ReadOnlyAccess + targeted denies), read-only Kubernetes access entries, and credential-broker access to GitHub, MongoDB and Snowflake. Every credential is minted by a pinned, argument-less broker that writes it straight to a file — never to stdout, never through the model.
- **`cred-sweep`** (`/agent-sandbox:cred-sweep`) — runs *inside* the sandbox and audits it: hunts for plaintext credentials reachable from the read-only identity across S3, Lambda, CloudFormation, EC2 user-data, ECS, CodeBuild and SSM Parameter Store, and pivots any it finds into an escalation-chain narrative. Reports locations only, never values.
- **`revoke`** — deletes the sandbox (full teardown or single-account). Delete-only, no disable. Not user-invocable, so it has no slash command; Claude reaches for it when you ask to tear the sandbox down. *Not yet implemented.*

Start with `/agent-sandbox:provision init`, then `/agent-sandbox:provision provision-account` for each cloud account.

## Hooks

This plugin registers a `PreToolUse` / `PostToolUse` pair on `Edit` (see `hooks/hooks.json`). They record a file's permissions before an edit and restore them after, because `Edit` replaces the file at mode `0600` and would otherwise strip the read access `claude-ro` depends on. They are declared by the plugin, so nothing writes paths into your `settings.json`; installing the plugin is all that is needed.

## Threat model

A reasoning agent that decides on a destructive action it considers reasonable — not a typo, not an external attacker. The defense is structural: `claude-ro`'s cloud identity has no mutation capability. One deliberate exception exists (an optional per-cluster SOCKS tunnel broker); see `skills/provision/SKILL.md` for the full model before trusting this in your environment.

## Install

```
/plugin marketplace add AmitZoh/amit-cc-plugins
/plugin install agent-sandbox@amit-cc-plugins
```

From a local clone instead, when iterating on the plugin itself:

```
/plugin marketplace add /path/to/this/repo
/plugin install agent-sandbox@amit-cc-plugins
```

Or test in a single session without installing:

```
claude --plugin-dir /path/to/this/repo/agent-sandbox
```

macOS only, and `init` needs admin rights on the machine.

Scripts locate their own code via `Path(__file__)`, and slash-command instructions reference `${CLAUDE_PLUGIN_ROOT}` — there's no fixed literal path to type. All three skills install together; `cred-sweep` cross-imports `provision`'s `_common.py` and AWS provider as a sibling under this plugin's `skills/` directory.

`claude-ro` discovers skills only through `~/.claude/skills`, never through your plugins directory, so `cred-sweep` — the one skill meant to run *inside* the sandbox — is linked there for you by `init` and re-linked by `refresh-settings`. It consequently appears as a personal skill named `cred-sweep` rather than `/agent-sandbox:cred-sweep`. `provision` and `revoke` are deliberately left out of `claude-ro`'s reach.

## Where installed files point

`init` creates `/usr/local/claude-ro-skills`, a root-owned symlink to the plugin's `skills/` directory. The brokers in `/usr/local/bin` and the lockdown launchd job reach the code through it, so none of them stores a real path, and `~/.claude/skills/cred-sweep` is linked through it too rather than at the version-numbered plugin cache. One link moves on an update; nothing else has to.

After updating the plugin — or moving between a local clone and an installed copy — run `/agent-sandbox:provision refresh-settings` to repoint it and re-render everything that uses it.

## State

`state.json` (+ `.bak`, `.lock`) lives at `~/.claude/plugins/data/agent-sandbox/` (mode 700, not under this plugin's own installed directory), so it survives a plugin version bump — a plugin install lives under a version-numbered cache path that would otherwise orphan it. It holds account IDs, ARNs and cluster names; nothing more sensitive than that ever touches disk in the sandbox.

## Details

Each skill's `SKILL.md` under `skills/` is the source of truth for its sub-commands, playbook and troubleshooting — this README only orients. Start with `skills/provision/SKILL.md`.
