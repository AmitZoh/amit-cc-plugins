# amit-cc-plugins

A personal [Claude Code](https://code.claude.com) plugin marketplace.

## Use it

Add the marketplace once, then install whichever plugins you want from it:

```
/plugin marketplace add AmitZoh/amit-cc-plugins
/plugin install concise-prose@amit-cc-plugins
/plugin install agent-sandbox@amit-cc-plugins
/plugin install git-tools@amit-cc-plugins
```

## Plugins

| Plugin | What it does | What you type |
| --- | --- | --- |
| [`concise-prose`](./concise-prose) | Reshapes output for fast human reading and enforces a standalone end-of-turn SUMMARY via a Stop hook. | nothing — it works through hooks |
| [`agent-sandbox`](./agent-sandbox) | Provisions a read-only AWS+Kubernetes+GitHub+MongoDB+Snowflake sandbox for Claude Code, sweeps it for plaintext credentials reachable from the sandbox identity, and deletes it when done. | `/agent-sandbox:provision` to set it up, then `claude-ro` to launch a sandboxed session |
| [`git-tools`](./git-tools) | Sets up a daily launchd job that auto-commits and pushes a repo, resolves pull conflicts, and surfaces push errors at the next session start. | `/git-tools:setup-auto-commit` |

## Layout convention

- **Small plugins** live in this repo as their own subdirectory, listed in `.claude-plugin/marketplace.json` with a local `source` (`"./plugin-name"`).
- **Large plugins** live in their own dedicated repo and are added here as a new entry in the `plugins` array with an external git `source`, so the marketplace can aggregate them without copying the code in.

## Contributing

The repo is public but only the owner has write access. Open a pull request for any change.

Every change goes through a private staging remote before it reaches this repo's public `origin`. The owner's clone calls that remote `private` (see the repo owner for access).

1. **Stage.** Push the change to `private`. Work-in-progress commits are fine there.
2. **Test.** The owner tests the staged change.
3. **Approve.** The owner explicitly approves that change for `origin`.
4. **Release.** Push the approved change to `origin` as one commit. Squash the change's staging commits into that one commit, but never combine unrelated changes into it. To release several changes, push each commit separately, oldest first.

Nothing reaches `origin` before step 3. An approval to "push" means a push to `private` unless the owner names `origin`.
