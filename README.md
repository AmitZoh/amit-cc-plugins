# amit-cc-plugins

A personal [Claude Code](https://code.claude.com) plugin marketplace.

## Use it

Add the marketplace once, then install whichever plugins you want from it:

```
/plugin marketplace add AmitZoh/amit-cc-plugins
/plugin install concise-prose@amit-cc-plugins
/plugin install agent-sandbox@amit-cc-plugins
```

## Plugins

| Plugin | What it does | What you type |
| --- | --- | --- |
| [`concise-prose`](./concise-prose) | Reshapes output for fast human reading and enforces a standalone end-of-turn SUMMARY via a Stop hook. | nothing — it works through hooks |
| [`agent-sandbox`](./agent-sandbox) | Provisions a read-only AWS+Kubernetes+GitHub+MongoDB+Snowflake sandbox for Claude Code, sweeps it for plaintext credentials reachable from the sandbox identity, and deletes it when done. | `/agent-sandbox:provision`, `/agent-sandbox:cred-sweep` |

## Layout convention

- **Small plugins** live in this repo as their own subdirectory, listed in `.claude-plugin/marketplace.json` with a local `source` (`"./plugin-name"`).
- **Large plugins** live in their own dedicated repo and are added here as a new entry in the `plugins` array with an external git `source`, so the marketplace can aggregate them without copying the code in.

## Contributing

The repo is public but only the owner has write access. Open a pull request for any change.

Every push to this repo's public `origin` must be squashed to a single commit — work happens on a private staging remote first (see repo owner for details) and only lands here once it's ready.
