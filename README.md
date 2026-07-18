# amit-cc-plugins

A personal [Claude Code](https://code.claude.com) plugin marketplace.

## Use it

```
/plugin marketplace add AmitZoh/amit-cc-plugins
/plugin install concise-prose@amit-cc-plugins
```

## Plugins

| Plugin | What it does |
| --- | --- |
| [`concise-prose`](./concise-prose) | Reshapes output for fast human reading and enforces a standalone end-of-turn SUMMARY via a Stop hook. |

## Layout convention

- **Small plugins** live in this repo as their own subdirectory, listed in `.claude-plugin/marketplace.json` with a local `source` (`"./plugin-name"`).
- **Large plugins** live in their own dedicated repo and are added here as a new entry in the `plugins` array with an external git `source`, so the marketplace can aggregate them without copying the code in.

## Contributing

The repo is public but only the owner has write access. Open a pull request for any change.
