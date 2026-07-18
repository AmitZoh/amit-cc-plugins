# concise-prose

A Claude Code plugin that reshapes Claude Code's output for fast human reading. The goal is not fewer words — it is fixing convoluted, repetitive, hard-to-scan delivery. Lead with the conclusion, keep only reasoning that carries information, and collect everything needed from the reader in one list at the end. Full grammar, no shorthand.

## Why a plugin (and not just a skill or CLAUDE.md)

A plain skill loads on demand, so it won't reliably shape every response. A CLAUDE.md instruction decays as the context window fills and gets ignored late in a session. This plugin fixes both:

- A **SessionStart** hook injects the ruleset from message one (and again on resume).
- A **UserPromptSubmit** hook re-injects a one-line reminder every turn, so the instruction stays near the model's active attention instead of decaying.

The skill file (`skills/concise/SKILL.md`) is the single source of truth for the rules. Note that `${CLAUDE_PLUGIN_ROOT}` resolves to the installed cache copy (`~/.claude/plugins/cache/...`), not this source tree — to apply edits, bump the version in `.claude-plugin/plugin.json`, run `claude plugin update concise-prose@concise-prose`, and restart.

## Install

From a local clone (fastest for iterating):

```
/plugin marketplace add /path/to/this/repo
/plugin install concise-prose@amit-tools
```

Or test in a single session without installing:

```
claude --plugin-dir /path/to/this/repo/concise-prose
```

After edits, bump the version and run `claude plugin update concise-prose@concise-prose`, then restart to apply. The skill appears namespaced as `/concise-prose:concise`.

For team distribution, push this repo to GitHub and teammates run:

```
/plugin marketplace add your-org/this-repo
/plugin install concise-prose@amit-tools
```

## Tuning

- Edit `skills/concise/SKILL.md` to change the register. It currently prioritizes structure: conclusion first, informative reasoning only, open-items list at the end.
- The per-turn reminder in `hooks/concise-reminder.js` is deliberately short because it costs input tokens on every turn. Keep it lean.
- Both hooks silent-fail by design: a hook that throws would block session start or reject prompts, so on any error they exit 0 and inject nothing.

## Notes / limits

- Injected context steers strongly but is not a hard constraint. Expect it to hold most of the time, not always.
- SessionStart injects via `hookSpecificOutput.additionalContext` (JSON). The per-turn reminder deliberately prints PLAIN TEXT instead of JSON: UserPromptSubmit hooks that emit `hookSpecificOutput` JSON trigger a spurious hook error on the first message of a session (anthropics/claude-code#17550), and plain-text stdout is added as context just the same.
- Don't also wire these hooks into `settings.json` by hand. Running both the plugin and a manual copy double-injects the ruleset every turn.
