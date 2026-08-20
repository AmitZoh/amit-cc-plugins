# concise-prose

A Claude Code plugin that reshapes Claude Code's output for fast human reading. The goal is not fewer words — it is fixing convoluted, repetitive, hard-to-scan delivery. Lead with the conclusion, keep only reasoning that carries information. Full grammar, no shorthand.

## How it works (v1.3)

- A **SessionStart** hook injects the ruleset from message one (and again on resume). The skill file (`skills/concise/SKILL.md`) is the single source of truth for the rules.
- A **Stop** hook (`hooks/stop-summary.py`) delivers a summary *out-of-band* at the end of substantive turns. It never blocks the main model. Flow:
  1. A marker file (`~/.claude/plugins/data/concise-prose/state-<session_id>.json`, transcript line count) delimits the window: everything after the last delivered summary.
  2. A whitelist filter extracts only response data from the transcript window: assistant text, real user messages, and `queue-operation` enqueues (messages the user sent mid-turn — these never become `user` entries in the transcript, so any "walk back to the last user message" approach misses them entirely). Tool calls, tool results, thinking, attachments, task-notification bodies, slash-command envelopes, and `isMeta`/sidechain entries are excluded.
  3. The filtered text is piped to `/Users/amitzohar/.local/bin/claude -p --model haiku`. The call deliberately omits `--bare`, because `--bare` also skips credential loading and the summarizer then fails with "Not logged in". Recursion is instead prevented by `CONCISE_SUMMARIZER=1` in the child's environment, backed by `--settings '{"disableAllHooks":true}'`; the call also passes an empty `--allowedTools`, an empty MCP config, and `--disable-slash-commands`. The summarizer may use only facts present in its input, and lists OPEN ITEMS only for questions the text explicitly poses.
  4. The result is emitted as `{"systemMessage": ...}` — rendered by the client as `stop-summary says: <content>` at zero main-model cost.

Re-summarization is impossible by construction: the summary exists only as a `hook_system_message` attachment, an entry type the whitelist can never admit, and the marker makes everything before it unreadable. Turns with under 600 chars of new assistant text are skipped without advancing the marker, so short turns accrue into the next window.

Design history: v1.2 used `decision: "block"`, which re-ran the main model with full context and tool access to write its own summary. That summary routinely introduced facts absent from the reply, invented open items (sometimes doing research to populate them), fired on empty turns, and roughly doubled output length — each occurrence costing a full-context inference. The per-turn UserPromptSubmit reminder from v1.2 is also gone: it demonstrably failed to shape behavior and its "a separate step adds it" wording described a mechanism that did not exist (it does now).

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

Note that `${CLAUDE_PLUGIN_ROOT}` resolves to the installed cache copy (`~/.claude/plugins/cache/...`), not this source tree — to apply edits, bump the version in `.claude-plugin/plugin.json`, run `claude plugin update concise-prose@concise-prose`, and restart. The skill appears namespaced as `/concise-prose:concise`.

For team distribution, push this repo to GitHub and teammates run:

```
/plugin marketplace add your-org/this-repo
/plugin install concise-prose@amit-tools
```

## Tuning

- Edit `skills/concise/SKILL.md` to change the register.
- `stop-summary.py` constants: `MIN_ASSISTANT_CHARS` (skip threshold, default 600), `MAX_WINDOW_CHARS` (summarizer input cap, default 50k), `CLAUDE_TIMEOUT_S` (must stay under the 90s hook timeout in `hooks.json`), and `SUMMARIZER_PROMPT`.
- Debug the filter without a model call: `python3 hooks/stop-summary.py --extract-window <transcript.jsonl> [marker-line]` prints the extracted window.
- All hooks silent-fail by design: on any error they exit 0 and do nothing. A missing summary must never break a turn.

## Notes / limits

- Injected context (SessionStart) steers strongly but is not a hard constraint. The Stop-hook summary is the reliable layer.
- Requires the `claude` CLI on PATH (used headless for the Haiku call) and `python3`.
- The summary renders via the hook `systemMessage` channel. Verified against the v2.1.220 client bundle: `hook_system_message` renders unconditionally in the normal view; only `PreToolUse`/`PostToolUse` hook attachments are hidden.
- Don't also wire these hooks into `settings.json` by hand — running both the plugin and a manual copy double-fires.
