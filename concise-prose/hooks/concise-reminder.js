#!/usr/bin/env node
// UserPromptSubmit hook. Re-injects a short reminder every turn.
//
// This is the anti-decay mechanism. A single SessionStart injection loses
// weight as the window fills — the same reason a static CLAUDE.md gets ignored
// late in a session. A one-line reminder each turn keeps the rule near the
// model's active attention. Keep it SHORT: paid as input tokens every turn.
//
// HARD RULE: never throw. A thrown UserPromptSubmit hook rejects the user's
// prompt. Wrapped; on failure we exit 0 silently.

function main() {
  // NOTE: UserPromptSubmit hooks that emit hookSpecificOutput JSON trigger a
  // spurious "UserPromptSubmit hook error" on the first message of a session
  // (anthropics/claude-code#17550). Plain-text stdout is also added as context
  // for this event and avoids the error, so we print plain text, not JSON.
  const reminder =
    "Reminder: write for fast human reading. Lead with the conclusion or " +
    "decision. Make each point once; don't restate it in another section. " +
    "Don't over-structure: use headings and bullets only when they genuinely " +
    "aid scanning. Keep reasoning only where it carries information (what you " +
    "checked, what's ruled out and why); cut process narration, filler, " +
    "openers, closers, and hedging. Full grammar, no shorthand. Do not write " +
    "your own closing summary or open-questions list — a separate step adds it " +
    "at the very end. Offload heavy search, multi-file reading, and independent " +
    "actions to background subagents when you can: they run in parallel and " +
    "keep bulk output out of your context, so you keep only their conclusions. " +
    "Reproduce code, commands, and errors verbatim.";

  process.stdout.write(reminder);
}

try {
  main();
} catch (_) {
  process.exit(0);
}
