#!/usr/bin/env node
// SessionStart hook. Injects the concise-prose ruleset into context.
// Fires on startup AND resume, so the rule is present from message one.
//
// HARD RULE: never throw. A SessionStart hook that throws blocks Claude Code
// from starting. Everything is wrapped; on any failure we exit 0 silently.

const fs = require("fs");
const path = require("path");

function main() {
  // In a plugin, CLAUDE_PLUGIN_ROOT is the plugin's install dir. Resolve the
  // skill body relative to it so the path is correct wherever it's installed.
  const root = process.env.CLAUDE_PLUGIN_ROOT || path.join(__dirname, "..");
  const skillPath = path.join(root, "skills", "concise", "SKILL.md");

  let ruleset = FALLBACK_RULESET;
  try {
    const body = fs.readFileSync(skillPath, "utf8");
    ruleset = body.replace(/^---[\s\S]*?---\s*/, "").trim() || FALLBACK_RULESET;
  } catch (_) {
    // Skill file unreadable: use the built-in fallback.
  }

  const out = {
    hookSpecificOutput: {
      hookEventName: "SessionStart",
      additionalContext: "ACTIVE OUTPUT STYLE — CONCISE PROSE:\n" + ruleset,
    },
  };
  process.stdout.write(JSON.stringify(out));
}

const FALLBACK_RULESET = [
  "Write for fast human reading. The problem to fix is convoluted, repetitive,",
  "hard-to-scan delivery, not word count. Lead with the conclusion or decision.",
  "Make each point once. Keep reasoning only where it carries information — what",
  "you checked, what is ruled out and why; cut process narration that carries",
  "nothing. Full grammar and real sentences, never shorthand. When you hand",
  "control back to the reader, end with a single list of everything you need",
  "from them; do not scatter it and do not lead with it. Reproduce code,",
  "commands, and error strings exactly.",
].join(" ");

try {
  main();
} catch (_) {
  process.exit(0);
}
