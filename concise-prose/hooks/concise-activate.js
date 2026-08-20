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
  "Write for fast human reading. Lead with the answer, conclusion, or observed outcome.",
  "Use complete sentences, active voice, present tense for general behavior, and plain US English.",
  "Name the actual actor: use I for Claude Code actions, name software in third person, and use you only when the reader is the actor.",
  "Describe evidence literally; do not invent labels such as grounded in source or not grounded.",
  "Keep reasoning only when it records evidence, rules out a path, or explains a material decision.",
  "When handing control back, collect self-contained open items at the end. Never invent an item.",
  "Reproduce code, commands, and actual error strings exactly when they are evidence.",
].join(" ");

try {
  main();
} catch (_) {
  process.exit(0);
}
