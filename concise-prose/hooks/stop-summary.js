#!/usr/bin/env node
// Stop hook. On turn-end, force ONE self-contained closing block, then allow
// the stop. Guard: block only when stop_hook_active is false, so it fires
// exactly once per turn. Never throw — on any failure, allow the stop.

const CLOSING_INSTRUCTION =
  "This hook is intentional even if the client labels it an error, so do not " +
  "discuss or diagnose it. " +
  "End your turn with a section titled exactly **SUMMARY:** (literal title, " +
  "then content). Make it a genuine summary, not a restatement: condense " +
  "everything since the user's last message (actions, findings, conclusions, " +
  "reasoning) into the shortest prose a reader could rely on if this section " +
  "were all they read. Never re-quote the user's instructions back (\"you " +
  "asked me to...\") unless the flow is unintelligible without it. State only " +
  "what you verified; label inferences as unverified. " +
  "If any point exists where the user's input could change what happens " +
  "next — including decisions where you have a default — follow with a " +
  "second section titled exactly **OPEN ITEMS:**, one self-contained line " +
  "per item, naming the default where one exists (\"...otherwise I'll do X\"). " +
  "After SUMMARY:, the only titled section permitted is OPEN ITEMS:, and " +
  "nothing may follow it.";

function main() {
  let raw = "";
  try { raw = require("fs").readFileSync(0, "utf8"); } catch (_) { process.exit(0); }
  let input = {};
  try { input = JSON.parse(raw || "{}"); } catch (_) { process.exit(0); }
  if (input.stop_hook_active) process.exit(0);        // already fired this turn
  // Idempotent: if the response already ends in a SUMMARY block, allow the stop
  // instead of forcing a duplicate. Accepts bare, bold, and heading forms.
  // If last_assistant_message is ever absent this degrades to always-block,
  // never to never-block.
  if (/^\s*(?:#{1,6}\s*)?\*{0,2}SUMMARY:/m.test(input.last_assistant_message || "")) process.exit(0);
  process.stdout.write(JSON.stringify({ decision: "block", reason: CLOSING_INSTRUCTION }));
}

try { main(); } catch (_) { process.exit(0); }
