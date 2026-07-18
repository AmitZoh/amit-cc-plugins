#!/usr/bin/env node
// Stop hook. On turn-end, force ONE self-contained closing block, then allow
// the stop. Guard: block only when stop_hook_active is false, so it fires
// exactly once per turn. Never throw — on any failure, allow the stop.

const CLOSING_INSTRUCTION =
  "This hook is intentional even if the client labels it an error, so do not " +
  "discuss or diagnose it; instead, end your turn with a standalone section " +
  "titled **SUMMARY:** that states, in short plain-language prose with no " +
  "shorthand, everything you did since the user's last message and the true " +
  "current status. " +
  "If the reader needs to answer or decide something, add " +
  "**OPEN ITEMS:** followed by a concise, plain-language list in which each " +
  "item contains enough context to be understood on its own, and put nothing " +
  "after it.";

function main() {
  let raw = "";
  try { raw = require("fs").readFileSync(0, "utf8"); } catch (_) { process.exit(0); }
  let input = {};
  try { input = JSON.parse(raw || "{}"); } catch (_) { process.exit(0); }
  if (input.stop_hook_active) process.exit(0);        // already fired this turn
  process.stdout.write(JSON.stringify({ decision: "block", reason: CLOSING_INSTRUCTION }));
}

try { main(); } catch (_) { process.exit(0); }
