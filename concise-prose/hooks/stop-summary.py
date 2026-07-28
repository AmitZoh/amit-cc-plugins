#!/usr/bin/env python3
"""Stop hook: delegated summarizer.

Instead of blocking the main model (which re-runs a full-context inference
with tool access, and historically invented facts, padded open items, and
doubled output), this hook summarizes out-of-band:

  1. Extract the response text the user actually saw since the last summary
     (marker-delimited window over the session transcript).
  2. Pipe it to a cheap headless model call (`claude -p --bare --model haiku`).
  3. Deliver the result via {"systemMessage": ...} — rendered by the client
     as "<hookName> says: <content>" — at zero main-model cost.

Re-summarization is impossible by construction, not by detection: the summary
exists only as a hook_system_message attachment, an entry type the whitelist
below can never admit, and the marker makes everything before it unreadable.

Heuristics are confined to classifying transcript entries as response data
vs non-response data. Everything downstream is a deterministic rule.

HARD RULE: never break the turn. Any failure — bad stdin, unreadable
transcript, missing claude CLI, timeout — exits 0 silently.
"""

import json
import os
import subprocess
import sys

STATE_DIR = os.path.expanduser("~/.claude/plugins/data/concise-prose")
MIN_ASSISTANT_CHARS = 600   # skip threshold on filtered assistant text
MAX_WINDOW_CHARS = 50_000   # cap fed to the summarizer (truncated from the front)
CLAUDE_TIMEOUT_S = 75       # must stay under the hooks.json timeout (90)
NO_SUMMARY_SENTINEL = "NO_SUMMARY"

SUMMARIZER_PROMPT = (
    "You are a post-response summarizer. stdin holds the visible text of a "
    "coding-assistant session segment: assistant replies, user messages, and "
    "queued user messages, in order. Your job is to condense it, never to "
    "reproduce or restate it.\n"
    "\n"
    "SUPPRESSION — decide this first:\n"
    "If the only summary you could write would be nearly as long as the text "
    "it summarizes, or would repeat a postamble, recap, or conclusion the "
    "text already ends with, then do not write a summary at all: output "
    f"exactly {NO_SUMMARY_SENTINEL} on its own line. A well-structured reply "
    "that already leads with its conclusion is the normal case for this. "
    "Suppressing the summary is a correct and expected outcome, not a "
    "failure. If open items are present per the rules below, output the "
    f"OPEN ITEMS: section after the {NO_SUMMARY_SENTINEL} line; otherwise "
    "output nothing further.\n"
    "\n"
    "SELF-CONTAINMENT — this governs everything you write:\n"
    "Write as if the reader will read your output and NOTHING else. They "
    "will never see the text you are summarizing. Therefore you may not "
    "refer to anything your own output has not already introduced and "
    "explained. Concretely: no 'the aforementioned', 'as described above', "
    "'the three findings', 'this approach', 'the fix', or any pronoun or "
    "definite reference that points into the source text rather than into "
    "your own sentences. Every file, name, number, decision, and technical "
    "term you mention must be identified where you mention it. If a sentence "
    "only makes sense to someone who read the source, either supply the "
    "missing detail or delete the sentence.\n"
    "Get brevity by covering FEWER things completely, never by referring to "
    "more things incompletely. Three points a stranger can fully understand "
    "beat ten they cannot.\n"
    "\n"
    "SUMMARY:\n"
    "- Use ONLY facts present in the supplied text. Introduce nothing.\n"
    "- Substantially shorter than the source — a fraction of it, not a trim.\n"
    "- Plain prose. No preamble, no code fences, no headers.\n"
    "\n"
    "OPEN ITEMS:\n"
    "An open item is a point where the reader's input changes what happens "
    "next: a question put to them, a decision or approval awaiting them, a "
    "blocker, or a missing input. It must be EXPLICITLY present in the "
    "supplied text — something the text asks the reader, or states it is "
    "waiting on. Do not infer items from work that could be done, risks "
    "worth noting, adjacent improvements, or your own suggestions.\n"
    "- If one or more such items are present, you MUST end your output with "
    "a section titled exactly 'OPEN ITEMS:', one line per item, naming the "
    "default where the text states one. Each line must be understandable on "
    "its own by a reader who has seen nothing else, including your summary: "
    "state what is being decided and about what, not just 'approve the "
    "change' or 'confirm the approach'.\n"
    "- If none are present, omit the section entirely. Never invent an item "
    "to fill it, and never pad a real item list with weaker ones."
)


def extract_window(transcript_path, marker):
    """Filter transcript lines after `marker` down to response data.

    Whitelist (never blacklist): assistant text blocks, real user text
    messages, and queue-operation enqueues. Tool calls, tool results,
    thinking, attachments, and metadata entry types are all excluded by
    simply not matching.

    Returns (segments, total_lines, assistant_chars) where segments is a
    list of (label, text).
    """
    with open(transcript_path, encoding="utf-8") as f:
        lines = [l for l in f.read().split("\n") if l.strip()]

    segments = []
    assistant_chars = 0
    enqueued = set()  # dequeued messages appear twice (enqueue + user entry)

    # Client-generated user-typed envelopes, marked structurally by the
    # client's own tags rather than by isMeta: slash-command plumbing, and
    # task notifications whose bodies are raw subagent reports (the assistant
    # reply is the user-facing digest of those; feeding them to the summarizer
    # reintroduces the facts-not-in-the-reply failure).
    envelope_prefixes = (
        "<command-name>",
        "<local-command-stdout>",
        "<local-command-caveat>",
        "<task-notification>",
    )

    for line in lines[marker:]:
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue

        if entry.get("isMeta") or entry.get("isSidechain"):
            continue  # hook feedback, caveats, subagent traffic

        etype = entry.get("type")

        if etype == "queue-operation":
            if entry.get("operation") == "enqueue":
                content = entry.get("content")
                if isinstance(content, str) and content.strip():
                    enqueued.add(content.strip())
                    segments.append(("User (queued)", content.strip()))
            continue

        if etype not in ("assistant", "user"):
            continue

        message = entry.get("message") or {}
        role = message.get("role")
        content = message.get("content")

        texts = []
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
        text = "\n".join(t for t in texts if t).strip()
        if not text:
            continue

        if role == "assistant":
            assistant_chars += len(text)
            segments.append(("Assistant", text))
        elif role == "user":
            if text in enqueued:
                continue  # exact-match dedup of the enqueue/user double write
            if text.startswith(envelope_prefixes):
                continue
            segments.append(("User", text))

    return segments, len(lines), assistant_chars


def summarize(window_text):
    """One-shot headless call. Returns summary text, or None to stay silent."""
    env = dict(os.environ, CONCISE_SUMMARIZER="1")
    # NOT --bare: it skips credential loading ("Not logged in"). Instead keep
    # auth and explicitly disable everything else. The prompt must precede the
    # variadic --mcp-config or it gets swallowed as a config path.
    try:
        result = subprocess.run(
            [
                "claude", "-p", SUMMARIZER_PROMPT,
                "--model", "haiku",
                "--settings", '{"disableAllHooks":true}',
                "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
            ],
            input=window_text,
            capture_output=True,
            text=True,
            timeout=CLAUDE_TIMEOUT_S,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    summary = result.stdout.strip()

    # Suppression: the sentinel may stand alone, or be followed by an
    # OPEN ITEMS: section that must survive on its own.
    if summary.startswith(NO_SUMMARY_SENTINEL):
        summary = summary[len(NO_SUMMARY_SENTINEL):].strip()
        if not summary.startswith("OPEN ITEMS:"):
            return ""  # success, nothing worth showing

    return summary  # "" here also means silence


def load_marker(session_id):
    try:
        with open(os.path.join(STATE_DIR, f"state-{session_id}.json"), encoding="utf-8") as f:
            return int(json.load(f).get("marker", 0))
    except (OSError, ValueError, json.JSONDecodeError):
        return 0


def save_marker(session_id, marker):
    os.makedirs(STATE_DIR, exist_ok=True)
    path = os.path.join(STATE_DIR, f"state-{session_id}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"marker": marker}, f)
    os.replace(tmp, path)


def main():
    if os.environ.get("CONCISE_SUMMARIZER") == "1":
        return  # we are the headless child (belt; --bare is the suspenders)

    # Debug/test mode: print the filtered window and exit. No model call.
    if len(sys.argv) >= 3 and sys.argv[1] == "--extract-window":
        marker = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        segments, total, chars = extract_window(sys.argv[2], marker)
        for label, text in segments:
            print(f"[{label}] {text}")
        print(f"--- lines={total} assistant_chars={chars}", file=sys.stderr)
        return

    hook_input = json.load(sys.stdin)
    if hook_input.get("stop_hook_active"):
        return

    session_id = hook_input.get("session_id")
    transcript_path = hook_input.get("transcript_path")
    if not session_id or not transcript_path:
        return

    marker = load_marker(session_id)
    segments, total_lines, assistant_chars = extract_window(transcript_path, marker)

    if assistant_chars < MIN_ASSISTANT_CHARS:
        return  # marker NOT advanced: short turns accrue into the next window

    window_text = "\n\n".join(f"[{label}]\n{text}" for label, text in segments)
    if len(window_text) > MAX_WINDOW_CHARS:
        window_text = (
            "[NOTE: window truncated from the front]\n...\n"
            + window_text[-MAX_WINDOW_CHARS:]
        )

    summary = summarize(window_text)
    if summary is None:
        return  # call failed: marker NOT advanced, content retried next stop

    save_marker(session_id, total_lines)
    if summary:
        print(json.dumps({"systemMessage": summary}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(0)
