#!/bin/bash
# PreToolUse Edit hook: snapshot the file's mode so the matching PostToolUse
# hook can restore it after Edit replaces the inode at 0600. Installed by
# agent-sandbox-provision/scripts/init.py phase_local_edit_mode_hooks.
set -e
F=$(jq -r '.tool_input.file_path // empty')
[ -z "$F" ] && exit 0
[ ! -e "$F" ] && exit 0
mkdir -p /tmp/.cc-edit-mode-cache
H=$(printf '%s' "$F" | shasum -a 256 | cut -d' ' -f1)
stat -f '%Lp' "$F" > "/tmp/.cc-edit-mode-cache/$H" 2>/dev/null || true
