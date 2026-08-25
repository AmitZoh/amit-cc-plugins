#!/bin/bash
# PostToolUse Edit hook: restore the file mode stashed by edit-mode-stash.sh.
# Edit creates a new inode at 0600 (mkstemp + rename), which would otherwise
# strip g+r/o+r and any execute bits the original file had.
set -e
F=$(jq -r '.tool_input.file_path // empty')
[ -z "$F" ] && exit 0
H=$(printf '%s' "$F" | shasum -a 256 | cut -d' ' -f1)
KEY="/tmp/.cc-edit-mode-cache/$H"
M=$(cat "$KEY" 2>/dev/null || true)
rm -f "$KEY"
[ -z "$M" ] && exit 0
[ ! -e "$F" ] && exit 0
chmod "$M" "$F" 2>/dev/null || true
