#!/usr/bin/env bash
# e2e-test.sh — interactive end-to-end test for agent-sandbox-provision.
#
# Run from the skill directory (the parent of scripts/):
#   ./e2e-test.sh [aws-profile] [aws-region] [cluster-name]
#
# All args optional. Defaults: profile from $AWS_PROFILE or "default";
# region from $AWS_REGION/$AWS_DEFAULT_REGION or `aws configure get region`.
#
# Recoverability: re-run with `START_AT=N ./e2e-test.sh ...` to resume at
# step N. State on disk (state.json, AWS resources) carries forward.
#
# Do NOT run other agent-sandbox-provision commands in another terminal
# while this script is paused — they will race on state.json.

set -euo pipefail

# ----- args -----

PROFILE="${1:-${AWS_PROFILE:-default}}"
REGION="${2:-${AWS_REGION:-${AWS_DEFAULT_REGION:-}}}"
CLUSTER="${3:-}"
START_AT="${START_AT:-1}"

if [ -z "$REGION" ]; then
  REGION=$(aws --profile "$PROFILE" configure get region 2>/dev/null || true)
fi

if [ -z "$REGION" ]; then
  echo "no region found (not in args, env, or profile '$PROFILE'). Pass it explicitly: $0 [profile] <region>"
  exit 1
fi

echo "Using profile=$PROFILE region=$REGION${CLUSTER:+ cluster=$CLUSTER}"

SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="$SKILL_DIR/scripts"
# state.json/.bak/.lock live outside SKILL_DIR (see _common.py) — a plugin
# install lives under a version-numbered cache path, so state has to survive
# a version bump. Must track _common.py's STATE_DIR.
STATE_DIR="$HOME/.claude/plugins/data/agent-sandbox-provision"

# ----- ui helpers -----

bold()  { printf '\033[1m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }

step_num=0
step() {
  step_num="$1"
  shift
  if [ "$step_num" -lt "$START_AT" ]; then
    return 1
  fi
  printf '\n%s\n' "$(bold "=== Step $step_num: $1 ===")"
  return 0
}

pause() {
  printf '\n%s\n' "$(yellow ">>> $1")"
  if [ -n "${2:-}" ]; then printf '%s\n' "$2"; fi
  printf '\n%s' "$(bold 'Press Enter to continue (or Ctrl-C to abort)... ')"
  read -r _
}

confirm() {
  printf '\n%s ' "$(bold "$1 [y/N]")"
  read -r ans
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ----- pre-flight: FDA probe -----

TCC_PROBE="$HOME/Documents/.agent-sandbox-fda-probe-$$"
if ! touch "$TCC_PROBE" 2>/dev/null; then
  echo "$(red 'This terminal lacks Full Disk Access.')"
  echo "Grant it: System Settings → Privacy & Security → Full Disk Access → enable for this terminal app."
  echo "Then re-run."
  exit 1
fi
rm -f "$TCC_PROBE"

# ----- pre-flight: stale claude-ro user -----

if id -u claude-ro >/dev/null 2>&1; then
  echo "$(yellow 'claude-ro user already exists from a previous run.')"
  STALE_DIR="/Users/claude-ro/.kube/per-launch"
  if [ -d "$STALE_DIR" ] && [ -n "$(sudo -n ls -A "$STALE_DIR" 2>/dev/null || true)" ]; then
    if confirm "Clean up stale per-launch kubeconfigs in $STALE_DIR?"; then
      sudo rm -rf "$STALE_DIR"/*
      echo "cleaned."
    fi
  fi
fi

# ----- steps -----

step 1 "Pre-flight: verify the AWS profile resolves to an IAM-user ARN" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run aws sts get-caller-identity for profile $PROFILE." \
        "Read-only. Resolves the profile ARN + account ID, then asks you to confirm."
  ARN=$(aws --profile "$PROFILE" sts get-caller-identity --query Arn --output text 2>/dev/null) || {
    echo "$(red "could not run sts:get-caller-identity for profile $PROFILE")"
    exit 1
  }
  ACCOUNT_FROM_STS=$(aws --profile "$PROFILE" sts get-caller-identity --query Account --output text 2>/dev/null)
  echo "Profile $PROFILE resolves to:"
  echo "  ARN:        $ARN"
  echo "  Account ID: $ACCOUNT_FROM_STS"
  echo "  Region:     $REGION"
  echo "  Cluster:    ${CLUSTER:-<none — provision-account only, no cluster will be bound>}"
  case "$ARN" in
    arn:aws:iam::*:user/*)
      echo "$(green 'OK — IAM user principal.')"
      ;;
    *)
      echo "$(red 'FAIL — v1 supports IAM-user principals only.')"
      exit 1
      ;;
  esac
  if ! confirm "Proceed against account $ACCOUNT_FROM_STS in $REGION${CLUSTER:+ (cluster: $CLUSTER)}${CLUSTER:- (no cluster)}?"; then
    echo "aborted at step $step_num"; exit 1
  fi
fi

step 2 "Pre-flight: inspect /usr/local/bin for things init may overwrite" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to list /usr/local/bin/{claude, aws, kubectl}." \
        "Read-only. Shows current state before init local_binaries phase later overwrites."
  for b in claude aws kubectl; do
    if [ -e "/usr/local/bin/$b" ] || [ -L "/usr/local/bin/$b" ]; then
      printf '  %-8s ' "$b" ; ls -la "/usr/local/bin/$b" 2>/dev/null || echo '<unreadable>'
    else
      printf '  %-8s %s\n' "$b" "(not present — init will create a symlink)"
    fi
  done
fi

step 3 "Lockdown dry-run scan — preview which files would be chmodded" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run lockdown.py scan --dry-run." \
        "Read-only walk of your home dir. No chmods. Shows Tier 1 file count + top directories."
  SCAN_JSON=$(python3 "$SCRIPTS/lockdown.py" scan --dry-run)
  python3 - <<PYEOF
import json, collections, sys
d = json.loads(r'''$SCAN_JSON''')
t1 = d.get("tier1_applied") or []
t2 = d.get("tier2_candidates") or []
log = d.get("dry_run_log", "(no log path emitted)")
print(f"Tier 1 (auto chmod 600): {len(t1)} files")
print(f"Tier 2 candidates (need classification later): {len(t2)} files")
print(f"Full dry-run log: {log}")
print()
if t1:
    print("Tier 1 — top 20 directories by file count:")
    buckets = collections.Counter(p["path"].rsplit("/", 1)[0] for p in t1)
    for d_, n in buckets.most_common(20):
        print(f"  {n:5d}  {d_}")
PYEOF
fi

step 4 "init dry-run — confirm machine-prep plan without side effects" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run init.py --dry-run." \
        "Read-only. Walks every init phase logging what it would do. No filesystem changes."
  python3 "$SCRIPTS/init.py" --dry-run --yes
fi

step 5 "Real init — provisions claude-ro user, sudoers, ACL, launchd plist, binary symlinks" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run init.py for real." \
        "Creates claude-ro macOS user, ACL on home, sudoers entry, kubeconfig dir, binary symlinks, launchd plist. No AWS calls."
  if ! confirm "About to actually run init (machine prep, no AWS). Proceed?"; then
    echo "aborted at step $step_num"; exit 1
  fi
  python3 "$SCRIPTS/init.py" --yes
  echo "$(green 'init completed.')"
fi

step 6 "provision-account dry-run — confirm AWS-side plan without side effects" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run provision_account.py --dry-run." \
        "Read-only. Walks every AWS phase logging what it would do. No AWS mutations."
  python3 "$SCRIPTS/provision_account.py" \
    --provider aws \
    --aws-profile "$PROFILE" \
    --aws-account-id "${ACCOUNT_FROM_STS:-$(aws --profile "$PROFILE" sts get-caller-identity --query Account --output text)}" \
    --aws-region "$REGION" \
    --dry-run --yes
fi

step 7 "Real provision-account — creates RO IAM role + ensures org-shared verify fixtures" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run provision_account.py for real." \
        "Creates per-user RO IAM role, attaches ReadOnlyAccess + inline guardrails, ensures org-shared verify fixtures. Idempotent."
  if [ -z "${ACCOUNT_FROM_STS:-}" ]; then
    ACCOUNT_FROM_STS=$(aws --profile "$PROFILE" sts get-caller-identity --query Account --output text)
  fi
  if ! confirm "About to provision user-account binding for profile '$PROFILE' on account $ACCOUNT_FROM_STS. Proceed?"; then
    echo "aborted at step $step_num"; exit 1
  fi
  python3 "$SCRIPTS/provision_account.py" \
    --provider aws \
    --aws-profile "$PROFILE" \
    --aws-account-id "$ACCOUNT_FROM_STS" \
    --aws-region "$REGION" \
    --yes
  echo "$(green 'provision-account completed.')"
fi

# Read ACCOUNT_ID from state.json (provision-account populates it).
# Tolerant if state.json doesn't exist yet (early steps don't need it) or after cleanup deleted it.
ACCOUNT_ID=""
if [ -f "$STATE_DIR/state.json" ]; then
  ACCOUNT_ID=$(python3 -c "import json; print(json.load(open('$STATE_DIR/state.json')).get('default_account_id',''))" 2>/dev/null || echo "")
fi

# ----- cluster binding (if requested) — must run BEFORE launcher smoke + sandbox tests -----

if [ -n "$CLUSTER" ]; then
  step 8 "bind-cluster — bind '$CLUSTER' to the user's RO role" || true
  if [ "$step_num" -ge "$START_AT" ]; then
    pause "About to run bind_cluster.py for cluster $CLUSTER." \
          "Adds EKS access entry for the per-user RO role, ensures org-shared supplemental ClusterRole exists, creates verify pod + samples CRD-kind sentinel."
    if ! confirm "About to bind cluster '$CLUSTER' to account $ACCOUNT_ID. Proceed?"; then
      echo "aborted at step $step_num"; exit 1
    fi
    python3 "$SCRIPTS/bind_cluster.py" \
      --provider aws \
      --aws-account-id "$ACCOUNT_ID" \
      --cluster-name "$CLUSTER" \
      --aws-region "$REGION" \
      --yes
    echo "$(green "bind-cluster completed.")"
  fi
fi

step 9 "Run verify suite against the bound account" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run verify.py against account $ACCOUNT_ID." \
        "Read-only. Assumes the RO role and runs the deny-suite checks."
  if python3 "$SCRIPTS/verify.py" --provider aws --aws-account-id "$ACCOUNT_ID"; then
    echo "$(green 'verify passed.')"
  else
    echo "$(red 'verify failed.') Inspect the per-check output above."
    if ! confirm "Continue anyway?"; then exit 1; fi
  fi
fi

step 10 "Smoke-test the launcher" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run /usr/local/bin/claude-ro --account $ACCOUNT_ID --version." \
        "Exercises the launcher assume-role path. No mutations."
  if [ -x /usr/local/bin/claude-ro ]; then
    echo "Running: /usr/local/bin/claude-ro --account $ACCOUNT_ID --version"
    /usr/local/bin/claude-ro --account "$ACCOUNT_ID" --version || \
      echo "$(yellow 'launcher invocation returned non-zero; can be normal if claude --version exits non-zero.')"
  else
    echo "$(yellow '/usr/local/bin/claude-ro not found.')"
  fi
fi

step 11 "Sandbox sanity test — confirm SECRETS are denied to claude-ro" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to ask you to perform a manual test in a separate terminal." \
        "You will launch claude-ro and try to read your SSH private key. PASS = denied."
fi

if [ -n "$CLUSTER" ]; then
  step 12 "Manual k8s smoke test" || true
  if [ "$step_num" -ge "$START_AT" ]; then
    pause "About to ask you to run kubectl commands in a separate terminal." \
          "You will exercise kubectl get pods (PASS = listed), kubectl get secrets (PASS = forbidden), kubectl delete pod (PASS = forbidden)."
  fi
fi

step 13 "Lockdown classification — CC orchestration via claude -p" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to invoke claude -p --permission-mode auto." \
        "Runs lockdown.py scan --dry-run, classifies 30 Tier 2 candidates via subagents, writes verdicts JSON. Prompt forbids chmods, deletes, and writes outside the verdicts file."
  VERDICTS_FILE="$STATE_DIR/lockdown-verdicts-$(date +%Y%m%dT%H%M%SZ).json"
  PROMPT="Run python3 $SCRIPTS/lockdown.py scan --dry-run, take a random sample of 30 Tier 2 candidates from the output, dispatch them to subagents in batches of 8 to classify each as sensitive or not_sensitive based on filename + path, and write the verdicts JSON to $VERDICTS_FILE. Do not run the apply phase. Under no circumstances should you write to any other path, chmod any files, delete anything, or perform any other mutating action — the only writes you should perform are to the verdicts JSON file specified above."
  echo "About to invoke: claude -p --permission-mode auto with this prompt:"
  printf '  %s\n' "$PROMPT"
  echo
  echo "Expected output file: $VERDICTS_FILE"
  echo "This runs lockdown.py scan in DRY-RUN mode (no chmods), classifies a sample of 30 Tier 2"
  echo "candidates via subagents, and writes the verdicts JSON. The prompt explicitly forbids"
  echo "any writes other than to the verdicts file. No apply phase, no filesystem mutations."
  if ! confirm "Proceed?"; then
    echo "aborted at step $step_num"; exit 1
  fi
  if claude -p --permission-mode auto "$PROMPT"; then
    echo "$(green 'claude -p returned successfully.')"
  else
    echo "$(yellow 'claude -p returned non-zero — check output above.')"
  fi
  if [ -f "$VERDICTS_FILE" ]; then
    echo "Verdicts file written. First few entries:"
    python3 -c "
import json
d = json.load(open('$VERDICTS_FILE'))
v = d.get('verdicts', d)
items = list(v.items())[:5] if isinstance(v, dict) else v[:5]
for k in items: print(' ', k)
print(f'  ... ({len(v)} total)')
"
  else
    echo "$(red "Verdicts file $VERDICTS_FILE not found — orchestration failed.")"
  fi
fi

step 14 "Launchd verification — confirm plist is loaded and scheduled (no trigger)" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run launchctl print to inspect launchd state." \
        "Read-only. Does NOT trigger the lockdown job. Just confirms the plist is loaded and scheduled."
  PLIST="$HOME/Library/LaunchAgents/com.claude-ro.lockdown.plist"
  UID_NUM=$(id -u)
  echo "Checking launchd state (no kickstart, no filesystem mutations)..."
  echo
  if [ ! -f "$PLIST" ]; then
    echo "$(red "plist not found at $PLIST")"
  else
    echo "Plist file: $PLIST exists"
    echo
    echo "--- launchctl print output ---"
    launchctl print "gui/$UID_NUM/com.claude-ro.lockdown" 2>&1 | head -40 || true
    echo "--- end launchctl print ---"
  fi
fi

step 15 "Idempotency check — re-run provision-account dry-run, expect refusal or no-op" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to re-run provision_account.py --dry-run." \
        "Read-only. Confirms idempotency / refusal-to-overwrite-existing-binding behavior."
  python3 "$SCRIPTS/provision_account.py" \
    --provider aws \
    --aws-profile "$PROFILE" \
    --aws-account-id "$ACCOUNT_ID" \
    --aws-region "$REGION" \
    --dry-run --yes || \
    echo "$(yellow 'provision-account exited non-zero on re-run; expected if it refuses to overwrite an existing binding.')"
fi

if [ -n "$CLUSTER" ]; then
  step 16 "Cleanup: unbind-cluster" || true
  if [ "$step_num" -ge "$START_AT" ]; then
    pause "About to run unbind_cluster.py for cluster $CLUSTER." \
          "Removes the per-user EKS access entry. Org-shared supplemental ClusterRole is preserved."
    if confirm "Unbind cluster $CLUSTER?"; then
      python3 "$SCRIPTS/unbind_cluster.py" \
        --provider aws \
        --aws-account-id "$ACCOUNT_ID" \
        --cluster-name "$CLUSTER" \
        --yes
    fi
  fi
fi

step 17 "Cleanup: deprovision-account" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to run deprovision_account.py for account $ACCOUNT_ID." \
        "Deletes the per-user RO role and EKS access entries. Org-shared verify fixtures and supplemental ClusterRoles are preserved."
  if [ -z "$ACCOUNT_ID" ]; then
    echo "$(yellow 'No bound account in state.json — skipping deprovision-account.')"
  elif confirm "Tear down the binding between user and account $ACCOUNT_ID?"; then
    python3 "$SCRIPTS/deprovision_account.py" \
      --provider aws \
      --aws-account-id "$ACCOUNT_ID" \
      --yes
  fi
fi

step 18 "Cleanup: undo init (machine-side artifacts)" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to undo what init did on this machine." \
        "Kills any claude-ro processes; uninstalls the launchd plist; removes /etc/sudoers.d/claude-ro; removes the ACL on \$HOME; deletes the claude-ro macOS user (which wipes /Users/claude-ro/); flushes dscache; removes /usr/local/bin/{claude-ro,claude,aws} symlinks (kubectl is preserved — pre-existed init); deletes state.json + .bak + .lock."
  if confirm "Undo init now?"; then
    pkill -f /usr/local/bin/claude-ro 2>/dev/null || true
    sudo pkill -u claude-ro 2>/dev/null || true
    launchctl bootout "gui/$(id -u)/com.claude-ro.lockdown" 2>/dev/null || true
    rm -f "$HOME/Library/LaunchAgents/com.claude-ro.lockdown.plist"
    sudo rm -f /etc/sudoers.d/claude-ro /usr/local/bin/claude-ro /usr/local/bin/claude /usr/local/bin/aws
    chmod -a "claude-ro allow read,execute,readattr" "$HOME" 2>/dev/null || true
    sudo sysadminctl -deleteUser claude-ro -secure 2>/dev/null || true
    sudo dscacheutil -flushcache 2>/dev/null || true
    rm -f "$STATE_DIR/state.json" "$STATE_DIR/state.json.bak" "$STATE_DIR/state.lock"
    echo "$(green 'Local cleanup complete.')"
  fi
fi

step 19 "Manual cleanup notes — org-shared resources (Skill 3 not yet implemented)" || true
if [ "$step_num" -ge "$START_AT" ]; then
  pause "About to print notes for org-shared resources that survive deprovision." \
        "Read-only. Lists AWS verify fixtures and per-cluster supplemental ClusterRoles."
  cat <<EOF

Org-shared resources remain in account $ACCOUNT_ID. They're meant to be reused across all engineers
sharing the account; delete them only when no engineer in the org is still using the sandbox.

  S3 bucket:        claude-ro-verify-$ACCOUNT_ID
  KMS:              alias/claude-ro-verify (and the underlying key)
  Secrets Manager:  claude-ro-verify-deny
  DynamoDB table:   claude-ro-verify-deny
  CloudWatch Logs:  /aws/claude-ro-verify-deny
  ClusterRoles:     claude-ro-crd-read-<cluster> on each cluster you bound
  Verify pods:      claude-ro-verify-deny in 'default' namespace on each cluster you bound

  Delete via aws CLI / kubectl, or wait for sandbox-revoke purge-org-fixtures (Skill 3, deferred).

EOF
fi

printf '\n%s\n' "$(green '=== End-to-end test complete. ===')"
