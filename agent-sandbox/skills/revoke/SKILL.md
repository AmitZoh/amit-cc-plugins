---
name: revoke
description: Delete the read-only cloud sandbox provisioned by the provision skill. Delete-only — no disable. Sub-commands delete (full teardown) and delete-account (single-account teardown). NOT YET IMPLEMENTED.
user-invocable: false
---

# Sandbox Revoke — NOT YET IMPLEMENTED

This skill is part of the read-only cloud sandbox bundle. The full implementation lands after `provision` is in place. See `~/.claude/plans/refactored-twirling-flask.md` for the design.

When implemented, this skill will provide:

- `delete` — full teardown of every bound account's RO role + EKS access entries, the macOS user (with home wipe via `sysadminctl -secure`), the launcher, sudoers entry, ACL, per-launch kubeconfigs, launchd plist, and `state.json`. Binary symlinks under `/usr/local/bin/{claude,aws,kubectl}` are left in place. **Org-shared verify fixtures inside each AWS account are NOT deleted** (other engineers in the same account may still be using them); use `purge-org-fixtures` for that.
- `delete-account ACCOUNT` — single-account teardown. Removes the local user's RO role, EKS access entries, supplemental ClusterRoles, and the account's entry in `state.json`. Org-shared verify fixtures stay.
- `purge-org-fixtures ACCOUNT --confirm` — destructive, account-scoped: deletes the shared verify fixtures (`claude-ro-verify-<account_id>` S3 bucket and contents, `alias/claude-ro-verify` KMS alias + key, `claude-ro-verify-deny` Secrets Manager secret / DynamoDB table / CloudWatch Logs group, per-cluster `claude-ro-verify-deny` pods). Run only when **no engineer in the org is still using this account's sandbox**. Requires `--confirm`.

Reactivation is via `/agent-sandbox:provision provision-account`, not a separate enable flow.
