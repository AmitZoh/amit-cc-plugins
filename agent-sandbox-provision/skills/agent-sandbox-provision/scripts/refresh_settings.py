#!/usr/bin/env python3
"""Re-render every LOCAL artifact of the sandbox from state, without re-binding anything.

This is the "I updated the skill" command. Binds and unbinds already re-render what they
touch, but a skill update changes the TEMPLATES — and nothing re-applies a template until
the thing it renders is bound again. Re-running a bind to pick up a template fix means
re-supplying every flag for a setup that has not changed, which is exactly what this
avoids: everything here is read back out of state.json.

Re-renders:
  * /etc/sudoers.d/claude-ro (the base rule) and the claude-ro lockdown launchd plist,
    plus the ACLs on the secrets and runtime directories
  * the broker helpers in /usr/local/bin (mint-github / mint-mongodb / mint-snowflake /
    mint-aws-<account> / tunnel-<cluster>) and their pinned sudoers drop-ins
  * the git credential helper and gh shim, when GitHub is bound
  * the claude-ro launcher
  * the SessionStart capability note
  * claude-ro's settings.json — the auto-mode classifier rules (see _auto_mode_config in
    _common.py, which explains why the classifier has to be told what the brokers are)

Touches NO cloud provider, and deliberately so. Rendering a broker is a pure
state-to-file operation: the rendered scripts do their AWS / GitHub / MongoDB / Snowflake /
cluster work when they RUN, not when they are written. Nothing here mints a credential,
reaches a cluster, or edits state.json.

NOT in scope, both on purpose:
  * The cloud side — IAM role and policies, EKS access entries and RBAC, the GitHub App
    installation, the Mongo user, the Snowflake service user and its registered public key.
    Re-applying those is a reconcile against five live providers, not a re-render, and the
    bind sub-commands own it.
  * The SOCKS proxy Deployment. It is per-session by design and the launcher deletes it on
    exit; re-creating it here would leave an orphan pod running in the cluster with
    authentication disabled, outside any session that would clean it up.
"""
from __future__ import annotations

import argparse

import _common as common
import bind_github
import init
import render_launcher


def _rerender_machine(username: str, ctx: common.Ctx) -> None:
    """Re-render the machine-level artifacts `init` lays down that are rendered from a
    TEMPLATE — so a skill update reaches them — plus the two idempotent directory guards.

    Deliberately NOT everything init does: creating the macOS user, its keychain, and the
    binary symlinks are one-time setup, not template renders, and re-running them is not
    this command's business.

    /etc/sudoers.d/claude-ro is a whole-file render of templates/sudoers.tmpl (one
    {{USERNAME}} substitution, no hand-editable content). It is its own drop-in, so
    rewriting it cannot disturb the per-broker drop-ins, and phase_local_sudoers validates
    with `visudo -c` and raises rather than installing a file that does not parse."""
    common.ensure_secrets_dir(ctx=ctx)
    common.ensure_runtime_dir(ctx=ctx)
    init.phase_local_sudoers(username, ctx=ctx)
    init.phase_local_launchd(username, ctx=ctx)


def _rerender_brokers(state: dict, ctx: common.Ctx) -> list[str]:
    """Re-render + reinstall every broker state says should exist, from the CURRENT
    templates, each with its pinned sudoers rule. Returns the helper names touched."""
    user = common.current_username()
    accounts = state.get("accounts") or []
    orgs = state.get("github") or []
    dbs = state.get("mongodb") or []
    snowflakes = state.get("snowflake") or []
    done: list[str] = []

    if orgs:  # ONE shared, argument-less helper serving every bound org
        common.install_broker_helper("github", None, common.render_github_broker(), ctx=ctx)
        common.install_broker_sudoers("github", None, ctx=ctx)
        done.append(common.broker_helper_name("github"))
        # The git credential helper and gh shim are rendered from templates too, so a
        # skill update changes them the same way it changes a broker. Both are public,
        # idempotent, and expect the caller's admin_session. NOTE: install_gh_shim
        # self-skips when the real `gh` on PATH already resolves to the shim, so on a
        # machine where it is installed and first on PATH this is a no-op — it cannot
        # re-render itself without a record of the real gh path.
        bind_github.install_git_wiring(user, ctx=ctx)
        bind_github.install_gh_shim(user, ctx=ctx)
        done.append(str(bind_github.GIT_CRED_HELPER_PATH.name))
    if dbs:  # ONE shared helper serving every bound DB; optional SOCKS port
        common.install_broker_helper("mongodb", None, common.render_mongodb_broker(), ctx=ctx)
        common.install_broker_sudoers("mongodb", None, ctx=ctx, allow_arg=True)
        done.append(common.broker_helper_name("mongodb"))
    if snowflakes:  # ONE shared, argument-less helper serving every bound Snowflake account
        common.install_broker_helper("snowflake", None, common.render_snowflake_broker(), ctx=ctx)
        common.install_broker_sudoers("snowflake", None, ctx=ctx)
        done.append(common.broker_helper_name("snowflake"))
    for record in accounts:  # one per account; optional region
        acct = record["account_id"]
        common.install_broker_helper("aws", acct, common.render_aws_broker(record), ctx=ctx)
        common.install_broker_sudoers("aws", acct, ctx=ctx, allow_arg=True)
        done.append(common.broker_helper_name("aws", acct))
    for arn in sorted({r["via_cluster"] for r in dbs if r.get("via_cluster")}):
        label = common.tunnel_cluster_label(arn)  # one per cluster; session id + port
        common.install_broker_helper("tunnel", label, common.render_tunnel_broker(arn), ctx=ctx)
        common.install_broker_sudoers("tunnel", label, ctx=ctx, allow_arg=True)
        done.append(common.broker_helper_name("tunnel", label))
    return done


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Re-render the sandbox's local artifacts — brokers, sudoers, launcher, "
                    "capability note, auto-mode classifier rules — from state. Touches no "
                    "cloud provider and does not re-bind.")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)

    # Preview off the same generator that does the writing, so what is printed is exactly
    # what lands — no second code path to drift out of sync.
    bash_allow, environment, allow = common._auto_mode_config(state)
    if not bash_allow:
        raise SystemExit(
            "nothing is bound — run provision-account or a bind-* sub-command first; "
            "there would be nothing to re-render.")

    print(f"Re-render from state ({len(bash_allow)} broker(s)), touching no cloud provider:")
    for rule in bash_allow:
        print(f"    {rule}")
    print("  + their pinned sudoers rules, the claude-ro launcher, the capability note,")
    print(f"  + {len(environment)} environment entrie(s) and {len(allow)} classifier ALLOW "
          f"rule(s) in claude-ro's settings.json.")

    with common.admin_session(
        title="agent-sandbox-provision: re-render local artifacts",
        actions=["Re-apply ACLs on the claude-ro secrets + runtime directories",
                 "Re-render /etc/sudoers.d/claude-ro (visudo-validated before install)",
                 "Re-render the claude-ro lockdown launchd plist",
                 "Re-render broker helpers + pinned sudoers in /usr/local/bin from state",
                 "Re-render the claude-ro git credential helper + gh shim, and re-point "
                 "claude-ro's gitconfig at the helper",
                 "Re-render /usr/local/bin/claude-ro (launcher)",
                 "Rewrite /Users/claude-ro/.claude/settings.json — capability note + "
                 "auto-mode classifier rules"],
    ):
        _rerender_machine(common.current_username(), ctx)
        _rerender_brokers(state, ctx)
        render_launcher.write_launcher(render_launcher.render(state), dry_run=ctx.dry_run)
        common.install_capability_note(ctx=ctx)


if __name__ == "__main__":
    main()
