#!/usr/bin/env python3
"""
bind_mongodb: grant claude-ro read-only access to one MongoDB deployment
(Atlas or self-hosted / ScaleGrid).

No admin/provisioning credential ever touches the laptop. As its FIRST action this
prints a copy-paste command for the DB owner to create a per-engineer read-only
user `claude-ro-<engineer>` (readAnyDatabase@admin) and set a password. It then
waits — resumably — for you to paste that password into a secure dialog, stores it
in a mode-600 file, and installs the per-identity broker helper + sudoers drop-in.

Usage (Atlas):
    bind_mongodb.py --name prod --kind atlas --srv-host prod-0.ab12.mongodb.net \\
        --default-db app [--options "readPreference=secondaryPreferred"]

Usage (self-hosted / ScaleGrid):
    bind_mongodb.py --name reporting --kind self_hosted \\
        --hosts n1.sg.net:27017,n2.sg.net:27017 --default-db reporting \\
        [--options "tls=true&replicaSet=RS-abc"]
"""

from __future__ import annotations

import argparse
import pathlib
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


def _create_user_command(kind: str, username: str, record: dict) -> str:
    """The exact instruction the DB owner runs to create the read-only user."""
    if kind == "atlas":
        return (
            f"  In the Atlas UI:  Database Access → Add New Database User\n"
            f"    • Username: {username}\n"
            f"    • Password: autogenerate (or choose a strong one) — you'll paste it back\n"
            f"    • Built-in Role: \"Only read any database\" (readAnyDatabase)\n"
            f"  Or with the Atlas CLI:\n"
            f"    atlas dbusers create --username {username} \\\n"
            f"      --role readAnyDatabase@admin --projectId <PROJECT_ID> --password <PW>"
        )
    return (
        f"  As a DB admin, create the read-only user (run this however you connect):\n\n"
        f"    db.getSiblingDB(\"admin\").createUser({{\n"
        f"      user: \"{username}\",\n"
        f"      pwd: \"<CHOOSE A STRONG PASSWORD>\",\n"
        f"      roles: [ {{ role: \"readAnyDatabase\", db: \"admin\" }} ]\n"
        f"    }})"
    )


def _show_create_user(name: str, kind: str, username: str, record: dict) -> None:
    """Print the create-user instruction (first run only)."""
    instruction = _create_user_command(kind, username, record)
    print(
        f"\nMongoDB read-only user needed for {name!r}. Have your DB admin create it "
        f"(no admin credential is stored here):\n\n{instruction}\n",
        file=sys.stderr,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Bind claude-ro to one MongoDB deployment (read-only).")
    ap.add_argument("--name", required=True,
                    help="Identifier for this DB (also its runtime cred filename, <name>.uri).")
    ap.add_argument("--kind", required=True, choices=["atlas", "self_hosted"])
    ap.add_argument("--srv-host", help="SRV host (Atlas, or self-hosted with SRV).")
    ap.add_argument("--hosts", help="host[:port][,...] (self-hosted without SRV).")
    ap.add_argument("--auth-db", default="admin", help="Auth database (default admin).")
    ap.add_argument("--default-db", required=True, help="Default database for the URI.")
    ap.add_argument("--options", default="",
                    help="Extra connection-string params, e.g. tls=true&replicaSet=RS.")
    ap.add_argument("--auth", choices=["password", "aws-iam"], default="password",
                    help="Auth method. password (default): a stored RO-user password. "
                         "aws-iam (Atlas only): the DB user is claude-ro's per-account RO "
                         "role; connections use MONGODB-AWS with claude-ro's minted RO creds "
                         "— no password, no stored secret, no DB-owner password handoff.")
    ap.add_argument("--iam-account",
                    help="aws-iam only: which provisioned AWS account's RO role authenticates "
                         "to this Atlas DB. Defaults to the sole provisioned account.")
    ap.add_argument("--via-cluster",
                    help="Kubectl context (in YOUR kubeconfig) of a cluster that can reach "
                         "this DB. claude-ro then stands up a per-session SOCKS5 tunnel "
                         "through it on demand (engineer-run broker; claude-ro's RO role "
                         "never touches the cluster). The tunnel's local port is chosen "
                         "per session at run time — not stored here.")
    ap.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    name = common.validate_identifier(args.name)
    srv = bool(args.srv_host)
    if args.kind == "atlas":
        if not args.srv_host:
            ap.error("--kind atlas requires --srv-host")
        if args.hosts:
            ap.error("--kind atlas uses --srv-host, not --hosts")
    else:
        if bool(args.srv_host) == bool(args.hosts):
            ap.error("--kind self_hosted requires exactly one of --srv-host / --hosts")
        if args.hosts:
            common.validate_mongo_hosts(args.hosts)

    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)

    # ---- AWS IAM auth (Atlas only): no password, no stored secret. The Atlas DB user is
    #      claude-ro's per-account RO role; connections use MONGODB-AWS with claude-ro's
    #      minted RO creds. Handled entirely here, then return. ----
    if args.auth == "aws-iam":
        if args.kind != "atlas":
            ap.error("--auth aws-iam is Atlas-only (self_hosted MongoDB can't use AWS IAM)")
        if args.via_cluster:
            ap.error("--auth aws-iam is for public Atlas; --via-cluster (tunnel) doesn't apply")
        _bind_iam(args, name, srv, state, ctx=ctx)
        return

    engineer = common.current_username()
    username = f"claude-ro-{engineer}"
    secret_ref = f"mongodb-{name}.key"

    record = {
        "name": name,
        "kind": args.kind,
        "srv": srv,
        "username": username,
        "auth_db": args.auth_db,
        "default_db": args.default_db,
        "secret_ref": secret_ref,
    }
    if srv:
        record["srv_host"] = args.srv_host
    else:
        record["hosts"] = args.hosts
    if args.options:
        record["options"] = args.options

    # SOCKS tunnel wiring: record only WHICH cluster reaches this DB. The tunnel and its
    # local port are per-session and chosen at run time by the claude-ro-tunnel broker —
    # no port is stored here (the agent passes the live port to the Mongo minter).
    #
    # Guard: the via_cluster must be an EKS ARN whose account is already provisioned —
    # the tunnel broker maps the ARN's account to that account's assumer_profile to
    # authenticate. Reject otherwise, so the dependency fails at bind, not at run time.
    if args.via_cluster:
        via = common.resolve_kube_context(args.via_cluster)
        account, _region, _name = common.parse_eks_arn(via)  # rejects non-ARN contexts
        if not any(a.get("account_id") == account for a in state.get("accounts") or []):
            raise SystemExit(
                f"cluster {via} is in AWS account {account}, which isn't provisioned.\n"
                f"Run provision_account for {account} first — the tunnel broker needs its "
                f"assumer_profile to reach the cluster.")
        record["via_cluster"] = via

    resuming = _is_resuming(state, name)
    existing = next((m for m in (state.get("mongodb") or []) if m["name"] == name), None)
    if existing is not None and not resuming:
        secret_here = (common.SECRETS_DIR / existing["secret_ref"]).exists()
        if secret_here:
            # Already bound with a stored credential → UPDATE in place: apply the new
            # connection settings, KEEP the password, re-render the launcher. No
            # create-user, no password dialog. (Rotate the credential via unbind+rebind.)
            if not common.prompt_yes_no(
                    f"'{name}' is already bound. Update it to the settings you just passed "
                    f"(hosts / db / options / tunnel)? The stored password is kept.",
                    default=True, ctx=ctx):
                print("aborted", file=sys.stderr)
                sys.exit(1)
            if ctx.dry_run:
                common.log.info("[dry-run] would update %s in place and re-render the launcher", name)
                return
            record["granted_at"] = existing.get("granted_at") or common.now_iso()
            with common.update_state() as s:
                s["mongodb"] = [record if m["name"] == name else m
                                for m in (s.get("mongodb") or [])]
            via = record.get("via_cluster")
            actions = ["Re-render /usr/local/bin/claude-ro (tunnel-cleanup context list)"]
            if via:
                actions.append(f"Install SOCKS tunnel broker for cluster {via}")
            with common.admin_session(
                title=f"agent-sandbox: update MongoDB {name}",
                actions=actions,
            ):
                _rerender_launcher(ctx=ctx)
                if via:
                    common.ensure_runtime_dir(ctx=ctx)
                    _install_tunnel_broker(via, ctx=ctx)
            tunneled = record.get("via_cluster") or existing.get("via_cluster")
            common.log.info("updated MongoDB %s (password unchanged).%s", name,
                            " Relaunch claude-ro to pick up tunnel changes." if tunneled else "")
            return
        # No stored credential (partial/broken bind) → clear the stale record and fall
        # through to a fresh two-phase bind.
        common.log.info("re-binding %s from scratch (no stored credential found)", name)
        _teardown(existing, ctx=ctx)

    if ctx.dry_run:
        if resuming:
            common.log.info("[dry-run] would prompt for %s's password and bind it (no writes)", name)
        else:
            _show_create_user(name, args.kind, username, record)
            common.log.info("[dry-run] would register %s as pending; re-run once the user "
                            "exists to enter its password (no writes)", name)
        return

    if not resuming:
        # First run for this DB: show the create-user command, register the bind as
        # pending, and STOP. No password prompt — the user doesn't exist yet. Re-run the
        # SAME command once it does.
        _show_create_user(name, args.kind, username, record)
        with common.update_state() as s:
            common.begin_operation(s, "bind-mongodb", {"kind": "mongodb", "name": name})
            common.mark_phase(s, "awaiting_db_user")
        common.log.info("%s is now pending. Once your DB admin has created the user, re-run "
                        "the SAME bind-mongodb command to enter the password they gave you.", name)
        return

    # Resuming: the user exists — just take the password your admin handed you. No
    # instruction re-print; this run is only about entering the password.
    common.log.info("resuming bind-mongodb for %s — enter the password your DB admin set "
                    "for %s.", name, username)
    try:
        password = common.prompt_secret(
            f"Paste the password your DB admin set for {username}")
    except SystemExit:
        common.log.info("no password entered — re-run bind-mongodb to resume when ready.")
        sys.exit(0)
    if not password.strip():
        common.log.info("empty password — re-run bind-mongodb to resume.")
        sys.exit(0)

    record["granted_at"] = common.now_iso()

    # One shared, argument-less broker mints URIs for ALL bound DBs. Its content is
    # identity-independent (reads mongodb[] at run time), so we (re)install it on every
    # bind — idempotent.
    helper = common.render_mongodb_broker()
    via = record.get("via_cluster")
    tunnel_actions = [f"Install SOCKS tunnel broker for cluster {via}"] if via else []
    with common.admin_session(
        title=f"agent-sandbox: bind MongoDB {name}",
        actions=[
            f"Create secrets dir {common.SECRETS_DIR} (once)",
            f"Create runtime dir {common.RUNTIME_DIR} (once)",
            f"Install shared mint helper {common.broker_helper_path('mongodb')}",
            f"Install sudoers drop-in {common.broker_sudoers_path('mongodb')}",
            "Install claude-ro capability note + SessionStart hook",
            *tunnel_actions,
            "Re-render /usr/local/bin/claude-ro (tunnel-cleanup context list)",
        ],
    ):
        common.ensure_secrets_dir(ctx=ctx)
        common.ensure_runtime_dir(ctx=ctx)
        common.secret_store(secret_ref, password, ctx=ctx)
        with common.update_state() as s:
            common.mark_phase(s, "secret_stored")
        common.install_broker_helper("mongodb", None, helper, ctx=ctx)
        common.install_broker_sudoers("mongodb", None, ctx=ctx, allow_arg=True)
        common.install_capability_note(ctx=ctx)
        with common.update_state() as s:
            common.mark_phase(s, "broker_installed")
        # Commit the record BEFORE rendering the launcher (the tunnel-context list is
        # rendered from state) and before installing the tunnel broker (which reads the
        # cluster's port from state) — same early-commit recoverability pattern as
        # bind-github: any later failure leaves a consistent, resumable state.
        with common.update_state() as s:
            if not any(m["name"] == name for m in s.get("mongodb") or []):
                s.setdefault("mongodb", []).append(record)
            common.mark_phase(s, "state_commit")
        if via:
            _install_tunnel_broker(via, ctx=ctx)
        _rerender_launcher(ctx=ctx)

    mongo = common.load_provider("mongodb")
    mongo.provision(record, password, ctx=ctx)
    with common.update_state() as s:
        common.mark_phase(s, "provider_verified")
        common.end_operation(s)

    common.log.info("bound MongoDB %s (user %s). In claude-ro, the shared mint broker "
                    "writes each DB's URI to /usr/local/claude-ro-runtime/mongodb/<name>.uri.",
                    name, username)


def _install_tunnel_broker(via_cluster: str, *, ctx: common.Ctx) -> None:
    """Install this cluster's on-demand SOCKS tunnel broker + its pinned (argless)
    sudoers rule, and refresh the capability note so it advertises the tunnel.
    Idempotent. Must run inside an ACTIVE admin_session."""
    label = common.tunnel_cluster_label(via_cluster)
    helper = common.render_tunnel_broker(via_cluster)
    common.install_broker_helper("tunnel", label, helper, ctx=ctx)
    common.install_broker_sudoers("tunnel", label, ctx=ctx, allow_arg=True)
    common.install_capability_note(ctx=ctx)


def _resolve_iam_account(args, state: dict) -> dict:
    """The accounts[] record whose RO role authenticates this Atlas IAM DB: --iam-account
    if given, else the sole provisioned account (ambiguous if more than one)."""
    accounts = state.get("accounts") or []
    if not accounts:
        raise SystemExit("--auth aws-iam needs a provisioned account (its RO role is the "
                         "Atlas DB user). Run provision_account first.")
    if args.iam_account:
        common.validate_aws_account_id(args.iam_account)
        acct = next((a for a in accounts if a.get("account_id") == args.iam_account), None)
        if acct is None:
            raise SystemExit(f"account {args.iam_account} isn't provisioned "
                             f"(known: {', '.join(a['account_id'] for a in accounts)}).")
        return acct
    if len(accounts) > 1:
        raise SystemExit("multiple accounts are provisioned; pass --iam-account <id> to pick "
                         "which one's RO role authenticates to this Atlas DB "
                         f"({', '.join(a['account_id'] for a in accounts)}).")
    return accounts[0]


def _bind_iam(args, name: str, srv: bool, state: dict, *, ctx: common.Ctx) -> None:
    """Bind an Atlas DB via AWS IAM: the DB user is claude-ro's per-account RO role, so
    there's no password / stored secret / DB-owner password handoff. Single-phase — record
    the binding, (re)install the shared mint broker, and print the ARN the DB owner adds
    in Atlas."""
    account = _resolve_iam_account(args, state)
    role_arn = account["ro_role_arn"]

    record = {
        "name": name, "kind": "atlas", "srv": srv,
        "auth": "aws_iam",
        "aws_account_id": account["account_id"],
        "iam_role_arn": role_arn,
        "auth_db": args.auth_db,
        "default_db": args.default_db,
        "granted_at": common.now_iso(),
    }
    if srv:
        record["srv_host"] = args.srv_host
    else:
        record["hosts"] = args.hosts
    if args.options:
        record["options"] = args.options

    print(
        f"\nAWS IAM DB user needed for {name!r} in Atlas (no password — nothing is stored here):\n"
        f"  Database Access -> Add New Database User -> Authentication Method: AWS IAM\n"
        f"    AWS IAM Type:  IAM Role\n"
        f"    ARN:           {role_arn}\n"
        f"    Built-in Role: \"Only read any database\" (readAnyDatabase)\n"
        f"  This ARN is YOUR per-user RO role for account {account['account_id']} — it grants only\n"
        f"  your claude-ro sandbox, and it changes if you re-provision the account.\n",
        file=sys.stderr,
    )
    if ctx.dry_run:
        common.log.info("[dry-run] would record aws_iam Atlas DB %s (role %s) + install broker",
                        name, role_arn)
        return

    # Switching an existing password DB to IAM: drop its now-unused stored secret.
    existing = next((m for m in (state.get("mongodb") or []) if m["name"] == name), None)
    if existing and existing.get("secret_ref"):
        common.secret_delete(existing["secret_ref"], ctx=ctx)

    helper = common.render_mongodb_broker()
    with common.admin_session(
        title=f"agent-sandbox: bind MongoDB {name} (AWS IAM)",
        actions=[
            f"Create runtime dir {common.RUNTIME_DIR} (once)",
            f"Install shared mint helper {common.broker_helper_path('mongodb')}",
            f"Install sudoers drop-in {common.broker_sudoers_path('mongodb')}",
            "Install claude-ro capability note + SessionStart hook",
        ],
    ):
        common.ensure_runtime_dir(ctx=ctx)
        common.install_broker_helper("mongodb", None, helper, ctx=ctx)
        common.install_broker_sudoers("mongodb", None, ctx=ctx, allow_arg=True)
        common.install_capability_note(ctx=ctx)
        with common.update_state() as s:
            s.setdefault("mongodb", [])
            if any(m["name"] == name for m in s["mongodb"]):
                s["mongodb"] = [record if m["name"] == name else m for m in s["mongodb"]]
            else:
                s["mongodb"].append(record)
            op = s.get("pending_operation")
            if op and (op.get("target") or {}).get("name") == name:
                common.end_operation(s)  # clear a leftover password-bind bookmark

    common.log.info(
        "bound MongoDB %s (AWS IAM, role %s). Add that ARN as an Atlas DB user (IAM Role, "
        "readAnyDatabase); then in claude-ro mint the account creds "
        "(claude-ro-mint-aws-%s) before connecting via MONGODB-AWS.",
        name, role_arn, account["account_id"])


def _rerender_launcher(*, ctx: common.Ctx) -> None:
    """Re-render /usr/local/bin/claude-ro from current state (the Mongo tunnel calls
    are baked into it). Must run inside an ACTIVE admin_session. Skipped with a
    warning when no AWS account is bound yet (no launcher exists to re-render)."""
    import render_launcher
    if ctx.dry_run:
        common.log.info("[dry-run] would re-render %s", render_launcher.LAUNCHER_PATH)
        return
    try:
        rendered = render_launcher.render(common.state_read())
    except SystemExit as exc:
        common.log.warning("launcher not re-rendered (%s) — run render_launcher.py "
                           "after provisioning an account", exc)
        return
    path = str(render_launcher.LAUNCHER_PATH)
    common.admin_run_a(["tee", path], input_text=rendered)
    common.admin_run_a(["chmod", "755", path])
    common.admin_run_a(["chown", "root:wheel", path])
    common.log.info("re-rendered %s", path)


def _is_resuming(state: dict, name: str) -> bool:
    op = state.get("pending_operation")
    return bool(op and op.get("kind") == "bind-mongodb"
                and (op.get("target") or {}).get("name") == name)


def _teardown(record: dict, *, ctx: common.Ctx) -> None:
    """Overwrite path: drop one DB's stored secret + state record. The shared mint
    broker stays (other DBs use it, and the main flow reinstalls it anyway). The
    remote DB user is owner-managed and left intact."""
    name = record["name"]
    common.secret_delete(record["secret_ref"], ctx=ctx)
    with common.update_state() as s:
        s["mongodb"] = [m for m in (s.get("mongodb") or []) if m["name"] != name]


if __name__ == "__main__":
    main()
