#!/usr/bin/env python3
"""
bind_snowflake: grant claude-ro read-only access to one Snowflake account.

Takes NO arguments. Everything it needs is either derived or asked for in plain
language, with the exact place to find it — because every value Snowflake needs
here is one an engineer cannot produce from memory, and the one that looks like
the answer in the UI (the profile menu's user name) is the value that fails.

No admin credential touches the laptop, and nothing that expires is stored. An
RSA key pair is generated locally and the public half goes into a forwardable
request for whoever holds USERADMIN, creating a `TYPE = SERVICE_AGENT` account
that holds nothing but a read-only role. The broker later signs a JWT with the
private half and uses it to mint tokens pinned to that role.

Two-phase and resumable, like bind_mongodb:
  Phase A  gathers everything from one pasted query result, generates the key
           pair, stores it, prints the admin request, and stops.
  Phase B  (re-run once the admin has run it) mints end-to-end and installs the
           broker.

Usage:
    bind_snowflake.py
"""

from __future__ import annotations

import argparse
import datetime
import os
import pathlib
import subprocess
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402

# Privileges a role may hold and still be offered. Deliberately narrow: OPERATE
# can resume a warehouse (i.e. spend money) and anything CREATE/INSERT-shaped is
# a write, so neither belongs in a read-only sandbox.
READ_ONLY_PRIVILEGES = frozenset({"SELECT", "USAGE", "REFERENCES", "MONITOR", "READ"})

DISCOVERY_SQL = """EXECUTE IMMEDIATE $$
DECLARE
  info STRING; roles ARRAY; r STRING; privs STRING;
BEGIN
  info := (SELECT CURRENT_ORGANIZATION_NAME()||'-'||CURRENT_ACCOUNT_NAME()
                  ||' user='||CURRENT_USER()
                  ||' warehouse='||COALESCE(CURRENT_WAREHOUSE(),'none'));
  roles := (SELECT PARSE_JSON(CURRENT_AVAILABLE_ROLES()));
  FOR i IN 0 TO ARRAY_SIZE(roles)-1 DO
    r := roles[i]::STRING;
    EXECUTE IMMEDIATE 'SHOW GRANTS TO ROLE "' || r || '"';
    privs := (SELECT COALESCE(LISTAGG(DISTINCT "privilege", '+')
                     WITHIN GROUP (ORDER BY "privilege"), 'none')
              FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())));
    info := info || ' | ' || r || '=' || privs;
  END FOR;
  RETURN info;
END;
$$;"""


def _parse_discovery(line: str) -> tuple[str, str, str, dict[str, set[str]]]:
    """Parse the single cell the discovery query returns:

        <ACCOUNT> user=<NAME> warehouse=<WH> | ROLE=PRIV+PRIV | ROLE=PRIV

    Returns (account, user, warehouse, {role: {privileges}}).
    """
    segments = [s.strip() for s in line.strip().split("|") if s.strip()]
    if not segments:
        raise SystemExit("that doesn't look like the query's output — it should be a "
                         "single line starting with the account identifier.")

    head = segments[0].split()
    account = head[0]
    user = warehouse = ""
    for token in head[1:]:
        if token.startswith("user="):
            user = token[5:]
        elif token.startswith("warehouse="):
            warehouse = token[10:]
    if not account or not user:
        raise SystemExit("couldn't find the account and user in that line. Paste the "
                         "whole cell, exactly as the query returned it.")
    if warehouse.lower() == "none":
        warehouse = ""

    roles: dict[str, set[str]] = {}
    for seg in segments[1:]:
        if "=" not in seg:
            continue
        name, _, privs = seg.partition("=")
        roles[name.strip()] = {p.strip().upper() for p in privs.split("+") if p.strip()}
    if not roles:
        raise SystemExit("no roles found in that line — paste the whole cell.")
    return account, user, warehouse, roles


def _choose_role(roles: dict[str, set[str]]) -> str:
    """Offer only read-only roles, and say what disqualified the rest. A user who
    can see why a role was excluded can act on it; a filtered list they can't
    explain just looks broken."""
    readonly, rejected = [], []
    for name, privs in sorted(roles.items()):
        extra = privs - READ_ONLY_PRIVILEGES
        (rejected.append((name, extra)) if extra else readonly.append(name))

    if not readonly:
        lines = "\n".join(f"    {n} — can {', '.join(sorted(e))}" for n, e in rejected)
        raise SystemExit(
            "None of your roles are read-only, so there is nothing safe to bind:\n\n"
            f"{lines}\n\n"
            "Ask whoever administers Snowflake for a read-only role, then run this "
            "again. Something like:\n\n"
            "    CREATE ROLE IF NOT EXISTS CLAUDE_RO_READER;\n"
            "    GRANT USAGE ON DATABASE <db> TO ROLE CLAUDE_RO_READER;\n"
            "    GRANT USAGE ON ALL SCHEMAS IN DATABASE <db> TO ROLE CLAUDE_RO_READER;\n"
            "    GRANT SELECT ON ALL TABLES IN DATABASE <db> TO ROLE CLAUDE_RO_READER;\n"
            "    GRANT SELECT ON FUTURE TABLES IN DATABASE <db> TO ROLE CLAUDE_RO_READER;\n"
            "    GRANT ROLE CLAUDE_RO_READER TO USER <you>;")

    # Printed rather than folded into the picker prompt: it can run to several lines,
    # and Claude Code relays this output to the user alongside the dialog.
    for name, extra in rejected:
        print(f"  {name} — not offered, it can {', '.join(sorted(extra))}",
              file=sys.stderr)

    if len(readonly) == 1:
        print(f"Using {readonly[0]} — the only read-only role you hold.", file=sys.stderr)
        return readonly[0]
    return common.pick_from_list(
        "Which role should the sandbox use? It will read whatever this role can "
        "read, and nothing else.", readonly)


def _choose_name(account: str, state: dict) -> str:
    """Ask what to call this account. The formal identifier is recorded, but it is
    a string of letters and digits — it should never be the handle a human types."""
    taken = {s["name"] for s in (state.get("snowflake") or [])}
    print(f"\nThis account is {account}.", file=sys.stderr)
    print("What do you want to call it? Short and lowercase — it's how you and the "
          "agent\nwill refer to it later. For example: prod, analytics, warehouse.",
          file=sys.stderr)
    while True:
        raw = common.prompt_text(
            f"What do you want to call {account}? Short and lowercase, e.g. prod"
        ).strip().lower()
        if not raw:
            continue
        if raw in taken:
            print(f"'{raw}' is already bound — pick another name.", file=sys.stderr)
            continue
        try:
            return common.validate_identifier(raw)
        except SystemExit as exc:
            print(str(exc), file=sys.stderr)


def _gather() -> tuple[str, str, str, dict[str, set[str]]]:
    """Prerequisite, then one query, then one paste."""
    print(
        "\nFirst, log in to Snowflake in your browser.\n"
        "\n"
        "  Go to app.snowflake.com. If you get a 'Select an account to sign into'\n"
        "  screen, you are not logged in yet — pick your account there, or type its\n"
        "  identifier if it isn't offered, and sign in.\n"
        "\n"
        "Once you're in, open a SQL worksheet and run this. It reads nothing but your\n"
        "own account, user and roles — it changes nothing:\n"
        f"\n{DISCOVERY_SQL}\n"
        "\nIt returns a single cell. Copy it — a box will ask you to paste it.\n",
        file=sys.stderr)
    line = common.prompt_text(
        "Paste the single cell the Snowflake query returned").strip()
    if not line:
        raise SystemExit("nothing pasted — run this again when you have the result.")
    return _parse_discovery(line)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Bind claude-ro to one Snowflake account (read-only). Takes no "
                    "arguments — it asks for what it needs.")
    ap.add_argument("--yes", action="store_true", help="Skip confirmation prompts.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    ctx = common.Ctx.from_args(args)
    state = common.state_read(validate=True)

    pending = _pending_name(state)
    if pending:
        record = next((s for s in (state.get("snowflake") or [])
                       if s["name"] == pending), None)
        if record is None:  # bookmark without a record: nothing to resume
            with common.update_state() as s:
                common.end_operation(s)
        else:
            _phase_b(record, ctx=ctx)
            return

    if ctx.dry_run:
        common.log.info("[dry-run] would ask you to paste one query result, pick a "
                        "role, name the account, then generate a key pair and print "
                        "the admin request (no writes)")
        return

    _phase_a(ctx=ctx, state=state)


def _phase_a(*, ctx: common.Ctx, state: dict) -> None:
    """Gather, generate, store, print the request, stop."""
    # With no --name to collide on, a re-run means "bind another account". Say what
    # is already bound before asking for anything, so a mistaken re-run is obvious
    # at the top rather than at the naming step.
    already = state.get("snowflake") or []
    if already:
        print("\nAlready bound: "
              + ", ".join(f"{s['name']} ({s['account']})" for s in already)
              + "\nThis will bind an additional account — Ctrl-C if that isn't what "
                "you meant.", file=sys.stderr)

    account, whoami, warehouse, roles = _gather()
    role = _choose_role(roles)
    name = _choose_name(account, state)

    snow = common.load_provider("snowflake")
    engineer = common.current_username()
    service_user = f"CLAUDE_RO_{engineer.upper().replace('-', '_').replace('.', '_')}"
    secret_ref = f"snowflake-{name}.key"

    private_pem, public_body = snow.generate_keypair()
    record = {
        "name": name,
        "account": account,
        "service_user": service_user,
        "qualified_username": snow.qualified_username(account, service_user),
        "public_key_fp": snow.public_key_fingerprint(public_body),
        "role": role,
        "secret_ref": secret_ref,
        "granted_at": common.now_iso(),
    }
    if warehouse:
        record["warehouse"] = warehouse

    # Escalate ONLY to create the secrets dir, and only if it isn't already there.
    # Writing the key itself is plain file I/O into a directory this user owns —
    # secret_store's own contract is "No admin needed" — so on a machine where init
    # has run, Phase A asks for no password at all.
    if not _secrets_dir_ready():
        with common.admin_session(
            title=f"agent-sandbox-provision: bind Snowflake {name}",
            actions=[f"Create secrets dir {common.SECRETS_DIR} (once)"],
        ):
            common.ensure_secrets_dir(ctx=ctx)

    common.secret_store(secret_ref, private_pem, ctx=ctx)
    with common.update_state() as s:
        common.begin_operation(s, "bind-snowflake", {"kind": "snowflake", "name": name})
        common.mark_phase(s, "secret_stored")
    # Commit before the broker exists, so a failure here still leaves a consistent,
    # resumable state — the early-commit pattern from bind-mongodb. The broker is
    # deliberately NOT installed yet: until the admin registers the public key nothing
    # can be minted, and the sandbox should never be handed a credential that cannot work.
    with common.update_state() as s:
        if not any(x["name"] == name for x in s.get("snowflake") or []):
            s.setdefault("snowflake", []).append(record)
        common.mark_phase(s, "awaiting_db_user")

    today = datetime.date.today().isoformat()
    print("\n" + "=" * 78, file=sys.stderr)
    print("Send this to whoever administers Snowflake. It is complete — they paste and\n"
          "run it, and there is nothing for them or you to fill in.", file=sys.stderr)
    print("=" * 78 + "\n", file=sys.stderr)
    message = snow.admin_request(service_user, role, warehouse, public_body,
                                 engineer=engineer, today=today)
    print(message, file=sys.stderr)
    print("=" * 78, file=sys.stderr)

    # Put it on the pasteboard too. The message is the deliverable of this whole
    # phase, and it is long enough that anything relaying it is tempted to
    # summarise — which leaves the user with no way to actually send it.
    try:
        subprocess.run(["pbcopy"], input=message, text=True, check=True, timeout=5)
        print("This message is now on your clipboard — paste it to your Snowflake "
              "admin as-is.", file=sys.stderr)
    except (OSError, subprocess.SubprocessError):
        pass  # non-fatal: the message is printed above regardless
    common.log.info("'%s' is pending. Once they've run it, run bind-snowflake again — "
                    "you won't be asked any of this a second time.", name)


def _phase_b(record: dict, *, ctx: common.Ctx) -> None:
    """Mint end-to-end, then install the broker."""
    name = record["name"]
    common.log.info("checking whether %s is ready (account %s, role %s) …",
                    name, record["account"], record.get("role"))

    secret = common.secret_read(record["secret_ref"])
    snow = common.load_provider("snowflake")
    snow.provision(record, secret, ctx=ctx)  # SystemExit with guidance on failure

    helper = common.render_snowflake_broker()
    needs_runtime_dir = not _runtime_dir_ready()
    with common.admin_session(
        title=f"agent-sandbox-provision: enable Snowflake {name}",
        actions=[
            *([f"Create runtime dir {common.RUNTIME_DIR} (once)"]
              if needs_runtime_dir else []),
            f"Install shared mint helper {common.broker_helper_path('snowflake')}",
            f"Install sudoers drop-in {common.broker_sudoers_path('snowflake')}",
            "Install claude-ro capability note + SessionStart hook",
        ],
    ):
        if needs_runtime_dir:
            common.ensure_runtime_dir(ctx=ctx)
        common.install_broker_helper("snowflake", None, helper, ctx=ctx)
        # No allow_arg: this broker takes no arguments, so the pin is the strict
        # exact-path form.
        common.install_broker_sudoers("snowflake", None, ctx=ctx)
        common.install_capability_note(ctx=ctx)
        with common.update_state() as s:
            common.mark_phase(s, "broker_installed")

    with common.update_state() as s:
        common.mark_phase(s, "provider_verified")
        common.end_operation(s)

    common.log.info("Snowflake '%s' is live in the sandbox — reads as %s, and it cannot "
                    "switch to any other role.", name, record.get("role"))


def _secrets_dir_ready() -> bool:
    """True when the secrets dir already exists and this user can write to it — i.e.
    `init` has run, so storing a key needs no escalation. Checked rather than assumed,
    because a dir left root-owned by an older install would still need one."""
    return common.SECRETS_DIR.is_dir() and os.access(common.SECRETS_DIR, os.W_OK)


def _runtime_dir_ready() -> bool:
    """Same check for the runtime dir. It does not remove Phase B's admin prompt —
    the broker binary (/usr/local/bin), its sudoers drop-in and claude-ro's settings
    all genuinely need root — but it keeps the dialog from listing work it isn't
    going to do."""
    return common.RUNTIME_DIR.is_dir() and os.access(common.RUNTIME_DIR, os.W_OK)


def _pending_name(state: dict) -> str | None:
    op = state.get("pending_operation")
    if op and op.get("kind") == "bind-snowflake":
        return (op.get("target") or {}).get("name")
    return None


if __name__ == "__main__":
    main()
