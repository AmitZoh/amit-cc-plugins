#!/usr/bin/env python3
"""
Snowflake credential-source provider.

Grants claude-ro read-only Snowflake access via a **named RSA key pair carrying a
ROLE_RESTRICTION**. bind-snowflake generates the pair on the engineer's Mac and
prints a forwardable request for whoever holds USERADMIN, creating a
`TYPE = SERVICE_AGENT` account and registering the public half restricted to an
existing read-only role. The broker signs a short-lived JWT from the private half
on demand; the key never enters the sandbox.

Why NAMED key pairs (Snowflake, 2026-07-15) and not the legacy `RSA_PUBLIC_KEY`
property: a legacy key carries no role restriction, so any session holding it can
act as any role its user holds. A named key pair can be registered with
ROLE_RESTRICTION, and then "the key pair can only be used to authenticate if the
role requested in the JWT matches this role". That restriction is what makes a
locally-signed JWT safe to hand to the sandbox.

Why not a PAT, which also supports ROLE_RESTRICTION: PATs require the user to be
subject to a network policy to generate and use — verified the hard way against a
live SERVICE_AGENT account — and there is no equivalent requirement for key pairs.
The PAT also needed minting round-trips, rotation, and a privilege grant that let
the account manage its own tokens. None of that exists here: signing is local,
nothing expires on a schedule, and nothing is rotated.

WHAT THIS DOES NOT CONTAIN: Snowflake's PUBLIC pseudo-role is "automatically
granted to every user and every role", and privileges inherit upward, so a session
pinned to the read-only role ALSO holds whatever PUBLIC holds account-wide.
ROLE_RESTRICTION stops the credential selecting a different role; it does not
strip inherited privileges. The only remedy is revoking those privileges from
PUBLIC account-wide, which is the org's call. bind surfaces PUBLIC's privileges so
nobody is misled about the boundary.

`mint` is STDLIB ONLY (openssl for RS256): it runs in the broker hot path, so no
third-party deps, no _ensure_pkg.

Contract: see providers/_interface.md → "Credential-source provider contract".
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

# Snowflake caps key-pair JWTs at 60 minutes regardless of the `exp` we sign. Sign
# for slightly under so clock skew never produces an already-dead token.
JWT_LIFETIME_SECONDS = 3540
# The name the key pair is registered under on the Snowflake account.
KEY_PAIR_NAME = "claude_ro"
UA = "claude-ro-sandbox"


# ---------- low-level: JWT + SQL REST API ----------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def account_host(account: str) -> str:
    """`kpsovyc-ta51714` → `kpsovyc-ta51714.snowflakecomputing.com`. This is the
    ORG-QUALIFIED identifier from the Snowsight URL, NOT what CURRENT_ACCOUNT()
    returns — that is the account locator and does not route."""
    return f"{account}.snowflakecomputing.com"


def jwt_account(account: str) -> str:
    """The account component of the JWT's iss/sub: uppercased, with any
    region/cloud suffix stripped (`xy12345.eu-west-1` → `XY12345`)."""
    return account.split(".")[0].upper()


def _sign_jwt(record: dict, pem: str) -> str:
    """RS256-sign a Snowflake key-pair JWT with openssl (no PyJWT/cryptography).

    The JWT format is unchanged by named key pairs — Snowflake still selects the
    key by the fingerprint in `iss`. The qualified username and fingerprint are
    computed once at bind time and stored, so this path only concatenates and a
    mistake surfaces during bind rather than every time the broker runs.
    """
    qualified = record["qualified_username"]
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({
        "iss": f"{qualified}.{record['public_key_fp']}",
        "sub": qualified,
        "iat": now,
        "exp": now + JWT_LIFETIME_SECONDS,
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    fd, path = tempfile.mkstemp(prefix="claude-ro-sf-", suffix=".pem")
    try:
        os.write(fd, pem.encode())
        os.close(fd)
        os.chmod(path, 0o600)
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", path],
            input=signing_input, capture_output=True, check=False,
        )
        if proc.returncode != 0:
            raise SystemExit(
                "openssl RS256 signing failed (is the Snowflake private key valid "
                "and unencrypted?):\n" + proc.stderr.decode(errors="replace"))
        sig = _b64url(proc.stdout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return f"{header}.{payload}.{sig}"


def _sql(record: dict, jwt: str, statement: str, *, role: str | None = None,
         timeout: int = 30) -> tuple[int, dict | None]:
    """Run one statement through the SQL REST API. Returns (status, parsed);
    raises only on transport errors so callers can branch on HTTP status.

    `role` defaults to the record's bound role and is sent in the request body.
    That is not cosmetic: the key pair's ROLE_RESTRICTION means Snowflake accepts
    the JWT only when the requested role matches, so omitting it can fail auth
    outright rather than merely picking a different role.

    The Python connector is deliberately unused: it derives a JWT from a private
    key itself and has no documented way to accept a pre-made one, so using it
    would mean putting the durable key inside the sandbox."""
    url = f"https://{account_host(record['account'])}/api/v2/statements"
    body: dict = {"statement": statement, "timeout": timeout}
    chosen = role if role is not None else record.get("role")
    if chosen:
        body["role"] = chosen
    if record.get("warehouse"):
        body["warehouse"] = record["warehouse"]
    if record.get("database"):
        body["database"] = record["database"]
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={
            "Authorization": f"Bearer {jwt}",
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": UA,
        })
    try:
        with urllib.request.urlopen(req, timeout=timeout + 10) as resp:
            payload = resp.read()
            return resp.status, (json.loads(payload) if payload.strip() else None)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = None
        return exc.code, parsed


def _error_text(status: int, data: dict | None) -> str:
    """Snowflake sometimes appends a literal 'null' to its message (e.g. "JWT token
    is invalid. null"). Trim it — this is the error a user sees most often, before
    the admin has registered the key, and it should not look like our bug."""
    msg = ((data or {}).get("message") or "").strip()
    if msg.endswith("null"):
        msg = msg[:-4].rstrip(" .")
    return msg or f"HTTP {status}"


def _cell(data: dict | None, column: str) -> str | None:
    """Read one column of the first row BY NAME. Column order in Snowflake's
    responses is not a contract; positional indexing here would be a latent bug."""
    if not data:
        return None
    names = [c.get("name", "").lower()
             for c in (data.get("resultSetMetaData") or {}).get("rowType") or []]
    rows = data.get("data") or []
    if not rows or column.lower() not in names:
        return None
    return rows[0][names.index(column.lower())]


# ---------- contract: mint / revoke / provision / verify ----------

def mint(record: dict, secret: str) -> dict:
    """Return {'SNOWFLAKE_JSON': <json blob>}. STDLIB ONLY.

    Signing is local — no network call, nothing to rotate, nothing to clean up if
    it is called a thousand times. The blob carries the JWT plus every non-secret
    value needed to build a request, because the sandbox cannot read state.json and
    a bare token would leave it guessing at exactly the values that made this hard
    the first time round."""
    jwt = _sign_jwt(record, secret)
    expires = (_dt.datetime.now(_dt.timezone.utc)
               + _dt.timedelta(seconds=JWT_LIFETIME_SECONDS))
    return {"SNOWFLAKE_JSON": json.dumps({
        "account": record["account"],
        "host": account_host(record["account"]),
        "user": record["service_user"],
        "role": record.get("role") or "",
        "warehouse": record.get("warehouse") or "",
        "database": record.get("database") or "",
        "token": jwt,
        "token_type": "KEYPAIR_JWT",
        "expires_at": expires.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }, indent=2)}


def revoke(record: dict, secret: str) -> None:
    """No-op. The account is owner-managed and this machine holds no privilege to
    remove the key registration — deliberately, since granting one would mean the
    sandbox's own credential could manage its own credentials. Deleting the local
    private key is what ends access from here; unbind prints the DROP USER
    statement for the owner to retire the account itself."""
    return None


def owner_teardown_sql(record: dict) -> str:
    """The statement the Snowflake owner runs to retire the account for good."""
    return f"DROP USER IF EXISTS {record['service_user']};"


def owner_teardown_request(record: dict) -> str:
    """The message the engineer forwards to retire the account, mirroring
    admin_request. Unbinding needs the admin just as binding did, so it gets the
    same treatment — a message that explains itself, not a bare statement the
    engineer has to write an email around.

    This matters beyond tidiness: leaving the account behind means a later re-bind
    generates a new key pair while `CREATE USER IF NOT EXISTS` quietly declines to
    recreate the user, and the next bind fails looking exactly like an admin who
    never ran the request.

    Slack-formatted, same as admin_request — see its docstring for the rules."""
    fence = "```"
    return f"""Hi — could you remove the read-only Snowflake service account I had you
create for the sandbox on my Mac?

{fence}
DROP USER IF EXISTS {record['service_user']};
{fence}

The private key it authenticated with is already deleted on my side, so it can no
longer be used either way — this just retires the account itself."""


def provision(record_in: dict, secret: str, *, ctx) -> dict:
    """Probe at bind time: sign a JWT and confirm it authenticates and can read.

    Raises SystemExit on failure; Snowflake is always network-reachable, so there
    is no legitimate 'unreachable, skip it' case here."""
    jwt = _sign_jwt(record_in, secret)
    status, data = _sql(record_in, jwt, "SELECT CURRENT_USER(), CURRENT_ROLE()")
    if status != 200:
        raise SystemExit(
            f"Snowflake read probe failed ({_error_text(status, data)}).\n"
            f"  account: {record_in['account']}\n"
            f"  user:    {record_in['service_user']}\n"
            f"  role:    {record_in.get('role')}\n"
            "A JWT-invalid message means the key pair is not registered on that "
            "account yet — the admin request from bind-snowflake has not been run.\n"
            "A role-shaped message means the key was registered with a different "
            "ROLE_RESTRICTION than this bind recorded, or the role was never "
            "granted to the account.")
    ctx.logger.info("snowflake: read probe OK for %s", record_in["name"])
    return record_in


def verify(record: dict, env: dict, *, ctx) -> list[dict]:
    """Prove read works, the session runs as the bound role, the credential cannot
    switch roles, and a write is denied."""
    blob = json.loads(env["SNOWFLAKE_JSON"])
    jwt = blob["token"]
    results: list[dict] = []

    status, data = _sql(record, jwt, "SELECT CURRENT_USER(), CURRENT_ROLE()")
    read_ok = status == 200
    actual_role = (_cell(data, "CURRENT_ROLE()") or "") if read_ok else ""
    results.append({
        "name": "snowflake_read",
        "expected": "200", "actual": str(status),
        "passed": read_ok,
        "detail": "" if read_ok else _error_text(status, data),
    })

    expected_role = (record.get("role") or "").upper()
    if read_ok and expected_role:
        role_ok = actual_role.upper() == expected_role
        results.append({
            "name": "snowflake_role",
            "expected": expected_role, "actual": actual_role or "(none)",
            "passed": role_ok,
            "detail": "" if role_ok else
                      "the session is not running as the role this bind recorded",
        })

    if not read_ok:
        for skipped in ("snowflake_role_switch_denied", "snowflake_write_denied"):
            results.append({
                "name": skipped, "expected": "denied", "actual": "skipped",
                "passed": True, "detail": "read failed, so this could not be tested",
            })
        return results

    # The check the whole design turns on: with ROLE_RESTRICTION, asking for any
    # other role must fail. Without it a locally-signed JWT could select anything
    # the account holds, which is precisely why the legacy RSA_PUBLIC_KEY property
    # is not used. NOTE this proves the credential cannot SELECT another role — it
    # says nothing about privileges the bound role INHERITS from PUBLIC.
    sstatus, _ = _sql(record, jwt, "SELECT CURRENT_ROLE()", role="PUBLIC")
    switch_denied = sstatus != 200
    results.append({
        "name": "snowflake_role_switch_denied",
        "expected": "refused", "actual": str(sstatus),
        "passed": switch_denied,
        "detail": "" if switch_denied else
                  "the key pair authenticated as PUBLIC — its ROLE_RESTRICTION is "
                  "not confining it, and the sandbox is not contained",
    })

    probe = "CLAUDE_RO_WRITE_PROBE"
    wstatus, _ = _sql(record, jwt, f"CREATE DATABASE IF NOT EXISTS {probe}")
    denied = wstatus != 200
    if not denied:
        _sql(record, jwt, f"DROP DATABASE IF EXISTS {probe}")
    results.append({
        "name": "snowflake_write_denied",
        "expected": "privilege error", "actual": str(wstatus),
        "passed": denied,
        "detail": "" if denied else
                  f"CREATE DATABASE was NOT denied for role {record.get('role')!r} "
                  "(the probe database was dropped again) — bind a read-only role",
    })
    return results


# ---------- bind-time helpers (NOT the hot path) ----------

def generate_keypair() -> tuple[str, str]:
    """Generate an unencrypted 2048-bit RSA key pair with openssl.

    Returns (private_pem, public_key_body), the latter stripped of PEM header,
    footer and newlines — the exact form `PUBLIC_KEY = '…'` expects, so the admin
    request needs no further editing. Unencrypted because mint() must sign without
    a passphrase; the key is stored mode-600 with a claude-ro deny-ACE."""
    with tempfile.TemporaryDirectory(prefix="claude-ro-sf-key-") as tmp:
        key_path = os.path.join(tmp, "rsa_key.p8")
        proc = subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-out", key_path,
             "-pkeyopt", "rsa_keygen_bits:2048"],
            capture_output=True, check=False)
        if proc.returncode != 0:
            raise SystemExit("openssl key generation failed:\n"
                             + proc.stderr.decode(errors="replace"))
        os.chmod(key_path, 0o600)
        pub = subprocess.run(["openssl", "rsa", "-in", key_path, "-pubout"],
                             capture_output=True, check=False)
        if pub.returncode != 0:
            raise SystemExit("openssl public-key extraction failed:\n"
                             + pub.stderr.decode(errors="replace"))
        with open(key_path, "r", encoding="utf-8") as fh:
            private_pem = fh.read()
    body = "".join(line for line in pub.stdout.decode().splitlines()
                   if line and not line.startswith("-----"))
    return private_pem, body


def public_key_fingerprint(public_key_body: str) -> str:
    """`SHA256:<base64>` over the public key's DER — the suffix Snowflake matches
    the JWT's `iss` against to select which registered key pair is being used."""
    der = base64.b64decode(public_key_body)
    return "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def qualified_username(account: str, service_user: str) -> str:
    """<ACCOUNT>.<USER>, uppercased — the JWT `sub`, and the stem of `iss`."""
    return f"{jwt_account(account)}.{service_user.upper()}"


def admin_request(service_user: str, role: str, warehouse: str,
                  public_key_body: str, *, engineer: str, today: str) -> str:
    """The message the engineer forwards to whoever holds USERADMIN.

    Deliberately a message and not a bare statement: the engineer should not have
    to explain or justify it, and an admin who has never heard of this skill should
    be able to approve or reject it without asking a single question. Every value
    is substituted — there is nothing to fill in. No role is created; an existing
    read-only role is reused.

    Formatted for SLACK's markup, since that is where it gets pasted: `*bold*` not
    `**bold**`, bare triple-backtick fences with no language tag (Slack would render
    `sql` as the first line of the code), single backticks for identifiers, and no
    `-` bullets — Slack disables list conversion on paste."""
    wh = f"\n  DEFAULT_WAREHOUSE = {warehouse}" if warehouse else ""
    fence = "```"
    return f"""Hi — I'm setting up read-only Snowflake access for an AI coding assistant
that runs in a locked-down sandbox on my Mac.

It needs to query Snowflake but must never change anything. Rather than give it my
own credentials, this creates a separate service account and registers a key that is
pinned to the `{role}` role — *the credential cannot authenticate as any other role,
even if it leaks*. No new role is created; it reuses `{role}`, which I already have.

I can't create the account myself; that needs `USERADMIN`. Everything else is done on
my side: the key pair was generated locally, only the public half is below, and the
private half never leaves my Mac or enters the sandbox. Nothing here needs a network
policy, and nothing expires or needs rotating.

Could you run this? *It's complete, nothing to fill in:*

{fence}
CREATE USER IF NOT EXISTS {service_user}
  TYPE = SERVICE_AGENT
  DEFAULT_ROLE = {role}
  DEFAULT_SECONDARY_ROLES = (){wh}
  COMMENT = 'Read-only sandbox for Claude Code, requested by {engineer} on {today}. Revoke with DROP USER.';

GRANT ROLE {role} TO USER {service_user};

ALTER USER {service_user} ADD KEY PAIR {KEY_PAIR_NAME}
  PUBLIC_KEY = '{public_key_body}'
  ROLE_RESTRICTION = '{role}'
  COMMENT = 'claude-ro sandbox; role-restricted';
{fence}

To revoke at any point: `DROP USER {service_user};`"""
