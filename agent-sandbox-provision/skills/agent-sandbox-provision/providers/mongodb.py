#!/usr/bin/env python3
"""
MongoDB credential-source provider (Atlas and self-hosted / ScaleGrid).

There is NO admin/provisioning credential on the laptop. A per-engineer read-only
DB user `claude-ro-<engineer>` (readAnyDatabase@admin) is created out of band by
the DB owner (bind-mongodb prints the exact command). Only that user's password is
stored, in a mode-600 file. `mint` assembles a `MONGODB_URI` from the state record
+ the stored password.

`mint` is STDLIB ONLY (runs in the launcher/broker hot path). `verify` may pull in
pymongo via _ensure_pkg (it is not the hot path).

Contract: see providers/_interface.md → "Credential-source provider contract".
"""

from __future__ import annotations

import re
import urllib.parse


# ---------- URI assembly ----------

def build_uri(record: dict, password: str | None = None, *, include_proxy: bool = True,
              proxy_port: int | None = None) -> str:
    """mongodb[+srv]://[<user>:<pw>@]<host>/<db>?authSource=...&<options>. Hosts/options
    come from validated state fields.

    auth=aws_iam (Atlas): no userinfo — `authSource=$external&authMechanism=MONGODB-AWS`.
    The identity is claude-ro's RO role; the MongoDB driver picks up its (minted) AWS
    creds from the environment at connect time, so nothing secret lives in the URI.

    Password auth (default): userinfo is percent-encoded from username + `password`.

    Tunneled DBs (record has via_cluster) additionally get proxyHost/proxyPort options
    pointing at the per-session local SOCKS5 tunnel; `proxy_port` is the live port the
    per-cluster tunnel broker returned. `include_proxy=False` omits them for clients that
    route through SOCKS at the socket layer instead (pymongo+PySocks in verify)."""
    scheme = "mongodb+srv" if record.get("srv") else "mongodb"
    host = record["srv_host"] if record.get("srv") else record["hosts"]
    default_db = record.get("default_db", "")
    path = f"/{default_db}" if default_db else "/"

    if record.get("auth") == "aws_iam":
        params = ["authSource=$external", "authMechanism=MONGODB-AWS"]
        opts = record.get("options")
        if opts:
            params.append(opts)
        return f"{scheme}://{host}{path}?{'&'.join(params)}"

    user = urllib.parse.quote(record["username"], safe="")
    pw = urllib.parse.quote(password or "", safe="")
    params = [f"authSource={urllib.parse.quote(record.get('auth_db', 'admin'), safe='')}"]
    opts = record.get("options")
    if opts:
        params.append(opts)
    if include_proxy and record.get("via_cluster") and proxy_port:
        params.append("proxyHost=127.0.0.1")
        params.append(f"proxyPort={int(proxy_port)}")
    query = "&".join(p for p in params if p)
    return f"{scheme}://{user}:{pw}@{host}{path}?{query}"


# ---------- contract: mint / revoke / provision / verify ----------

def mint(record: dict, secret: str | None = None, *, proxy_port: int | None = None) -> dict:
    """Return {'MONGODB_URI': <connection string>}. STDLIB ONLY. For aws_iam records
    `secret` is unused (no stored password). For password records `secret` is the RO
    user's password; `proxy_port` is the live per-session tunnel port, baked as
    proxyPort."""
    if record.get("auth") == "aws_iam":
        return {"MONGODB_URI": build_uri(record, proxy_port=proxy_port)}
    password = (secret or "").rstrip("\n")
    return {"MONGODB_URI": build_uri(record, password, proxy_port=proxy_port)}


def revoke(record: dict, secret: str) -> None:
    """No-op: the DB owner owns claude-ro-<engineer>; the laptop has no admin
    credential to delete it. unbind only removes the local password."""
    return None


def provision(record_in: dict, secret: str, *, ctx) -> dict:
    """Best-effort connectivity probe. Never fails the bind on unreachability
    (self-hosted may be VPC-only); just logs. Returns the record unchanged."""
    ok, detail = _probe(record_in, secret, ctx=ctx)
    if ok:
        ctx.logger.info("mongodb: read probe OK for %s", record_in["name"])
    else:
        ctx.logger.warning("mongodb: could not verify %s from here (%s). Binding "
                           "anyway — it may only be reachable from the sandbox / VPC.",
                           record_in["name"], detail)
    return record_in


def verify(record: dict, env: dict, *, ctx) -> list[dict]:
    """Prove a read works and a write is denied. `env` is a freshly-minted
    {'MONGODB_URI': ...}. Unreachable → reported as a best-effort skip (not a hard
    fail), since the DB may only be reachable from inside the sandbox/VPC.

    Tunneled DBs: pymongo has no native SOCKS support, so route at the socket layer
    via PySocks (rdns=True → hostnames resolve proxy-side, inside the cluster) and
    strip the mongosh-only proxyHost/proxyPort params from the URI. Requires the
    per-session tunnel to be up (a claude-ro session running); otherwise this reports
    the usual best-effort unreachable skip."""
    # Reset any SOCKS patch left by a previously-verified DB before deciding whether
    # THIS one needs one — the patch is process-global, and verify --all loops here.
    _socks_reset()
    uri = env["MONGODB_URI"]
    # Tunneled DB: route pymongo through the SOCKS port carried in the minted URI (the
    # port is per-session dynamic, so we read it from the URI rather than state).
    _pp = re.search(r"proxyPort=(\d+)", uri) if record.get("via_cluster") else None
    if _pp:
        _socks_patch(int(_pp.group(1)))
        uri = _strip_proxy_params(uri)
    MongoClient, OperationFailure, PyMongoError = _import_pymongo()
    default_db = record.get("default_db") or "admin"
    results: list[dict] = []
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
    except Exception as exc:  # noqa: BLE001 — reachability is best-effort
        results.append({
            "name": "mongodb_reachability",
            "expected": "reachable", "actual": "unreachable",
            "passed": True,
            "detail": f"unreachable from the provisioning host ({exc.__class__.__name__}); "
                      "verify from inside the sandbox instead",
        })
        return results

    # Read check.
    try:
        client[default_db].list_collection_names()
        read_ok, rdetail = True, ""
    except Exception as exc:  # noqa: BLE001
        read_ok, rdetail = False, str(exc)
    results.append({
        "name": "mongodb_read", "expected": "ok",
        "actual": "ok" if read_ok else "denied",
        "passed": read_ok, "detail": rdetail,
    })

    # Write-denied check: an insert must be rejected for a read-only user.
    coll = client[default_db]["claude_ro_verify"]
    try:
        coll.insert_one({"claude_ro_verify": True})
        # Unexpected success → the user is NOT read-only. Best-effort cleanup.
        try:
            coll.delete_many({"claude_ro_verify": True})
        except Exception:  # noqa: BLE001
            pass
        results.append({
            "name": "mongodb_write_denied", "expected": "denied", "actual": "allowed",
            "passed": False,
            "detail": "insert SUCCEEDED — the DB user is not read-only; recreate it "
                      "with only readAnyDatabase@admin",
        })
    except OperationFailure as exc:
        results.append({
            "name": "mongodb_write_denied", "expected": "denied", "actual": "denied",
            "passed": True, "detail": f"insert rejected ({exc.code})",
        })
    except PyMongoError as exc:
        results.append({
            "name": "mongodb_write_denied", "expected": "denied",
            "actual": "error", "passed": False, "detail": str(exc),
        })
    return results


# ---------- helpers ----------

def _strip_proxy_params(uri: str) -> str:
    """Drop the mongosh-only proxyHost/proxyPort query params (pymongo rejects
    unknown options; its SOCKS routing happens at the socket layer instead)."""
    import re
    uri = re.sub(r"[&?]proxy(Host|Port)=[^&]*", "", uri)
    # A stripped first param can leave '...&a=b' without '?': normalize.
    if "?" not in uri and "&" in uri:
        uri = uri.replace("&", "?", 1)
    return uri.rstrip("?&")


_ORIG_SOCKET = None  # the real socket.socket, captured before the first SOCKS patch


def _socks_patch(port: int) -> None:
    """Route all subsequent socket connections through the local SOCKS5 tunnel.
    rdns=True: hostname resolution happens proxy-side (inside the cluster), so
    VPC-internal replica-member names resolve. PySocks installs as module 'socks'.
    The patch is process-global — pair it with _socks_reset() (verify does)."""
    global _ORIG_SOCKET
    import sys as _sys
    import pathlib as _pathlib
    _sys.path.insert(0, str(_pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import _common as common
    socks = common._ensure_pkg("socks", "PySocks")
    import socket
    if _ORIG_SOCKET is None:
        _ORIG_SOCKET = socket.socket
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", port, rdns=True)
    socket.socket = socks.socksocket


def _socks_reset() -> None:
    """Undo a prior _socks_patch so the next connection uses the real socket. No-op
    if nothing was patched yet."""
    if _ORIG_SOCKET is not None:
        import socket
        socket.socket = _ORIG_SOCKET


def _import_pymongo():
    import sys
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "scripts"))
    import _common as common
    pymongo = common._ensure_pkg("pymongo")
    from pymongo.errors import OperationFailure, PyMongoError
    return pymongo.MongoClient, OperationFailure, PyMongoError


def _probe(record: dict, secret: str, *, ctx) -> tuple[bool, str]:
    try:
        MongoClient, _OpF, _Err = _import_pymongo()
    except SystemExit as exc:
        return False, f"pymongo unavailable: {exc}"
    # include_proxy=False: pymongo rejects the mongosh-only proxy params. A tunneled
    # DB is typically unreachable from here anyway (the tunnel is per-session) — the
    # caller already treats that as a best-effort skip.
    uri = build_uri(record, secret.rstrip("\n"), include_proxy=False)
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, exc.__class__.__name__
