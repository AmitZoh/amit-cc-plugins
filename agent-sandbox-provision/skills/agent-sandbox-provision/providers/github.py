#!/usr/bin/env python3
"""
GitHub credential-source provider.

Grants claude-ro read-only GitHub access via a **GitHub App** created through the
App-Manifest flow (bind-github walks the user through two browser clicks; GitHub
hands the App private key back to the skill). The launcher / broker mints ~1h
read-only installation tokens on demand from that key — the key never enters the
sandbox.

`mint` is STDLIB ONLY (openssl for RS256, urllib for HTTP): it runs in the broker
hot path, so no third-party deps, no _ensure_pkg. `verify` may pull deps but here
it also only needs urllib.

Contract: see providers/_interface.md → "Credential-source provider contract".
"""

from __future__ import annotations

import base64
import http.server
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import typing as t
import urllib.error
import urllib.request
import webbrowser

API = "https://api.github.com"
UA = "claude-ro-sandbox"

# Read-only permission set requested for the App and minted into every token.
RO_PERMISSIONS = {
    "contents": "read",
    "metadata": "read",
    "issues": "read",
    "pull_requests": "read",
}


# ---------- low-level HTTP + JWT ----------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _api(method: str, url: str, *, token: str | None = None, bearer: str | None = None,
         body: dict | None = None, timeout: int = 20) -> tuple[int, dict | None]:
    """One GitHub API call. Returns (status, parsed_json_or_None). Raises only on
    transport errors; HTTP error statuses are returned so callers can branch."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": UA,
    }
    if token is not None:
        headers["Authorization"] = f"token {token}"
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
            parsed = json.loads(payload) if payload.strip() else None
            return resp.status, parsed
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = None
        return exc.code, parsed


def _app_jwt(app_id: str, pem: str) -> str:
    """RS256-sign a short-lived App JWT with openssl (no PyJWT/cryptography).
    iat is backdated 60s for clock skew; exp is +9min (GitHub caps at 10)."""
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(
        {"iat": now - 60, "exp": now + 540, "iss": int(app_id)}).encode())
    signing_input = f"{header}.{payload}".encode()
    fd, path = tempfile.mkstemp(prefix="claude-ro-app-", suffix=".pem")
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
                "openssl RS256 signing failed (is the App private key valid?):\n"
                + proc.stderr.decode(errors="replace"))
        sig = _b64url(proc.stdout)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return f"{header}.{payload}.{sig}"


def _installation_token(app_id: str, installation_id: str, pem: str) -> str:
    jwt = _app_jwt(app_id, pem)
    status, data = _api(
        "POST", f"{API}/app/installations/{installation_id}/access_tokens",
        bearer=jwt, body={"permissions": RO_PERMISSIONS})
    if status != 201 or not data or "token" not in data:
        msg = (data or {}).get("message", f"HTTP {status}")
        raise SystemExit(
            f"could not mint GitHub installation token (installation "
            f"{installation_id}): {msg}")
    return data["token"]


# ---------- contract: mint / revoke / provision / verify ----------

def mint(record: dict, secret: str) -> dict:
    """Return {'password': <~1h read-only installation token>}. STDLIB ONLY. Mints
    from the org-App's stored app_id + installation_id + private key. Used by both the
    broker (per bound org) and verify."""
    token = _installation_token(record["app_id"], record["installation_id"], secret)
    return {"password": token}


def revoke(record: dict, secret: str) -> None:
    """Uninstall the App from the account (DELETE the installation) using the
    still-present private key. Idempotent: 404 is success. Called by unbind-github
    BEFORE the secret file is deleted."""
    jwt = _app_jwt(record["app_id"], secret)
    status, data = _api(
        "DELETE", f"{API}/app/installations/{record['installation_id']}", bearer=jwt)
    if status in (204, 404):
        return
    msg = (data or {}).get("message", f"HTTP {status}")
    raise SystemExit(f"could not uninstall GitHub App installation: {msg}")


def provision(record_in: dict, secret: str, *, ctx) -> dict:
    """Probe: mint a token from the captured key and confirm it can list the
    installation's repositories. Returns the record unchanged on success."""
    token = _installation_token(
        record_in["app_id"], record_in["installation_id"], secret)
    status, _ = _api("GET", f"{API}/installation/repositories?per_page=1", token=token)
    if status != 200:
        raise SystemExit(
            f"GitHub App installed but a read probe failed (HTTP {status}). "
            "Check the App has read access to at least metadata + contents.")
    ctx.logger.info("github: read probe OK for %s", record_in["name"])
    return record_in


def verify(record: dict, env: dict, *, ctx) -> list[dict]:
    """Prove read works and a write is denied. `env` is a freshly-minted
    {'password': token}. Write test is fail-safe: it PATCHes a repo field to its
    CURRENT value, so even an unexpected success mutates nothing."""
    token = env["password"]
    results: list[dict] = []

    status, repos = _api(
        "GET", f"{API}/installation/repositories?per_page=5", token=token)
    read_ok = status == 200
    results.append({
        "name": "github_read_repositories",
        "expected": "200", "actual": str(status),
        "passed": read_ok,
        "detail": "" if read_ok else "could not list installation repositories",
    })

    repo = None
    if read_ok and repos:
        for r in (repos.get("repositories") or []):
            repo = r
            break
    if repo is None:
        results.append({
            "name": "github_write_denied",
            "expected": "403 (no write)", "actual": "skipped",
            "passed": True,
            "detail": "no accessible repositories to test write-denial against",
        })
        return results

    owner = repo["owner"]["login"]
    name = repo["name"]
    # Fail-safe no-op write: set description to its current value.
    wstatus, wdata = _api(
        "PATCH", f"{API}/repos/{owner}/{name}",
        token=token, body={"description": repo.get("description")})
    denied = wstatus in (403, 404)  # 403 forbidden; 404 = not visible for write
    results.append({
        "name": "github_write_denied",
        "expected": "403/404", "actual": str(wstatus),
        "passed": denied,
        "detail": "" if denied else
                  f"write to {owner}/{name} was NOT denied (status {wstatus}) — "
                  f"the App has write access; reduce its permissions",
    })
    return results


def detect_account_type(login: str, *, ctx=None) -> str:
    """Return 'org' or 'user' for `login`, using the UNAUTHENTICATED public API (no
    creds — safe in dry-run). Checks /orgs first, then /users (an account can be either).
    Raises SystemExit if the login exists as neither. Rate-limits don't block a bind:
    they default to 'org' (the manifest create page will still let you correct it)."""
    log = ctx.logger if ctx is not None else None
    status, _ = _api("GET", f"{API}/orgs/{login}")
    if status == 200:
        if log:
            log.info("github: %r is an organization", login)
        return "org"
    status_u, data_u = _api("GET", f"{API}/users/{login}")
    if status_u == 200:
        typ = (data_u or {}).get("type", "User")
        kind = "org" if typ == "Organization" else "user"
        if log:
            log.info("github: %r is a %s account", login,
                     "organization" if kind == "org" else "personal user")
        return kind
    if status in (403, 429) or status_u in (403, 429):
        if log:
            log.warning("could not verify %r (rate-limited) — assuming org", login)
        return "org"
    raise SystemExit(
        f"GitHub login '{login}' not found as an organization OR a user (HTTP "
        f"{status}/{status_u}). Check the handle (the name in its github.com URL).")


# ---------- App-Manifest flow (used by bind-github) ----------

class _ManifestHandler(http.server.BaseHTTPRequestHandler):
    manifest_json = ""
    github_new_url = ""
    captured: dict = {}

    def log_message(self, *args):  # silence the default stderr access log
        pass

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/callback"):
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            code = (qs.get("code") or [None])[0]
            type(self).captured["code"] = code
            self._html(
                "GitHub App created. You can close this tab and return to the "
                "terminal.")
            return
        # Landing page: auto-POST the manifest to GitHub.
        form = (
            f'<form id="f" method="post" action="{self.github_new_url}">'
            f'<input type="hidden" name="manifest" '
            f'value=\'{self.manifest_json.replace("&", "&amp;").replace(chr(39), "&#39;")}\'>'
            '</form><script>document.getElementById("f").submit();</script>'
        )
        self._html("Redirecting you to GitHub to create the read-only App…" + form)

    def _html(self, body: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"<!doctype html><meta charset=utf-8>{body}".encode())


def _host8() -> str:
    """8 hex chars derived from the hostname, for a globally-unique App slug."""
    import hashlib
    return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:8]


def expected_app_name(login: str | None) -> str:
    """The deterministic App name the manifest flow will request on this host.
    Exposed so bind-github can name a possible leftover before the flow starts;
    GitHub App names are globally unique, so a leftover with this name blocks
    re-creation."""
    return f"claude-ro-{login or 'user'}-{_host8()}"[:34]


def account_settings_url(login: str, account_type: str) -> str:
    """The settings page that owns the App for `login` — org vs personal user."""
    if account_type == "org":
        return f"https://github.com/organizations/{login}/settings/apps"
    return "https://github.com/settings/apps"


def create_account_app(login: str, account_type: str, *, ctx) -> dict:
    """Create a read-only GitHub App OWNED BY `login` (an org, or a personal user
    account) and install it there. Owner == install target, so it stays PRIVATE (no
    public App). `account_type` routes the manifest to the org create page vs the
    personal one. Two browser steps: Create, then Install. Returns
    {app_id, app_slug, installation_id, login, pem}.

    Interactive — the part of bind-github that cannot run headless.
    """
    log = ctx.logger
    app_name = expected_app_name(login)  # claude-ro-<login>-<host8>, globally unique

    httpd = http.server.HTTPServer(("127.0.0.1", 0), _ManifestHandler)
    port = httpd.server_address[1]
    redirect = f"http://127.0.0.1:{port}/callback"

    manifest = {
        "name": app_name,
        "url": "https://github.com/anthropics/claude-code",
        "redirect_url": redirect,
        "public": False,  # private is fine: owner == install target
        "default_permissions": RO_PERMISSIONS,
        "default_events": [],
    }
    if account_type == "org":
        new_url = f"https://github.com/organizations/{login}/settings/apps/new"
    else:
        new_url = "https://github.com/settings/apps/new"  # personal account

    _ManifestHandler.manifest_json = json.dumps(manifest)
    _ManifestHandler.github_new_url = new_url
    _ManifestHandler.captured = {}

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    landing = f"http://127.0.0.1:{port}/"
    log.info("Opening your browser to create the read-only GitHub App %r owned by %s (%s).",
             app_name, login, account_type)
    log.info("If it doesn't open, visit: %s", landing)
    webbrowser.open(landing)

    deadline = time.monotonic() + 120
    while _ManifestHandler.captured.get("code") is None:
        if time.monotonic() > deadline:
            httpd.shutdown()
            raise SystemExit(
                f"timed out waiting for GitHub to create the App {app_name!r} for "
                f"{login!r}. If an App with that name already exists (a leftover blocks "
                f"re-creation), delete it at {account_settings_url(login, account_type)} "
                f"and re-run.")
        time.sleep(0.5)
    code = _ManifestHandler.captured["code"]
    httpd.shutdown()

    status, data = _api("POST", f"{API}/app-manifests/{code}/conversions")
    if status not in (200, 201) or not data:
        msg = (data or {}).get("message", f"HTTP {status}")
        raise SystemExit(f"GitHub App-manifest conversion failed: {msg}")
    app_id = str(data["id"])
    app_slug = data["slug"]
    pem = data["pem"]

    install_url = f"https://github.com/apps/{app_slug}/installations/new"
    log.info("Now install the App on %s: %s  (approve it in the browser)", login, install_url)
    webbrowser.open(install_url)
    installation_id = _await_installation(app_id, pem, login, ctx=ctx)
    return {
        "app_id": app_id,
        "app_slug": app_slug,
        "installation_id": installation_id,
        "login": login,
        "pem": pem,
    }


def _await_installation(app_id: str, pem: str, login: str | None, *, ctx,
                        timeout: int = 120) -> str:
    """Poll GET /app/installations (App JWT) until the user finishes installing,
    then return the matching installation id."""
    log = ctx.logger
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jwt = _app_jwt(app_id, pem)
        status, data = _api("GET", f"{API}/app/installations", bearer=jwt)
        if status == 200 and data:
            if login:
                for inst in data:
                    if (inst.get("account") or {}).get("login", "").lower() == login.lower():
                        return str(inst["id"])
            if len(data) == 1:
                return str(data[0]["id"])
            if len(data) > 1:
                # Ambiguous — pick the most recent; log so the user can see.
                inst = sorted(data, key=lambda i: i.get("id", 0))[-1]
                log.warning("multiple installations found; using id %s (account %s)",
                            inst["id"], (inst.get("account") or {}).get("login"))
                return str(inst["id"])
        time.sleep(3)
    raise SystemExit(
        "timed out waiting for the App installation. Finish installing in the "
        "browser, then re-run bind-github (it will resume).")
