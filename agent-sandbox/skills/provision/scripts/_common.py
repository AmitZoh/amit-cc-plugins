"""
Shared helpers for agent-sandbox sub-commands.

This module is imported by every sub-command. It owns:

- The Ctx dataclass (state snapshot + parsed config + dry-run flag + logger)
- state_read / state_write_atomic with flock + atomic mv + .bak rotation
- aws_assume_role_clean_env (env-clearing assume-role)
- kubectl_smoke_check (post-bind sanity check)
- load_provider (dynamic import of providers/<name>.py)
- TTY prompt helpers (prompt_yes_no, pick_from_list) with --yes / --no for non-interactive
- A small structured logger

No third-party deps. Stdlib only.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime
import fcntl
import importlib
import importlib.util
import json
import logging
import os
import pathlib
import re
import shutil
import site
import subprocess
import sys
import tempfile
import textwrap
import time
import typing as t


def _ensure_pkg(import_name: str, pip_name: str | None = None) -> t.Any:
    """Import `import_name`, installing it on first run if missing via pip3 --user.

    Provisioning should be one command, not two; we auto-install rather than
    requiring the user to manage deps. Do not call this from module top-level
    (would require the dep to be present before init.py can even start) — call
    it lazily, the first time the dep is needed."""
    pip_name = pip_name or import_name
    try:
        return importlib.import_module(import_name)
    except ImportError:
        pass
    log = get_logger()
    log.info("%s not found; installing via pip3 install --user %s", import_name, pip_name)
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--user", "--quiet", pip_name],
            stdout=sys.stderr, stderr=sys.stderr,
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit(
            f"failed to auto-install {pip_name} (exit {exc.returncode}). "
            f"Run manually: pip3 install --user {pip_name}"
        ) from exc
    site.main()
    importlib.invalidate_caches()
    return importlib.import_module(import_name)


def _ensure_pyyaml() -> t.Any:
    return _ensure_pkg("yaml", "pyyaml")


def _ensure_boto3() -> t.Any:
    return _ensure_pkg("boto3")

# SKILL_DIR is derived from this module's own location, NOT from `~`. _common.py
# lives at <SKILL_DIR>/scripts/_common.py, so two parents up is SKILL_DIR. Robust
# against running under a different effective user (e.g. via `sudo -u claude-ro`),
# where `~` would resolve to the wrong home and `state.json` would not be found.
# Still correct for templates/scripts/providers, which are read-only and ship
# alongside this file — only state.json/.bak/.lock move out (see STATE_DIR below).
SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent

# STATE_DIR is fixed and version-independent, NOT under SKILL_DIR: as a plugin,
# this code is installed under a version-numbered cache path, so anything written
# under SKILL_DIR would be orphaned (and unreadable by the next version) the
# moment the plugin is updated. mode 0700 because state.json holds AWS account
# IDs/ARNs/cluster names.
STATE_DIR = pathlib.Path(os.path.expanduser("~/.claude/plugins/data/agent-sandbox"))
STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(STATE_DIR, 0o700)

STATE_PATH = STATE_DIR / "state.json"
STATE_BAK_PATH = STATE_DIR / "state.json.bak"
STATE_LOCK_PATH = STATE_DIR / "state.lock"
SCHEMA_PATH = SKILL_DIR / "state.schema.json"
CONFIG_PATH = SKILL_DIR / "skill-config.yaml"

SCHEMA_VERSION = 2

# ---------- logging ----------

def get_logger(name: str = "agent-sandbox") -> logging.Logger:
    """Return the shared logger. First caller initialises it; subsequent callers reuse.

    `propagate=False` is critical: child loggers (e.g. "agent-sandbox.aws") are
    set up with their own handlers, and Python's logging hierarchy by default
    propagates messages up to ancestor loggers — so a message emitted on
    "agent-sandbox.aws" would print once via that handler AND a second time via
    the parent "agent-sandbox" handler. Disabling propagation eliminates the
    duplicate."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


log = get_logger()


# ---------- config (skill-config.yaml) ----------

def load_config() -> dict:
    """Parse skill-config.yaml into a dict. Auto-installs PyYAML on first run if missing.
    String values are run through os.path.expandvars so `$HOME` etc. work."""
    yaml = _ensure_pyyaml()
    text = CONFIG_PATH.read_text()
    data = yaml.safe_load(text) or {}
    return _expand_env(data)


def _expand_env(node: t.Any) -> t.Any:
    """Walk a parsed YAML tree, applying os.path.expandvars to strings."""
    if isinstance(node, dict):
        return {k: _expand_env(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_expand_env(v) for v in node]
    if isinstance(node, str):
        return os.path.expandvars(node)
    return node


# ---------- state.json read / write ----------

@contextlib.contextmanager
def _state_lock(timeout_seconds: int = 30):
    """Acquire an advisory lock on state.lock. flock-based; auto-released on exit.
    Times out with a clear error rather than hanging forever."""
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(STATE_LOCK_PATH), os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"could not acquire {STATE_LOCK_PATH} within {timeout_seconds}s"
                    )
                time.sleep(0.1)
        yield
    finally:
        with contextlib.suppress(Exception):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def state_read(*, validate: bool = False) -> dict:
    """Read state.json under the lock. Returns the empty-init shape if the file does not
    exist (init has never run). Hard-fails if the file is newer than this skill, and
    migrates older versions in memory. Pass validate=True on the command path to schema-
    validate the on-disk file first (pulls in jsonschema — NOT for the launcher path)."""
    with _state_lock():
        return _state_read_unlocked(validate=validate)


def _state_read_unlocked(*, validate: bool = False) -> dict:
    if not STATE_PATH.exists():
        return _empty_state()
    text = STATE_PATH.read_text()
    if not text.strip():
        return _empty_state()
    state = json.loads(text)
    sv = state.get("schema_version")
    if not isinstance(sv, int) or sv > SCHEMA_VERSION:
        raise SystemExit(
            f"state.json schema_version is {sv!r}; this skill understands up to "
            f"{SCHEMA_VERSION}. Update the skill (it's older than the state file)."
        )
    # GitHub is a per-org array of org-owned Apps (github[]). Drop the abandoned
    # single-App experiment (github_app) and the legacy default_github, and ensure
    # github[] exists. In-memory only; converges on the next write.
    state.pop("github_app", None)
    state.pop("default_github", None)
    state.setdefault("github", [])
    # snowflake[] arrived after v2 shipped, so _migrate (v1→v2 only) never backfills it
    # on an existing v2 file. Default it here alongside github[], same in-memory-only
    # treatment: consumers all use .get(), but this keeps the shape uniform on read.
    state.setdefault("snowflake", [])
    # Records bound before account_type existed were all org-owned (the only kind the
    # earlier per-org code created). Default them to "org".
    for _rec in state.get("github") or []:
        if isinstance(_rec, dict):
            _rec.setdefault("account_type", "org")
    # Validate the ON-DISK shape before migrating, so a broken config is rejected
    # as-is rather than silently migrated. Gated by `validate` because the schema
    # check pulls in jsonschema (via _ensure_pkg) — fine on the command path, but
    # the launcher's render_* scripts must stay stdlib-only, so they read without it.
    if validate:
        _validate_state(state)
    # Migrate older versions IN MEMORY. Read stays side-effect-free; the file
    # converges to the current version on the next update_state() write.
    if sv < SCHEMA_VERSION:
        state = _migrate(state, sv)
    return state


def _migrate(state: dict, from_v: int) -> dict:
    """Upgrade an older state dict to SCHEMA_VERSION in memory. Idempotent."""
    if from_v == 1:
        state.setdefault("github", [])
        state.setdefault("mongodb", [])
        state["schema_version"] = 2
        from_v = 2
    # snowflake[] was added after v2 shipped, so it is optional in the schema rather
    # than a version bump — backfill the key so callers can index it unconditionally.
    state.setdefault("snowflake", [])
    return state


def _validate_state(state: dict) -> None:
    """Validate `state` against state.schema.json. Raises SystemExit with the
    first error on failure. Uses jsonschema (auto-installed on first use) — call
    only on the command path, never from the launcher's stdlib-only render_*."""
    jsonschema = _ensure_pkg("jsonschema")
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(state), key=lambda e: list(e.path))
    if errors:
        e = errors[0]
        loc = "/".join(str(p) for p in e.path) or "(root)"
        raise SystemExit(
            f"state.json failed schema validation at {loc}: {e.message}\n"
            "The on-disk config is malformed; fix it before running this command."
        )


def _empty_state() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "user": {"username": os.getenv("USER", "")},
        "macos_user": "claude-ro",
        "default_account_id": "",
        "accounts": [],
        "github": [],
        "mongodb": [],
        "snowflake": [],
        "lockdown": {"classifier_cache": {}},
        "extensions": [],
        "pending_operation": None,
    }


def state_write_atomic(state: dict) -> None:
    """Atomically write state.json with a one-generation backup.

    Order matters: COPY (not move) state.json -> state.json.bak first, THEN atomic-replace
    tmp -> state.json. This way state.json always exists and points at *something* valid:
    the old contents until the replace lands, the new contents afterward. An earlier
    version moved state.json -> .bak first, which left a window where state.json was
    missing and the next read returned an empty-init shape.

    Caller MUST hold the lock via update_state(); use that wrapper instead of calling
    this directly."""
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        dir=str(STATE_DIR),
        prefix=".state.",
        suffix=".tmp",
        delete=False,
        encoding="utf-8",
    )
    try:
        json.dump(state, tmp, indent=2, sort_keys=False)
        tmp.write("\n")
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.chmod(tmp.name, 0o600)
        # Back up the existing state.json by COPYING (not moving) so a crash here
        # leaves state.json intact at the old contents.
        if STATE_PATH.exists():
            shutil.copy2(STATE_PATH, STATE_BAK_PATH)
            os.chmod(STATE_BAK_PATH, 0o600)
        # Atomic replace: state.json transitions in one syscall.
        os.replace(tmp.name, STATE_PATH)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp.name)
        raise


@contextlib.contextmanager
def update_state(*, validate: bool = True) -> t.Iterator[dict]:
    """Acquire the lock, yield a mutable snapshot of state, write atomically on exit.
    Use this for any read-modify-write of state.json:

        with update_state() as state:
            state["accounts"].append(...)

    Validates the on-disk file before migrating (command path — jsonschema is fine
    here). Pass validate=False only in narrow cases where the caller knows the file
    may be legitimately mid-migration."""
    with _state_lock():
        state = _state_read_unlocked(validate=validate)
        yield state
        state_write_atomic(state)


# ---------- AWS helpers ----------

# Env vars AWS's credential chain checks BEFORE the profile. Cleared in the
# context manager below so a named profile actually wins.
AWS_AMBIENT_CREDENTIAL_VARS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
)


@contextlib.contextmanager
def aws_env_cleared() -> t.Iterator[None]:
    """Temporarily pop AWS_ACCESS_KEY_ID / SECRET / SESSION_TOKEN / SECURITY_TOKEN
    from the parent process's environment so a named profile is what boto3 picks
    up. Restored on exit (even on exception)."""
    saved: dict[str, str] = {}
    for k in AWS_AMBIENT_CREDENTIAL_VARS:
        if k in os.environ:
            saved[k] = os.environ.pop(k)
    try:
        yield
    finally:
        os.environ.update(saved)


def boto3_session(profile: str) -> t.Any:
    """Return a boto3.Session bound to `profile`, with ambient AWS_* cleared
    inside the call so the profile actually wins. Caller is responsible for
    using the returned session promptly — env vars are restored on return,
    but the session caches its credential resolver, so once it's bound to the
    profile it stays bound."""
    boto3 = _ensure_boto3()
    with aws_env_cleared():
        return boto3.Session(profile_name=profile)


@dataclasses.dataclass
class AssumedCreds:
    access_key: str
    secret_key: str
    session_token: str
    expiration: str  # ISO 8601


def aws_assume_role_clean_env(role_arn: str, profile: str, *,
                              session_name: str | None = None,
                              duration_seconds: int = 43200,
                              eventual_consistency_timeout: int = 45) -> AssumedCreds:
    """Assume `role_arn` using `profile` as the assumer. Clears ambient AWS_*
    env vars first so the profile actually wins. Returns short-lived creds.

    Retries on IAM eventual consistency: when CreateRole / UpdateAssumeRolePolicy
    has just landed, the trust policy can take 5-30s to propagate to all STS
    endpoints. During that window, sts:AssumeRole returns AccessDenied for what
    will shortly become a valid call. We retry with capped exponential backoff
    when the error code + message match that pattern.

    Raises AssumeRoleError on permanent failure (with classify() to distinguish
    profile-missing from creds-expired so callers can print the right hint)."""
    botocore_exc = _ensure_pkg("botocore.exceptions")
    sn = session_name or f"agent-sandbox-{int(time.time())}"

    deadline = time.monotonic() + eventual_consistency_timeout
    delay = 1.5
    attempts = 0
    while True:
        attempts += 1
        try:
            session = boto3_session(profile)
            sts = session.client("sts")
            resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=sn,
                DurationSeconds=duration_seconds,
            )
            break
        except botocore_exc.ProfileNotFound as exc:
            raise AssumeRoleError(role_arn, profile, str(exc)) from exc
        except botocore_exc.NoCredentialsError as exc:
            raise AssumeRoleError(role_arn, profile, str(exc)) from exc
        except botocore_exc.ClientError as exc:
            err = (exc.response.get("Error") or {})
            code = err.get("Code") or ""
            msg = err.get("Message") or str(exc)
            transient = (
                code in ("AccessDenied", "InvalidClientTokenId")
                and "sts:AssumeRole" in msg
                and time.monotonic() < deadline
            )
            if not transient:
                raise AssumeRoleError(role_arn, profile, str(exc)) from exc
            log.info(
                "assume-role on %s not yet valid (IAM eventual consistency), "
                "retrying in %.1fs (attempt %d, %.0fs remaining)",
                role_arn, delay, attempts,
                max(0, deadline - time.monotonic()),
            )
            time.sleep(delay)
            delay = min(delay * 1.6, 8.0)

    c = resp["Credentials"]
    return AssumedCreds(
        access_key=c["AccessKeyId"],
        secret_key=c["SecretAccessKey"],
        session_token=c["SessionToken"],
        expiration=c["Expiration"].isoformat()
            if hasattr(c["Expiration"], "isoformat") else str(c["Expiration"]),
    )


class AssumeRoleError(RuntimeError):
    """Raised by aws_assume_role_clean_env. Distinguishes profile-missing from
    creds-expired so callers can print the right hint."""

    def __init__(self, role_arn: str, profile: str, underlying: str):
        self.role_arn = role_arn
        self.profile = profile
        self.underlying = underlying
        super().__init__(f"could not assume {role_arn} as profile {profile}")

    def classify(self) -> str:
        u = self.underlying.lower()
        if "profilenotfound" in u or "could not be found" in u or "the config profile" in u:
            return "profile_missing"
        if "expiredtoken" in u or "expired" in u or "invalidclienttokenid" in u:
            return "creds_expired"
        return "unknown"

    def hint(self) -> str:
        cls = self.classify()
        if cls == "profile_missing":
            return (
                f'Profile "{self.profile}" is not defined in ~/.aws/credentials or ~/.aws/config.\n'
                f"Define it, or change accounts[].assumer_profile in state.json to one that exists."
            )
        if cls == "creds_expired":
            return (
                f'Profile "{self.profile}" exists but its creds are expired or invalid.\n'
                f"Refresh (e.g. `aws sso login --profile {self.profile}`) and retry."
            )
        return f"Try: AWS_PROFILE={self.profile} aws sts get-caller-identity"


def aws_caller_identity(profile: str) -> dict:
    """Return {Account, Arn, UserId} for `profile`. Clears ambient AWS_* first."""
    session = boto3_session(profile)
    sts = session.client("sts")
    return sts.get_caller_identity()


# ---------- kubectl helpers ----------

def kubectl_smoke_check(context: str, *, kubeconfig: str | None = None,
                        timeout_seconds: int = 10) -> tuple[bool, str]:
    """Fast post-bind sanity check: can we list CRDs cluster-wide as the bound principal?
    Returns (ok, detail). Used by bind-cluster after the access entry + ClusterRole land,
    before the full verify suite runs."""
    cmd = ["kubectl", "--context", context, "auth", "can-i",
           "list", "customresourcedefinitions.apiextensions.k8s.io",
           "--all-namespaces"]
    env = dict(os.environ)
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    try:
        proc = subprocess.run(
            cmd, env=env, capture_output=True, text=True,
            timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout_seconds}s"
    out = (proc.stdout or proc.stderr or "").strip()
    return (out == "yes"), out


# ---------- provider loader ----------

def load_provider(name: str) -> t.Any:
    """Dynamically import providers/<name>.py and return the module.

    The module MUST be registered in sys.modules BEFORE exec_module() runs.
    Python 3.14's @dataclasses.dataclass resolves forward refs via
    sys.modules.get(cls.__module__).__dict__ — if the module isn't there,
    it gets None and crashes with AttributeError. Same pattern bites pickle,
    typing.get_type_hints, and any other introspection that walks
    cls.__module__. The standard importlib-from-file recipe registers in
    sys.modules first; we follow it."""
    path = SKILL_DIR / "providers" / f"{name}.py"
    if not path.exists():
        raise SystemExit(f"provider not found: {path}")
    fq_name = f"providers.{name}"
    spec = importlib.util.spec_from_file_location(fq_name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"could not load provider {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[fq_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        # If exec fails, don't leave a half-loaded module entry in sys.modules.
        sys.modules.pop(fq_name, None)
        raise
    return module


# ---------- Ctx ----------

@dataclasses.dataclass
class Ctx:
    """Passed to provider methods. Carries config + dry-run flag + logger.
    Providers must NOT mutate state.json directly — the orchestrator owns the lock."""
    config: dict
    dry_run: bool = False
    logger: logging.Logger = dataclasses.field(default_factory=lambda: get_logger())
    yes: bool = False  # auto-answer all interactive prompts as "yes"

    @classmethod
    def from_args(cls, args: t.Any) -> "Ctx":
        cfg = load_config()
        return cls(
            config=cfg,
            dry_run=getattr(args, "dry_run", False),
            yes=getattr(args, "yes", False),
        )


# ---------- TTY prompts ----------

def prompt_yes_no(question: str, *, default: bool = False, ctx: Ctx | None = None) -> bool:
    """Read a y/N answer from stdin. Honours ctx.yes for non-interactive runs.
    Non-TTY (Claude Code Bash, launchd, ssh-without-tty): pops a macOS osascript
    `display dialog` with Continue/Cancel buttons. Same dialog family as
    _prompt_password_via_osascript, so the full multi-line question renders
    without the ~255-char Authorization Services cap. No GUI default button —
    dismiss / Esc / dialog failure all return `default`."""
    if ctx is not None and ctx.yes:
        log.info("[--yes] %s", question)
        return True
    if not sys.stdin.isatty():
        dialog_title = "agent-sandbox"
        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')
        # NO default button, deliberately. These dialogs gate infrastructure actions —
        # creating cloud identities, deleting keys, rewriting sudoers — so Return must
        # not commit anything. Every one requires a deliberate click. Escape still
        # dismisses, and a dismissal returns `default`, which every destructive caller
        # passes as False.
        osa_line = (
            f'display dialog "{_esc(question)}" '
            f'buttons {{"Cancel", "Continue"}} '
            f'with icon caution with title "{_esc(dialog_title)}"'
        )
        proc = subprocess.run(
            ["osascript", "-e", osa_line, "-e", "button returned of result"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            log.info("dialog dismissed; using default (%s) for: %s",
                     default, question.splitlines()[0])
            return default
        return proc.stdout.strip() == "Continue"
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        try:
            resp = input(question + suffix).strip().lower()
        except EOFError:
            return default
        if resp == "":
            return default
        if resp in ("y", "yes"):
            return True
        if resp in ("n", "no"):
            return False
        print("Please answer y or n.", file=sys.stderr)


def prompt_secret(message: str, *, title: str = "agent-sandbox") -> str:
    """Capture a single-line secret WITHOUT it touching argv, shell history, or the
    model. TTY → getpass; non-TTY (Claude Code / no terminal) → a macOS
    hidden-answer osascript dialog. Raises SystemExit if the dialog is canceled."""
    if sys.stdin.isatty():
        import getpass
        return getpass.getpass(message + ": ")

    def _esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    osa_line = (
        f'display dialog "{_esc(message)}" with hidden answer '
        f'default answer "" with icon caution with title "{_esc(title)}"'
    )
    proc = subprocess.run(
        ["osascript", "-e", osa_line, "-e", "text returned of result"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        if "User canceled" in (proc.stderr or ""):
            raise SystemExit("secret entry canceled")
        raise SystemExit(f"secret dialog failed: {proc.stderr}")
    return proc.stdout.rstrip("\n")


def prompt_text(message: str, *, title: str = "agent-sandbox") -> str:
    """Capture one line of NON-secret input. TTY → input(); non-TTY (Claude Code
    Bash, launchd) → a visible-answer osascript dialog, the same channel
    prompt_secret uses.

    Bind flows are orchestrated by Claude Code through the Bash tool, where stdin
    is not a TTY — a bare input() there dies on EOF before the flow starts, and CC
    has no way to write into its stdin. Anything a bind asks for must come through
    here. Raises SystemExit if canceled."""
    if sys.stdin.isatty():
        try:
            return input(message + ": ").strip()
        except EOFError:
            raise SystemExit(f"no input for: {message}")

    def _esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')

    osa_line = (
        f'display dialog "{_esc(message)}" default answer "" '
        f'with icon note with title "{_esc(title)}"'
    )
    proc = subprocess.run(
        ["osascript", "-e", osa_line, "-e", "text returned of result"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        if "User canceled" in (proc.stderr or ""):
            raise SystemExit(f"canceled at: {message}")
        raise SystemExit(f"input dialog failed: {proc.stderr}")
    return proc.stdout.rstrip("\n").strip()


def pick_from_list(prompt: str, items: list[str], *,
                   default_index: int | None = None,
                   ctx: Ctx | None = None) -> str:
    """Pick one of `items`. Honours ctx.yes (returns the default). Errors clearly if
    no default and not a TTY."""
    if not items:
        raise ValueError("pick_from_list called with empty items")
    if ctx is not None and ctx.yes:
        idx = default_index if default_index is not None else 0
        log.info("[--yes] picking %r for: %s", items[idx], prompt)
        return items[idx]
    if not sys.stdin.isatty():
        # Claude Code runs binds through the Bash tool, so "not a TTY" is the normal
        # case, not an edge one. Show a real picker rather than failing or silently
        # taking a default the user never saw.
        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')
        listing = ", ".join(f'"{_esc(i)}"' for i in items)
        # NO default items, deliberately — same rule as prompt_yes_no. Nothing is
        # pre-highlighted, so Return commits nothing and the row has to be clicked.
        # Escape still dismisses, and a dismissal falls back to `default_index` below.
        osa_line = (
            f'choose from list {{{listing}}} with title "agent-sandbox" '
            f'with prompt "{_esc(prompt)}"'
        )
        proc = subprocess.run(["osascript", "-e", osa_line],
                              capture_output=True, text=True, check=False)
        chosen = proc.stdout.strip()
        if proc.returncode == 0 and chosen and chosen != "false":
            return chosen
        if default_index is not None:
            log.info("picker dismissed; using default (%s)", items[default_index])
            return items[default_index]
        raise SystemExit(f"nothing picked for: {prompt}")
    print(prompt, file=sys.stderr)
    for i, item in enumerate(items, start=1):
        marker = " (default)" if default_index is not None and i - 1 == default_index else ""
        print(f"  {i}. {item}{marker}", file=sys.stderr)
    while True:
        try:
            resp = input("> ").strip()
        except EOFError:
            if default_index is not None:
                return items[default_index]
            raise SystemExit("EOF on stdin and no default")
        if resp == "" and default_index is not None:
            return items[default_index]
        if resp.isdigit():
            n = int(resp)
            if 1 <= n <= len(items):
                return items[n - 1]
        if resp in items:
            return resp
        print(f"Please answer 1-{len(items)} or paste an exact item.", file=sys.stderr)


def resolve_idempotency_conflict(entity: str, ctx: Ctx) -> str:
    """When a mutating sub-command targets an entity already in state.json, ask the
    user what to do. Returns one of "overwrite", "stop", or "custom:<text>".
    Honours ctx.yes (returns "stop" so non-interactive runs never silently overwrite).
    Non-TTY (Claude Code Bash, launchd): pops an osascript display dialog with
    Stop / Overwrite buttons; "custom" is TTY-only. No default button — a dismissal
    is Stop (fail-closed)."""
    if ctx.yes:
        log.warning("[--yes] %r already exists; stopping (use without --yes to overwrite)", entity)
        return "stop"
    if not sys.stdin.isatty():
        dialog_title = "agent-sandbox"
        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"')
        text = (
            f"'{entity}' already exists in state.json.\n\n"
            f"  • Stop — exit without changes\n"
            f"  • Overwrite — tear down the existing entity and re-run the operation"
        )
        # NO default button, deliberately. Overwrite tears down a real entity, so
        # Return must not commit either choice. Escape still dismisses, and a
        # dismissal is "stop" (fail-closed).
        osa_line = (
            f'display dialog "{_esc(text)}" '
            f'buttons {{"Stop", "Overwrite"}} '
            f'with icon caution with title "{_esc(dialog_title)}"'
        )
        proc = subprocess.run(
            ["osascript", "-e", osa_line, "-e", "button returned of result"],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            log.info("dialog dismissed for %r; stopping", entity)
            return "stop"
        return "overwrite" if proc.stdout.strip() == "Overwrite" else "stop"
    print(textwrap.dedent(f"""
        '{entity}' already exists in state.json.
          1. overwrite — tear down the existing entity and re-run the operation
          2. stop — exit without changes (default)
          3. custom — describe a different intent in free text
    """).strip(), file=sys.stderr)
    while True:
        try:
            resp = input("> ").strip().lower()
        except EOFError:
            return "stop"
        if resp in ("", "2", "stop", "s"):
            return "stop"
        if resp in ("1", "overwrite", "o"):
            return "overwrite"
        if resp in ("3", "custom", "c"):
            try:
                detail = input("describe: ").strip()
            except EOFError:
                return "stop"
            return f"custom:{detail}"
        print("Please answer 1, 2, or 3.", file=sys.stderr)


# ---------- file/system helpers ----------

def now_iso() -> str:
    """ISO 8601 UTC, second precision. datetime.utcnow() is deprecated in 3.12+."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_uuid8() -> str:
    """8 hex chars, suitable for the claude-ro-<short_uuid> role name."""
    import uuid
    return uuid.uuid4().hex[:8]


# ---------- input validators ----------
# Free strings that get interpolated into shell or stored in state.json. Validated
# at intake (e.g. provision-account) so downstream renderers can rely on the shape.

_SAFE_PROFILE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SAFE_REGION_RE = re.compile(r"^[a-z]{2,3}-[a-z]+-[0-9]+$")
_SAFE_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")


def validate_aws_profile(profile: str) -> str:
    """Reject anything that could be shell-interpolated dangerously. Profiles
    are AWS CLI section names; the AWS docs allow letters/digits/_-./. We're
    strict because this lands in the bash launcher template."""
    if not profile or not _SAFE_PROFILE_RE.match(profile):
        raise SystemExit(
            f"invalid AWS profile name: {profile!r}\n"
            "Allowed characters: letters, digits, underscore, dot, hyphen."
        )
    return profile


def validate_aws_region(region: str) -> str:
    """AWS regions follow `<area>-<location>-<n>` (e.g. us-east-1, eu-west-1)."""
    if not region or not _SAFE_REGION_RE.match(region):
        raise SystemExit(
            f"invalid AWS region: {region!r}\n"
            "Expected pattern: <area>-<location>-<n> (e.g. us-east-1)."
        )
    return region


def validate_aws_account_id(account_id: str) -> str:
    """AWS account IDs are 12 decimal digits."""
    if not _SAFE_ACCOUNT_RE.match(account_id):
        raise SystemExit(
            f"invalid AWS account ID: {account_id!r}\n"
            "Expected: 12 decimal digits."
        )
    return account_id


# github[]/mongodb[] identifiers. The `name` lands in three sensitive places: the
# launcher env selector, the per-identity helper's filename under /usr/local/bin,
# and the secret filename. Restrict hard so none of those can be traversed or
# shell-expanded.
_SAFE_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_SAFE_APP_ID_RE = re.compile(r"^[0-9]+$")
_SAFE_MONGO_HOSTS_RE = re.compile(
    r"^[A-Za-z0-9.-]+(:[0-9]{1,5})?(,[A-Za-z0-9.-]+(:[0-9]{1,5})?)*$"
)


def validate_identifier(name: str) -> str:
    """github/mongodb --name. Letters/digits/underscore/dot/hyphen, 1-40 chars,
    must start alphanumeric. Rejects path-traversal and shell-meta outright."""
    if not name or not _SAFE_IDENT_RE.match(name):
        raise SystemExit(
            f"invalid identifier: {name!r}\n"
            "Allowed: 1-40 chars, letters/digits/underscore/dot/hyphen, "
            "starting with a letter or digit."
        )
    return name


def validate_github_app_id(app_id: str) -> str:
    """GitHub App id / installation id: decimal digits only."""
    if not app_id or not _SAFE_APP_ID_RE.match(app_id):
        raise SystemExit(f"invalid GitHub numeric id: {app_id!r} (digits only).")
    return app_id


def validate_mongo_hosts(hosts: str) -> str:
    """`host[:port][,host[:port]...]`. Lands in the connection string; keep strict."""
    if not hosts or not _SAFE_MONGO_HOSTS_RE.match(hosts):
        raise SystemExit(
            f"invalid mongo hosts: {hosts!r}\n"
            "Expected host[:port] entries separated by commas, e.g. "
            "n1.example.net:27017,n2.example.net:27017."
        )
    return hosts


def validate_kube_context(ctx_name: str) -> str:
    """A kubectl context name in the ENGINEER's kubeconfig (used for the Mongo SOCKS
    tunnel). EKS contexts are often ARNs, so allow ':' '/' '@' '.' — it is always
    shlex-quoted at render, this is defence-in-depth."""
    if not ctx_name or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,199}$", ctx_name):
        raise SystemExit(f"invalid kubectl context name: {ctx_name!r}")
    return ctx_name


def validate_socks_port(port: int) -> int:
    """Local listen port for a per-session SOCKS tunnel (unprivileged range)."""
    if not isinstance(port, int) or not (1024 <= port <= 65535):
        raise SystemExit(f"invalid SOCKS port: {port!r} (expected 1024-65535)")
    return port


def resolve_kube_context(name: str) -> str:
    """Resolve a possibly-short cluster name to a full kubectl context in the ENGINEER's
    kubeconfig (for the Mongo SOCKS tunnel). Exact match wins; else a unique
    '.../cluster/<name>' or '.../<name>' suffix; else a unique substring. CLIENT-ONLY —
    reads the local kubeconfig, never contacts a cluster. Errors (listing candidates) on
    none or ambiguous, so a bad name fails at bind, not silently at launch."""
    validate_kube_context(name)
    proc = subprocess.run(["kubectl", "config", "get-contexts", "-o", "name"],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(
            "could not list kubectl contexts to resolve --via-cluster "
            f"({(proc.stderr or '').strip() or 'kubectl failed'}).")
    ctxs = [c.strip() for c in proc.stdout.splitlines() if c.strip()]
    if name in ctxs:
        return name
    for pred in (lambda c: c.endswith("/cluster/" + name),
                 lambda c: c.endswith("/" + name),
                 lambda c: name in c):
        hits = sorted({c for c in ctxs if pred(c)})
        if len(hits) == 1:
            log.info("resolved --via-cluster %r -> %s", name, hits[0])
            return hits[0]
        if len(hits) > 1:
            raise SystemExit(
                f"--via-cluster {name!r} is ambiguous; matches: {', '.join(hits)}. "
                "Use the exact context name.")
    raise SystemExit(
        f"--via-cluster {name!r} matched no kubectl context. Your contexts:\n  "
        + "\n  ".join(ctxs or ["(none)"]))


def run(cmd: list[str], *, env: dict | None = None, check: bool = True,
        capture: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    """Thin subprocess.run wrapper that logs the command and raises with stderr on failure."""
    log.debug("$ %s", " ".join(cmd))
    proc = subprocess.run(
        cmd, env=env, check=False,
        capture_output=capture, text=True,
        input=input_text,
    )
    if check and proc.returncode != 0:
        raise SystemExit(
            f"command failed (exit {proc.returncode}): {' '.join(cmd)}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


def admin_run(cmd: list[str], *, check: bool = True, capture: bool = True,
              input_text: str | None = None,
              prompt: str | None = None) -> subprocess.CompletedProcess:
    """Run cmd with admin privileges. Uses plain sudo when stdin is a TTY (so the
    user gets the familiar terminal password prompt), otherwise routes through
    `osascript -e 'do shell script ... with administrator privileges'` which pops
    a macOS Authorization Services GUI dialog. The latter works from any context —
    Claude Code's Bash tool, launchd, ssh-without-tty — and macOS caches the
    auth for ~5 minutes so a sequence of admin_run calls typically prompts once.

    `prompt`, if set, becomes the explanatory text in the auth dialog (AppleScript
    `with prompt`). Pass it on the first admin_run of a session to show the user
    WHAT they're about to authorize. Ignored in TTY mode. macOS truncates the
    prompt around ~255 characters.

    Pass cmd WITHOUT a leading `sudo` — this helper handles escalation."""
    if cmd and cmd[0] == "sudo":
        raise ValueError("admin_run: pass cmd without leading 'sudo' — escalation is handled here")
    if sys.stdin.isatty():
        return run(["sudo"] + cmd, check=check, capture=capture, input_text=input_text)
    # Build a shell-safe command line for `do shell script`. AppleScript needs
    # backslashes and double-quotes escaped inside its string literal.
    import shlex
    shell_cmd = shlex.join(cmd)
    applescript_str = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    osa_line = f'do shell script "{applescript_str}"'
    if prompt is not None:
        prompt_str = prompt.replace("\\", "\\\\").replace('"', '\\"')
        osa_line += f' with prompt "{prompt_str}"'
    osa_line += " with administrator privileges"
    osa = ["osascript", "-e", osa_line]
    log.debug("$ (admin) %s", shell_cmd)
    proc = subprocess.run(
        osa, check=False, capture_output=capture, text=True, input=input_text,
    )
    if check and proc.returncode != 0:
        raise SystemExit(
            f"admin command failed (exit {proc.returncode}): {shell_cmd}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


class AdminSessionCanceled(Exception):
    """Raised when the user dismisses the admin_session password dialog."""


class AdminSessionAuthFailed(Exception):
    """Raised when the typed password fails sudo validation after retries."""


_TTY_SENTINEL = object()
_active_admin_helper: t.Any = None  # path str | _TTY_SENTINEL | None


def _prompt_password_via_osascript(title: str, actions: list[str]) -> str | None:
    """Pop a hidden-answer dialog enumerating the privileged actions. Returns
    the typed password, or None on cancel."""
    if not actions:
        raise ValueError("admin_session requires at least one action")
    bullets = "\n".join(f"  • {a}" for a in actions)
    text = (
        f"{title}\n\n"
        f"The following actions will run as root:\n{bullets}\n\n"
        f"Enter your macOS account password:"
    )
    dialog_title = "agent-sandbox"
    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')
    osa_line = (
        f'display dialog "{esc(text)}" with hidden answer '
        f'default answer "" with icon caution with title "{esc(dialog_title)}"'
    )
    proc = subprocess.run(
        ["osascript", "-e", osa_line, "-e", "text returned of result"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        # User canceled → osascript exits 1 with "User canceled." on stderr.
        if "User canceled" in (proc.stderr or ""):
            return None
        raise SystemExit(
            f"osascript dialog failed (exit {proc.returncode}): {proc.stderr}"
        )
    return proc.stdout.rstrip("\n")


def _validate_sudo_password(pw: str) -> bool:
    """Pipe pw to `sudo -S -v`. Returns True if it authenticates."""
    proc = subprocess.run(
        ["sudo", "-S", "-v"],
        input=pw + "\n", text=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode == 0


@contextlib.contextmanager
def admin_session(title: str, actions: list[str]) -> t.Iterator[None]:
    """Single-prompt admin session.

    `title` and `actions` are shown to the user in the password dialog —
    the dialog is the user's one and only chance to approve, so every
    privileged step inside the with-block must be declared in `actions`
    up front. After the user approves once, all subsequent `admin_run_a`
    calls run silently via the askpass helper.

    Non-TTY: pops one osascript dialog enumerating `actions`, validates
    the typed password against `sudo -S -v`, caches it in a mode-600
    file inside a mode-700 temp dir, and writes a tiny askpass helper
    that `cat`s the file. `SUDO_ASKPASS` is passed per-call via env= to
    each `subprocess.run` (not via os.environ mutation).

    On exit (try/finally + atexit + SIGINT/SIGTERM): the password file is
    overwritten with random bytes, both files are unlinked, and the temp
    dir is removed.

    TTY: short-circuits — no temp files, no dialog, admin_run_a falls
    through to plain sudo and relies on sudo's own ~5min timestamp.
    """
    if not actions:
        raise ValueError("admin_session requires at least one action")
    global _active_admin_helper
    if _active_admin_helper is not None:
        raise RuntimeError("admin_session is not re-entrant")

    if sys.stdin.isatty():
        _active_admin_helper = _TTY_SENTINEL
        try:
            yield
        finally:
            _active_admin_helper = None
        return

    pw: str | None = None
    for attempt in range(3):
        candidate = _prompt_password_via_osascript(title, actions)
        if candidate is None:
            raise AdminSessionCanceled("user canceled password dialog")
        if _validate_sudo_password(candidate):
            pw = candidate
            break
        if attempt == 2:
            raise AdminSessionAuthFailed("sudo rejected the password after 3 attempts")
    assert pw is not None

    import shlex as _shlex, atexit, signal
    tmpdir = pathlib.Path(tempfile.mkdtemp(prefix="sandbox-"))
    pw_path = tmpdir / "pw"
    helper_path = tmpdir / "askpass.sh"

    def _cleanup() -> None:
        try:
            if pw_path.exists():
                size = pw_path.stat().st_size or 1
                with open(pw_path, "wb") as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
                pw_path.unlink()
        except OSError:
            pass
        try:
            if helper_path.exists():
                helper_path.unlink()
        except OSError:
            pass
        try:
            tmpdir.rmdir()
        except OSError:
            pass

    fd = os.open(pw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, pw.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    pw = None  # drop in-memory reference

    helper_content = f"#!/bin/sh\nexec /bin/cat {_shlex.quote(str(pw_path))}\n"
    fd = os.open(helper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        os.write(fd, helper_content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

    atexit.register(_cleanup)
    saved_sigint = signal.getsignal(signal.SIGINT)
    saved_sigterm = signal.getsignal(signal.SIGTERM)

    def _sig_handler(signum, frame):  # type: ignore[no-untyped-def]
        _cleanup()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    _active_admin_helper = str(helper_path)
    try:
        yield
    finally:
        _active_admin_helper = None
        try:
            signal.signal(signal.SIGINT, saved_sigint)
            signal.signal(signal.SIGTERM, saved_sigterm)
        except (ValueError, TypeError):
            pass
        try:
            atexit.unregister(_cleanup)
        except Exception:
            pass
        _cleanup()


def admin_session_active() -> bool:
    """True inside a `with admin_session(...)` block. Lets a helper that normally opens
    its own session join the caller's instead: admin_session is deliberately NOT
    re-entrant (it raises), so a helper called from both contexts has to ask. The helper
    must still be listed in the caller's `actions` — joining a session must never hide an
    action from the approval dialog."""
    return _active_admin_helper is not None


def admin_run_a(cmd: list[str], *, check: bool = True, capture: bool = True,
                input_text: str | None = None) -> subprocess.CompletedProcess:
    """Run cmd as root inside an active admin_session. One `sudo -A` subprocess
    per call; the askpass helper supplies the cached password silently, so the
    user sees no additional dialogs after admin_session's initial prompt.

    Must be called inside `with admin_session(...):` — raises RuntimeError
    otherwise. Pass cmd WITHOUT a leading `sudo`.
    """
    if cmd and cmd[0] == "sudo":
        raise ValueError("admin_run_a: pass cmd without leading 'sudo'")
    helper = _active_admin_helper
    if helper is None:
        raise RuntimeError("admin_run_a called outside admin_session")
    if helper is _TTY_SENTINEL:
        return run(["sudo"] + cmd, check=check, capture=capture, input_text=input_text)

    env = {**os.environ, "SUDO_ASKPASS": helper}
    log.debug("$ (admin_run_a) %s", " ".join(cmd))
    if input_text is not None:
        proc = subprocess.run(
            ["sudo", "-A"] + cmd,
            env=env, input=input_text, text=True,
            capture_output=capture, check=False,
        )
    else:
        proc = subprocess.run(
            ["sudo", "-A"] + cmd,
            env=env, text=True,
            stdin=subprocess.DEVNULL,
            capture_output=capture, check=False,
        )
    if check and proc.returncode != 0:
        raise SystemExit(
            f"admin command failed (exit {proc.returncode}): {' '.join(cmd)}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc


def which_one(binary: str, *, search_path: str | None = None) -> str | None:
    """Like shutil.which, but with a custom PATH for the inherited-by-claude-ro check."""
    if search_path is None:
        return shutil.which(binary)
    saved = os.environ.get("PATH")
    try:
        os.environ["PATH"] = search_path
        return shutil.which(binary)
    finally:
        if saved is None:
            del os.environ["PATH"]
        else:
            os.environ["PATH"] = saved


# ---------- credential-source broker + secret storage ----------
#
# GitHub/MongoDB identities are reached through a per-identity, argument-less mint
# helper at /usr/local/bin/claude-ro-mint-<kind>-<name> (root-owned). claude-ro may
# run exactly those helpers as the real user via a pinned per-identity sudoers
# drop-in — nothing else. The durable secret lives in a mode-600 file OUTSIDE the
# sandbox-ACL'd home, so ownership+mode is the enforcing control (a deny-ACE for
# claude-ro is a secondary layer, because on macOS ACLs outrank mode bits).

SECRETS_DIR = pathlib.Path("/usr/local/claude-ro-secrets")
BROKER_BIN_DIR = pathlib.Path("/usr/local/bin")
SUDOERS_DROPIN_DIR = pathlib.Path("/etc/sudoers.d")
BROKER_TEMPLATE = SKILL_DIR / "templates" / "claude-ro-mint.tmpl"
MONGODB_BROKER_TEMPLATE = SKILL_DIR / "templates" / "claude-ro-mint-mongodb.tmpl"
GITHUB_BROKER_TEMPLATE = SKILL_DIR / "templates" / "claude-ro-mint-github.tmpl"
SNOWFLAKE_BROKER_TEMPLATE = SKILL_DIR / "templates" / "claude-ro-mint-snowflake.tmpl"
AWS_BROKER_TEMPLATE = SKILL_DIR / "templates" / "claude-ro-mint-aws.tmpl"
TUNNEL_BROKER_TEMPLATE = SKILL_DIR / "templates" / "claude-ro-tunnel.tmpl"

# Runtime credential dir: where brokers write short-lived/working creds as FILES that
# claude-ro reads directly (so values never transit stdout / the model). Mirror image
# of SECRETS_DIR — engineer-owned, but with an INHERITED *allow*-read ACE for claude-ro
# (SECRETS_DIR carries a deny-ACE). Distinct from SECRETS_DIR: durable secrets vs the
# working creds derived from them.
RUNTIME_DIR = pathlib.Path("/usr/local/claude-ro-runtime")

# Stable indirection to the skill's real location. Everything we RENDER into a
# file that outlives this process — the brokers, the tunnel helper, the lockdown
# plist — references the skill through this symlink instead of SKILL_DIR, so the
# skill's own path is never copied into an installed artifact. Renaming the
# plugin, bumping its version, or moving between a personal-skill and a plugin
# install then only has to repoint one link (refresh-settings does this) rather
# than re-render every consumer.
#
# Safe to dereference from a root-run helper: /usr/local is root:wheel 0755, so
# the link itself is not user-writable. Its TARGET is user-owned, but that is
# exactly what the absolute path pointed at before — no boundary changes.
SKILL_LINK = pathlib.Path("/usr/local/claude-ro-skill")
SKILL_SCRIPTS_LINK = SKILL_LINK / "scripts"
# aws writes two files per account here: <account_id>.credentials and
# <account_id>.kubeconfig (the per-account minter's output). tunnel holds one
# <cluster-label>.pid per active SOCKS port-forward, so the launcher can kill it on
# session exit. snowflake writes one <name>.json per bound record, holding the signed
# short-lived JWT plus the non-secret connection values.
_RUNTIME_KINDS = ("github", "mongodb", "aws", "tunnel", "snowflake")

# Discoverability: a non-secret capability note + a SessionStart hook in claude-ro's
# Claude Code settings, so CC learns the brokers exist each session (CLAUDE.md gets
# ignored; a SessionStart hook is re-asserted every session).
CAPABILITY_SCRIPT_PATH = pathlib.Path("/usr/local/bin/claude-ro-capabilities")
CLAUDE_RO_SETTINGS = pathlib.Path("/Users/claude-ro/.claude/settings.json")


def current_username() -> str:
    """The real (invoking) user — the runas target for the broker sudoers rule and
    the owner of the secret files. Prefers the recorded state username, falls back
    to $USER/$LOGNAME."""
    try:
        u = (_state_read_unlocked().get("user") or {}).get("username")
        if u:
            return u
    except Exception:  # noqa: BLE001 — state may not exist yet
        pass
    u = os.environ.get("USER") or os.environ.get("LOGNAME")
    if not u:
        raise SystemExit("could not determine the real username ($USER unset).")
    return u


def broker_helper_name(kind: str, name: str | None = None) -> str:
    """/usr/local/bin filename for a broker helper. `kind` in {github,mongodb,aws,tunnel}.
    `name` is a validated identifier for a per-identity helper (github: one per org;
    aws: one per account, name=account_id; tunnel: one per cluster, name=cluster label);
    `name=None` is the singleton helper `claude-ro-mint-<kind>` (mongodb: one shared
    helper for ALL bound DBs; snowflake likewise).

    tunnel helpers are named `claude-ro-tunnel-<label>` (not `claude-ro-mint-…`) — they
    stand up a SOCKS tunnel rather than mint a credential."""
    if kind not in ("github", "mongodb", "aws", "tunnel", "snowflake"):
        raise ValueError(f"unknown broker kind: {kind!r}")
    if kind == "tunnel":
        validate_identifier(name)  # tunnel is always per-cluster (name required)
        return f"claude-ro-tunnel-{name}"
    if name is None:
        return f"claude-ro-mint-{kind}"
    validate_identifier(name)
    return f"claude-ro-mint-{kind}-{name}"


def broker_helper_path(kind: str, name: str | None = None) -> pathlib.Path:
    return BROKER_BIN_DIR / broker_helper_name(kind, name)


def broker_sudoers_path(kind: str, name: str | None = None) -> pathlib.Path:
    return SUDOERS_DROPIN_DIR / broker_helper_name(kind, name)


def _secret_path(secret_ref: str) -> pathlib.Path:
    """Resolve a secret_ref (a bare filename) to its absolute path, rejecting any
    path separators so a crafted ref can't escape SECRETS_DIR."""
    if not secret_ref or "/" in secret_ref or secret_ref in (".", ".."):
        raise SystemExit(f"invalid secret_ref: {secret_ref!r}")
    return SECRETS_DIR / secret_ref


def _deny_ace(path: pathlib.Path) -> None:
    """Best-effort secondary deny-ACE for claude-ro. Non-fatal: ownership+mode is
    the primary control, so a chmod-ACL hiccup must not break bind."""
    proc = subprocess.run(
        ["chmod", "+a",
         "claude-ro deny read,write,execute,delete,append,search,"
         "readattr,readextattr,readsecurity,list,add_file,add_subdirectory,delete_child",
         str(path)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        log.warning("could not apply deny-ACE on %s (ownership+mode still enforce): %s",
                    path, (proc.stderr or "").strip())


def _allow_ace(path: pathlib.Path) -> None:
    """Grant claude-ro read+traverse via an INHERITED allow-ACE (mirror of _deny_ace).
    Inheritable so files a broker later writes here are claude-ro-readable despite
    mode 600. Non-fatal: warn on failure."""
    proc = subprocess.run(
        ["chmod", "+a",
         "claude-ro allow read,execute,readattr,readextattr,readsecurity,list,search,"
         "file_inherit,directory_inherit",
         str(path)],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        log.warning("could not apply allow-ACE on %s: %s", path, (proc.stderr or "").strip())


def ensure_secrets_dir(*, ctx: Ctx | None = None) -> None:
    """Create SECRETS_DIR (mode 700, owned by the real user) outside the sandbox
    home, with a secondary deny-ACE for claude-ro. Idempotent. Requires an active
    admin_session (uses admin_run_a)."""
    user = current_username()
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would ensure secrets dir %s (700, %s)", SECRETS_DIR, user)
        return
    admin_run_a(["install", "-d", "-m", "700", "-o", user, "-g", "staff",
                 str(SECRETS_DIR)])
    _deny_ace(SECRETS_DIR)
    log.info("ensured secrets dir %s (owner %s, 700 + deny-ACE)", SECRETS_DIR, user)


def ensure_skill_symlink(*, ctx: Ctx | None = None) -> None:
    """Point SKILL_LINK at this skill's real directory, root-owned. Idempotent —
    re-running repoints an existing link rather than failing, which is what makes
    it the repair path after a rename, a version bump, or a move between a
    personal-skill and a plugin install. Requires an active admin_session.

    Must run BEFORE anything that renders SKILL_SCRIPTS_LINK into an installed
    file, otherwise those files reference a link that does not exist yet."""
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would symlink %s → %s", SKILL_LINK, SKILL_DIR)
        return
    # -n so an existing symlink-to-dir is replaced rather than followed (which
    # would drop the new link INSIDE the old target). -f to replace atomically.
    admin_run_a(["ln", "-sfn", str(SKILL_DIR), str(SKILL_LINK)])
    log.info("symlinked %s → %s", SKILL_LINK, SKILL_DIR)


def ensure_runtime_dir(*, ctx: Ctx | None = None) -> None:
    """Create RUNTIME_DIR + per-kind subdirs (700, real-user-owned) with an inherited
    allow-read ACE for claude-ro, so brokers can write mode-600 cred files there that
    claude-ro reads directly. Idempotent. Requires an active admin_session."""
    user = current_username()
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would ensure runtime dir %s (700, %s, +claude-ro allow-read)",
                 RUNTIME_DIR, user)
        return
    admin_run_a(["install", "-d", "-m", "700", "-o", user, "-g", "staff", str(RUNTIME_DIR)])
    _allow_ace(RUNTIME_DIR)  # apply BEFORE creating subdirs so they inherit it
    for kind in _RUNTIME_KINDS:
        admin_run_a(["install", "-d", "-m", "700", "-o", user, "-g", "staff",
                     str(RUNTIME_DIR / kind)])
    log.info("ensured runtime dir %s (owner %s, 700 + inherited claude-ro allow-read)",
             RUNTIME_DIR, user)


_CAP_SCRIPT = r'''#!/bin/sh
# claude-ro capabilities (agent-sandbox). Printed at SessionStart. Lists
# ONLY the brokers that are installed (a broker exists iff that access is bound), so
# it never advertises an unbound provider. Do NOT edit by hand.
found=0
if [ -x /usr/local/bin/claude-ro-mint-github ]; then
  found=1
  cat <<'GH'

GitHub (read-only, all installed orgs at once):
  sudo -u __USER__ /usr/local/bin/claude-ro-mint-github
    -> writes /usr/local/claude-ro-runtime/github/<org>.token per org (prints '<org> <path>').
  gh / REST:  GH_TOKEN=$(cat /usr/local/claude-ro-runtime/github/<org>.token) gh ...
  git:        transparent (the credential helper reads the file for the repo's org).
GH
fi
if [ -x /usr/local/bin/claude-ro-mint-mongodb ]; then
  found=1
  cat <<'MG'

MongoDB (read-only):
  Non-tunneled DBs:  sudo -u __USER__ /usr/local/bin/claude-ro-mint-mongodb
  Tunneled DBs: start the cluster's tunnel first (see below), then pass its port:
                     sudo -u __USER__ /usr/local/bin/claude-ro-mint-mongodb <port>
    -> writes /usr/local/claude-ro-runtime/mongodb/<name>.uri per DB (prints '<name> <path>').
  mongosh "$(cat /usr/local/claude-ro-runtime/mongodb/<name>.uri)"
  AWS-IAM Atlas DBs (its .uri shows authMechanism=MONGODB-AWS): no password — auth is your
  minted RO creds. Mint that account first, then point the driver at those creds:
    sudo -u __USER__ /usr/local/bin/claude-ro-mint-aws-<account>
    AWS_SHARED_CREDENTIALS_FILE=/usr/local/claude-ro-runtime/aws/<account>.credentials \
      mongosh "$(cat /usr/local/claude-ro-runtime/mongodb/<name>.uri)"
MG
fi
if [ -x /usr/local/bin/claude-ro-mint-snowflake ]; then
  found=1
  cat <<'SF'

Snowflake (read-only role, short-lived JWT):
  sudo -u __USER__ /usr/local/bin/claude-ro-mint-snowflake
    -> writes /usr/local/claude-ro-runtime/snowflake/<name>.json per account (prints '<name> <path>').
  That JSON holds token (a JWT) and token_type KEYPAIR_JWT, plus the non-secret host,
  user, role, warehouse.
  POST https://<host>/api/v2/statements with headers
    Authorization: Bearer <token>
    X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT
  and a body that MUST include "role": "<the role from that JSON>" — the key is registered
  with ROLE_RESTRICTION, so the role requested in the JWT has to match it.
  snowflake-connector-python will NOT work: it derives its own JWT from a private key this
  sandbox does not have.
  The credential cannot select another role, but the session still inherits whatever the
  PUBLIC pseudo-role holds account-wide — PUBLIC is granted to every user and every role.
  The token expires in under an hour: re-run the broker for a fresh one, do NOT cache it.
SF
fi
for b in /usr/local/bin/claude-ro-mint-aws-*; do
  [ -x "$b" ] || continue
  found=1
  acct=${b##*/claude-ro-mint-aws-}
  cat <<AWS

AWS account $acct (read-only, short-lived; on-demand, optional region arg):
  sudo -u __USER__ $b [region]
    -> writes /usr/local/claude-ro-runtime/aws/$acct.credentials and .kubeconfig (prints their paths).
  aws:     AWS_SHARED_CREDENTIALS_FILE=/usr/local/claude-ro-runtime/aws/$acct.credentials AWS_DEFAULT_REGION=<region> aws ...
  kubectl: KUBECONFIG=/usr/local/claude-ro-runtime/aws/$acct.kubeconfig kubectl ...
  Re-run the minter if a call returns ExpiredToken; k8s rides on the same creds.

  KUBERNETES RULES — both are mandatory, and both exist because of real incidents:

  1. ALWAYS pass --context. NEVER rely on the current context; there isn't one. This
     account's kubeconfig deliberately sets no current-context, so a command without
     --context reaches NO cluster: kubectl falls back to its built-in
     http://localhost:8080 default and fails with 'connection refused'. Seeing
     localhost:8080 in an error means you FORGOT --context -- it is never a VPN or
     cluster problem. That design is intentional: several clusters share this
     kubeconfig, production among them, and a default would silently send an
     unqualified command to whichever sorted first. List them with
       KUBECONFIG=... kubectl config get-contexts -o name
     and name one explicitly on EVERY command. Never infer the target from a previous
     command, and never say a context is 'already current' — none is.

  2. CHECK CONNECTIVITY FIRST, per context, before any other cluster command:
       kubectl --context <ctx> --request-timeout=10s get --raw /readyz     # prints: ok
     The cluster endpoints are VPN-gated while the EKS control-plane API is not, so
     minting credentials can SUCCEED while every cluster command hangs. This probe is
     trivial and must answer in well under 10s: 'ok' means proceed, anything else --
     timeout, i/o timeout, connection refused -- means CONNECTIVITY, not an empty
     cluster. Stop and report it. Do not retry, do not fall back to a broader query, and
     never read a timeout as 'no resources found'. Re-run the probe after any cluster
     command fails oddly; a VPN can drop mid-session. One error is NOT connectivity: a
     refusal naming localhost:8080 is rule 1 -- a missing --context -- so fix the command
     rather than reporting the cluster unreachable.
AWS
done
for t in /usr/local/bin/claude-ro-tunnel-*; do
  [ -x "$t" ] || continue
  found=1
  cl=${t##*/claude-ro-tunnel-}
  cat <<TUN

Mongo SOCKS tunnel for cluster $cl (engineer-run, per-session; needed BEFORE Mongo DBs reached via this cluster):
  PORT=\$(sudo -u __USER__ $t "\$CLAUDE_RO_SESSION" | awk '{print \$2}')
    -> starts a per-session tunnel on a free port and prints '<cluster> <port>'.
  Then mint with that port:  sudo -u __USER__ /usr/local/bin/claude-ro-mint-mongodb "\$PORT"
  If a Mongo call fails (tunnel dropped), re-run with the SAME port: sudo -u __USER__ $t "\$CLAUDE_RO_SESSION" "\$PORT"
TUN
done
if [ "$found" = 1 ]; then
  printf '\nCredentials are delivered as FILES — read them from disk; never print a token, URI, or key.\n'
fi
'''


def _capability_script_text() -> str:
    """The SessionStart capabilities script, with the real runas user baked in."""
    return _CAP_SCRIPT.replace("__USER__", current_username())


# --- auto-mode classifier config -------------------------------------------
# Claude Code's auto mode judges each tool call with an LLM classifier that sees only the
# command string and the transcript. It has no tools and cannot read a broker script to
# learn that the script is pinned, argument-proof, and read-only. Told nothing, it blocks
# ordinary sandbox work on shape alone: the mint helpers look like credential
# materialization, and a cluster whose name carries `prod` matches its sensitive-target
# heuristic. Worse, its shipped Environment defaults assert "Cloud provider(s): None
# configured" and "no additional orgs configured" — false here, and actively against us,
# since every bound provider then reads as somewhere untrusted.
#
# So we restate those Environment lines from state, and add ALLOW rules describing the
# brokers. Everything derives from state: an unbound provider contributes nothing, and the
# generated block shrinks when you unbind. Auto-mode rules are honoured only from USER
# settings — Claude Code parses and discards them in project/local settings as
# repo-controllable.

_AM_IDENTITY = (
    "**Sandbox identity**: this account (`{ro_user}`) has no write capability of its own, "
    "enforced outside the agent: AWS is an assumed role with ReadOnlyAccess plus targeted "
    "denies, Kubernetes is view-only RBAC via cluster access entries, GitHub is a read-only "
    "App installation token, MongoDB is a read-only DB user, Snowflake is a read-only role. "
    "Direct mutation is refused by the provider, not by the agent's judgment.{tunnel_caveat}"
)
_AM_TUNNEL_CAVEAT = (
    " The one exception is the tunnel broker described in the ALLOW rules, which is bounded "
    "and separately authorized."
)
_AM_CREDS = (
    "**Credential delivery**: short-lived credentials here arrive as mode-600 files under "
    "`{runtime_dir}`, written by pinned brokers. Reading one into the consuming command's "
    "environment is the intended path — it exists so secret values never enter the "
    "transcript. Printing a credential's contents to stdout remains blocked."
)
_AM_MINT_RULE = (
    "Pinned Credential Brokers: `sudo -u {user} {bin_dir}/claude-ro-mint-*` are credential "
    "brokers installed by the agent-sandbox skill, each reached through a sudoers "
    "rule pinned to that exact path. Argv is either ignored entirely (github) or validated "
    "against a fixed set — an AWS region, a SOCKS port — with anything further refused. They "
    "read durable secrets the sandbox account cannot read, mint short-lived READ-ONLY "
    "credentials, write them to mode-600 files, and print only non-secret metadata (names "
    "and paths) to stdout. Invoking one, and reading the file it names, is not Credential "
    "Materialization, Credential Exploration, or Auto-Mode Bypass."
)
_AM_TUNNEL_RULE = (
    "Pinned Tunnel Broker: `sudo -u {user} {bin_dir}/claude-ro-tunnel-<cluster>` is a "
    "per-cluster broker whose target cluster is compiled into the script at bind time — it "
    "is NOT an argument. Its only arguments are a session id and an optional port, both "
    "validated. It creates a Deployment named `claude-ro-socks-<port>` running a SOCKS5 "
    "proxy in that cluster and port-forwards to it, using the engineer's cluster-admin "
    "credentials, because the sandbox identity deliberately holds no cluster write. This IS "
    "a cluster write against {clusters}, and the user has given standing consent for this "
    "specific bounded action: the agent cannot choose the cluster, the namespace, the image, "
    "or the workload shape, and the tunnel exists solely as a network path to MongoDB "
    "databases with no public endpoint. Treat it as authorized for Shared Cluster Mutation "
    "and Modify Shared Resources. It opens no interactive shell — `kubectl exec`, `attach`, "
    "and bare-shell payloads against the same cluster remain blocked."
)


def _auto_mode_config(state: dict) -> tuple[list[str], list[str], list[str]]:
    """Build (bash allow rules, Environment entries, ALLOW rules) for what is CURRENTLY
    bound. Every entry derives from state — an unbound provider contributes nothing."""
    user = current_username()
    ro_user = state.get("macos_user") or "claude-ro"
    bin_dir = str(BROKER_BIN_DIR)

    def sudo(kind: str, name: str | None = None, *, takes_arg: bool) -> str:
        # `Bash(cmd)` is an exact match; `Bash(cmd:*)` is a prefix match allowing the
        # optional trailing argument. Paths come from the same helper that installs them.
        path = broker_helper_path(kind, name)
        return f"Bash(sudo -u {user} {path}{':*' if takes_arg else ''})"

    accounts = state.get("accounts") or []
    orgs = state.get("github") or []
    dbs = state.get("mongodb") or []
    snowflakes = state.get("snowflake") or []
    tunnels = sorted({r["via_cluster"] for r in dbs if r.get("via_cluster")})
    tunnel_labels = [tunnel_cluster_label(arn) for arn in tunnels]

    bash_allow: list[str] = []
    if orgs:
        bash_allow.append(sudo("github", takes_arg=False))       # argless: ignores argv
    if dbs:
        bash_allow.append(sudo("mongodb", takes_arg=True))       # optional SOCKS port
    if snowflakes:
        bash_allow.append(sudo("snowflake", takes_arg=False))    # argless: takes no argv
    for account in accounts:
        bash_allow.append(sudo("aws", account["account_id"], takes_arg=True))  # optional region
    for label in tunnel_labels:
        bash_allow.append(sudo("tunnel", label, takes_arg=True))  # session id [+ port]

    if not bash_allow:
        return [], [], []  # nothing bound — say nothing

    # Environment entries. Each of the first four RESTATES a shipped default that is false
    # once the corresponding provider is bound; without them the classifier reads "None
    # configured" and treats bound infrastructure as untrusted.
    environment: list[str] = []
    if accounts:
        environment.append(
            "**Cloud provider(s)**: AWS — " + ", ".join(
                f"account {a['account_id']} (default region {a.get('default_region', 'unset')})"
                for a in accounts
            ) + ". Reached only by assuming that account's read-only role; the sandbox holds "
            "no long-lived AWS key and no write permission.")
    if orgs:
        environment.append(
            "**Source control**: the trusted repo and its remote(s), plus GitHub " + ", ".join(
                f"{o.get('account_type', 'org')} `{o['login']}`" for o in orgs
            ) + " — reached with a read-only App installation token scoped to that "
            "installation. Repositories under these owners are inside the trust boundary "
            "for reads; the token cannot write, and pushes are unaffected by this entry.")
    clusters = [(c, a) for a in accounts for c in (a.get("clusters") or [])]
    if clusters:
        environment.append(
            "**Sensitive remote targets**: " + ", ".join(
                f"`{c['cluster_name']}` (EKS, {c['region']}, account {a['account_id']})"
                for c, a in clusters
            ) + " — bound to this sandbox and reachable by it ONLY through view-only "
            "Kubernetes RBAC. A `prod` in one of these names does not imply the sandbox can "
            "change it. Non-interactive read verbs against them are ordinary work here. "
            "Interactive channels — `kubectl exec -it`, `attach`, bare shells — remain "
            "sensitive regardless: they are opaque to this classifier.")
    if dbs:
        environment.append(
            "**MongoDB**: " + ", ".join(
                f"`{d['name']}`" + (" (via the cluster tunnel)" if d.get("via_cluster") else "")
                for d in dbs
            ) + " — each reached with a read-only database user. Queries against them are "
            "ordinary work here, not Production Reads: the credential cannot write, drop, or "
            "modify. Returned documents are still data — apply the sensitivity rules to "
            "anything read out of them.")
    if snowflakes:
        environment.append(
            "**Snowflake**: " + ", ".join(f"`{s['name']}`" for s in snowflakes)
            + " — each reached with a read-only role, through a short-lived JWT signed "
            "locally by a pinned broker and written to a file. Queries against them are "
            "ordinary work here, not Production Reads: the role cannot write, drop, or "
            "modify. Returned rows are still data — apply the sensitivity rules to "
            "anything read out of them.")
    environment.append(_AM_IDENTITY.format(
        ro_user=ro_user, tunnel_caveat=_AM_TUNNEL_CAVEAT if tunnel_labels else ""))
    environment.append(_AM_CREDS.format(runtime_dir=str(RUNTIME_DIR)))

    allow = [_AM_MINT_RULE.format(user=user, bin_dir=bin_dir)]
    if tunnel_labels:
        allow.append(_AM_TUNNEL_RULE.format(
            user=user, bin_dir=bin_dir,
            clusters=", ".join(f"`{lbl}`" for lbl in tunnel_labels)))
    return bash_allow, environment, allow


def _merge_auto_mode(settings: dict, state: dict) -> None:
    """Merge the generated auto-mode config into `settings` in place. The generated
    entries are OWNED by this skill and rewritten wholesale on every run (like the brokers
    themselves) — hand edits to them do not survive a re-bind. Bash allow rules the user
    added for anything else are preserved."""
    bash_allow, environment, allow = _auto_mode_config(state)

    perms = settings.setdefault("permissions", {})
    ours = f"Bash(sudo -u {current_username()} {BROKER_BIN_DIR}/claude-ro-"
    kept = [r for r in (perms.get("allow") or []) if not r.startswith(ours)]
    if kept or bash_allow:
        perms["allow"] = kept + bash_allow
    else:
        perms.pop("allow", None)
    if not perms:
        settings.pop("permissions", None)

    if environment or allow:
        # "$defaults" inherits Claude Code's built-in entries at that position; ours follow,
        # so a restated Environment line is read after the default it corrects.
        settings["autoMode"] = {"environment": ["$defaults", *environment],
                                "allow": ["$defaults", *allow]}
    else:
        settings.pop("autoMode", None)


def install_capability_note(*, ctx: Ctx | None = None) -> None:
    """Install a SessionStart capabilities note in claude-ro's Claude Code settings so CC
    discovers the brokers each session, plus the auto-mode classifier rules that stop it
    blocking them (see _auto_mode_config). Both describe ONLY what is bound — never an
    unbound provider. Idempotent + non-destructive (merges into settings.json, preserving
    other keys). Requires an active admin_session."""
    cmd = str(CAPABILITY_SCRIPT_PATH)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would install %s + claude-ro SessionStart hook", cmd)
        return
    # 1. Capabilities script: root-owned, world-executable (non-secret).
    admin_run_a(["tee", str(CAPABILITY_SCRIPT_PATH)], input_text=_capability_script_text())
    admin_run_a(["chmod", "755", str(CAPABILITY_SCRIPT_PATH)])
    admin_run_a(["chown", "root:wheel", str(CAPABILITY_SCRIPT_PATH)])
    # 2. Merge a SessionStart hook into claude-ro's settings.json (read+write AS
    #    claude-ro so we neither need nor grant extra access, and never clobber other
    #    settings). Add our entry only if absent.
    admin_run_a(["install", "-d", "-m", "755", "-o", "claude-ro", "-g", "staff",
                 str(CLAUDE_RO_SETTINGS.parent)])
    proc = admin_run_a(["-u", "claude-ro", "cat", str(CLAUDE_RO_SETTINGS)], check=False)
    try:
        settings = (json.loads(proc.stdout)
                    if proc.returncode == 0 and (proc.stdout or "").strip() else {})
    except json.JSONDecodeError:
        log.warning("claude-ro settings.json is not valid JSON — skipping SessionStart hook")
        return
    before = json.dumps(settings, sort_keys=True)
    sess = settings.setdefault("hooks", {}).setdefault("SessionStart", [])
    present = any(
        h.get("command") == cmd
        for entry in sess if isinstance(entry, dict)
        for h in (entry.get("hooks") or []) if isinstance(h, dict)
    )
    if not present:
        sess.append({"hooks": [{"type": "command", "command": cmd}]})
    # 3. Auto-mode rules are refreshed on EVERY call, not only the first: a later bind adds
    #    a provider the classifier has to be told about, and an unbind has to remove it.
    #    Diffing the whole document keeps the write idempotent without an early return.
    _merge_auto_mode(settings, state_read())
    if json.dumps(settings, sort_keys=True) == before:
        log.info("claude-ro SessionStart hook + auto-mode rules already current")
        return
    admin_run_a(["-u", "claude-ro", "tee", str(CLAUDE_RO_SETTINGS)],
                input_text=json.dumps(settings, indent=2) + "\n")
    log.info("installed claude-ro SessionStart capability hook + auto-mode classifier rules")


def secret_store(secret_ref: str, content: str, *, ctx: Ctx | None = None) -> None:
    """Write `content` to SECRETS_DIR/<secret_ref>, mode 600, owned by the real user
    (who runs this). No admin needed — the dir is user-owned. Applies a deny-ACE."""
    path = _secret_path(secret_ref)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would store secret %s (600)", path)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    _deny_ace(path)
    log.info("stored secret %s (600)", path)


def secret_read(secret_ref: str) -> str:
    """Read a stored secret. Used by bind (probe) and the broker helper (mint)."""
    path = _secret_path(secret_ref)
    if not path.exists():
        raise SystemExit(
            f"secret file missing: {path}\n"
            "Re-run the matching bind-github / bind-mongodb command."
        )
    return path.read_text()


def secret_delete(secret_ref: str, *, ctx: Ctx | None = None) -> None:
    """Remove a stored secret (unbind). Idempotent."""
    path = _secret_path(secret_ref)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would delete secret %s", path)
        return
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    log.info("deleted secret %s", path)


def runtime_cred_path(kind: str, name: str) -> pathlib.Path:
    """Absolute path for a runtime credential file, rejecting traversal in `name`.
    `kind` in {github, mongodb}."""
    if kind not in _RUNTIME_KINDS:
        raise ValueError(f"unknown runtime kind: {kind!r}")
    if not name or "/" in name or name in (".", ".."):
        raise SystemExit(f"invalid runtime cred name: {name!r}")
    return RUNTIME_DIR / kind / name


def write_runtime_cred(kind: str, name: str, content: str) -> pathlib.Path:
    """Write a runtime credential file, mode 600, and return its path. STDLIB ONLY
    (broker hot path). The dir's inherited allow-ACE grants claude-ro read."""
    path = runtime_cred_path(kind, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return path


def read_runtime_cred(kind: str, name: str) -> str | None:
    """Read a runtime credential/metadata file, or None if absent. STDLIB ONLY."""
    path = runtime_cred_path(kind, name)
    try:
        return path.read_text()
    except FileNotFoundError:
        return None


def install_broker_helper(kind: str, name: str | None, rendered: str, *,
                          ctx: Ctx | None = None) -> None:
    """Write a mint helper to /usr/local/bin (root:wheel, 755) so claude-ro cannot
    rewrite it. `name=None` installs the singleton `claude-ro-mint-<kind>`. Requires
    an active admin_session."""
    path = broker_helper_path(kind, name)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would install broker helper %s", path)
        return
    admin_run_a(["tee", str(path)], input_text=rendered)
    admin_run_a(["chmod", "755", str(path)])
    admin_run_a(["chown", "root:wheel", str(path)])
    log.info("installed broker helper %s", path)


def remove_broker_helper(kind: str, name: str | None = None, *, ctx: Ctx | None = None) -> None:
    path = broker_helper_path(kind, name)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would remove broker helper %s", path)
        return
    admin_run_a(["rm", "-f", str(path)])
    log.info("removed broker helper %s", path)


def install_broker_sudoers(kind: str, name: str | None, *, ctx: Ctx | None = None,
                           allow_arg: bool = False) -> None:
    """Install a pinned sudoers drop-in letting claude-ro run exactly this one helper
    as the real user. `name=None` pins the singleton `claude-ro-mint-<kind>`.
    visudo-validated, mode 440 root:wheel. Requires an active admin_session.

    `allow_arg`: also pin a second rule allowing trailing arguments (aws region;
    tunnel session-id + port; mongo port). The helper itself strictly validates those
    arguments (allow-listed region / integer port / digit session-id) and ignores
    anything else, and the account/role/cluster stay hardcoded in the helper — so this
    is a bounded relaxation of the zero-argument pin, not a blank `helper *` that could
    smuggle a different action."""
    user = current_username()
    validate_aws_profile(user)  # reuse the strict safe-name check for the runas user
    helper = broker_helper_path(kind, name)
    dropin = broker_sudoers_path(kind, name)
    lines = [f"claude-ro ALL=({user}) NOPASSWD: {helper}\n"]
    if allow_arg:
        lines.append(f"claude-ro ALL=({user}) NOPASSWD: {helper} *\n")
    line = "".join(lines)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would install sudoers drop-in %s: %s",
                 dropin, " | ".join(x.strip() for x in lines))
        return
    with tempfile.NamedTemporaryFile("w", suffix=".sudoers", delete=False) as f:
        f.write(line)
        tmp = f.name
    try:
        proc = admin_run_a(["visudo", "-c", "-f", tmp], check=False)
        if proc.returncode != 0:
            raise SystemExit(f"sudoers validation failed for {dropin}: {proc.stderr}")
        admin_run_a(["install", "-m", "440", "-o", "root", "-g", "wheel",
                     tmp, str(dropin)])
    finally:
        os.unlink(tmp)
    log.info("installed sudoers drop-in %s", dropin)


def remove_broker_sudoers(kind: str, name: str | None = None, *, ctx: Ctx | None = None) -> None:
    dropin = broker_sudoers_path(kind, name)
    if ctx is not None and ctx.dry_run:
        log.info("[dry-run] would remove sudoers drop-in %s", dropin)
        return
    admin_run_a(["rm", "-f", str(dropin)])
    log.info("removed sudoers drop-in %s", dropin)


def render_broker_helper(kind: str, name: str, secret_ref: str) -> str:
    """Render templates/claude-ro-mint.tmpl for one identity. The helper is
    argument-less: kind/name/secret_ref are baked in at render time."""
    template = BROKER_TEMPLATE.read_text()
    scripts_dir = str(SKILL_SCRIPTS_LINK)
    # All substituted values are validated identifiers / a bare filename / a fixed
    # path, so no shell-meta reaches the rendered helper.
    validate_identifier(name)
    if kind not in ("github", "mongodb"):
        raise ValueError(f"unknown broker kind: {kind!r}")
    _secret_path(secret_ref)  # reject traversal in secret_ref
    out = template
    for k, v in {
        "KIND": kind,
        "NAME": name,
        "SECRET_REF": secret_ref,
        "SKILL_SCRIPTS_DIR": scripts_dir,
        "PYTHON": sys.executable,
    }.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def render_mongodb_broker() -> str:
    """Render templates/claude-ro-mint-mongodb.tmpl — the SINGLE shared, argument-less
    helper that mints a URI for every bound DB. Content is identity-independent (it
    reads mongodb[] from state at run time), so it is the same for any set of DBs."""
    template = MONGODB_BROKER_TEMPLATE.read_text()
    out = template
    for k, v in {
        "SKILL_SCRIPTS_DIR": str(SKILL_SCRIPTS_LINK),
        "PYTHON": sys.executable,
    }.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def render_snowflake_broker() -> str:
    """Render templates/claude-ro-mint-snowflake.tmpl — the SINGLE shared, argument-less
    helper that signs a short-lived JWT for every bound record and writes each to
    runtime/snowflake/<name>.json. Content is identity-independent (it reads snowflake[]
    from state at run time)."""
    template = SNOWFLAKE_BROKER_TEMPLATE.read_text()
    out = template
    for k, v in {
        "SKILL_SCRIPTS_DIR": str(SKILL_SCRIPTS_LINK),
        "PYTHON": sys.executable,
    }.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def render_github_broker() -> str:
    """Render templates/claude-ro-mint-github.tmpl — the SINGLE shared, argument-less
    helper that mints a token for EVERY bound org and writes each to
    runtime/github/<org>.token. Content is identity-independent (it reads the github[]
    records at run time)."""
    template = GITHUB_BROKER_TEMPLATE.read_text()
    out = template
    for k, v in {
        "SKILL_SCRIPTS_DIR": str(SKILL_SCRIPTS_LINK),
        "PYTHON": sys.executable,
    }.items():
        out = out.replace("{{" + k + "}}", v)
    return out


_SAFE_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_./+=,@-]+$")


def render_aws_broker(record: dict) -> str:
    """Render templates/claude-ro-mint-aws.tmpl for ONE account. Per-account and
    on-demand: account_id / role / profile / default-region are baked in, so nothing
    claude-ro passes can change WHICH account or role it mints — only the (allow-listed)
    region argument. All substituted values are validated first."""
    template = AWS_BROKER_TEMPLATE.read_text()
    account_id = validate_aws_account_id(record["account_id"])
    role_arn = record["ro_role_arn"]
    validate_aws_profile(record["assumer_profile"])
    region = validate_aws_region(record["default_region"])
    if not _SAFE_ROLE_ARN_RE.match(role_arn):
        raise SystemExit(f"refusing to bake suspicious role ARN into broker: {role_arn!r}")
    out = template
    for k, v in {
        "ACCOUNT_ID": account_id,
        "DEFAULT_REGION": region,
        "SKILL_SCRIPTS_DIR": str(SKILL_SCRIPTS_LINK),
        "PYTHON": sys.executable,
    }.items():
        out = out.replace("{{" + k + "}}", v)
    return out


def sanitize_eks_region(region: str) -> str:
    """Validate a caller-supplied region for the AWS minter. The account/role are
    hardcoded in the broker, so the region is the ONLY thing argv can influence — gate
    it hard: first the region-name format, then membership in the real EKS region set
    (botocore's bundled endpoint data — no network). Rejects anything else."""
    validate_aws_region(region)  # format gate
    boto3 = _ensure_boto3()
    available = set(boto3.Session().get_available_regions("eks"))
    if available and region not in available:
        raise SystemExit(
            f"region {region!r} is not a known AWS EKS region.\n"
            "Pass a valid region (e.g. eu-west-1), or omit it for the account default."
        )
    return region


def aws_account_record(account_id: str) -> dict:
    """Return the accounts[] record for `account_id` from state.json, or exit. Used by
    the per-account AWS minter (stdlib-only state read)."""
    validate_aws_account_id(account_id)
    state = state_read()
    rec = next((a for a in state.get("accounts") or []
                if a.get("account_id") == account_id), None)
    if rec is None:
        raise SystemExit(
            f"no AWS account {account_id!r} in state.json — re-run provision-account.")
    return rec


_EKS_ARN_RE = re.compile(r"^arn:aws:eks:([a-z0-9-]+):([0-9]{12}):cluster/(.+)$")


def parse_eks_arn(arn: str) -> tuple[str, str, str]:
    """Split an EKS cluster ARN into (account_id, region, cluster_name), or exit.
    A Mongo DB's via_cluster must be an EKS ARN so the tunnel broker can map it to a
    provisioned account (and that account's assumer_profile)."""
    m = _EKS_ARN_RE.match(arn)
    if not m:
        raise SystemExit(
            f"not an EKS cluster ARN: {arn!r}\n"
            "Expected arn:aws:eks:<region>:<account>:cluster/<name> — the tunnel needs "
            "the account to pick its assumer profile. Alias contexts aren't supported.")
    region, account, name = m.group(1), m.group(2), m.group(3)
    return account, region, name


def tunnel_cluster_label(via_cluster: str) -> str:
    """Filename-safe, stable per-cluster label for the tunnel broker. Uses the cluster
    short name (the segment after 'cluster/') when the context is an EKS ARN, else a
    sanitized form of the whole context. Always passes validate_identifier."""
    tail = via_cluster.rsplit("/", 1)[-1] if "/" in via_cluster else via_cluster
    label = re.sub(r"[^A-Za-z0-9_.-]", "-", tail).strip("-")
    if not label or not label[0].isalnum():
        label = "c-" + label.lstrip("-")
    return label[:40]


def sanitize_port(s: str) -> int:
    """Validate a caller-supplied TCP port argument for the tunnel / mongo brokers:
    an integer in the unprivileged range 1024-65535. This is hygiene, not a security
    boundary — claude-ro can reach any port anyway; it just keeps a clean integer out
    of the URI / port-forward."""
    try:
        port = int(s)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid port: {s!r} (expected an integer 1024-65535)")
    if not (1024 <= port <= 65535):
        raise SystemExit(f"port out of range: {port} (expected 1024-65535)")
    return port


def sanitize_session_id(s: str) -> str:
    """Validate the launcher session id (CLAUDE_RO_SESSION = the launcher PID): plain
    decimal digits. Lands in a runtime pidfile name, so keep it to digits only."""
    if not s or not s.isdigit() or len(s) > 20:
        raise SystemExit(f"invalid session id: {s!r} (expected the launcher PID, digits only)")
    return s


def render_tunnel_broker(via_cluster: str) -> str:
    """Render templates/claude-ro-tunnel.tmpl for ONE cluster. Per-cluster: the cluster
    ARN is baked in; the broker mints its own admin kubeconfig via boto3 (keyed off the
    account's assumer_profile) so it needs no KUBECONFIG env or aws CLI under sudo. The
    absolute kubectl path is resolved here (engineer's full env) and baked in, so the
    broker doesn't depend on sudo's PATH."""
    validate_kube_context(via_cluster)
    parse_eks_arn(via_cluster)  # reject non-ARN contexts early
    label = tunnel_cluster_label(via_cluster)
    validate_identifier(label)
    kubectl = shutil.which("kubectl")
    if not kubectl:
        raise SystemExit("kubectl not found on PATH — install it before binding a "
                         "tunneled MongoDB (the tunnel broker shells out to it).")
    template = TUNNEL_BROKER_TEMPLATE.read_text()
    out = template
    for k, v in {
        "VIA_CLUSTER": via_cluster,
        "LABEL": label,
        "KUBECTL": kubectl,
        "SKILL_SCRIPTS_DIR": str(SKILL_SCRIPTS_LINK),
        "PYTHON": sys.executable,
    }.items():
        out = out.replace("{{" + k + "}}", v)
    return out


# ---------- pending_operation helpers ----------

def begin_operation(state: dict, kind: str, target: dict) -> None:
    """Stamp pending_operation onto state. Caller writes state afterward."""
    state["pending_operation"] = {
        "kind": kind,
        "target": target,
        "last_completed_phase": None,
        "started_at": now_iso(),
    }


def mark_phase(state: dict, phase: str) -> None:
    """Record completion of a phase. Caller writes state afterward."""
    op = state.get("pending_operation")
    if op is None:
        # The operation completed cleanly between calls — nothing to record.
        return
    op["last_completed_phase"] = phase


def end_operation(state: dict) -> None:
    """Clear pending_operation after a successful state_commit + verify."""
    state["pending_operation"] = None


def resume_phase_index(state: dict, phases: list[str], expected_kind: str,
                       expected_target: dict | None = None) -> int:
    """Return the index of the next phase to run. 0 if no pending op or kind mismatch."""
    op = state.get("pending_operation")
    if op is None:
        return 0
    if op["kind"] != expected_kind:
        return 0
    if expected_target is not None and op.get("target") != expected_target:
        return 0
    last = op.get("last_completed_phase")
    if last is None:
        return 0
    try:
        return phases.index(last) + 1
    except ValueError:
        return 0
