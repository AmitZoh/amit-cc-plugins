#!/usr/bin/env python3
"""
Three-tier sensitive-file lockdown — orchestrated by Claude Code.

Two phases:

  scan [--dry-run]   Walk the lockdown roots and emit a JSON report on stdout:
                       - Tier 1 files chmod'd directly (deterministic).
                       - Tier 2 candidates that need a verdict (filename + path
                         only — content is never read or sent).
                       - Cache hits short-circuited from prior runs.
                     state.json is NOT mutated.

  apply              Read verdicts JSON from stdin, apply chmods, update state.
                       Verdicts are 'sensitive' or 'not_sensitive' only — no
                       'unsure'. Anything malformed is treated as 'sensitive'
                       (fail safe). state.json's classifier_cache is keyed by
                       absolute path only (filename-only verdicts are pure
                       functions of the path; mtime/size are irrelevant).

Claude Code runs scan, classifies the candidate names by reasoning over them
internally (or via a Haiku sub-agent), then runs apply with the result. There
is no ANTHROPIC_API_KEY, no review_queue, no interactive y/N during a sweep.

Unattended runs (launchd at 03:00) invoke `claude -p '...'` to enter CC
headless; the same scan -> classify -> apply flow runs there.
"""

from __future__ import annotations

import argparse
import datetime
import fnmatch
import json
import os
import pathlib
import sys

SKILL_DIR = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SKILL_DIR / "scripts"))
import _common as common  # noqa: E402


# ---------- file walking ----------

def _is_excluded(path: pathlib.Path, excl_names: set[str]) -> bool:
    return any(p in excl_names for p in path.parts)


def _walk(root: pathlib.Path, excl_names: set[str]):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in excl_names]
        for name in filenames:
            yield pathlib.Path(dirpath) / name


# ---------- pattern matching ----------

def _matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _project_root_above(path: pathlib.Path, markers: list[str]) -> bool:
    cur = path.parent
    while True:
        if any((cur / m).exists() for m in markers):
            return True
        if cur.parent == cur:
            return False
        cur = cur.parent


def _in_tier2_path(path: pathlib.Path, prefixes: list[str], markers: list[str],
                   home: pathlib.Path) -> bool:
    s = str(path)
    for pref in prefixes:
        if pref == "<project_root_marker>":
            continue
        expanded = os.path.expanduser(pref).rstrip("/")
        if s.startswith(expanded + "/") or s == expanded:
            return True
    if _project_root_above(path, markers):
        return True
    if path.parent == home and path.name.startswith("."):
        return True
    return False


# ---------- helpers ----------

def _chmod_600(path: pathlib.Path, *, dry_run: bool) -> None:
    if dry_run:
        return
    os.chmod(path, 0o600)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------- scan ----------

def scan(*, dry_run: bool = False, verbose: bool = False) -> dict:
    """Walk lockdown_roots, apply Tier 1, emit Tier-2 candidates.

    Returns the JSON-serialisable result the orchestrator sees on stdout."""
    cfg = common.load_config()
    roots_cfg = cfg.get("lockdown_roots") or ["$HOME"]
    roots = [pathlib.Path(os.path.expanduser(os.path.expandvars(r))) for r in roots_cfg]
    home = pathlib.Path(os.path.expanduser("~"))

    tier1 = cfg.get("tier_1_patterns") or []
    tier2_names = cfg.get("tier_2_name_patterns") or []
    tier2_prefixes = cfg.get("tier_2_path_prefixes") or []
    tier2_markers = cfg.get("tier_2_project_root_markers") or []
    excludes = cfg.get("tier_3_excludes") or []
    excl_names = {e.rstrip("/") for e in excludes}

    state = common.state_read()
    cache = (state.get("lockdown") or {}).get("classifier_cache", {}) or {}

    tier1_applied: list[dict] = []
    candidates: list[dict] = []
    cache_hits = {"sensitive": 0, "not_sensitive": 0}

    for root in roots:
        if not root.exists():
            common.log.warning("lockdown root does not exist: %s", root)
            continue
        for path in _walk(root, excl_names):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue

            name = path.name

            if _matches_any(name, tier1):
                if verbose:
                    common.log.info("tier-1: %s", path)
                tier1_applied.append({"path": str(path), "action": "chmod 600"})
                _chmod_600(path, dry_run=dry_run)
                continue

            if not _matches_any(name, tier2_names):
                continue
            if not _in_tier2_path(path, tier2_prefixes, tier2_markers, home):
                continue

            cached = cache.get(str(path))
            if cached:
                v = cached if isinstance(cached, str) else cached.get("verdict")
                if v == "sensitive":
                    cache_hits["sensitive"] += 1
                    tier1_applied.append({"path": str(path),
                                          "action": "chmod 600 (cached)"})
                    _chmod_600(path, dry_run=dry_run)
                    continue
                if v == "not_sensitive":
                    cache_hits["not_sensitive"] += 1
                    continue
                # Unknown / legacy verdict shape: re-classify.

            candidates.append({"path": str(path), "name": name})

    result = {
        "tier1_applied": tier1_applied,
        "tier2_candidates": candidates,
        "cache_hits": cache_hits,
        "summary": {
            "tier1_count": len(tier1_applied),
            "tier2_candidate_count": len(candidates),
            "cache_hits_sensitive": cache_hits["sensitive"],
            "cache_hits_clean": cache_hits["not_sensitive"],
        },
    }

    if dry_run:
        ts = _now_iso()
        # /tmp gets cleared on macOS reboot, so no rotation logic needed.
        log_path = pathlib.Path("/tmp") / f"lockdown-dryrun-{ts}.log"
        with open(log_path, "w") as f:
            f.write(f"# Lockdown dry-run scan at {ts}\n")
            for entry in tier1_applied:
                f.write(f"  {entry['action']}: {entry['path']}\n")
            f.write(f"\n# Tier-2 candidates ({len(candidates)}):\n")
            for c in candidates:
                f.write(f"  candidate: {c['path']}\n")
        os.chmod(log_path, 0o600)
        result["dry_run_log"] = str(log_path)

    return result


# ---------- apply ----------

def apply(verdicts: dict[str, str]) -> dict:
    """Apply orchestrator-supplied verdicts.

    Verdicts are 'sensitive' or 'not_sensitive' only. Anything else is treated
    as 'sensitive' (fail safe). state.json's classifier_cache is updated
    keyed by absolute path → verdict (no mtime/size — filename-only
    classification is a pure function of the path)."""
    applied: list[dict] = []
    sensitive_count = 0
    clean_count = 0
    coerced_count = 0

    with common.update_state() as state:
        cache = state.setdefault("lockdown", {}).setdefault("classifier_cache", {})

        for path, verdict in verdicts.items():
            if verdict not in ("sensitive", "not_sensitive"):
                # Fail safe: anything unrecognized is treated as sensitive.
                common.log.warning("verdict %r for %s coerced to 'sensitive'", verdict, path)
                verdict = "sensitive"
                coerced_count += 1

            cache[path] = verdict
            if verdict == "sensitive":
                try:
                    os.chmod(path, 0o600)
                    applied.append({"path": path, "action": "chmod 600"})
                    sensitive_count += 1
                except OSError as exc:
                    applied.append({"path": path, "action": f"chmod failed: {exc}"})
            else:
                clean_count += 1

    return {
        "applied_chmods": applied,
        "summary": {
            "sensitive": sensitive_count,
            "not_sensitive": clean_count,
            "coerced_to_sensitive": coerced_count,
        },
    }


# ---------- CLI ----------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Three-tier sensitive-file lockdown sweep (CC-orchestrated).",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp_scan = sub.add_parser("scan", help="Walk roots; apply Tier 1; emit Tier-2 candidates JSON.")
    sp_scan.add_argument("--dry-run", action="store_true",
                         help="Do not chmod or update state. Writes a log file under SKILL_DIR.")
    sp_scan.add_argument("--verbose", "-v", action="store_true")

    sub.add_parser("apply",
                   help="Read verdicts JSON from stdin, apply chmods, update cache.")

    args = ap.parse_args()

    if args.cmd == "scan":
        result = scan(dry_run=args.dry_run, verbose=args.verbose)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return

    if args.cmd == "apply":
        try:
            payload = json.load(sys.stdin)
        except json.JSONDecodeError as exc:
            print(f"could not parse verdicts JSON from stdin: {exc}", file=sys.stderr)
            sys.exit(2)
        verdicts = payload.get("verdicts") or {}
        if not isinstance(verdicts, dict):
            print("apply expects {\"verdicts\": {<path>: <verdict>, ...}}", file=sys.stderr)
            sys.exit(2)
        result = apply(verdicts)
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return


if __name__ == "__main__":
    main()
