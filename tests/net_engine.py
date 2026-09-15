#!/usr/bin/env python3
"""net_engine — the regression-net runner for this project.

Self-contained on purpose: it depends on nothing outside this repository.

Contract (the whole convention in five rules):
  1. Tiers run in NET.json order. A tier is a subprocess; exit 0 = pass.
     A scored tier also prints `NET_SCORE <float>` on stdout; the engine compares it
     against `threshold` (floor) and `baseline` (strict ratchet: score >= baseline).
  2. Deterministic tiers are the hard gate. LLM tiers run per --llm/policy; when not
     run they are reported SKIPPED — skipped is never counted as passed.
  3. Green run -> tests/.net-stamp.json with the environment fingerprint
     (source hash + declared external prompt/skill/config hashes + model id).
     A fingerprint mismatch later means "the system changed since last green".
  4. Every run (green or red) -> tests/.net-lastrun.json. bless.py reads it; only
     the project owner's terminal bless updates baselines. The engine never edits NET.json.
  5. Exit 0 = ALL GREEN. Exit 1 = FAILURES — do not ship changes.
"""

import fnmatch
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
NET = os.path.join(HERE, "NET.json")
STAMP = os.path.join(HERE, ".net-stamp.json")
LASTRUN = os.path.join(HERE, ".net-lastrun.json")

ALWAYS_EXCLUDE = [
    "**/__pycache__/**", "**/*.pyc", "**/.DS_Store", "**/node_modules/**",
    "**/.git/**", "tests/.net-stamp.json", "tests/.net-lastrun.json",
]


def _load_net():
    with open(NET) as f:
        return json.load(f)


def _iso_now():
    out = subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                         capture_output=True, text=True)
    return out.stdout.strip()


def _matches(rel, patterns):
    # fnmatch has no globstar: also try each pattern with "**/" stripped, so
    # "**/*.py" matches both "app.py" and "src/app.py" (fnmatch * crosses "/").
    for p in patterns:
        if (fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(os.path.basename(rel), p)
                or fnmatch.fnmatch(rel, p.replace("**/", ""))):
            return True
    return False


def _source_files(cfg):
    include = cfg.get("source", ["**/*"])
    exclude = list(cfg.get("exclude", [])) + ALWAYS_EXCLUDE
    found = []
    for root, dirs, files in os.walk(PROJECT):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules", ".git")]
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, PROJECT)
            if _matches(rel, exclude):
                continue
            if _matches(rel, include):
                found.append(rel)
    return sorted(found)


def _hash_files(pairs):
    """pairs: list of (label, absolute_path). Missing files hash as MISSING:<label>."""
    h = hashlib.sha256()
    for label, path in pairs:
        h.update(label.encode())
        if os.path.isfile(path):
            with open(path, "rb") as f:
                h.update(hashlib.sha256(f.read()).digest())
        else:
            h.update(b"MISSING")
    return h.hexdigest()


def fingerprint(net):
    cfg = net.get("fingerprint", {})
    rels = _source_files(cfg)
    source_hash = _hash_files([(r, os.path.join(PROJECT, r)) for r in rels])
    externals = [os.path.expanduser(p) for p in cfg.get("external", [])]
    external_hash = _hash_files([(p, p) for p in externals])
    # The model that governs quality is the OPERATOR model — the one that does the
    # project's work — not whichever harness happened to type `run_all.py`. When
    # NET.json declares it, the declaration wins outright: otherwise two sessions
    # driven by different models would stamp different ids and flip each other
    # STALE forever. Env stays the source
    # for projects whose operator IS the session model (no operator_model key).
    model = (cfg.get("operator_model")
             or os.environ.get("NET_MODEL")
             or os.environ.get("ANTHROPIC_MODEL")
             or "unspecified")
    return {"source": source_hash, "external": external_hash,
            "model": model if cfg.get("model_sensitive", True) else "n/a",
            "n_source_files": len(rels)}


def run_tier(tier):
    """Returns (status, score, detail): status in PASS/FAIL/SKIP."""
    cmd = tier["cmd"]
    try:
        out = subprocess.run(cmd, cwd=PROJECT, capture_output=True, text=True,
                             timeout=tier.get("timeout", 900))
    except subprocess.TimeoutExpired:
        return "FAIL", None, "timeout"
    except FileNotFoundError as e:
        return "FAIL", None, f"cmd not found: {e}"
    score = None
    for line in (out.stdout or "").splitlines():
        if line.startswith("NET_SCORE "):
            try:
                score = float(line.split()[1])
            except (IndexError, ValueError):
                return "FAIL", None, f"bad NET_SCORE line: {line!r}"
    if out.returncode != 0:
        tail = ((out.stderr or out.stdout) or "").strip().splitlines()[-3:]
        return "FAIL", score, " / ".join(tail) or f"exit {out.returncode}"
    if tier.get("scored"):
        if score is None:
            return "FAIL", None, "scored tier printed no NET_SCORE line"
        if "threshold" in tier and score < tier["threshold"]:
            return "FAIL", score, f"score {score} < threshold {tier['threshold']}"
        if tier.get("ratchet", True) and "baseline" in tier and score < tier["baseline"]:
            return "FAIL", score, (f"score {score} < blessed baseline {tier['baseline']} "
                                   "(strict ratchet — inform the project owner; their call)")
        return "PASS", score, f"score {score}"
    return "PASS", score, "ok"


def stale_check(net):
    """--stale-check: exit 0 fresh, 1 stale/red/never-run. Prints one reason line.
    The single source of truth for freshness; callers must never re-derive this."""
    fp = fingerprint(net)
    if not os.path.isfile(STAMP):
        print("STALE no green run recorded (tests/.net-stamp.json missing)")
        return 1
    with open(STAMP) as f:
        stamp = json.load(f)
    old = stamp.get("fingerprint", {})
    for key in ("source", "external", "model"):
        if old.get(key) != fp.get(key):
            print(f"STALE fingerprint drift: {key} changed since last green run")
            return 1
    print("FRESH")
    return 0


def main(argv):
    net = _load_net()
    if "--stale-check" in argv:
        return stale_check(net)
    run_llm = "--llm" in argv
    skip_llm = "--no-llm" in argv
    fp = fingerprint(net)

    policy = net.get("llm_policy", "on_fingerprint_change")
    if not run_llm and not skip_llm:
        if policy == "always":
            run_llm = True
        elif policy == "on_fingerprint_change" and os.path.isfile(STAMP):
            with open(STAMP) as f:
                old = json.load(f)
            llm_fp = old.get("llm_fingerprint")
            run_llm = llm_fp != {"external": fp["external"], "model": fp["model"]}
        elif policy == "on_fingerprint_change":
            run_llm = True  # never had a green LLM pass

    results, improvements = [], []
    for tier in net.get("tiers", []):
        is_llm = tier.get("kind") == "llm"
        if is_llm and not run_llm:
            results.append((tier["name"], "SKIP", None, "LLM tier not requested (never counted as passed)"))
            continue
        status, score, detail = run_tier(tier)
        results.append((tier["name"], status, score, detail))
        if (status == "PASS" and tier.get("scored") and "baseline" in tier
                and score is not None and score > tier["baseline"]):
            improvements.append((tier["name"], tier["baseline"], score))

    hard_fail = any(s == "FAIL" for _, s, _, _ in results)
    all_green = not hard_fail

    lastrun = {
        "ts": _iso_now(), "fingerprint": fp, "all_green": all_green,
        "llm_ran": run_llm,
        "tiers": {n: {"status": s, "score": sc, "detail": d} for n, s, sc, d in results},
    }
    with open(LASTRUN, "w") as f:
        json.dump(lastrun, f, indent=2)

    if all_green:
        stamp = {"ts": lastrun["ts"], "fingerprint": fp,
                 "tiers": lastrun["tiers"]}
        if run_llm:
            stamp["llm_fingerprint"] = {"external": fp["external"], "model": fp["model"]}
        elif os.path.isfile(STAMP):
            with open(STAMP) as f:
                prev = json.load(f).get("llm_fingerprint")
            if prev:
                stamp["llm_fingerprint"] = prev
        with open(STAMP, "w") as f:
            json.dump(stamp, f, indent=2)

    width = max((len(n) for n, _, _, _ in results), default=4)
    for n, s, sc, d in results:
        print(f"{s:<5} {n:<{width}}  {d}")
    if improvements:
        for n, b, sc in improvements:
            print(f"NOTE  {n}: improved {b} -> {sc} — blessable (project owner: tests/bless.py)")
    print("ALL GREEN" if all_green else "FAILURES — do not ship changes")
    return 0 if all_green else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
