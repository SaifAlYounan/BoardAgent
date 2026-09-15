#!/usr/bin/env python3
"""bless — accept a DELIBERATE baseline change. the project owner's command, run from their own terminal.

Two-phase, like the rest of the house:
    tests/bless.py          # show the baseline diff from the last net run; exit 1; write NOTHING
    tests/bless.py --yes    # write the new baselines into NET.json (record the reason in the change log)

Rules:
  - Only scored tiers' baselines move, and only to the score of the LAST run (green or not —
    accepting a lower number is explicitly the project owner's decision, shown as such).
  - Hand-verified goldens are NEVER touched here; they are only replaced by a new human audit.
  - The model is gate-denied from running `--yes`; a baseline that moved without this ritual
    is a defect. (Strict ratchet lives in net_engine; this is the one door through it.)
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NET = os.path.join(HERE, "NET.json")
LASTRUN = os.path.join(HERE, ".net-lastrun.json")


def main(argv):
    yes = "--yes" in argv
    if not os.path.isfile(LASTRUN):
        print("No .net-lastrun.json — run tests/run_all.py first.")
        return 1
    with open(NET) as f:
        net = json.load(f)
    with open(LASTRUN) as f:
        last = json.load(f)

    changes = []
    for tier in net.get("tiers", []):
        if not tier.get("scored"):
            continue
        res = last["tiers"].get(tier["name"], {})
        score = res.get("score")
        if score is None:
            continue
        if "baseline" not in tier or score != tier["baseline"]:
            changes.append((tier, score))

    if not changes:
        print("Baselines already match the last run — nothing to bless.")
        return 0

    for tier, score in changes:
        if "baseline" not in tier:
            arrow = "NEW BASELINE — the ratchet arms here"
            frm = "(none)"
        else:
            arrow = ("IMPROVEMENT" if score > tier["baseline"]
                     else "REGRESSION you are accepting")
            frm = tier["baseline"]
        print(f"- {tier['name']}: baseline {frm} -> {score}   ({arrow})")

    if not yes:
        print("\nNOT written. Re-run with --yes to accept the diff above "
              "(record the reason in the change log).")
        return 1

    for tier, score in changes:
        tier["baseline"] = score
    with open(NET, "w") as f:
        json.dump(net, f, indent=2)
        f.write("\n")
    print(f"\nBlessed {len(changes)} baseline(s) into NET.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
