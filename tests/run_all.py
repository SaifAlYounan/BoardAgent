#!/usr/bin/env python3
"""The one command: run this project's full regression net.

    tests/run_all.py            # deterministic tiers + LLM tiers per NET.json policy
    tests/run_all.py --llm      # force LLM tiers too
    tests/run_all.py --no-llm   # deterministic only (LLM reported SKIPPED, never passed)

Green before + green after a change = no drift. Red after = the change did something
you must either fix or bring to the project owner (tests/bless.py is their command, not an automated one).
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import net_engine

if __name__ == "__main__":
    sys.exit(net_engine.main(sys.argv[1:]))
