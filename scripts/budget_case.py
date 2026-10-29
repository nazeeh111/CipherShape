#!/usr/bin/env python3
"""Execute the predeclared memory tradeoff: sharing can be infeasible."""
import argparse
from dataclasses import replace
from pathlib import Path
from ciphershape.apps import analytics
from ciphershape.planner import Costs, choose, estimate
from ciphershape.runtime import read_json, write_json
from study import run_plan, tuned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--costs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    costs = Costs(**read_json(args.costs))
    costs.validate()
    if not costs.measured:
        parser.error("measured development costs are required")
    args.out.mkdir(parents=True, exist_ok=False)
    w = analytics(8)
    ordinary, _ = choose(w, costs)
    # A public six-ciphertext budget instantiates the memory negative case
    # declared before calibration. No private data is examined to choose it.
    tight = replace(w, budget=replace(w.budget, max_live_bytes=6*costs.live_ciphertext_bytes))
    try:
        tuned(tight, costs)
    except ValueError:
        shared_feasible = False
    else:
        shared_feasible = True
    selected, candidates = choose(tight, costs)
    report = run_plan(tight, selected, args.out / "executed", "http")
    result = {"accepted": report["accepted"], "budget_bytes": tight.budget.max_live_bytes,
              "ordinary_sharing": ordinary.sharing, "tight_budget_sharing": selected.sharing,
              "tuned_shared_baseline_feasible": shared_feasible,
              "selected_prediction": estimate(selected, costs), "candidates": candidates,
              "execution": report,
              "interpretation": "Recomputation fits the declared memory budget; it is not a universal latency improvement."}
    write_json(args.out / "client-budget-case.json", result)
    print({k: result[k] for k in ("accepted", "budget_bytes", "tight_budget_sharing", "tuned_shared_baseline_feasible")})


if __name__ == "__main__":
    main()
