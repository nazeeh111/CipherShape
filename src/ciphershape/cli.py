"""Task-centered command line: declare, compile, encrypt, evaluate, decrypt."""
from __future__ import annotations
import argparse
from contextlib import nullcontext
from dataclasses import asdict
import json
from pathlib import Path
import sys
import time

from .apps import analytics, analytics_reference, trained_model, model_reference, model_task_accuracy
from .graph import Workload, evaluate
from .planner import Costs, Plan, choose, compile_plan
from .runtime import (ProtocolError, setup, encrypt, evaluate_server, decrypt,
                      read_json, write_json, binary_dir, folder_bytes)
from .api import local_endpoint, evaluate_http


def application(name: str) -> Workload:
    return analytics() if name == "analytics" else trained_model()


def default_inputs(name: str, changed: bool = False) -> dict:
    if name == "analytics":
        return {"x": [-.8, -.5, -.1, .2, .3, .5, .7, .9] if not changed else [.9, .7, .5, .3, .2, -.1, -.5, -.8],
                "y": [.1, -.2, .3, -.4, .5, -.6, .7, -.8]}
    return {"features": [.2, -.4, .6, -.8] if not changed else [-.7, .3, .1, .9]}


def load_plan(public: Path) -> Plan:
    p = read_json(public / "plan.json")
    p["basis"] = tuple(p["basis"])
    p["instructions"] = tuple(p["instructions"])
    p["inputs"] = tuple(tuple(x) for x in p["inputs"])
    p["outputs"] = tuple(p["outputs"])
    return Plan(**p)


def run_demo(app: str, destination: Path, costs: Costs | None = None,
             variant: str = "planner", changed: bool = False, transport: str = "http") -> dict:
    w = application(app)
    start = time.perf_counter()
    if variant == "planner":
        plan, candidates = choose(w, costs or Costs(), w.budget.requests, w.budget.upload_bytes_per_second)
    else:
        plan = compile_plan(w, sharing="per-output" if variant == "independent" else "shared",
                            retention="retain" if variant == "naive" else "last-use")
        candidates = []
    compilation = time.perf_counter() - start
    if destination.exists():
        raise ProtocolError("demo destination must be new")
    destination.mkdir(parents=True)
    pub, priv = destination / "server", destination / "client/private"
    manifest = setup(w, plan, pub, priv)
    inp = default_inputs(app, changed)
    runs = []
    with local_endpoint(pub) if transport == "http" else nullcontext(None) as endpoint:
        for i in range(2):
            if i:
                inp = default_inputs(app, not changed)
            request, response = destination / f"request-{i}", destination / f"response-{i}"
            begin = time.perf_counter()
            enc = encrypt(w, plan, pub, priv, inp, request)
            server = (evaluate_http(endpoint[0], endpoint[1], request, response) if endpoint else
                      evaluate_server(pub, request, response))
            answers, dec = decrypt(pub, priv, request, response)
            reference = (analytics_reference if app == "analytics" else model_reference)(inp)
            approximated = evaluate(w, inp)
            approximation_error = max(abs(reference[k] - approximated[k]) for k in reference)
            encryption_error = max(abs(approximated[k] - answers[k]) for k in reference)
            passed = approximation_error + encryption_error <= w.tolerance and dec["max_nonresult_slot"] <= w.tolerance
            runs.append({"request": i, "inputs_changed": bool(i), "original_float": reference,
                         "approximated_plaintext": approximated, "decrypted": answers,
                         "approximation_error": approximation_error, "encryption_error": encryption_error,
                         "accepted": passed, "end_to_end_seconds": time.perf_counter() - begin,
                         **enc, **server, **dec})
    result = {"application": app, "variant": variant, "program_id": plan.program_id,
              "parameters": manifest["parameters"], "plan": {"layout": plan.layout,
              "basis": plan.basis, "sharing": plan.sharing, "retention": plan.retention, "stats": plan.stats},
              "compilation_seconds": compilation, "setup_seconds": manifest["setup_seconds"],
              "setup_bytes": folder_bytes(pub), "runs": runs, "candidates": candidates,
              "calibrated": bool(costs and costs.measured), "accepted": all(x["accepted"] for x in runs)}
    result["transport"] = transport
    if app == "model":
        result["task_accuracy"] = model_task_accuracy()
    # This evidence contains answers and therefore stays on the client.
    write_json(destination / "client/report.json", result)
    if not result["accepted"]:
        raise ProtocolError("numerical contract failed; see client report")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compile small numerical endpoints for encrypted OpenFHE evaluation.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("demo", help="run both changed-input requests and verify three numerical paths locally")
    p.add_argument("application", choices=["analytics", "model"])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--variant", choices=["planner", "independent", "naive", "tuned"], default="planner")
    p.add_argument("--costs", type=Path)
    p.add_argument("--transport", choices=["http", "file"], default="http")
    p = sub.add_parser("compile", help="select a public plan and create separated client/server artifacts")
    p.add_argument("application", choices=["analytics", "model"])
    p.add_argument("--public", type=Path, required=True)
    p.add_argument("--private", type=Path, required=True)
    p.add_argument("--costs", type=Path)
    p = sub.add_parser("encrypt", help="client: validate private JSON and create ciphertext request")
    p.add_argument("application", choices=["analytics", "model"])
    p.add_argument("--public", type=Path, required=True)
    p.add_argument("--private", type=Path, required=True)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--request", type=Path, required=True)
    p = sub.add_parser("evaluate", help="server: evaluate ciphertext request, without client files")
    p.add_argument("--public", type=Path, required=True)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--response", type=Path, required=True)
    p = sub.add_parser("decrypt", help="client: decrypt returned endpoints locally")
    for name in ["public", "private", "request", "response"]:
        p.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        costs = Costs(**read_json(args.costs)) if getattr(args, "costs", None) else Costs()
        if args.command == "demo":
            report = run_demo(args.application, args.out, costs, args.variant, transport=args.transport)
            print(json.dumps({"accepted": report["accepted"], "client_report": str((args.out / "client/report.json").resolve()),
                              "program_id": report["program_id"], "calibrated": report["calibrated"]}, indent=2))
        elif args.command == "compile":
            w = application(args.application)
            plan, candidates = choose(w, costs, w.budget.requests, w.budget.upload_bytes_per_second)
            manifest = setup(w, plan, args.public, args.private)
            print(json.dumps({"program_id": manifest["program_id"], "layout": plan.layout, "basis": plan.basis,
                              "candidate_count": len(candidates), "calibrated": costs.measured}, indent=2))
        elif args.command == "encrypt":
            report = encrypt(application(args.application), load_plan(args.public), args.public, args.private,
                             read_json(args.input), args.request)
            print(json.dumps(report, indent=2))
        elif args.command == "evaluate":
            report = evaluate_server(args.public, args.request, args.response)
            print(json.dumps(report, indent=2))
        else:
            answers, _ = decrypt(args.public, args.private, args.request, args.response)
            print(json.dumps(answers, indent=2))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"CipherShape: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
