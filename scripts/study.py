#!/usr/bin/env python3
"""Calibrate on development graphs, then execute a frozen confirmation study.

Reports containing synthetic answers stay in the client's study directory. They
are not server logs. An unsuccessful run is retained and makes this command fail.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import nullcontext
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import time
import traceback

from ciphershape.api import evaluate_http, local_endpoint
from ciphershape.apps import (analytics, analytics_reference, model_reference,
                              model_task_accuracy, trained_model)
from ciphershape.graph import Workload, dot, evaluate, private
from ciphershape.planner import Costs, choose, compile_plan, estimate
from ciphershape.runtime import (binary_dir, decrypt, digest, encrypt,
                                 evaluate_server, folder_bytes, read_json, setup,
                                 write_json)

OPS = {"input", "add", "sub", "mul", "scale", "weights", "rotate", "mask"}
PARAMETERS = {"security": "HEStd_128_classic", "depth": 4, "scale_bits": 45,
              "first_mod_bits": 55}


def development_dot() -> Workload:
    x = private("x", 8)
    return Workload("development_dot", (x,), (("dot", dot(x, (0.125,) * 8)),))


def fixture(w: Workload, changed: bool) -> dict[str, list[float]]:
    """Original, public synthetic examples, unrelated to any user data."""
    result = {}
    for index, node in enumerate(w.inputs):
        n = node.shape[0]
        if changed:
            result[str(node.value)] = [(-1.0 if (i + index) % 2 else 1.0) for i in range(n)]
        else:
            result[str(node.value)] = [((i * 3 + index * 5) % 17 - 8) / 10 for i in range(n)]
    return result


def original_float(w: Workload, values: dict) -> dict:
    if w.name == "analytics":
        return analytics_reference(values)
    if w.name == "trained_model":
        return model_reference(values)
    return {"dot": sum(values["x"]) / 8}


def graph_description(w: Workload) -> dict:
    # Fixed ordering and structural edges make this a graph+shape+contract digest,
    # independent of planner statistics or development-calibrated coefficients.
    a = w.validate()
    ids = {n: i for i, n in enumerate(a.nodes)}
    return {"name": w.name, "nodes": [{"op": n.op, "args": [ids[x] for x in n.args],
            "value": n.value, "shape": n.shape, "bounds": n.bounds} for n in a.nodes],
            "outputs": [(k, ids[n]) for k, n in w.outputs],
            "tolerance": w.tolerance, "max_depth": w.max_depth,
            "budget": asdict(w.budget), "parameters": PARAMETERS}


def graph_digest(w: Workload) -> str:
    return hashlib.sha256(json.dumps(graph_description(w), sort_keys=True).encode()).hexdigest()


def frozen_provenance(path: Path) -> dict:
    if not path.is_file():
        raise ValueError("freeze the confirmation specification before calibration")
    spec = read_json(path)
    if (spec.get("frozen_before_calibration") is not True or spec.get("horizons") != [1, 100] or
            spec.get("requests_per_variant") != 2 or
            spec.get("variants") != ["independent", "naive", "tuned", "planner"] or
            spec.get("tolerance") != 1e-4):
        raise ValueError("unsupported frozen confirmation contract")
    confirmation = {row["name"]: row for row in spec["confirmation"]}
    expected_graphs = {"analytics8": analytics(8), "model4": trained_model()}
    if set(confirmation) != set(expected_graphs):
        raise ValueError("confirmation graphs differ from the frozen study")
    for name, workload in expected_graphs.items():
        if confirmation[name]["graph_sha256"] != hashlib.sha256(repr(workload).encode()).hexdigest():
            raise ValueError("confirmation graph changed after freezing")
    # Preserve the supplied specification verbatim by hash. The implementation's
    # exact confirmation graphs, public fixtures and frequencies are also fixed.
    return {"specification_sha256": digest(path), "specification": spec,
            "graphs": {"analytics8": graph_digest(analytics(8)),
                       "model4": graph_digest(trained_model())},
            "public_fixtures": {name: [fixture(w, False), fixture(w, True)]
                                for name, w in (("analytics8", analytics(8)),
                                                ("model4", trained_model()))},
            "request_horizons": [1, 100], "requests_executed_per_variant": 2,
            "variants": ["independent", "naive", "tuned", "planner"],
            "parameters": PARAMETERS}


def host() -> dict:
    bins = binary_dir()
    root = Path(__file__).resolve().parents[1]
    sources = sorted([*root.joinpath("src/ciphershape").glob("*.py"),
                      *root.joinpath("native").glob("*.cpp"),
                      *root.joinpath("native").glob("*.h"), Path(__file__).resolve()])
    return {"platform": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(),
            "source_sha256": {str(p.relative_to(root)): digest(p) for p in sources},
            "native_sha256": {name: digest(bins / name) for name in
                              ("ciphershape-client", "ciphershape-server")}}


def run_plan(w: Workload, plan, destination: Path, transport: str,
             compilation_seconds: float = 0.0) -> dict:
    destination.mkdir(parents=True, exist_ok=False)
    public, private = destination / "server", destination / "client/private"
    result = {"workload": w.name, "graph_sha256": graph_digest(w),
              "program_id": plan.program_id, "plan": asdict(plan),
              "compilation_seconds": compilation_seconds, "transport": transport,
              "public_synthetic_data_only": True, "runs": [], "accepted": False}
    report_path = destination / "client/report.json"
    try:
        manifest = setup(w, plan, public, private)
        result.update({"parameters": manifest["parameters"],
                       "setup_seconds": manifest["setup_seconds"],
                       "setup_bytes": folder_bytes(public),
                       "key_artifact_bytes": {p.name: p.stat().st_size for p in public.iterdir()
                                              if p.suffix == ".bin"},
                       "private_key_bytes_client_only": (private / "secret.bin").stat().st_size})
        for key, expected in PARAMETERS.items():
            if manifest["parameters"].get(key) != expected:
                raise ValueError("native parameters differ from the frozen study contract")
        endpoint = local_endpoint(public) if transport == "http" else nullcontext(None)
        with endpoint as connection:
            for i in range(2):
                values = fixture(w, bool(i))
                request, response = destination / f"request-{i}", destination / f"response-{i}"
                begin = time.perf_counter()
                enc_begin = time.perf_counter()
                enc = encrypt(w, plan, public, private, values, request)
                encryption_wall = time.perf_counter() - enc_begin
                server_begin = time.perf_counter()
                if transport == "http":
                    server = evaluate_http(*connection, request, response, w.budget.max_payload_bytes)
                else:
                    server = evaluate_server(public, request, response)
                server_wall = time.perf_counter() - server_begin
                dec_begin = time.perf_counter()
                answers, client = decrypt(public, private, request, response)
                decryption_wall = time.perf_counter() - dec_begin
                end_to_end = time.perf_counter() - begin
                reference_begin = time.perf_counter()
                original = original_float(w, values)
                plaintext_original_seconds = time.perf_counter() - reference_begin
                reference_begin = time.perf_counter()
                approximated = evaluate(w, values)
                plaintext_graph_seconds = time.perf_counter() - reference_begin
                approximation_error = max(abs(original[k] - approximated[k]) for k in original)
                encryption_error = max(abs(approximated[k] - answers[k]) for k in original)
                accepted = (approximation_error + encryption_error <= w.tolerance and
                            client["max_nonresult_slot"] <= w.tolerance)
                row = {"request_index": i, "changed_input": bool(i),
                       "public_synthetic_fixture": values, "original_float": original,
                       "approximated_plaintext": approximated, "decrypted": answers,
                       "approximation_error": approximation_error, "encryption_error": encryption_error,
                       "tolerance": w.tolerance, "accepted": accepted,
                       "plaintext_original_seconds": plaintext_original_seconds,
                       "plaintext_graph_seconds": plaintext_graph_seconds,
                       "end_to_end_seconds": end_to_end, "encryption_wall_seconds": encryption_wall,
                       "server_and_transfer_wall_seconds": server_wall,
                       "decryption_wall_seconds": decryption_wall, **enc, **server, **client}
                result["runs"].append(row)
                write_json(report_path, result)
                if not accepted:
                    raise ValueError("numerical contract failed; client evidence retained")
        result["accepted"] = all(x["accepted"] for x in result["runs"])
        if w.name == "trained_model":
            result["task_accuracy_against_synthetic_target"] = model_task_accuracy()
    except Exception as exc:
        result["failure"] = {"type": type(exc).__name__, "message": str(exc),
                             "traceback_client_only": traceback.format_exc()}
        report_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(report_path, result)
        raise
    finally:
        if report_path.parent.exists():
            write_json(report_path, result)
    return result


def calibrate(out: Path, frozen: dict, transport: str) -> dict:
    specs = [("analytics4_direct", analytics(4), "packed", "direct"),
             ("analytics4_unit", analytics(4), "packed", "unit"),
             ("dot8_direct", development_dot(), "packed", "direct"),
             ("dot8_no_rotations", development_dot(), "scalar", "direct")]
    reports = []
    for name, w, layout, basis in specs:
        begin = time.perf_counter()
        plan = compile_plan(w, layout, basis)
        compile_seconds = time.perf_counter() - begin
        report = run_plan(w, plan, out / name, transport, compile_seconds)
        reports.append(report)
        write_json(out / "client/development-partial.json", {"runs": reports})
    samples: dict[str, list[float]] = defaultdict(list)
    for report in reports:
        for run in report["runs"]:
            for op in run["trace"]:
                samples[op["op"]].append(op["seconds"])
    if set(samples) != OPS or any(not v for v in samples.values()):
        raise ValueError("development measurements do not cover the complete supported instruction set")
    base = next(r for r in reports if not r["plan"]["basis"])
    base_bytes = sum(base["key_artifact_bytes"].values())
    rotation_bytes = [r["key_artifact_bytes"]["rot.bin"] / len(r["plan"]["basis"])
                      for r in reports if r["plan"]["basis"]]
    # A marginal setup estimator, not a direct microbenchmark: raw noisy samples
    # remain in the report. Clamp negative differences and disclose the estimator.
    marginal_setup = [(r["setup_seconds"] - base["setup_seconds"]) / len(r["plan"]["basis"])
                      for r in reports if r["plan"]["basis"]]
    overhead_samples = [{"development": name, "rotation_keys": len(report["plan"]["basis"]),
                         "seconds": max(0.0, run["server_process_seconds"] - run["evaluation_seconds"])}
                        for (name, *_), report in zip(specs, reports)
                        for run in report["runs"]]
    direct_overhead = statistics.median(row["seconds"] for row in overhead_samples
                                       if row["development"] == "analytics4_direct")
    unit_overhead = statistics.median(row["seconds"] for row in overhead_samples
                                     if row["development"] == "analytics4_unit")
    rotation_load = max(0.0, direct_overhead - unit_overhead)
    request_base = max(0.0, statistics.median(row["seconds"] - row["rotation_keys"] * rotation_load
                                            for row in overhead_samples))
    encryption_samples = [run["encryption_seconds"] / len(report["plan"]["inputs"])
                          for report in reports for run in report["runs"]]
    decryption_samples = [run["decryption_seconds"] / len(report["plan"]["outputs"])
                          for report in reports for run in report["runs"]]
    ct_bytes = max((out / name / "request-0/0.bin").stat().st_size for name, *_ in specs)
    coefficients = [run["peak_coefficient_bytes"] / run["peak_live_ciphertexts"]
                    for report in reports for run in report["runs"]]
    costs = Costs(op_seconds={op: statistics.median(samples[op]) for op in sorted(OPS)},
                  base_setup_seconds=base["setup_seconds"],
                  rotation_setup_seconds=max(0.0, statistics.median(marginal_setup)),
                  base_setup_bytes=base_bytes,
                  rotation_key_bytes=int(max(rotation_bytes) + 0.999999),
                  ciphertext_bytes=ct_bytes,
                  live_ciphertext_bytes=max(ct_bytes, int(max(coefficients) + 0.999999)),
                  request_base_seconds=request_base,
                  rotation_load_seconds=rotation_load,
                  encryption_seconds_per_ciphertext=statistics.median(encryption_samples),
                  decryption_seconds_per_ciphertext=statistics.median(decryption_samples),
                  measured=True)
    costs.validate()
    result = {"phase": "calibrate", "frozen": frozen, "host": host(), "costs": asdict(costs),
              "operation_sample_counts": {k: len(v) for k, v in samples.items()},
              "marginal_rotation_setup_samples_seconds": marginal_setup,
              "server_startup_overhead_samples": overhead_samples,
              "encryption_seconds_per_ciphertext_samples": encryption_samples,
              "decryption_seconds_per_ciphertext_samples": decryption_samples,
              "estimator_notes": ["Operation costs are median measured native trace durations, including trace accounting overhead.",
                                  "Base setup is the measured no-rotation setup. Marginal rotation setup is the nonnegative median difference per key; raw noisy differences are retained.",
                                  "Rotation bytes use the maximum measured bytes per basis key. Live-ciphertext bytes use a conservative maximum of serialized input bytes and observed peak coefficient bytes divided by live count.",
                                  "Server process minus native evaluation time estimates startup/context/key loading. Per-rotation loading is the nonnegative difference of analytics4 direct/unit median overheads; base startup is the nonnegative median residual over all development runs. Raw samples are retained.",
                                  "Encryption/decryption costs are median measured client subprocess durations per input/output ciphertext, including their native startup and serialization.",
                                  "HTTP wire bytes include base64/JSON bodies. Predicted bandwidth cost uses serialized ciphertext bytes; measured HTTP round trips are reported separately."],
              "development_reports": reports, "accepted": all(r["accepted"] for r in reports)}
    write_json(out / "costs.json", asdict(costs))
    write_json(out / "client/study.json", result)
    write_json(out / "calibration-provenance.json", {"frozen": frozen, "host": result["host"],
                                                   "costs_sha256": digest(out / "costs.json")})
    return result


def tuned(w: Workload, costs: Costs):
    candidates = [compile_plan(w, layout, basis, "shared", "last-use")
                  for layout in ("packed", "scalar") for basis in ("direct", "unit", "sparse")]
    # Restrict this baseline to shared graphs with last-use release. The full
    # planner additionally chooses sharing/recomputation and retention schedules.
    feasible = []
    for p in candidates:
        e = estimate(p, costs, w.budget.requests, w.budget.upload_bytes_per_second)
        b = w.budget
        if (e["setup_bytes"] <= b.max_setup_bytes and e["request_bytes"] <= b.max_upload_bytes and
                max(e["request_bytes"], e["response_bytes"]) <= b.max_payload_bytes and
                e["peak_live_bytes"] <= b.max_live_bytes and
                e["peak_live_bytes"] + e["setup_bytes"] <= b.max_memory_bytes and
                e["online_seconds"] <= min(b.max_online_seconds, b.max_seconds)):
            feasible.append((e["total_seconds"], p.program_id, p))
    if not feasible:
        raise ValueError("tuned baseline has no feasible plan")
    return min(feasible, key=lambda x: (x[0], x[1]))[2]


def confirm(out: Path, frozen: dict, costs_path: Path, transport: str) -> dict:
    provenance = read_json(costs_path.parent / "calibration-provenance.json")
    if provenance["frozen"] != frozen or provenance["costs_sha256"] != digest(costs_path):
        raise ValueError("confirmation specification or calibration changed after freezing")
    costs = Costs(**read_json(costs_path))
    if not costs.measured:
        raise ValueError("confirmation requires actual development calibration")
    costs.validate()
    current_host = host()
    if current_host != provenance["host"]:
        raise ValueError("hardware/runtime differs from calibration; recalibrate separately")
    result = {"phase": "confirm", "frozen": frozen, "host": current_host,
              "costs_sha256": digest(costs_path), "reports": [], "accepted": False,
              "comparison_limits": ["Plaintext is the overhead reference and is not expected to lose.",
                                    "No HEIR executable comparison was run by this script. Its layout/kernel optimizer is prior art, not an unmatched performance baseline.",
                                    "Two requests per variant support a small reproducible check, not a statistical performance claim.",
                                    "The model has one output, explicitly testing the case with no multi-output sharing benefit.",
                                    "Setup-amortization predictions are cost-model projections for one and one hundred requests; they are not measured one-hundred-request runs."]}
    try:
        for app, w in (("analytics8", analytics(8)), ("model4", trained_model())):
            for variant in ("independent", "naive", "tuned", "planner"):
                begin = time.perf_counter()
                candidates = []
                if variant == "independent":
                    plan = compile_plan(w, sharing="per-output", retention="last-use")
                elif variant == "naive":
                    plan = compile_plan(w, sharing="shared", retention="retain")
                elif variant == "tuned":
                    plan = tuned(w, costs)
                else:
                    plan, candidates = choose(w, costs)
                elapsed = time.perf_counter() - begin
                report = run_plan(w, plan, out / f"{app}_{variant}", transport, elapsed)
                report["variant"] = variant
                report["calibrated_prediction"] = estimate(plan, costs, w.budget.requests,
                                                            w.budget.upload_bytes_per_second)
                report["setup_amortization_predictions"] = {str(h): estimate(plan, costs, h,
                    w.budget.upload_bytes_per_second) for h in (1, 100)}
                report["all_planner_candidates"] = candidates
                result["reports"].append(report)
                write_json(out / "client/study.json", result)
        result["accepted"] = all(r["accepted"] for r in result["reports"])
    except Exception as exc:
        result["failure"] = {"type": type(exc).__name__, "message": str(exc),
                             "traceback_client_only": traceback.format_exc()}
        raise
    finally:
        write_json(out / "client/study.json", result)
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--phase", choices=("freeze", "calibrate", "confirm"), required=True)
    p.add_argument("--frozen", type=Path, default=Path("benchmarks/frozen-confirmation.json"))
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--costs", type=Path)
    p.add_argument("--transport", choices=("http", "file"), default="http")
    args = p.parse_args(argv)
    created = False
    try:
        frozen = frozen_provenance(args.frozen)
        if args.out.exists():
            raise ValueError("study output directory must be new; preserve earlier evidence")
        args.out.mkdir(parents=True)
        created = True
        (args.out / "client").mkdir()
        write_json(args.out / "frozen-before-tuning.json", frozen)
        if args.phase == "freeze":
            result = {"phase": "freeze", "frozen": frozen, "accepted": True}
        elif args.phase == "calibrate":
            result = calibrate(args.out, frozen, args.transport)
        else:
            if args.costs is None:
                raise ValueError("--costs is required for confirmation")
            result = confirm(args.out, frozen, args.costs, args.transport)
        print(json.dumps({"phase": args.phase, "accepted": result["accepted"],
                          "client_report": str((args.out / "client/study.json").resolve()),
                          "frozen_sha256": frozen["specification_sha256"]}, indent=2))
        return 0
    except Exception as exc:
        if created:
            write_json(args.out / "client/failure.json", {"type": type(exc).__name__, "message": str(exc),
                       "traceback_client_only": traceback.format_exc()})
        print(f"CipherShape study failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
