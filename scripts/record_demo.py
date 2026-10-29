#!/usr/bin/env python3
"""Record a real encrypted API walkthrough in editable asciicast v2 format."""
import argparse
import json
from pathlib import Path
import time
from ciphershape.cli import run_demo
from ciphershape.planner import Costs
from ciphershape.runtime import read_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--costs", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    cast = (args.out / "demo.cast").open("w")
    cast.write(json.dumps({"version": 2, "width": 105, "height": 30, "timestamp": int(time.time()),
                           "title": "CipherShape: actual changed-input encrypted API walkthrough"}) + "\n")
    start = time.perf_counter()
    def say(text):
        print(text, flush=True)
        cast.write(json.dumps([time.perf_counter()-start, "o", text+"\r\n"]) + "\n")
        cast.flush()
    costs = Costs(**read_json(args.costs)) if args.costs else Costs()
    try:
        say("CipherShape | real OpenFHE CKKS | HEStd_128_classic | no plaintext fallback")
        for app in ("analytics", "model"):
            say(f"CLIENT: compile {app}, generate owner keys, start separate loopback evaluator")
            report = run_demo(app, args.out / app, costs, transport="http")
            say(f"PUBLIC PLAN: {report['plan']['layout']}; rotation basis={report['plan']['basis']}; "
                f"sharing={report['plan']['sharing']}")
            for run in report["runs"]:
                say(f"SERVER PUBLIC METADATA request={run['request']} changed_input={run['inputs_changed']} "
                    f"bytes_in={run['request_bytes']} bytes_out={run['response_bytes']} "
                    f"evaluation_s={run['evaluation_seconds']:.4f}")
                say("CLIENT DECRYPTED: " + json.dumps(run["decrypted"], sort_keys=True))
                say(f"CLIENT CHECK: approximation_error={run['approximation_error']:.3g}; "
                    f"encryption_error={run['encryption_error']:.3g}; accepted={run['accepted']}")
        say("Complete. Decrypted answers and private keys stayed on the client side of the API.")
    except Exception as exc:
        say(f"FAILED: {type(exc).__name__}: {exc}")
        raise
    finally:
        cast.close()


if __name__ == "__main__":
    main()
