#!/usr/bin/env python3
"""First gate: real encryption, evaluator without client files, client decrypt."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
from ciphershape.graph import Workload, private, dot, evaluate
from ciphershape.planner import compile_plan
from ciphershape.runtime import setup, encrypt, evaluate_server, decrypt, write_json, binary_dir


def main():
    x = private("x", 4)
    workload = Workload("dot_proof", (x,), (("dot", dot(x, (.5, -.25, .125, .75))),))
    plan = compile_plan(workload)
    with tempfile.TemporaryDirectory(prefix="ciphershape-dot-client-") as ct, tempfile.TemporaryDirectory(prefix="ciphershape-dot-server-") as st:
        client, server = Path(ct), Path(st)
        public, private_dir = client / "public-export", client / "private"
        manifest = setup(workload, plan, public, private_dir)
        inputs = {"x": [.25, -.5, .75, -1.]}
        request = client / "request"
        enc = encrypt(workload, plan, public, private_dir, inputs, request)
        shutil.copytree(public, server / "public")
        shutil.copytree(request, server / "request")
        # Separate evaluator tree contains only allowed exports, ciphertexts and
        # an evaluation-only binary. There is no client/private input argument.
        shutil.copy2(binary_dir() / "ciphershape-server", server / "ciphershape-server")
        forbidden = [p for p in server.rglob("*") if p.name in {"secret.bin", "binding.json"}]
        assert not forbidden
        meta = evaluate_server(server / "public", server / "request", server / "response",
                               binaries=server)
        shutil.copytree(server / "response", client / "response")
        answers, dec = decrypt(public, private_dir, request, client / "response")
        reference = evaluate(workload, inputs)
        error = abs(reference["dot"] - answers["dot"])
        result = {"accepted": error <= workload.tolerance and dec["max_nonresult_slot"] <= workload.tolerance,
                  "reference": reference, "decrypted": answers, "encryption_error": error,
                  "server_client_only_files_absent": True, "parameters": manifest["parameters"],
                  **enc, **meta, **dec}
        print(json.dumps(result, indent=2))
        if not result["accepted"]:
            raise SystemExit(2)


if __name__ == "__main__":
    main()
