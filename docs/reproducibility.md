# Reproduce execution and the study

Build the pinned native backend using the README first. Every command below
requires a fresh output directory; earlier evidence is preserved. Use the
same `CIPHERSHAPE_NATIVE` absolute path throughout one study.

## Execution checks

```sh
python -m pytest -q
python scripts/prove_dot.py
ciphershape demo analytics --out runs/check-analytics
ciphershape demo model --out runs/check-model
```

The native tests require installed workers. Check pytest's skip summary; skipped
native tests do not establish confidential computation. The demonstration
reports three numerical paths independently: original float formula, compiled
plaintext graph and encrypted/decrypted execution. Approximation error compares
the first two; encryption error compares the last two. Their sum must meet the
declared tolerance, and non-result slots must remain within that tolerance.

The public linear model is fitted by deterministic ordinary least squares to
256 generated examples. A separate seed supplies 128 held-out examples for task
RMSE and maximum absolute error against the original synthetic target. That
task error is distinct from CKKS error. Training data, fixtures and target are
original generated material; there are no third-party dataset/weight licenses.
The result is a small inference application, not evidence of useful prediction
on a real population.

## Freeze, calibrate, confirm

The committed `benchmarks/frozen-confirmation.json` fixes graph hashes, shapes,
tolerance, security profile, variants, input patterns and request counts before tuning.
The preserved calibration provenance additionally records the exact generated
input vectors before the first development measurement.
The study verifies it before calibrating and preserves it by hash. It rejects
changed confirmation graphs, unmeasured costs or a changed runtime between
calibration and confirmation.

```sh
python scripts/study.py --phase freeze --out runs/freeze-1
python scripts/study.py --phase calibrate --out runs/calibration-1
python scripts/study.py --phase confirm --out runs/confirmation-1 \
  --costs runs/calibration-1/costs.json
```

HTTP is the default transport. Pass `--transport file` explicitly for a separate
trusted-local-file study. Do not combine transports in one comparison.
Development uses analytics length 4 and a dot product length 8. Confirmation
uses analytics length 8 and model length 4. It compares independent, naive
shared, tuned layout/key and full planner variants with two changed-input
requests each. One/100-request horizon values are predictions from calibrated
costs, not additional executed measurements.

Reports include compilation, context/key setup and artifact bytes, encryption,
evaluation, transfer, decryption, first/repeated request latency, instruction
traces, live coefficient storage and process peak memory. HTTP reports also
count base64/JSON body bytes and round-trip time; these body counts exclude
HTTP headers and transport framing. The setup/upload timing objective uses
declared bandwidth and serialized artifacts, not a measured wide-area network.
Plaintext timing is an overhead reference. Failures and partial reports remain
in the client's study directory and the command fails.

A lower predicted cost is not proof of a lower measured end-to-end latency.
Inspect measured and predicted values together. Two requests provide a small
local engineering comparison, without stable tail-latency or population-level
statistical claims. A matched external compiler comparison is unavailable.
Report ties, regressions and setup that never amortizes without recasting them
as wins.

## Independent installation

The recorded [silent replay](../assets/demo/ciphershape-demo.mp4) uses actual
HTTP execution reports. Reading holds are edited; the [asciicast](../assets/demo/demo.cast)
preserves execution timing. Re-record with `python scripts/record_demo.py
--costs benchmarks/results/development-costs.json --out runs/demo-new`.
The optional `scripts/render_replay.py` uses Pillow and FFmpeg to render those
reports; pass a local monospace font with `--font`. Font files are not redistributed.

Create a fresh clone or source extraction and a new virtual environment. Build
the native dependency there from its pinned revision. Install the Python wheel
without editable-source lookup, set `CIPHERSHAPE_NATIVE` to that installation's
workers, then run both changed-input demos and the test suite. Keep prior
private directories and generated run artifacts outside that installation.
Run the evaluation step with only public server artifacts and ciphertexts
present. This checks implementation separation; it is not a cryptographic proof.

Publication verification additionally requires the exact remote commit, passing
remote CI, release downloads and links, and execution from the downloaded source.
A local pass or configured workflow does not establish those outcomes. The
task's execution record tracks these gates separately.

## Platform limits

The native dependency is pinned by commit, and Python build/test dependencies
are pinned in the README and CI. Compiler/OS/Python identities and native binary
hashes are recorded with the study. Randomized encryption means ciphertexts and
timings are not bitwise reproducible. Numerical output must satisfy the error
contract instead.

The local reference host is Apple arm64. Linux CI is configured to execute the
same protocol. Linux workers apply hard address-space/allocation limits. The
tested macOS environment rejects a finite allocation limit; peak RSS is reported
and checked after execution, while admission estimates bound planned work.
This does not promise a hard macOS process-memory ceiling. Process peak memory
includes library/key overhead that live coefficient-byte counts omit.
