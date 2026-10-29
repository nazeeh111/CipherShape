# Deployment-budgeted planning

CipherShape enumerates a deliberately small plan space. It chooses a supported
plan for a fixed public workload and deployment budget. It does not change the
cryptographic security target to improve a result.

| Choice | Supported alternatives | Tradeoff |
| --- | --- | --- |
| Client layout | packed vector; one ciphertext per scalar | Packing reduces uploads; scalar layout removes reduction rotations. |
| Rotation keys | direct powers of two; unit step; sparse basis | Fewer keys reduce setup bytes but compose more online rotations. |
| Multi-output work | shared graph; independent per-output lowering | Sharing reuses equal intermediates; independent lowering recomputes them. |
| Lifetime | retain; release at last use | Last-use release reduces live ciphertext storage. Combined with independent lowering it permits recomputation instead of retention. |

The Cartesian product has 24 candidate configurations. Some lower to identical
plans, especially for a single output or a layout requiring no rotations. The
planner breaks cost ties by lower live memory, then setup bytes, then a
deterministic program digest.

The estimated objective, in seconds, is:

```text
setup_time + setup_bytes / bandwidth
+ request_count * (
    native_online_time
    + client_encryption_time + client_decryption_time
    + (request_bytes + response_bytes) / bandwidth
  )
```

Native online time sums measured instruction costs, per-request overhead and
rotation-key loading cost. Setup includes context and evaluation-key artifacts.
Feasibility checks cover setup bytes, upload/payload bytes, online time, live
ciphertext bytes, total memory admission and native instruction/input limits.
The total-memory estimate combines setup artifacts and live ciphertexts; it is
an admission model rather than a complete allocator model. Process peak RSS
(resident memory) is reported separately.

The compiler validates shapes, interval bounds and a conservative level budget
before lowering. Plans count ciphertext and plaintext products, rotations,
relinearizations, output masks, input ciphertexts and peak live ciphertexts.
Each export includes a full-packing binary mask. Runtime traces record actual
scale and levels under OpenFHE's automatic rescaling.
Automatic rescaling/alignment is charged inside measured
OpenFHE primitive times; the trace exposes resulting levels rather than an
exact count of every internal library rescale call. Layouts are chosen at the
client boundary; this version inserts no internal layout conversions, so its
conversion count is zero. It supports no bootstrap or decryption fallback.

All reuse is confined to one stateless invocation with matching program, input,
context and key epoch. There is no server cache indexed by secret plaintext and
no cross-owner reuse. Equal public graph nodes can share within that invocation.

## Calibration and comparison

`scripts/study.py` measures development graphs at the fixed CKKS profile.
Instruction costs use medians of native trace samples. Key bytes, ciphertext
bytes and setup are measured. The marginal setup/key-loading estimators can be
noisy; raw samples and estimator notes accompany the coefficients. Defaults in
`Costs()` are uncalibrated and must be labeled as such.

The frozen confirmation study compares:

1. Packed independent per-output lowering with last-use release.
2. Packed shared lowering retaining all intermediates.
3. Tuned layout/key choices with shared lowering and last-use release.
4. Full bounded deployment-budget search.

Identical graphs, output meanings, tolerances, security parameters and hardware
apply to all four. Predictions over one and 100 requests are amortization
estimates; they are not 100 executed trials. Two changed-input requests per
variant measure first and repeated execution. The single-output model is a
negative control for multi-output sharing. A speedup or universal benefit is
not assumed.

## Relation to HEIR

[HEIR already optimizes ciphertext layouts and kernels](https://heir.dev/docs/design/layout/),
hoists conversions and deduplicates common work in rotation cost analysis.
Packing, common-subexpression elimination and joint layout/kernel selection
are established compiler techniques. CipherShape's scoped contribution is an
explicit deployment objective over multi-output work, reusable key-basis size,
request frequency, transfer and retention/recomputation in a bounded runnable
system. It does not establish a new general layout optimizer.

There is currently no matched external HEIR measurement in the retained study.
The internal baselines are not HEIR substitutes. An external comparison requires
matching operators, scalar-output masking, precision, security, hardware and
all client/setup/transfer costs before making performance claims.
