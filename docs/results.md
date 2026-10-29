# Executed local study

All eight confirmation variants passed two changed-input HTTP requests on the
same Apple arm64 host. Every variant used OpenFHE 1.6.1, HEStd_128_classic,
ring dimension 16384, depth 4, 45-bit scale moduli and identical output masking.
The largest observed encryption error was **9.45e-9**, below the **1e-4** contract.
Original float, compiled plaintext and decrypted outputs are retained separately.

| Application / strategy | Setup MB | First request s | Repeated request s | Peak live coefficient MB |
| --- | ---: | ---: | ---: | ---: |
| Analytics / independent | 23.36 | 11.44 | 12.47 | 6.55 |
| Analytics / naive shared | 23.35 | 8.07 | 5.94 | 82.84 |
| Analytics / tuned | 23.35 | 8.76 | 7.64 | 9.18 |
| Analytics / planner | 23.35 | 6.48 | 10.51 | 9.18 |
| Model / independent | 17.84 | 1.84 | 1.71 | 3.93 |
| Model / naive shared | 17.84 | 1.19 | 1.57 | 8.91 |
| Model / tuned | 12.33 | 2.02 | 1.29 | 3.93 |
| Model / planner | 12.33 | 1.46 | 3.33 | 3.93 |

MB means decimal bytes divided by one million. Request time includes client
encryption, authenticated HTTP, server evaluation and client decryption.
Coefficient storage omits key maps and allocator/library overhead; full process
RSS appears in the raw reports. Setup artifacts are counted separately.
Independent outputs reuse uploaded input ciphertexts where legal, so duplicate
uploads do not manufacture a sharing benefit.

**There is no consistent measured latency win over the tuned baseline.** The
planner and tuned analytics plans are identical here. The model has one output
and supplies no multi-output sharing benefit. Its smaller key basis reduces
setup bytes while adding an online rotation; the observed request timings do
not establish amortization. The two samples per variant on a shared Mac are a
small engineering check with visible timing noise, not a statistical speedup
claim. No confirmation data was retuned to produce a positive result.

The separate memory case allows **7,873,842 live-ciphertext bytes**. Shared
last-use plans exceed that public budget. The full planner selects independent
recomputation, and both encrypted requests pass within the admitted plan. This
demonstrates a resource tradeoff, with extra repeated arithmetic, rather than a
universal performance improvement.

Plaintext remains the overhead reference and is much cheaper. Per-request
plaintext timings are recorded alongside all encryption costs. One/100-request
cost totals are model projections, not one hundred executed requests. A matched
external HEIR compiler measurement was unavailable; no claim against HEIR is made.
Automatic rescaling is included in primitive timings and resulting level/scale
traces; an exact count of internal rescale calls is not exposed here.

Read the [summary](../benchmarks/results/summary.json),
[full confirmation](../benchmarks/results/confirmation-study.json),
[development calibration](../benchmarks/results/development-calibration.json),
[cost coefficients](../benchmarks/results/development-costs.json),
[tight-memory execution](../benchmarks/results/memory-budget-case.json) and
[isolated encrypted dot proof](../benchmarks/results/isolated-dot-proof.json).
The [reproduction guide](reproducibility.md) explains the frozen specification.
