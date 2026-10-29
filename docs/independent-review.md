# Independent implementation review

Status: core numerical and protocol checks passed on 2026-10-29; release verification remains separate. This is an implementation review, not a cryptographic audit or malicious-ciphertext safety proof.

The reviewer worked separately from the implementation owner and used the attached objective as the acceptance contract. The review contributed [adversarial tests](../tests/test_adversarial_review.py). Early failures and standalone probes were retained in the isolated task-local reviewer workspace.

## Executed observations

- Initial adversarial run: 10 failed, 7 passed, 6 encrypted tests deliberately deselected because native binaries were unavailable. The failures identified missing total-memory admission, noninteger resource limits, frontend/native public-constant disagreement, and malformed-envelope exceptions.
- The first complete native review run executed 42 cases: 41 passed, and one control assertion needed updating because the resource meter now adds `peak_rss_bytes`. The updated control then passed independently, requiring both actual execution and positive measured memory. There were no encrypted numerical or protocol failures in that run.
- The final combined local suite subsequently passed **all 87 tests**, including the review cases, on the final client/server binaries. The retained test log was read back separately. The clean-wheel analytics and model runs also reported accepted changed-input execution.
- Real encrypted checks passed for boundary values, changed inputs and cancellation-prone sums. They compare the original centered statistics, explicitly compiled raw-moment formulas and encrypted/decrypted execution at the same declared tolerance. All decoded non-result real slots were checked. The final client rebuild additionally checks complex-slot residuals; its fresh-process dot proof passed with error approximately `3.32e-9` and maximum non-result complex magnitude `2.24e-10`.
- Actual native rejection checks passed for unmasked export, missing rotation keys, depth exhaustion, a wrong-key ciphertext with an otherwise correctly rehashed envelope, and truncated ciphertext with an updated digest. These last two reach native validation rather than stopping only at the outer integrity check.
- Other executed cases cover changed program/context/epoch/version binding, corrupted ciphertext digest, symlink rejection, forged/unrelated compiled plans, calibration validation, HMAC authentication, stale/non-finite timestamps, replay, excessive declared payload, incomplete headers, and a continuously slow body that must respect an absolute deadline.
- Cancellation controls first demonstrate that the disposable helper actually starts; they then verify that timeout or owner-server shutdown prevents its delayed side effect. These helpers test process lifecycle, not cryptographic execution. An earlier test incorrectly accepted a generic startup failure as cancellation; its assertion was tightened and the control rerun successfully.
- An independent explicit-slot interpreter checked 120 compiler plans across packed/scalar layouts, direct/unit/sparse key bases, shared/per-output computation and retain/last-use schedules. This is compiler-semantics evidence only; encrypted accuracy is a separate gate.
- Source review verified separate native client/server builds, a server API with no private-directory argument, client-only decryption diagnostics, explicit OpenFHE `HEStd_128_classic`, and multiplication by a full-packing `[1,0,...,0]` output mask. Display truncation is not used as the mask.
- A 30-node shared graph validated in approximately 0.00082 seconds on Python 3.13 after cached structural identities replaced recursive dataclass hashing. Before the fix, hashing 24 shared additions exceeded the ten-second probe limit on Python 3.13, while Python 3.14 masked the problem.
- The CKKS-only serialization adapter was compared with the pinned upstream headers. It preserves class versions, registration names, type traits, field serialization and context-factory canonicalization. Unsupported bootstrap/scheme-switch objects remain null. Fresh-process encrypted execution subsequently passed. A stock-header cross-reader interoperability build was not executed.

## Findings and disposition

| Finding | Disposition |
|---|---|
| Native memory limits checked only after evaluation; total-memory declaration unused | Pre-admission live-ciphertext estimate, own-child peak RSS measurement, client/server budget propagation, timeout/process-group cancellation and Linux allocation limits added. Actual worker-control accounting passes. macOS rejected finite `RLIMIT_DATA`, so this host has no hard native allocation guarantee; see [security limits](security.md). |
| Setup accepted arbitrary or unrelated `Plan` instructions | Canonical recompilation check added; forged/foreign plan tests pass. |
| Native interpreter could export an input without final masking | Native export now requires mask provenance; direct native rejection and encrypted unused-slot checks pass. |
| Fractional and boolean count/byte limits accepted | Integer validation added; regression passes. |
| Public constants accepted by graph but rejected by native parser | Shared finite bound added; regression passes. |
| Malformed envelopes surfaced raw Python exceptions | Object/binding validation added; regression passes. |
| Planner could mark request over payload/native-input limits feasible | Payload/input/instruction guards added; independent probes now reject oversized executable plans. |
| `choose()` silently substituted default request horizon/bandwidth for workload declarations | Defaults now use workload declarations; regression passes. |
| Incomplete/negative calibration produced negative calibrated latency | Complete finite nonnegative operation prices and positive byte sizes now validated; regression passes. |
| Per-output baseline uploaded duplicate representations of identical inputs | Upload mapping deduplicated while retaining independent encrypted arithmetic. |
| Idle HTTP timeout allowed continuously slow delivery to occupy the single handler | Absolute preauthentication deadline added; continuous slow-delivery regression passes. |
| Small shared graphs hash exponentially on supported Python versions | Cached structural identities added; Python 3.13 timing probe and regression pass. |

## Required remaining confirmation

The core run used client SHA-256 `9d1265b30b7c1f5081eb6d57b771b0086bcb68efefe8b9c0670f24f682427e42` and server SHA-256 `7e0cbe54e84b9d2daecaa9a685b4113243de443ee0d1aab973c7bf520107e827`. The serialization adapter SHA-256 was `9d29a194a387c3c55808ec8f59571c8da46ef42468f40b2cf3b9bc1dba0eb91c`.

The final complex-slot client SHA-256 is `3bbd387f9193ab1d0ee4b83bc07d09fe72681facddcaa9bde6e92dbe6fc29592`; the server hash is unchanged. Its proof is retained in the [isolated dot execution record](../benchmarks/results/isolated-dot-proof.json). These artifacts were read back independently after execution. The benchmark runtime is frozen separately in study provenance.

The completed local study was read back: all eight application/variant combinations accepted two changed-input requests each. Its numerical maximum error was `9.45e-9` at a `1e-4` tolerance. The planner did not establish a latency advantage over the strongest baseline; see the [measured results and limits](results.md).

Remote CI, source/download verification and the public release remain separate gates. Local execution and this review do not establish their completion.

Do not infer completed encrypted computation or a release from passing plaintext/interpreter tests. SHA-256 envelope checks provide binding and corruption detection; request authentication must be provided separately. A shared laptop is not isolation against its administrator.
