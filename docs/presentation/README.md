# Reorder x, preserve the encrypted boundary

This is an intentionally public synthetic analytics record from source **0fd63ab89535661e40cb798201fa206c3e0b7265**, version **0.1.1.dev0**. It uses the compatible original v0.1.0 macOS ARM64 native workers, archive SHA256 `dd79b48fa526aaf949384e8040f34e52c8de9efba4be2c7fe09cfa6f2e47b031`. OpenFHE supplies CKKS; CipherShape supplies the graph/compiler/planner and execution lifecycle. Required notices remain in the repository and this bundle's `licenses` directory.

Extract `cipherShape-analytics-reader.zip` into an empty directory and run:

```sh
python3 reopen.py
```

The standard-library reader checks every declared member, independently recomputes the seven ordinary float references per request and the fourteen observed encrypted-versus-compiled errors, and repeats the recorded client acceptance arithmetic. It does not rerun encryption or independently prove the server's cryptographic execution. Open [boundary.html](boundary.html) and [errors.html](errors.html), or the [narrow boundary](boundary-mobile.html) and [narrow error figure](errors-mobile.html), locally without network access or JavaScript.

## Read the result

- [synthetic-inputs.json](synthetic-inputs.json) gives both exact eight-value fixtures. Only x is reversed.
- [analytics-report.json](analytics-report.json) is the unmodified client report: inputs are identified separately, float and compiled references, decrypted outputs, parameters, plan, and operation traces are retained. Incidental timings are observations, not comparative benchmarks. `calibrated: false` means the planner used its provisional costs, not locally measured optimization evidence.
- [error-points.json](error-points.json) gives all fourteen plotted errors. The log axis spans 1e−12 through 1e−3 in both compositions. Circle/square shapes distinguish requests without relying on color. The separate dashed 1e−4 line is the declared tolerance, not an empirical confidence interval.
- [boundary.json](boundary.json) records public plan/parameters and SHA observations of the server's public key material and request/response artifacts. Its `external_artifact_observations_not_bundle_members` field is an index of the executed native artifacts, not files promised in this small reader. Ciphertext/key binaries are intentionally omitted; no secret key or authentication key is included.
- [controls.json](controls.json) records range rejection before publication, a response/request binding refusal, existing-output preservation and two differing ciphertext digests for the same input/context/key.
- [terminal.json](terminal.json) preserves actual successful command stdout with only the owned temporary path replaced by `<RUN>`.

## Run fresh native evaluation

Follow the repository README's current-source and digest-verified prebuilt-worker instructions, then choose a new output directory:

```sh
ciphershape demo analytics --out runs/analytics-fresh
```

The demo generates a client secret and public evaluation material, evaluates two encrypted requests across an authenticated loopback HTTP endpoint in separate native server processes, and saves the client report. Expect fresh keys, ciphertext bytes, request IDs, timings and numerical noise. Compare accepted numerical results and source/profile, not exact ciphertext hashes. This route is not a deployed remote service. Do not publish real client inputs, secrets or decrypted reports.

## Limits

The profile is bounded, approximate CKKS, depth 4, 8,192 slots in ring dimension 16,384, FLEXIBLEAUTO scaling and an HEStd_128_classic requested security profile. The supported threat model is honest-but-curious, not malicious-server correctness. Public code, weights, shapes, counts, sizes, timings and linkage remain visible. The local HMAC endpoint is not remote transport security. On macOS there is no hard address-space cap. Lifecycle staging supports the documented process-interruption recovery contract, not power-loss durability. Consult the repository security and lifecycle documentation before private use.

[render.py](render.py) is the editable figure source. It uses Matplotlib and portable Arial text. Its architecture panels are source-derived illustrations, not captured UI. PNGs are actual Chrome renders of those SVGs. The bundled figures and data stay readable without the renderer's dependencies.
