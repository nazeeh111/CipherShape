# Security contract

CipherShape targets client-input confidentiality against an honest-but-curious
server that follows the compiled protocol. OpenFHE 1.6.1 performs the cryptography.
The fixed profile is leveled CKKS, HEStd_128_classic, automatic ring selection,
depth 4, 45-bit scale moduli, 55-bit first modulus and FLEXIBLEAUTO scaling.
It does not bootstrap or silently decrypt intermediates. CKKS is approximate.

Code, model weights, dimensions, declared ranges, ciphertext sizes, operation
counts, timing and request linkage are public. Output leakage is outside input
encryption's protection. This is neither anonymity, differential privacy,
hidden-model protection nor malicious-server correctness. This unaudited
research release makes no enterprise-security claim.

The client generates keys, checks input ranges, encrypts and decrypts. Only
context, public/evaluation keys, public plans and ciphertexts are exported.
Client answers, raw decrypted values, decryption failures and noise diagnostics
never go back to the server. Final full-packing binary masks clear all
non-result slots, with their level and runtime charged. The evaluation binary
has an evaluation-only entry point and rejects unmasked output exports.

Each request runs in a fresh native process. Version, program digest, context
digest, owner key epoch and request identity must agree. No secret-plaintext
fingerprint or cross-request intermediate cache exists. The loopback HTTP API
uses standard HMAC-SHA256 request authentication, a 30-second freshness window,
nonce replay rejection and an ephemeral owner-scoped key passed in memory.
File-envelope SHA256 values are integrity/binding checks, not authentication.
Exported files require trusted local transport or an authenticated channel.
The included HTTP endpoint binds only to 127.0.0.1; remote deployment/TLS,
multi-owner service management and persistent sessions are out of scope.

Graph, shape, depth, payload, file-set and plan checks bound supported work.
Native workers have CPU/file-size limits and a wall-time kill path. Linux also
has allocation/address-space limits. macOS rejects finite RLIMIT_DATA on the
tested environment and does not offer the same hard memory guarantee here;
it uses admission checks and reports its own peak RSS. Peak live coefficient
bytes exclude key maps, allocator overhead and temporary library allocations;
full process RSS is reported separately. Failed checks are rejected, never
handled through a plaintext fallback.

Envelope validation is not a proof that adversarial native ciphertext parsing
is safe. The supported threat model follows OpenFHE's honest-but-curious model;
hostile authenticated owners, malicious ciphertexts and compromised local
hosts need stronger isolation than this local demonstration. A server cannot
check encrypted values against client range declarations. A shared-laptop demo
does not protect against an attacker controlling that laptop.

Sources: [OpenFHE security guidance](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/security.html),
[CKKS security discussion](https://openfhe.org/security-of-ckks/).
