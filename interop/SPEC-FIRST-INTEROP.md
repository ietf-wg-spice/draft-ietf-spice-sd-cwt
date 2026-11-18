# Spec-first security and interoperability follow-up

Executed 18 November 2026. The specification controls expected results; a peer's
behavior is not a reason to relax validation. This is an executable profile
comparison, not certification of complete SD-CWT conformance.

## Revisions and scope

- Python: `e15e39a`, [implementation PR #6](https://github.com/tradeverifyd/sd-cwt/pull/6).
- JavaScript: `93c0f6e`, [implementation PR #5](https://github.com/tradeverifyd/sd-cwt-js/pull/5).
- Beltram: `c6eb0e426ac3e8ecdbcadf70f2a9d44af05a748f`, still the tip of
  `feat/encrypted-disclosures` when checked with `git ls-remote` on this date.
- Specification: the repository's draft text at `477fb72`, checked alongside
  [published draft-08](https://www.ietf.org/archive/id/draft-ietf-spice-sd-cwt-08.html).
- Rust library source is unchanged. The expanded `cli.patch` enables its AEAD
  APIs and adds AES-256, all-disclosure encryption (nested maps/arrays), and typed
  key contexts. It does not move header 172 or re-sign/translate peer output.

## Results

| Suite | Result |
|---|---|
| Original default-AES-128 9-pair matrix | 54/54 passed |
| Expanded encrypted-disclosure checks | 259/261; two Rust failures |
| Extended profiles | 511 passed, 20 failed, 8 blocked / 539 |
| Rows in extended profiles involving only Python/JavaScript | 316/316 passed |
| Python full suite | 217 passed; Black, Ruff, MyPy passed |
| JavaScript full suite | 541 passed on Node 20/24/26; builds passed in CI |

Counts overlap and must not be added. A negative case is **blocked** when its
positive control fails; an unrelated rejection is not evidence for that negative
check. All 20 profile failures and eight blocked checks involve AES-256 and Rust.

New passing profiles include Rust Holder production and verification of nested
maps/arrays, reordered disclosures, no-key withholding, authenticated bad tags,
32/48/64-byte contexts in both directions, and partial encryption of a child or
of both parent and child while an unrelated array remains plaintext. Multi-key
routing and rotation remain Python/JavaScript tests; the Rust adapter selects one
key and context. ChaCha20 remains Python/JavaScript only.

## Remaining Rust discrepancy: header 172

The draft's AEAD section selects the algorithm from **protected** header 172,
with AES-128-GCM as the default when absent. Rust's `DisclosureEncryption` writes
172 in `SdUnprotected`; its `DisclosureDecryption` reads that unprotected value.

- With default AES-128, the three implementations can exchange presentations.
  Our verifiers ignore the misplaced algorithm and use the specified default;
  this does not make the Rust-produced header placement conformant.
- Given an independently issuer-signed credential with protected 172=2, Rust's
  verifier treats the algorithm as the default and returns success with the
  encrypted claims withheld. Complete-claims comparison catches that failure.
- Rust's AES-256 Holder adds unprotected 172=2 beside the issuer's protected 172=2.
  Python and JavaScript reject this protected/unprotected duplicate, as required
  by COSE. They also reject it without a decryption key.
- Rust-to-Rust AES-256 recovery works in this profile. Agreement between two
  instances of that implementation is not proof of spec conformity.

The former AES-256 **unsupported adapter** result is now an actual, reproducible
compatibility failure. Do not restore that label, read unprotected 172 as an
algorithm fallback, strip the header before verification, or suppress the
positive-control failures to obtain a green matrix.

The evidence archive includes native presentations, issuer-signed fixtures,
expected complete claims, exact commands, stderr, hashes, and repository states.
For example, `profiles/alg-2-draft/sd_cwt/encrypted/esdicawt_aead/full.*`
reproduces withheld claims, and
`profiles/alg-2-draft/esdicawt_aead/encrypted/sd_cwt_js/full.*` reproduces
`Duplicate or unprotected critical header`.

## Spec checks and limits

The implementation PRs add signed positive and adversarial tests for time and
audience policy, resolved holder-key binding (Python), duplicate/reused/unmatched
disclosures, nested reconstruction, COSE critical headers, and header conflicts.
Follow-up tests enforce KBT `iat < credential exp` even with clock leeway,
`application/sd-cwt` and `+sd-cwt` credential types, and rejection of CWT Claims
header 15 in a KBT. An earlier Python media-type spelling error was corrected.

This does **not** establish every requirement in the draft. Remaining work
includes an issuance/Holder-validation matrix, every permitted signature/hash
and confirmation-method profile, claims split between payload and protected
header 15 (including equal/conflicting redacted claims), exhaustive allowed
map-key and nesting checks, resource limits/fuzzing, and stateful replay and
revocation policy. SHA-256 is the supported high-level disclosure hash. The
Rust adapter also does not expose arbitrary single nested-path selections,
multiple keys, or ChaCha20. Those are explicitly untested, not passes.

The five Node 26 test failures were in the development-only `cose-js` oracle's
legacy CBOR synchronous stream collector. A test-only helper preserves the
independent encoder and cryptography and collects all output chunks; fixed-byte
and large-payload controls verify it. No tests were skipped. Python's dependency
audit now passes including development dependencies on Python 3.13 after replacing
Safety's incompatible filelock constraint with pip-audit and a fixed filelock
minimum. Node's production audit is clear; one unfixed elliptic advisory appears
as two low-severity development dependency findings (elliptic and cose-js).

## Reproduction and evidence

Build a new adapter checkout using `implementations/esdicawt_aead/setup.sh` and
set the three environment variables documented in `ENCRYPTED-INTEROP.md`.
Use the exact implementation commits above, installed from their checkouts.

```sh
"$SD_CWT_PYTHON" interop/run_profiles.py --rust \
  --python-repo /path/to/sd-cwt --js-repo "$SD_CWT_JS_DIR" \
  --output /tmp/new-security-profiles
"$SD_CWT_PYTHON" interop/run_encrypted.py \
  --impl sd_cwt --impl sd_cwt_js --impl esdicawt_aead \
  --python-repo /path/to/sd-cwt --js-repo "$SD_CWT_JS_DIR" \
  --rust-repo /path/to/esdicawt-adapter --output /tmp/new-security-encrypted
```

Both commands intentionally return nonzero for the documented failures. Tests
use explicit epoch 1725244300 inside the historical issuer validity window; they
do not disable time validation. Output directories must be new.

See [results and evidence](results/security-spec-2026-11-18/manifest.json).
Earlier dated reports and archives are retained as historical evidence; their
unit counts and adapter limitations are superseded by this follow-up.
