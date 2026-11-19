# Encrypted disclosure interoperability — 18 November 2026

> **Correction, 19 November:** This is a historical -08 experiment. Draft -09
> moves header 172 to unprotected headers; Beltram's placement is correct.
> The latest [pinned -09 rerun](SPEC-FIRST-INTEROP.md) passes all tested profiles.
> To reproduce this old snapshot, use its historical commits and saved patches,
> not the current -09 runners.


> Historical snapshot. See [the spec-first follow-up](SPEC-FIRST-INTEROP.md)
> for current implementation revisions, expanded adapter capabilities, and results.


**Follow-up:** [Deeper profile coverage](PROFILE-INTEROP.md) adds complete-claims
comparisons, nested/array disclosures, three algorithms, thumbprint contexts, and
two-key routing. The results below are the preserved first experiment.

The default AES-128-GCM disclosure format interoperates in both directions between
Python, JavaScript, and Beltram's encrypted-disclosures branch. The expanded run
passes **259 of 261 checks**: one draft-conformance difference and one unsupported
adapter capability remain. This is evidence for the cases below, not complete
SD-CWT conformance or arbitrary algorithm/profile interoperability.

## Revisions and changes under test

| Component | Revision | Local changes |
|---|---|---|
| Draft | `477fb7209b79ee4dd87a0946e030b681e07e6b7f` | Harness and report; normative draft and canonical fixtures unchanged |
| tradeverifyd/sd-cwt | `5a2744c8ebb2d67e912e450aa2c3fce70c61ff46` | Reject duplicate recovered disclosures; regression tests |
| tradeverifyd/sd-cwt-js | `55b32bef7135056207dccdca344eefc9a55244b1` | Reject duplicate recovered disclosures; regression tests |
| beltram/esdicawt | `c6eb0e426ac3e8ecdbcadf70f2a9d44af05a748f` | CLI adapter only; library source unchanged |

The Rust revision was the tip of `feat/encrypted-disclosures` when fetched. Its
stock interop CLI still rejects `--encrypt_list` and `--aead-key`; the library's
new APIs are behind its `aead` feature. The checked-in
[adapter patch](implementations/esdicawt_aead/cli.patch) enables that feature and
calls `new_encrypted_presentation_raw` and `verify_encrypted_sd_kbt`. Encryption,
decryption, serialization, disclosure validation, and signatures are performed
by Rust. The adapter does not repair or translate Rust's output.

The adapter deliberately supports encryption of only the draft's top-level claim
501, one AES-128-GCM key, and unsigned integer or text contexts. It resolves the
selected salt to claim 501 and fails on unsupported selections. Fixed nonces are
used only for the draft test vector; ordinary presentation calls use `OsRng`.
The adapter's subject handling is inherited from upstream's CLI. Neither the
adapter nor these tests are production key-management code.

## Results and limits

| Checks | Result |
|---|---|
| Existing draft vector: 9 Holder × Verifier pairs × 6 assertions | 54/54 passed |
| Expanded interoperability: fixed ciphertext, contexts, fresh nonces, encrypted-only presentations, with/without/wrong key | 138/138 passed |
| Expanded validation and header placement | 110/111 passed |
| Explicit protected algorithm fixtures | 11 passed, 1 unsupported |

The 54 original checks overlap the expanded suite and are **not added** to its
261 total. Each of Python and JavaScript passes all 79 verifier checks, including
Rust-produced presentations. Rust passes all 78 supported verifier checks.

The one conformance difference is **header 172 placement**. The draft's
[AEAD mechanism](../draft-ietf-spice-sd-cwt.md#aead) says `sd_aead` is protected;
Rust's `DisclosureEncryption::try_encrypt` sets it in `SdUnprotected`.
The default algorithm still interoperates because Python and JavaScript default
to AES-128-GCM when no protected algorithm exists. This passing matrix must not
be interpreted as agreement on explicit algorithm selection. Rust's AES-256
probe is marked **unsupported**, because this adapter only constructs
`Aes128Gcm` and rejects 32-byte keys. It is not evidence that Rust's generic AEAD
API cannot support AES-256.

The initial expanded baseline passed 250/261 checks. It found that Python
accepted both repeated encrypted disclosures and the same disclosure in plaintext
and ciphertext; JavaScript accepted repeated encrypted disclosures. These map
claims would disclose the same key at the same location twice, contrary to the
draft's validation step 8. Rust already rejected them. The local fixes compare
recovered plaintext disclosures before reconstruction, including when different
nonces produce different ciphertexts. These checks do not reject an opaque
ciphertext merely because a verifier has no key. The exact fixes are saved as
[Python](results/encrypted-disclosures-2026-11-18/sd-cwt.patch) and
[JavaScript](results/encrypted-disclosures-2026-11-18/sd-cwt-js.patch) patches.

Python's full test suite passes **152/152**; JavaScript's AEAD suite passes
**27/27**. JavaScript's full suite passes **493/498**. The same five failures
(two verification tests and three `cose-js` interop tests) reproduce on an
unchanged `55b32be` checkout using the same installed dependencies: **491/496**.
They are not presented as passing or fixed by this work. Logs are in the results
directory.

## What the probes establish

`run_encrypted.py` exercises every ordered Holder × Verifier pair. In addition
to the original fixture, it checks integer/text contexts, no-key forwarding,
random-nonce production, encrypted-only presentations, audience and holder
signature rejection, empty headers, altered nonces/ciphertexts/tags, duplicate
disclosures, foreign disclosures without a matching Redacted Claim Hash, and
incorrectly unwrapped plaintext.

Malformed embedded disclosures are re-signed with the Appendix C holder key.
Each pair must first pass both the original and re-signed positive controls;
otherwise a rejection is not counted as a successful negative test. Only exit 1
counts as rejection; missing commands, timeouts, and CLI usage errors do not.
Independent AES-GCM and COSE fixture construction uses `cryptography` and `cbor2`,
not the SD-CWT libraries. The explicit algorithm fixtures are also issuer-signed.
The plaintext, empty AAD, and ciphertext are pinned by the canonical draft
vector. Context checks verify carrying a context and decrypting with a selected
key; they do not establish a multi-key routing profile.

Not covered: nested/array encrypted disclosures, byte-string thumbprint contexts
across implementations, multiple recipient keys, all AEAD algorithms, alternative
hash algorithms, issuer interoperability, expiry/replay policy, or complete claims
set equivalence beyond the assertions in the runner. The fixed issuance is the
draft's credential, so this is a Holder/Verifier matrix.

## Reproduce

Use Python with `cbor2` and `cryptography`, Node with the JavaScript checkout's
installed dependencies, and a Rust toolchain capable of building the pinned
branch (tested with Rust 1.96.0). The Rust Cargo lockfile is checked in beside the
adapter so dependency branches do not float on replay.

```sh
# From the draft repository. The destination must not already exist.
interop/implementations/esdicawt_aead/setup.sh /tmp/esdicawt-aead
export ESDICAWT_AEAD_BIN=/tmp/esdicawt-aead/target/debug/interop
export SD_CWT_PYTHON=/path/to/sd-cwt/.venv/bin/python
export SD_CWT_JS_DIR=/path/to/sd-cwt-js

# For exact replay, check out the revisions above in separate checkouts and
# apply the saved sd-cwt.patch and sd-cwt-js.patch there with git apply.
# Python must be installed from that checkout (for example, pip install -e .).
"$SD_CWT_PYTHON" interop/run_aead.py \
  --impl sd_cwt --impl sd_cwt_js --impl esdicawt_aead
"$SD_CWT_PYTHON" interop/run_encrypted.py \
  --impl sd_cwt --impl sd_cwt_js --impl esdicawt_aead \
  --python-repo /path/to/sd-cwt --js-repo "$SD_CWT_JS_DIR" \
  --rust-repo /tmp/esdicawt-aead --output /tmp/new-encrypted-results
```

The expanded command intentionally exits 1 while the known header-placement
check fails. Do not suppress failures or replace the expected header location
to make the matrix green. Its output directory must be new. Results include
revision/dirty-state provenance, patch and source hashes, commands, exit codes,
input/output CBOR, stderr, and artifact SHA-256 hashes. Timestamps, random
nonces, and ECDSA signatures can change between runs; expected semantics and the
fixed encrypted-disclosure vector must not.

The [saved results](results/encrypted-disclosures-2026-11-18/results.json) and
[evidence archive](results/encrypted-disclosures-2026-11-18/evidence.tar.gz)
contain the expanded run. `baseline-results.json` and `baseline-evidence.tar.gz`
retain the pre-fix failures. The HTML report labels the previous main-branch
snapshot separately from this feature-branch experiment. No upstream changes
were pushed or published.
