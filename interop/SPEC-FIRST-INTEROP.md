# Latest-spec interoperability: draft -09

Executed 19 November 2026 against **draft-ietf-spice-sd-cwt-09**, verified as the
latest published draft in the IETF Datatracker. The editor's main branch and
published tag both resolve to `79c43819c74c3240b3eab8601996d2b694e30087`.

## Correction to the previous report

The 18 November report used -08 requirements and incorrectly called Beltram's
unprotected algorithm header 172 a current-spec defect. **That conclusion is
withdrawn.** Draft -09 moves `sd_aead` to unprotected headers, as Beltram already
implemented. Our implementations and test expectations needed updating. The
previous 511/539 and 259/261 results are historical -08 comparisons, not evidence
of a -09 Rust defect. Their immutable evidence is retained with that qualification.

## Exact revision and implementation pins

- Specification: [published draft -09](https://datatracker.ietf.org/doc/draft-ietf-spice-sd-cwt/09/),
  spec commit `79c43819c74c3240b3eab8601996d2b694e30087`.
- Python: `3054dd7`, [draft -09 PR #7](https://github.com/tradeverifyd/sd-cwt/pull/7).
- JavaScript: `1ed5ebe`, [draft -09 PR #6](https://github.com/tradeverifyd/sd-cwt-js/pull/6).
- Beltram: `c6eb0e426ac3e8ecdbcadf70f2a9d44af05a748f`, still the tip of
  `feat/encrypted-disclosures` when checked on 19 November. Library source is
  unchanged; `cli.patch` exposes its AEAD APIs through the interop CLI.

[spec-version.json](spec-version.json) records the published text hash and hashes
of the normative Markdown and all root CDDL files. Every runner checks those
source hashes before executing and records the manifest with its results. A
modified-schema negative control demonstrated that a mismatch aborts the run.
This pin makes results reproducible; future releases require an explicit spec
review and pin update, not silently using whatever happens to be on main.

## Reviewed -08 to -09 changes

| Change | Implementation and evidence |
|---|---|
| Section 12.1 / CDDL move 172 to unprotected headers | Holder-selected AES-128/AES-256/ChaCha20, preserving issuer-signed bytes; native Rust AES-256 fixtures in both libraries; nine Holder × Verifier combinations for AES profiles |
| Section 9 adds explicit AEAD processing | Available supported keys decrypt and authenticate; wrong selected keys invalidate; absent keys and unsupported permitted algorithms remain opaque; decrypted entries undergo normal hash/location checks |
| Nonce may select an out-of-band key | Python adds an entry-aware resolver; JavaScript already exposes entry and algorithm; nonce-lookup regression tests |
| IANA type for 171 includes optional context | Existing uint/text/bstr support retained; 32/48/64-byte contexts exercised across implementations |
| First-disclosure example digest corrected | Both libraries match `af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693`; six canonical binary fixtures checked against the -09 tag |

The full normative source/CDDL diff was reviewed and saved with the evidence.
Python's obsolete embedded -04/TBD schema was also replaced with the -09 schema.
The algorithm-selection APIs and migration behavior are documented in each
implementation's `DRAFT-09.md` and pinned in `SPEC-VERSION.json`.

**Editorial inconsistency for co-authors:** a later sentence in -09 section 12.1
still says “sd_aead protected header field.” The changed opening paragraph,
CDDL, and explicit placement change (`cf867df`, merged in #301) say unprotected.
The implementations and oracle follow the latter. No normative draft text was
modified by this interop PR.

## Executed results

| Suite | Result |
|---|---|
| Extended complete-claims profiles | **539/539 passed**, zero failed/blocked |
| Encrypted-disclosure and validation probes | **306/306 passed** |
| Original default-AES-128 9-pair matrix | **54/54 passed** |
| Python full suite | **234 passed**; Black, Ruff, MyPy passed |
| JavaScript full suite | **557 passed** on Node 20, 24, and 26; browser build passed |

Counts overlap and must not be added. The 306-case suite adds registered but
unsupported AEAD forwarding, prohibited-algorithm rejection, and AEGIS X tag
length checks to the corrected 261 probes. Negative cases require a successful
signed positive control. Unsupported-algorithm probes test opaque forwarding;
they do not claim cryptographic support for the unsupported cipher.

The 539 profiles cover native Holder/Verifier AES-128 and AES-256 in all nine
ordered implementation pairs, complete nested map/array claims, reversed order,
withholding without keys, invalid tags among valid entries, typed contexts, and
partial parent/child encryption. ChaCha20 and multi-key routing/rotation remain
Python/JavaScript profiles. The Rust adapter exposes AES-128/AES-256, one key and
context, and selection of all disclosures or claim 501; it does not rewrite
headers or re-sign peer output to obtain interoperability.

The canonical -09 binary examples are byte-identical to the copied -08 examples;
the corrected example digest was independently pinned. Derived regression tokens
use public Appendix C keys and historical verification clocks. Each library now
has a `fixtures/draft-09` directory with provenance, including native Rust
AES-256 output. Historical dates do not disable time validation.

## Reproduce

Build a new adapter checkout using `implementations/esdicawt_aead/setup.sh` and
set `ESDICAWT_AEAD_BIN` to its binary. Install Python and JavaScript from the
implementation revisions above; set `SD_CWT_PYTHON` and `SD_CWT_JS_DIR` accordingly.

```sh
"$SD_CWT_PYTHON" interop/run_profiles.py --rust \
  --python-repo /path/to/sd-cwt --js-repo "$SD_CWT_JS_DIR" \
  --output /tmp/new-draft09-profiles
"$SD_CWT_PYTHON" interop/run_encrypted.py \
  --impl sd_cwt --impl sd_cwt_js --impl esdicawt_aead \
  --python-repo /path/to/sd-cwt --js-repo "$SD_CWT_JS_DIR" \
  --rust-repo /path/to/esdicawt-adapter --output /tmp/new-draft09-encrypted
"$SD_CWT_PYTHON" interop/run_aead.py \
  --impl sd_cwt --impl sd_cwt_js --impl esdicawt_aead
```

All three commands now exit zero. Output directories must be new. Explicit
algorithm selection is a Holder option (`--aead-algorithm` for Python/JS); the
Rust adapter selects its associated AES type from the supplied key size. The
issuer fixture no longer embeds 172 in protected headers. Independently
constructed non-default-algorithm probes modify only unprotected issuer headers
and re-sign the enclosing KBT; the issuer-signed bytes stay unchanged.

[Manifest and evidence](results/draft-09-2026-11-19/manifest.json) include exact
commands, input/output CBOR, expected claims, stderr, implementation states,
specification/source hashes, unit logs, and archives. Historical 18 November
results and snapshots are retained separately and explicitly superseded.

## Limits

The tested profiles and reviewed revision delta now align with the latest
published spec. This is not exhaustive certification of every unchanged
requirement. Remaining work includes a complete issuance/Holder-validation
matrix, every signature/hash and confirmation-method profile, claims split
between payload and protected header 15, exhaustive map-key/nesting rules,
resource limits/fuzzing, and application replay/revocation policy. SHA-256 is the
supported high-level disclosure hash. These gaps are untested, not passes.
