# Deeper encrypted-disclosure coverage

> Historical snapshot. See [the spec-first follow-up](SPEC-FIRST-INTEROP.md)
> for current implementation revisions, expanded adapter capabilities, and results.


Follow-up to [the initial encrypted-disclosure experiment](ENCRYPTED-INTEROP.md).
Executed 18 November 2026 against the same base revisions, with the additional
local changes saved in `results/encrypted-profiles-2026-11-18/`.

## What improved

The initial checks established that claim 501 could be recovered. Comparing the
**entire returned claims set**, excluding the confirmation key that the Python
API deliberately omits, exposed a separate Python reconstruction defect:

- Nested disclosures such as `503.region` were incorrectly returned as top-level
  `region` claims.
- Public numeric labels such as 500 and 502 were dropped.
- Array disclosures were not restored to their original positions.

Python now resolves disclosures at their Redacted Claim Hash locations,
recursively reconstructs parent/child maps and array elements, removes
undisclosed elements, preserves numeric labels and unrelated CBOR tags, and
rejects duplicate map keys, repeated consumption, unreachable disclosures,
wrong map/array shapes, and excessive disclosure nesting. Disclosure input
order does not affect the result. Standard top-level aliases `iss`, `sub`, and
`iat` remain unchanged in the public Python API. Applications that relied on the
incorrect top-level `region` must use `claims[503]["region"]` instead.

## Executed results

| Suite | Result |
|---|---|
| Complete-claims reconstruction, before the fix | 136/220 passed |
| Same reconstruction cases, after the fix | 220/220 passed |
| Extended profile suite, including contexts and recipient routing | **316/316 passed** |
| Original encrypted-disclosure suite rerun | 259/261; same known Rust difference and adapter limitation |
| Python full unit suite | **183/183 passed** |
| JavaScript AEAD unit suite | **38/38 passed** |
| JavaScript full unit suite | 504/509; same five pre-existing failures |

The suites overlap in behavior; these counts are not a single combined score.
The original results and patches are retained separately and not rewritten.

`run_profiles.py` adds:

- The draft's complete map and array claims, plus an independently issuer-signed
  fixture with a disclosed parent map, a child disclosure, and an array element.
- Plaintext and fully encrypted presentations, no-key forwarding, reversed
  disclosure order, and one invalid tag among several valid encrypted entries.
- All four Python/JavaScript Holder × Verifier pairs under AES-128-GCM,
  AES-256-GCM, and ChaCha20-Poly1305. Explicit non-default algorithms are in the
  issuer-protected header.
- Rust verification of Python/JavaScript AES-128 presentations for both fixture
  shapes, including withholding and reordering. The existing Rust adapter still
  only produces top-level claim 501 and only exposes AES-128.
- Native Python/JavaScript production of 32-, 48-, and 64-byte thumbprint contexts;
  correct-key lookup, unknown contexts, wrong selected keys, and key-rotation
  candidate lists with the wrong key first.
- Two-recipient presentations where a verifier has both keys, either individual
  key, neither key, or one wrong selected key. These presentations combine native
  encrypted entries and are re-signed with the public fixture holder key; they
  test verifier routing, not a single multi-key Python Holder API call.

Regression fixtures from the other implementation are now included in each
library's AEAD unit suite. Authenticated malformed plaintext is also tested:
invalid CBOR, trailing data, non-preferred byte-string lengths, indefinite byte
strings, and ciphertext authenticated with nonempty AAD. The negative tests use
valid encryption tags so rejection must occur at the relevant decoding/AAD check.

## Real source coverage

Python's `.coveragerc` contained an exclusion line `...`, interpreted as a regex
matching almost every source line. Its old "100%" report measured zero statements.
The pattern now matches only a literal ellipsis statement; the standalone `pass`
pattern is anchored as well. No measured coverage decrease should be inferred
from replacing that invalid report with an actual one.

After the fixes and new tests, coverage.py reports:

| Scope | Line coverage | Branch coverage | Combined |
|---|---|---|---|
| AEAD module | 97.26% | 93.10% | **96.08%** |
| Redaction/reconstruction module | 96.70% | 89.29% | **94.14%** |
| Whole Python package | See saved JSON | See saved JSON | **61.16%** |

The overall figure identifies substantial remaining work, including the legacy
issuer, CLI, validation, and alternate API modules. High AEAD coverage does not
establish complete SD-CWT conformance.

JavaScript now has a dedicated pull-request regression workflow for
`tests/aead.test.js`, using the repository's existing pinned Actions and Node
20/24. Local execution was on Node 24; the hosted workflow has not been run or
published here. The deployment workflow still runs the full suite; the new
focused job does not suppress its five existing failures.

## Reproduce and review

Use the environment and Rust adapter setup from `ENCRYPTED-INTEROP.md`, then:

```sh
"$SD_CWT_PYTHON" interop/run_profiles.py --rust \
  --python-repo /path/to/sd-cwt --js-repo "$SD_CWT_JS_DIR" \
  --output /tmp/new-profile-results
```

Omit `--rust` for Python/JavaScript-only runs. The output directory must be new.
The runner writes input/output CBOR, commands, stderr, exact expected claims,
source hashes, repository revisions, dirty-state metadata, and artifact hashes.
The additional wrapper flags are `--aead-key-context-cbor FILE` for a typed CBOR
context and `--aead-key-map FILE` for a CBOR map from context to a key byte string
or array of candidate key byte strings. Unknown contexts return no key.

The [results](results/encrypted-profiles-2026-11-18/results.json),
[evidence archive](results/encrypted-profiles-2026-11-18/evidence.tar.gz),
[coverage JSON](results/encrypted-profiles-2026-11-18/python-coverage.json),
unit-suite logs, and complete implementation patches are saved together.
The implementation patches include the prior duplicate-disclosure fixes, new
regression fixtures, reconstruction code, coverage configuration, and JS workflow;
apply them to the original base revisions, not on top of the earlier patches.
Baseline evidence and the rerun of the first suite are included in the archive.

Remaining work includes Rust Holder production of nested disclosures, Rust
non-default algorithm and thumbprint-context interop, mixed encryption of a
parent and its descendants, alternative hash algorithms, issuer combinations,
expiry/replay profiles, and broader parser fuzzing. Header 172 placement still
needs alignment with the draft; a passing default-AES matrix does not settle it.
