# Interop implementation requirements

Each implementation is expected to write at least one of the following command line programs which calls their library or application inside a directory with the test files:

## Issue

Usage: issue <issuer_priv>
<!--             [--redact <redact_list>]  -->
             [--nonces <nonce_list>]
             [--time <secs_since_epoch>]

The program expects a CBOR map claims set on stdin. The claims set may include To Be Redacted tags and/or To Be Decoy tags. If an implementation does not support these tags, it MUST stop with an error code. Unless otherwise specified the claims set includes date claims and the cnf claim.

<issuer_priv> is the name of a file that contains a PEM-encoded private key

<!--
<redact_list> is the name of a CBOR file that contains either an array of map keys in the top level map of the claims set, or an array of CBOR pointers referring to the claims set.
-->

<nonce_list> is a CSV file whose first field is either the hex encoded SHA-256 hash of a disclosure without the first element, or an integer > 0; the second field is the nonce associated with either the hash of the array or map disclosure, or the integer of the decoy digest. If it is present, any field or decoy which matches will use the provided salt. If the file is not present, or any more disclosures are present, those discosures will have a random salt generated.
The file nonce_list.out is written to the current directory with all the nonces used.

If <secs_since_epoch> is present and is an integer, the time claims in the claims set are verified as if the current time were <secs_since_epoch>.

If successful, the program outputs an issued SD-CWT to stdout

It outputs parsing notes and errors on stderr

It returns 0 if it successful and another implementation-specific code otherwise

## Present

Usage: present <holder_priv> [--issuer <issuer_pub>]
               [--issuer-key { ignore | fetch | cache }]
               [--disclosure_list <disclosure_list> ]
               [--disclose_all]
               [--encrypt_list <encrypt_list>]
               [--aead-key <aead_key>]
               [--aead-key-context <key_context>]
               [--aead-nonces <aead_nonce_list>]
               [--audience <audience_string>]
               [--time <secs_since_epoch>]


<holder_priv> is the name of a file that contains a PEM-encoded private key of the holder.

<issuer_pub> is the name of a file that contains a PEM-encoded public key of the issuer. If it is not present and none of the issuer_key options is selected, verification of the SD-CWT fails.

if issuer-key is "ignore", no validation will be performed on the issuer
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to fetch the public key from the URL in the kid.
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to load a file in the local directory that has the value of the "filename" after the last forward slash in the URL.

if disclosure_all is selected, all disclosures are included in the presentation.

<disclosure_list> is the name of a CBOR file containing an array of salt values, indicating which disclosures to include.

<encrypt_list> is the name of a CBOR file containing an array of salt values, indicating which disclosures to send AEAD encrypted in `sd_aead_encrypted_claims` (171) instead of in plaintext in `sd_claims` (17). A disclosure in <encrypt_list> does not also need to be in <disclosure_list>, and is never sent in plaintext. The AEAD algorithm is `sd_aead` (172) from the SD-CWT protected header, or AEAD_AES_128_GCM if it is absent. Neither header parameter is sent as an empty array.

<aead_key> is the name of a file containing the hex encoded AEAD key. It is required with <encrypt_list>.

<key_context> is an optional `aead-key-context` added to every encrypted disclosure: an unsigned integer if it is all digits, otherwise a text string.

<aead_nonce_list> is a CSV file whose first field is the hex encoded salt of a disclosure in <encrypt_list> and whose second field is the hex encoded AEAD nonce to use for it. It exists only to make test vectors reproducible; without it every nonce is random.

<audience_string> is the KBT audience. If it is not present, "https://verifier.example/app" is used.

If <secs_since_epoch> is present and is an integer, the time claims in both KBT and SD-CWT are verified as if the current time were <secs_since_epoch>.

The program expects an Issuer SD-CWT on stdin

If successful, the program outputs a KBT to stdout

It outputs parsing notes and errors on stderr

It returns 0 if it successful and another implementation-specific code otherwise


## Verify

Usage: verify [--issuer <issuer_pub>]
              [--issuer-key { ignore | fetch | cache }]
              [--audience <audience_string>]
              [--aead-key <aead_key>]...
              [--time <secs_since_epoch>]

<issuer_pub> is the name of a file that contains a PEM-encoded public key of the issuer. If it is not present and none of the issuer_key options is selected, verification of the SD-CWT fails.

if issuer-key is "ignore", no validation will be performed on the issuer
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to fetch the public key from the URL in the kid.
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to load a file in the local directory that has the value of the "filename" after the last forward slash in the URL.

If <audience_string> is present, the implementation checks that the KBT audience contains the string (note: the audience could be an array).

<aead_key> is the name of a file containing a hex encoded AEAD key, and may be repeated. Each entry in `sd_aead_encrypted_claims` is decrypted with the keys given (selected by its `aead-key-context` if the implementation supports that) and then processed exactly as if it had been in `sd_claims`, so it must match a Redacted Claim Hash. If a key is given but fails to decrypt an entry, verification fails. Entries for which no key is given are not an error: they are left undisclosed (an initial Verifier may forward them), and the implementation notes them on stderr.

If <secs_since_epoch> is present and is an integer, the time claims in both KBT and SD-CWT are verified as if the current time were <secs_since_epoch>.

The program expects a KBT on stdin

If successful, the program outputs a CBOR validated claims set map to stdout

It outputs parsing notes and errors on stderr

It returns 0 if it successful and another implementation-specific code otherwise


## Target name

Each implementation is also expected to have a single implementation name of up to 16 characters containing only the following characters: [a-z0-9_]

Usage: target

Outputs the short name of the implementation to stdout (without a new line)


# Directory structure

Under the `interop` directory, there is an `implementations` directory.
Each implementation should have a directory under `implementations` with its short name. For example if I have an implementation called `foobar` that can be Issuer and Verifier, there will be directory `interop/implementations/foobar` containing executables called `issue`, `verify`, and `target`.

Results of test runs are in the `interop/tests` directory.
Combinations of implementations are of the form `I={issuer}_H={holder}_V={verifier}`.
For example using `foobar` with a Holder implementation called `baz` would result in an implementation string `I=foobar_H=baz_V=foobar`.
Individual test runs have a directory with a time stamp.
Individual test cases each have a name, like `shipping_manifest4`.

## AEAD encrypted disclosures

`run_aead.py` runs the `aead_first_disclosure` test case for every pair of implementations that has both `present` and `verify`, writing results to `tests/I=draft_H={holder}_V={verifier}/{timestamp}/`. The Issuer is the draft itself (`examples/issuer_cwt.cbor`), so no `issue` is needed. See `test_cases/aead_first_disclosure/README.md` for the checks.

```sh
SD_CWT_PYTHON=/path/to/sd-cwt/.venv/bin/python \
SD_CWT_JS_DIR=/path/to/sd-cwt-js \
  python3 run_aead.py            # or: run_aead.py --impl sd_cwt --impl sd_cwt_js
```

`run_aead.py` itself needs `cbor2`.

## Registered implementations

| Directory | Library | Roles | Setup |
|---|---|---|---|
| `esdicawt` | [beltram/esdicawt](https://github.com/beltram/esdicawt) (rust) | issue, present, verify | symlinks to a local `interop` build |
| `sd_cwt` | [tradeverifyd/sd-cwt](https://github.com/tradeverifyd/sd-cwt) (python) | present, verify | `SD_CWT_PYTHON`: a python with `sd-cwt` installed |
| `sd_cwt_js` | [tradeverifyd/sd-cwt-js](https://github.com/tradeverifyd/sd-cwt-js) (javascript) | present, verify | `SD_CWT_JS_DIR`: a checkout with `npm install` done |
