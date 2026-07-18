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
               [--time <secs_since_epoch>]


<holder_priv> is the name of a file that contains a PEM-encoded private key of the holder.

<issuer_pub> is the name of a file that contains a PEM-encoded public key of the issuer. If it is not present and none of the issuer_key options is selected, verification of the SD-CWT fails.

if issuer-key is "ignore", no validation will be performed on the issuer
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to fetch the public key from the URL in the kid.
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to load a file in the local directory that has the value of the "filename" after the last forward slash in the URL.

if disclosure_all is selected, all disclosures are included in the presentation.

<disclosure_list> is the name of a CBOR file containing an array of salt values, indicating which disclosures to include.

If <secs_since_epoch> is present and is an integer, the time claims in both KBT and SD-CWT are verified as if the current time were <secs_since_epoch>.

The program expects an Issuer SD-CWT on stdin

If successful, the program outputs a KBT to stdout

It outputs parsing notes and errors on stderr

It returns 0 if it successful and another implementation-specific code otherwise


## Verify

Usage: verify [--issuer <issuer_pub>]
              [--issuer-key { ignore | fetch | cache }]
              [--audience <audience_string>]
              [--time <secs_since_epoch>]

<issuer_pub> is the name of a file that contains a PEM-encoded public key of the issuer. If it is not present and none of the issuer_key options is selected, verification of the SD-CWT fails.

if issuer-key is "ignore", no validation will be performed on the issuer
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to fetch the public key from the URL in the kid.
if issuer-key is "fetch", and the kid (4) protected header value is an https: URL, the program will attempt to load a file in the local directory that has the value of the "filename" after the last forward slash in the URL.

If <audience_string> is present, the implementation checks that the KBT audience contains the string (note: the audience could be an array).

If <secs_since_epoch> is present and is an integer, the time claims in both KBT and SD-CWT are verified as if the current time were <secs_since_epoch>.

The program expects a KBT on stdin

If successful, the program outputs a CBOR validated claims set map to stdout

It outputs parsing notes and errors on stderr

It returns 0 if it successful and another implementation-specific code otherwise


## Target name

Each implementation is also expected to have a single implementation name of up to 16 characters containing only the following characters: [a-z0-9_]

Usage: target

Outputs the short name of the implementation to stdout (without a new line)
