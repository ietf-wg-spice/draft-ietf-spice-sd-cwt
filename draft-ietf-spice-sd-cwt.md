---
title: "SPICE SD-CWT"
category: info

docname: draft-ietf-spice-sd-cwt-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Secure Patterns for Internet CrEdentials"
keyword:
 - cose
 - cwt
 - selective disclosure
venue:
  group: "Secure Patterns for Internet CrEdentials"
  type: "Working Group"
  mail: "spice@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spice/"
  github: "ietf-wg-spice/draft-ietf-spice-sd-cwt"
  latest: "https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html"

author:
  -
    fullname: "Michael Prorock"
    organization: mesur.io
    email: "mprorock@mesur.io"
  -
    fullname: "Orie Steele"
    organization: Transmute
    email: "orie@transmute.industries"

  -
    ins: H. Birkholz
    name: Henk Birkholz
    org: Fraunhofer SIT
    abbrev: Fraunhofer SIT
    email: henk.birkholz@ietf.contact
    street: Rheinstrasse 75
    code: '64295'
    city: Darmstadt
    country: Germany

normative:
  RFC7515:
  RFC7519:
  RFC8392:
  BCP205:

informative:
  I-D.ietf-oauth-selective-disclosure-jwt: SD-JWT


--- abstract

This document describes a data minimization technique for use with CBOR Web Token (CWT) {{RFC8392}}.
The approach is based on SD-JWT {{-SD-JWT}}, with changes to align with CBOR Object Signing and Encryption (COSE).
This document updates {{RFC8392}}.


--- middle

# Introduction

This document updates RFC8392, enabling the holder of a CWT to disclose or redact special claims marked disclosable by the issuer of a CWT.
The approach is modeled after SD-JWT, with changes to align with conventions from CBOR Object Signing and Encryption (COSE).
The ability to minimize disclosure of sensitive identity attributes, while demonstrating possession of key material and enabling a verifier to confirm the attributes have been unaltered by the issuer, is an important building block for many digital credential use cases.
This specification brings selective disclosure capabilities to CWT, enabling application profiles to impose additional security criteria beyond the minimum security requirements this specification requires.
Specific use cases are out of scope for this document.
However, feedback has been gathered from a wide range of stakeholders, some of which is reflected in the examples provided in the appendix.


## Overview

Figure 1: High level SD-CWT Issuance and Presentation Flow

~~~ aasvg
Issuer                           Holder                         Verifier
  |                                |                                 |
  |                                +---+                             |
  |                                |   | Key Gen                     |
  |        Request SD-CWT          |<--+                             |
  |<-------------------------------|                                 |
  |                                |                                 |
  +------------------------------->|             Request Nonce       |
  |        Receive SD-CWT          +-------------------------------->|
  |                                |                                 |
  |                                |<--------------------------------+
  |                                |             Receive Nonce       |
  |                                +---+                             |
  |                                |   | Redact Claims               |
  |                                |<--+                             |
  |                                |                                 |
  |                                +---+                             |
  |                                |   | Demonstrate                 |
  |                                |<--+ Posession                   |
  |                                |                                 |
  |                                |             Present SD-CWT      |
  |                                +-------------------------------->|
  |                                |                                 |
~~~

This diagram captures the essential details necessary to issue and present an SD-CWT.
The parameters necessary to support these processes can be obtained using transports or protocols which are out of scope for this specification.
However the following guidance is generally recommended, regardless of protocol or transport.

1. The issuer SHOULD confirm the holder controls all confirmation material before issuing credentials using the `cnf` claim.
2. To protect against replay attacks, the verifier SHOULD provide a nonce, and reject requests that do not include an acceptable an nonce (cnonce). This guidance can be ignored in cases where replay attacks are mitigated at another layer.


# Terminology

{::boilerplate bcp14-tagged}


The terminology used in this document is inherited from RFC8392, RFC9052 and RFC9053.

This document defines the following new terms related to concepts originally described in SD-JWT.

Selective Disclosure CBOR Web Token (SD-CWT)
: A CWT with claims enabling selective disclosure with key binding.

Selective Disclosure Key Binding Token (SD-CWT-KBT)
: A CWT used to demonstrate possession of a confirmation method, associated to an SD-CWT.

Salted Disclosed Claims
: The salted claims disclosed via an SD-CWT.

Digested Salted Disclosed Claim
: A hash digest of a Salted Disclosed Claims.

Redacted keys
: The hashes of claims redacted from a map data structure.

Redacted elements
: The hashes of elements redacted from an array data structure.

Presented Disclosed Claimset
: The CBOR map containing zero or more Redacted keys or Redacted elements.

Validated Disclosed Claimset
: The CBOR map containing all mandatory to disclose claims signed by the issuer, all selectively disclosed claims presented by the holder, and ommiting all instances of redacted_keys and redacted_element claims that are present in the original sd_cwt.

Issuer
: An entity that produces a Selective Disclosure CBOR Web Token.

Holder
: An entity that presents a Selective Disclosure CBOR Web Token which includes a Selective Disclosure Key Binding Token.

Partial Disclosure
: When a subset of the original claims protected by the Issuer, are disclosed by the Holder.

Full Disclosure
: When the full set of claims protected by the Issuer, is disclosed by the Holder.

Verifier
: An entity that validates a Partial or Full Disclosure by a holder.

# Overview of Selective Disclosure CWT

## A CWT without Selective Disclosure

Below is the payload of a standard CWT without selective disclosure. It
consists of standard CWT claims, the holder confirmation key, and five specific
custom claims. The payload is shown below in CBOR Extended Diagnostic
Notation (EDN) {{!I-D.ietf-cbor-edn-literals}}. Note that some of the CWT claim
map keys shown in the examples have been invented for this example and do not
have registered integer keys.

~~~ cbor-diag
{
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "WRQ2RbY5RYJCIxfDQL9agl9fFSCYVu4Xocqb6zerc1M",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : {
      / cose key / 1 : {
        / alg: ES256 /  3: -7,
        / kty: EC2   /  1: 2,
        / crv: P-256 / -1: 1,
        / x / -2: b64'hVTrJ13Nb70cesZBqiyQ2SAi_Q0wJLWvGMfMYa1Sei0',
        / y / -3: b64'TceuLGd-ltDMgll2Vc6S1VA_VCk9h4ddHnnOR3AZQ0M'
      }
    },
    / name /  170 : "Alice Smith",
    / age_at_least_18 /  500 : true,
    / age_at_least_21 /  501 : false,
    / swversion / 271 : [
      "3.5.5",
      "4.1.7"
    ],
    / address /  187 : {
        "country"   : "us",          / United States /
        "region"    : "ca",          / California /
        "locality"  : "San Francisco",
        "post_code" : "94188"
    }
}
~~~

The custom claims consist of the Holder's name (Alice Smith), that she is at
least 18 years old but not yet 21, that her client supports software
versions 3.5.5 and 4.1.7, and her address is in San Francisco.

## Holder gets an SD-CWT from the Issuer

Alice would like to selectively disclose some of these (custom) claims to
different verifiers. (For brevity, we will leave out the name and locality
claims.) Note that some of the claims may not be selectively disclosable
(Alice's country and her oldest supported software version in this example).
First she requests an SD-CWT from her issuer. The issuer generates an SD-CWT as follows:

~~~ cbor-diag
/ cose-sign1 / 18([
  / protected / << {
    / alg / 1  : -35, / ES384 /
    / typ / 16 : "application/sd+cwt",
    / kid / 4  : 'https://issuer.example/cwk3.cbor'
  } >>,
  / unprotected / {
    / sd_claims / 17 : /these are all the disclosures/
    <<[
        <<[
            /salt/   h'8d5c15fa86265d8ff77a0e92720ca837',
            /claim/  500,  / age_at_least_18 /
            /value/  true
        ]>>,
        <<[
            /salt/   h'd84c364fad31e0075213141ca7d1408f',
            /claim/  501,  / age_at_least_21 /
            /value/  false
        ]>>,
        <<[
            /salt/   h'30eef86edeaa197df7bd3d17dd89cd87',
            /claim/  "region",
            /value/  "ca" /California/
        ]>>,
        <<[
            /salt/   h'284538c4a1881fac49b2edc550c1913e',
            /claim/  "post_code",
            /value/  "94188"
        ]>>,
        <<[
            /salt/   h'86c84b9c3614ba27073c7e5a475a2a13',
            /value/  "4.1.7"
        ]>>
    ]>>
  },
  / payload / << {
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "WRQ2RbY5RYJCIxfDQL9agl9fFSCYVu4Xocqb6zerc1M",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : {
      / cose key / 1 : {
        / alg: ES256 /  3: -7,
        / kty: EC2   /  1: 2,
        / crv: P-256 / -1: 1,
        / x / -2: h'hVTrJ13Nb70cesZBqiyQ2SAi_Q0wJLWvGMfMYa1Sei0',
        / y / -3: h'TceuLGd-ltDMgll2Vc6S1VA_VCk9h4ddHnnOR3AZQ0M'
      }
    },
#    / sd_hash / 11       : h'abcdef12', / TODO: fix ??? /
    / sd_alg /  12       : -16, / SHA-256 /
    / redacted_keys / 13 : [
        / redacted age_at_least_18 /
        h'7e6e350907d0ba3aa7ae114f8da5b360' +
        h'601c0bb7995cd40049b98e4f58fb6ec0',
        / redacted age_at_least_21 /
        h'1e7275bcda9bc183079cd4515c5c0282' +
        h'a2a0e9105b660933e2e68f9a3f40974b'
    ],
    / swversion / 271 : [
      "3.5.5",
      /redacted version "4.1.7" /
      { "...":  h'a0f74264a8c97655c958aff3687f1390' +
                h'ed0ab6f64cd78ba43c3fefee0de7b835' }
    ],
    "address": {
        "country" : "us",            / United States /
        /redacted_keys/ 13 : [
            / redacted region /
            h'c47e3b047c1cd6d9d1e1e01514bc2ec9' +
            h'ed010ac9ae1c93403ec72572bb1e00e7',
            / redacted post_code /
            h'0b616e522a05d8d134a834979710120d' +
            h'41ac1522b056d5f9509cf7e850047302'
        ]
    }
  } >>,
  / signature / h'3337af2e66959614' /TODO: fix /
])
~~~

Some of the claims are *redacted* in the payload. The corresponding
*disclosure* is communicated in the unprotected header in the `sd_claims`
key. For example, the `age_at_least_18` claim is a Salted Disclosed Claim,
consisting of a per-disclosure random salt, the claim name, and claim value.

~~~ cbor-diag
<<[
    /salt/   h'8d5c15fa86265d8ff77a0e92720ca837',
    /claim/  500,  / age_at_least_18 /
    /value/  true
]>>,
~~~

This is represented in hex by the CBOR byte string value:

~~~
5683508D5C15FA86265D8FF77A0E92720CA8371901F4F5
~~~

The SHA-256 hash (the hash algorithm identified in the `sd_hash` field in
the payload) of that bytes string is the Digested Salted Disclosed Claim
(in hex). The digest value is included in the payload in a `redacted_keys`
field for a Redacted Key (in this example), or in a named array for a Redacted Element (ex: for a redacted element of `swversion`).

~~~
7e6e350907d0ba3aa7ae114f8da5b360601c0bb7995cd40049b98e4f58fb6ec0
~~~

# Holder prepares an SD-CWT for a Verifier

When the Holder wants to send an SD-CWT and disclose none, some, or all
of the redacted values, it makes a list of the values to disclose and puts
them in `sd_claims` in the unprotected header.

For example, Alice decides to disclosure to a verifier the `age_at_least_18`
claim (true), the `region` claim (California), and the other element in the
`swversion` array (4.1.7).

~~~ cbor-diag
/ sd_claims / 17 : /just the disclosures chosen by the Holder/
<<[
	<<[
		/salt/   h'8d5c15fa86265d8ff77a0e92720ca837',
		/claim/  500,  / age_at_least_18 /
		/value/  true
	]>>,
	<<[
		/salt/   h'30eef86edeaa197df7bd3d17dd89cd87',
		/claim/  "region",
		/value/  "ca" /California/
	]>>,
	<<[
		/salt/   h'86c84b9c3614ba27073c7e5a475a2a13',
		/value/  "4.1.7"
	]>>
]>>
~~~

The Holder will also typically fetch a nonce from the Verifier to prevent
replay.

Finally, the Holder generates a Selective Disclosure Key Binding Token
(SD-KBT) that ties together any disclosures, the Verifier nonce and target
audience, and proof of possession of the Holder's private key.

~~~
/ sd_kbt    / 18 : << 18([
  / protected / << {
	  / alg / 1 : -7 / ES256 /,
	  / typ / 16 : "application/kb+cwt"
  } >>,
  / unprotected / {},
  / payload / << {
	/ cnonce / 39    : h'8c0f5f523b95bea44a9a48c649240803',
	/ aud     / 3    : "https://verifier.example/app",
	/ iat     / 6    : 1725283443, / 2024-09-02T06:24:03Z /
	/ sd_alg  / 12 : -16,  /SHA-256/
	/ sd_hash / 11 :
	/hash of sd_claims in target SD-CWT using hash in sd_alg/
    h'4287237578266d07a3a2909fab6579ce9b4ab8f61b67afa00f6724b9b952557b'
  } >>,
  / signature / h'1237af2e678945'  / TODO: fix /
]) >>
~~~

Finally, the unprotected part of the SD-CWT received from the Holder is replaced with the `sd_claims` and `sd_kbt` fields generated by the Holder.

Together the digests in protected parts of the issued SD-CWT, and the disclosures hashed in the SW-KBT are used by the Verifier to confirm the
disclosed claims.

# SD-CWT Issuance

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE.

An SD-CWT is a CWT containing the hash digest (the "blinded claim hash") of each blinded claim in `redacted_values` in the payload, and optionally the salted claim values (and often claim names) for the values that are actually disclosed in the `sd_claims` claim in the unprotected header. When blinding an individual item in an array, the value of the item is replaced with a dict containing only the special key "...".

~~~ cddl
redacted_element = { "...": bstr }
~~~

A Holder key binding CWT (#kbt) MUST be present in a `sd_kbt` claim in the unprotected header when presenting an SD-CWT to a Verifier.
The `sd_kbt` claim can only be absent when the Issuer is providing the
SD-CWT to the Holder.

An SD-CWT is a CWT containing zero or more Digested Salted Disclosed Claim, and zero or more Salted Disclosed Claims.
The salt acts as a blinding factor, preventing a Verifier of an SD-CWT from learning claims that were not intentionally disclosed by a Holder.

The following informative CDDL is provided to explain the syntax for an
SD-CWT presentation. A complete CDDL schema is in (#cddl).

Please note this example contains claims for demonstration of the disclosure syntax, such as `swversion`, `address`, and ``.

~~~ cddl
sd-cwt-presentation = #6.18([
   protected: bstr .cbor sd-protected,
   unprotected-presentation,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

sd-protected = {
   &(typ: 16) ^ => "application/sd+cwt",
   &(alg: 1) ^ => int,
   * key => any
}

unprotected-presentation = {
   &(sd_kbt: TBD2) ^ => bstr .cbor kbt-cwt,
   ? &(sd_claims: TBD1) ^ => bstr .cbor [ + bstr .cbor salted ],
   * key => any
}

sd-payload = {
    ; standard claims
      &(iss: 1) ^ => tstr, ; "https://issuer.example"
      &(sub: 2) ^ => tstr, ; "https://device.example"
      &(aud: 3) ^ => tstr, ; "https://verifier.example"
    ? &(exp: 4) ^ => int,  ; 1883000000
    ? &(nbf: 5) ^ => int,  ; 1683000000
      &(iat: 6) ^ => int,  ; 1683000000
      &(cnf: 8) ^ => { * key => any }, ; key confirmation
    ? &(cnonce: 39) ^ => bstr,
    ;
    ; sd-cwt new claims
      &(sd_alg: TBD4) ^ => int,            ; -16 for sha-256
    ? &(redacted_values: TBD5) ^ => [ * bstr ],
    * key => any
}
~~~

Disclosures for named claims are structured as a 32 bit salt, the name of the redacted element, and the disclosed value. For disclosures of items in an array, the name is ommitted.

~~~ cddl
salted = salted-claim / salted-element
salted-claim = [
  bstr ;.size 16,     ; 128-bit salt
  (int / text),      ; claim name
  any                ; claim value
]
salted-element = [
  bstr ;.size 16,     ; 128-bit salt
  any                ; claim value
]
~~~

## Creating a Key Binding Token {#kbt}

~~~ cddl

digested-salted-disclosed-claim = bstr;
salted-disclosed-claim = salted-claim / salted-element
salted-claim = [
  bstr .size 16,  ; 128-bit salt
  (int / text),   ; claim name
  any             ; claim value
]
salted-element = [
  bstr .size 16, ; 128-bit salt
  any            ; claim value
]
sd-cwt-cnf = COSE_Key / Encrypted_COSE_Key / kid
sd-cwt = [
  protected,
  unprotected: {
    ?(sd_claims: TBD1): bstr .cbor [ + salted-disclosed-claim ],
    ?(sd_kbt: TBD2): bstr .cbor sd-cwt-kbt,
  },
  payload :  bstr .cbor {
    ?(iss: 1) => tstr, ; "https://issuer.example"
    ?(sub: 2) => tstr, ; "https://device.example"
    ?(aud: 3) => tstr, ; "https://verifier.example"
    ?(exp: 4) => int,  ; 1883000000
    ?(nbf: 5) => int,  ; 1683000000
    ?(iat: 6) => int,  ; 1683000000
    &(cnf: 8) => sd-cwt-cnf,  ; 1683000000

    ?(sd_alg: TBD4) => int,             ; -16 for sha-256
    ?(redacted_keys: TBD5) => [         ; redacted map keys
      digested-salted-disclosed-claim
    ],

    ; redaction in an example map value that is an array
    &(example-array-key: -65537) => [
      123,
      { ; redacted array element
        &(redacted_element: TBD6) =>
        digested-salted-disclosed-claim
      },
      789,
      { ; redacted array element
        &(redacted_element: TBD6) =>
        digested-salted-disclosed-claim
      },
    ]
  }
  signature : bstr,
]
~~~

As described above, an SD-CWT is a CWT with claims that require confirmation and support selective disclosure.
Confirmation mitigates risks associated with bearer token theft.
Note that new confirmation methods might be registered and used after this document is published.
Selective disclosure enables data minimization.
The mechanism through which map keys and array elements are disclosed is different, see SD-CWT Validation for details.
CWT Claims which are not explictly marked redactable by the Issuer are mandatory to disclose by the Holder.
A detailed privacy and security analysis of all mandatory and optionally disclosed claims SHOULD be performed prior to issuance.

# SD-CWT Presentation

Presentations of an SD-CWT by a Holder to a Verifier require the Holder to issue an SD-CWT-KBT.

The SD-CWT-KBT is essential to assuring the Verifier:

- a) the Holder of the SD-CWT controls the confirmation method chosen by the Issuer.
- b) the Holder's disclosures have not been tampered with since confirmation occured.

The SD-CWT-KBT prevents an attacker from copying and pasting disclosures, or from adding or removing disclosures without detection.
Confirmation is established according to RFC 8747, using the `cnf` claim in the payload of the SD-CWT.
The Digested Salted Disclosed Claim are included in the `sd_hash` claim in the payload of the SD-CWT-KBT.

The proof of possession associated with the confirmation claim in an SD-CWT is called the SD-CWT-KBT.
As noted above, SD-CWT Issuance, `sd_kbt` SHALL be present in every presentation of an SD-CWT by a Holder to a Verifier.

~~~ cddl
kbt-cwt = #6.18([
   protected: bstr .cbor kbt-protected,
   kbt-unprotected,
   payload: bstr .cbor kbt-payload,
   signature: bstr
])

kbt-protected = {
   &(typ: 16)^ => "application/kb+cwt",
   &(alg: 1)^ => int,
   * key => any
}

kbt-unprotected = {
   * key => any
}

kbt-payload = {
      &(aud: 3) ^ => tstr, ; "https://verifier.example"
    ? &(exp: 4) ^ => int,  ; 1883000000
    ? &(nbf: 5) ^ => int,  ; 1683000000
      &(iat: 6) ^ => int,  ; 1683000000
      &(cnonce: 39) ^ => bstr,
      ; matches the hash of sd_claims in the presentation token
      &(sd_hash: TBD3) ^ => bstr,
    * key => any
}
~~~

Note that `sd_hash` is the digest using `sd_alg` of the `sd_claims` which are either Partially or Fully Redacted in the Presented SD-CWT.

The `cnonce` and `audience` are essential to assure the Verifier that the Holder is currently in control of the associated confirmation method, and that the holder intended to disclose the SD-CWT to the Verifier.

Note that `cnonce` is a `bstr` and MUST be treated as opaque to the Holder.

The details associated with these protocol parameters are out of scope for this document.

# SD-CWT Validation

The exact order of the following steps MAY be changed, as long as all checks are performed before deciding if an SD-CWT is valid.

First the Verifier must validate the SD-CWT as described in {{Section 7.2 of RFC8392}}.

After validation, the SD-CWT-KBT MUST be extracted from the unprotected header, and validated as described in {{Section 7.2 of RFC8392}}.

The Verifier MUST confirm the `sd_hash` claim of the validated SD-CWT-KBT matches the hash of the `sd_claims` member of the unprotected header, using the hash algorithm obtained from the validated `sd_alg` claim of the SD-CWT.

Next, the Verifier MUST extract and decode the disclosed claims from the `sd_claims` in the unprotected header.

The decoded `sd_claims` are converted to an intermediate data structure called a Digest To Disclosed Claim Map which is used to transform the Presented Disclosed Claimset, into a Validated Disclosed Claimset.

The Verifier MUST compute the hash of each `salted-disclosed-claim`, in order to match each disclosed value to each entry of the Presented Disclosed Claimset.

One possible concrete representation of the intermediate data structure for the Digest To Disclosed Claim Map could be:

~~~ cddl-ish
{
  &(digested-salted-disclosed-claim) => salted-disclosed-claim
}
~~~

The Verifier constructs an empty cbor map called the Validated Disclosed Claimset, and initializes it with all mandatory to disclose claims from the verified Presented Disclosed Claimset.

Next the Verifier performs a breadth first or depth first traversal of the Presented Disclosed Claimset, Validated Disclosed Claimset, using the Digest To Disclosed Claim Map to insert claims into the Validated Disclosed Claimset when they appear in the Presented Disclosed Claimset.
By performing these steps, the recipient can cryptographically verify the integrity of the protected claims and verify they have not been tampered with.
If there remain unused Digest To Disclosed Claim Map at the end of this procedure the SD-CWT MUST be considered invalid, as if the siganture had failed to verify.
Otherwise the SD-CWT is considered valid, and the Validated Disclosed Claimset is now a CWT Claimset with no claims marked for redaction.
Further validation logic can be applied to the Validated Disclosed Claimset, as it might normally be applied to a validated CWT claimset.


## Credential Types

This specification defines the CWT claim vct (for verifiable credential type). The vct value MUST be a case-sensitive StringOrURI (see {{RFC7519}}) value serving as an identifier for the type of the SD-CWT claimset. The vct value MUST be a Collision-Resistant Name as defined in Section 2 of {{RFC7515}}.

This claim is defined COSE based verifiable credentials, similar to the JOSE based verifiable credentials described in Section 3.2.2.1.1 of SD-JWT-VC.

Profiles built on this specifiation are also encouraged to use more specific media types, as described in [draft-ietf-cose-typ-header-parameter](https://datatracker.ietf.org/doc/draft-ietf-cose-typ-header-parameter/).


# Examples

TBD - Provide more examples

## Minimal spanning example

The following example contains claims needed to demonstrate redaction of key-value pairs and array elements.

~~~~~~~~~~
{::include ./sd-cwt-example.cbor-diag}
~~~~~~~~~~
{: #example-edn title="An EDN Example"}

# Security Considerations

Security considerations from COSE {RFC9052} and CWT {RFC8392} apply to this specificaton.

## Random Numbers

Each salt used to protect disclosed claims MUST be generated independently from the salts of other claims. The salts MUST be generated from a source of entropy that is acceptable to the issuer.
Poor choice of salts can lead to brute force attacks that can reveal redacted claims.

# IANA Considerations

## COSE Header Parameters

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).

### sd_claims

The following completed registration template per RFC8152 is provided:

Name: sd_claims
Label: TBD1 (requested assignment 17)
Value Type: bstr
Value Registry: (empty)
Description: A list of selectively disclosed claims, which were originally redacted, then later disclosed at the discretion of the sender.
Reference: RFC XXXX

### sd_kbt

The following completed registration template per RFC8152 is provided:

Name: sd_kbt
Label: TBD2 (requested assignment 18)
Value Type: bstr
Value Registry: (empty)
Description: Key binding token for disclosed claims
Reference: RFC XXXX

## CBOR Web Token (CWT) Claims

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cwt/cwt.xhtml).

### sd_alg

The following completed registration template per RFC8392 is provided:

Claim Name: sd_alg
Claim Description: Hash algorithm used for selective disclosure
JWT Claim Name: sd_alg
Claim Key: TBD4 (request assignment 12)
Claim Value Type(s): integer
Change Controller: IETF
Specification Document(s): RFC XXXX

### sd_hash

The following completed registration template per RFC8392 is provided:

Claim Name: sd_hash
Claim Description: Hash of encoded disclosed claims
JWT Claim Name: sd_hash
Claim Key: TBD3 (request assignment 11)
Claim Value Type(s): bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_values

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_values
Claim Description: Redacted claims in a map.
JWT Claim Name: redacted_keys
Claim Key: TBD5 (request assignment 13)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_element

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_element
Claim Description: Redacted element of an array
JWT Claim Name: redacted_element
Claim Key: TBD (request assignment TBD6)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### vct

The following completed registration template per RFC8392 is provided:

Claim Name: vct
Claim Description: Verifiable credential type
JWT Claim Name: vct
Claim Key: TBD (request assignment TBD7)
Claim Value Type(s): bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

## Media Types

This section requests the registration of new media types in https://www.iana.org/assignments/media-types/media-types.xhtml.

### application/sd+cwt

IANA is requested to add the following entry to the media types registry in accordance with RFC6838, RFC4289, and RFC6657.

The following completed registration template is provided:

* Type name: application
* Subtype name: sd+cwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary
* Security considerations: See the Security Considerations section
  of RFC XXXX, and {{RFC8392}}
* Interoperability considerations: n/a
* Published specification: RFC XXXX
* Applications that use this media type: TBD
* Fragment identifier considerations: n/a
* Additional information:
      Magic number(s): n/a
      File extension(s): n/a
      Macintosh file type code(s): n/a
* Person & email address to contact for further information:
  Michael Prorock, mprorock@mesur.io
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Michael Prorock, mprorock@mesur.io
* Change controller: IETF
* Provisional registration?  No

### application/kb+cwt

IANA is requested to add the following entry to the media types registry in accordance with RFC6838, RFC4289, and RFC6657.

The following completed registration template is provided:

* Type name: application
* Subtype name: kb+cwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: binary
* Security considerations: See the Security Considerations section
  of RFC XXXX, and {{RFC8392}}
* Interoperability considerations: n/a
* Published specification: RFC XXXX
* Applications that use this media type: TBD
* Fragment identifier considerations: n/a
* Additional information:
      Magic number(s): n/a
      File extension(s): n/a
      Macintosh file type code(s): n/a
* Person & email address to contact for further information:
  Orie Steele, orie@transmute.industries
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Orie Steele, orie@transmute.industries
* Change controller: IETF
* Provisional registration?  No


--- back

# Complete CDDL Schema {#cddl}

~~~~~~~~~~
{::include ./sd-cwts.cddl}
~~~~~~~~~~
{: #cddl-schema title="A complete CDDL description of SD-CWT"}

# Comparison to SD-JWT

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE.

## Media Types

The COSE equivalent of `application/sd-jwt` is `application/sd+cwt`.

THe COSE equivalent of `application/kb+jwt` is `application/kb+cwt`.

## Redaction Claims

The COSE equivalent of `_sd` is TBD5.

The COSE equivalent of `...` is TBD6.

## Issuance

The issuance process for SD-CWT is similar to SD-JWT, with the exception that a confirmation claim is REQUIRED.

## Presentation

The presentation process for SD-CWT is similar to SD-JWT, with the exception that a Key Binding Token is REQUIRED.

## Validation

The validation process for SD-JWT is similar to SD-JWT, however, JSON Objects are replaced with CBOR Maps which can contain integer keys and CBOR Tags.

# Implementation Status

Note to RFC Editor: Please remove this section as well as references to {{BCP205}} before AUTH48.

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{BCP205}}.
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to {{BCP205}}, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.
It is up to the individual working groups to use this information as they see fit".

## Transmute Prototype

Organization: Transmute Industries Inc

Name: https://github.com/transmute-industries/sd-cwt

Description: An open source implementation of this draft.

Maturity: Prototype

Coverage: The current version ('main') implements functionality similar to that described in this document, and will be revised, with breaking changes to support the generation of example data to support this specification.

License: Apache-2.0

Implementation Experience: No interop testing has been done yet. The code works as proof of concept, but is not yet production ready.

Contact: Orie Steele (orie@transmute.industries)

# Keys used in the examples

## Subject / Holder

Holder key pair in JWK format

~~~
{
  "kty": "EC",
  "alg": "ES256",
  "kid": "WRQ2RbY5RYJCIxfDQL9agl9fFSCYVu4Xocqb6zerc1M",
  "crv": "P-256",
  "x": "hVTrJ13Nb70cesZBqiyQ2SAi_Q0wJLWvGMfMYa1Sei0",
  "y": "TceuLGd-ltDMgll2Vc6S1VA_VCk9h4ddHnnOR3AZQ0M",
  "d": "V1moblm7OwAt3kZ9pLUvPQbmws1DlFbPBIW5uGQpTOU"
}
~~~

Input to Holder public JWK thumbprint (ignore line breaks)

~~~
{"crv":"P-256","kty":"EC","x":"hVTrJ13Nb70cesZBqiyQ2SAi_Q0wJLWvGMfMYa1S
ei0","y":"TceuLGd-ltDMgll2Vc6S1VA_VCk9h4ddHnnOR3AZQ0M"}
~~~

SHA-256 of the Holder public JWK input string (in hex)

~~~
59143645b6394582422317c340bf5a825f5f15209856ee17a1ca9beb37ab7353
~~~

Holder public JWK thumbprint

~~~
WRQ2RbY5RYJCIxfDQL9agl9fFSCYVu4Xocqb6zerc1M
~~~

Holder public key in PEM format

~~~
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhVTrJ13Nb70cesZBqiyQ2SAi/Q0w
JLWvGMfMYa1Sei1Nx64sZ36W0MyCWXZVzpLVUD9UKT2Hh10eec5HcBlDQw==
-----END PUBLIC KEY-----
~~~

Hodler private key in PEM format

~~~
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgV1moblm7OwAt3kZ9
pLUvPQbmws1DlFbPBIW5uGQpTOWhRANCAASFVOsnXc1vvRx6xkGqLJDZICL9DTAk
ta8Yx8xhrVJ6LU3HrixnfpbQzIJZdlXOktVQP1QpPYeHXR55zkdwGUND
-----END PRIVATE KEY-----
~~~

## Issuer

Issuer key pair in JWK format

~~~
{
"kty": "EC",
"alg": "ES384",
"kid": "https://issuer.example/cwk3.cbor",
"crv": "P-384",
"x":"wxeYsMeIX6NSj7-HfltMOm3GelpdxrMHtyjDclkm8qvl-0lkzZHjlIpUk_brtsu_",
"y":"j2x-x2FpHK03TE2qk4dFPxgFjs5Y6wqOhKBVox-3-SFLJ1CVIsFZ52T4cR4RYJVU",
"d":"ccVNIiGTfqYS2xIh8NPd93HJOBxOO-QdWqConWhfCc_vdMS78QR4P9V-h6sifQdM"
}
~~~

Input to Issuer JWK thumbprint (ignore line breaks)

~~~
{"crv":"P-384","kty":"EC","x":"wxeYsMeIX6NSj7-HfltMOm3GelpdxrMHtyjDclkm
8qvl-0lkzZHjlIpUk_brtsu_","y":"j2x-x2FpHK03TE2qk4dFPxgFjs5Y6wqOhKBVox-3
-SFLJ1CVIsFZ52T4cR4RYJVU"}
~~~

SHA-256 of the Issuer JWK input string (in hex)

~~~
18d4ddb7065d945357e3972dee76af4eddc7c285fb42efcfa900c6a4f8437850
~~~

Issuer JWK thumbprint

~~~
GNTdtwZdlFNX45ct7navTt3HwoX7Qu_PqQDGpPhDeFA
~~~

Issuer public key in PEM format

~~~
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEwxeYsMeIX6NSj7+HfltMOm3GelpdxrMH
tyjDclkm8qvl+0lkzZHjlIpUk/brtsu/j2x+x2FpHK03TE2qk4dFPxgFjs5Y6wqO
hKBVox+3+SFLJ1CVIsFZ52T4cR4RYJVU
-----END PUBLIC KEY-----
~~~

Issuer private key in PEM format

~~~
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBxxU0iIZN+phLbEiHw
0933cck4HE475B1aoKidaF8Jz+90xLvxBHg/1X6HqyJ9B0yhZANiAATDF5iwx4hf
o1KPv4d+W0w6bcZ6Wl3Gswe3KMNyWSbyq+X7SWTNkeOUilST9uu2y7+PbH7HYWkc
rTdMTaqTh0U/GAWOzljrCo6EoFWjH7f5IUsnUJUiwVnnZPhxHhFglVQ=
-----END PRIVATE KEY-----
~~~

# Acknowledgments
{:numbered="false"}

The authors would like to thank those that have worked on similar items for providing selective disclosure mechanisms in JSON, especially:
Brent Zundel, Roy Williams, Tobias Looker, Kristina Yasuda, Daniel Fett,
Oliver Terbu, and Michael Jones.
