---
v: 3
title: "SPICE SD-CWT"
category: std
docname: draft-ietf-spice-sd-cwt-latest
stream: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
area: "Security"
workgroup: "Secure Patterns for Internet CrEdentials"
updates: RFC8392
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

  -
    ins: R. Mahy
    fullname: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: "rohan.ietf@gmail.com"

normative:
  RFC7515:
  RFC7519:
  RFC8392:
  RFC9052:
  RFC8949:
  BCP205:

informative:
  I-D.draft-ietf-oauth-selective-disclosure-jwt: SD-JWT
  I-D.draft-ietf-oauth-sd-jwt-vc: SD-JWT-VC
---

--- abstract

This document describes a data minimization technique for use with CBOR Web Token (CWT).
The approach is based on Selective Disclosure JSON Web Token (SD-JWT), with changes to align with CBOR Object Signing and Encryption (COSE).


--- middle

# Introduction

This document updates the CBOR Web Token (CWT) specification {{RFC8392}}, enabling the holder of a CWT to disclose or redact special claims marked disclosable by the issuer of a CWT.
The approach is modeled after SD-JWT {{-SD-JWT}}, with changes to align with conventions from CBOR Object Signing and Encryption (COSE) {{RFC9052}}.
This specification enables Holders of CWT based credentials to prove the integrity and authenticity of selected attributes asserted by an Issuer about a Subject to a Verifier.
Although techniques such as one time use and batch issuance can improve the confidentiality and security characteristics of CWT based credential protocols, CWTs remain traceable.
Selective Disclosure CBOR Web Tokens (SD-CWTs) are CWTs and can be deployed in protocols that are already using CWTs, even if they contain no optional to disclose claims.
Credential types are distinguished by their attributes, for example a license to operate a vehicle and a license to import a product will contain different attributes.
The specification of credential types is out of scope for this document, and the examples used in this document are informative.
SD-CWT operates on CWT Claims Sets as described in {{RFC8392}}.
CWT Claims Sets contain Claim Keys and Claim Values.
SD-CWT enables Issuers to mark certain Claim Keys or Claim Values mandatory or optional for a holder of a CWT to disclose.
A verifier who does not understand optional to disclose Claims in an SD-CWT can still process the mandatory to disclose attributes.
Claim Keys and Claim Values which are not understood remain ignored as described in {{Section 3 of RFC8392}}.

## High level flow

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

This document uses terms from CWT {{RFC8392}}, and COSE {{!RFC9052}}
{{!RFC9053}}.

The terms Claim Name, Claim Key and Claim Value are defined in {{RFC8392}}.

This document defines the following new terms:

Selective Disclosure CBOR Web Token (SD-CWT):
: A CWT with claims enabling selective disclosure with key binding.

Selective Disclosure Key Binding Token (SD-CWT-KBT):
: A CWT used to demonstrate possession of a confirmation method, associated to an SD-CWT.

Issuer:
: An entity that produces a Selective Disclosure CBOR Web Token.

Holder:
: An entity that presents a Selective Disclosure CBOR Web Token which includes a Selective Disclosure Key Binding Token.

Verifier:
: An entity that validates a Partial or Full Disclosure by a holder.

Partial Disclosure:
: When a subset of the original claims protected by the Issuer, are disclosed by the Holder.

Full Disclosure:
: When the full set of claims protected by the Issuer, is disclosed by the Holder. An SD-CWT with no blinded claims (all claims are marked mandatory to disclose by the Issuer) is considered a Full Disclosure.

Salted Disclosed Claim:
: A salted claim disclosed in the unprotected header of an SD-CWT.

Digested Salted Disclosed Claim / Blinded Claim Hash:
: A hash digest of a Salted Disclosed Claim.

Blinded Claim:
: Any Redacted Claim Key or Redacted Claim Element which has been replaced in the
CWT payload by a Blinded Claim Hash.

Redacted Claim Key:
: The hash of a claim redacted from a map data structure.

Redacted Claim Element:
: The hash of an element redacted from an array data structure.

Presented Disclosed Claims Set:
: The CBOR map containing zero or more Redacted Claim Keys or Redacted Claim Elements.

Validated Disclosed Claims Set:
: The CBOR map containing all mandatory to disclose claims signed by the issuer, all selectively disclosed claims presented by the holder, and ommiting all undisclosed instances of Redacted Claim Keys and Redacted Claim Element claims that are present in the original SD-CWT.


# Overview of Selective Disclosure CWT

## A CWT without Selective Disclosure

Below is the payload of a standard CWT without selective disclosure.
It consists of standard CWT claims, the holder confirmation key, and five specific custom claims. The payload is shown below in CBOR Extended Diagnostic
Notation (EDN) {{!I-D.ietf-cbor-edn-literals}}. Note that some of the CWT claim map keys shown in the examples have been invented for this example and do not have registered integer keys.

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
        "postal_code" : "94188"
    }
}
~~~

The custom claims consist of the Holder's name (Alice Smith), that she is at least 18 years old but not yet 21, that her client supports software versions 3.5.5 and 4.1.7, and her address is in San Francisco.

## Holder gets an SD-CWT from the Issuer

Alice would like to selectively disclose some of these (custom) claims to different verifiers.
(For brevity, we will leave out the name and locality claims.) Note that some of the claims may not be selectively disclosable
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
    / sd_claims / 17 : / these are all the disclosures /
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
            /claim/  "postal_code",
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
    / sd_alg /  12       : -16, / SHA-256 /
    / redacted_claim_keys / 65556 : [
        / redacted age_at_least_18 /
        h'7e6e350907d0ba3aa7ae114f8da5b360' +
        h'601c0bb7995cd40049b98e4f58fb6ec0',
        / redacted age_at_least_21 /
        h'1e7275bcda9bc183079cd4515c5c0282' +
        h'a2a0e9105b660933e2e68f9a3f40974b'
    ],
    / swversion / 271 : [
      "3.5.5",
      / redacted version "4.1.7" /
      {
        / redacted_claim_element / 65555:
        h'a0f74264a8c97655c958aff3687f1390' +
        h'ed0ab6f64cd78ba43c3fefee0de7b835'
      }
    ],
    "address": {
        "country" : "us",            / United States /
        / redacted_claim_keys / 65556 : [
            / redacted region /
            h'c47e3b047c1cd6d9d1e1e01514bc2ec9' +
            h'ed010ac9ae1c93403ec72572bb1e00e7',
            / redacted postal_code /
            h'0b616e522a05d8d134a834979710120d' +
            h'41ac1522b056d5f9509cf7e850047302'
        ]
    }
  } >>,
  / signature / h'3337af2e66959614' /TODO: fix /
])
~~~

Some of the claims are *redacted* in the payload. The corresponding *disclosure* is communicated in the unprotected header in the `sd_claims` key.
For example, the `age_at_least_18` claim is a Salted Disclosed Claim, consisting of a per-disclosure random salt, the claim name, and claim value.

~~~ cbor-diag
<<[
    /salt/   h'8d5c15fa86265d8ff77a0e92720ca837',
    /claim/  500,  / age_at_least_18 /
    /value/  true
]>>,
~~~


The SHA-256 hash (the hash algorithm identified in the `sd_hash` field in the payload) of that bytes string is the Digested Salted Disclosed Claim (in hex).
The digest value is included in the payload in a `redacted_claim_keys` field for a Redacted Claim Key (in this example), or in a named array for a Redacted Claim Element (ex: for a redacted claim element of `swversion`).

~~~
7e6e350907d0ba3aa7ae114f8da5b360601c0bb7995cd40049b98e4f58fb6ec0
~~~

# Holder prepares an SD-CWT for a Verifier

When the Holder wants to send an SD-CWT and disclose none, some, or all of the redacted values, it makes a list of the values to disclose and puts them in `sd_claims` in the unprotected header.

For example, Alice decides to disclosure to a verifier the `age_at_least_18` claim (true), the `region` claim (California), and the other element in the `swversion` array (4.1.7).

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

The Holder MAY fetch a nonce from the Verifier to prevent replay, or obtain a nonce acceptable to the verifier through a process similar to the one described in draft-ietf-httpbis-unprompted-auth-12.

Finally, the Holder generates a Selective Disclosure Key Binding Token (SD-KBT) that ties together any disclosures, the Verifier nonce and target audience, and proof of possession of the Holder's private key.

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

Together the digests in protected parts of the issued SD-CWT, and the disclosures hashed in the SW-KBT are used by the Verifier to confirm the disclosed claims.

# SD-CWT definition

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE. An SD-CWT MUST include the protected header parameter `typ` {{!RFC9596}} with the value "application/sd-cwt" in the SD-CWT.

An SD-CWT is a CWT containing the "blinded claim hash" of at least one blinded claim in the CWT payload.
Optionally the salted claim values (and often claim names) for the corresponding Blinded Claim Hash are actually disclosed in the `sd_claims` claim in the unprotected header of the CWT (the disclosures).

Any party with a Salted Disclosed Claim can generate its hash, find that hash in the CWT payload, and unblind the content.
However a Verifier with the hash cannot reconstruct the corresponding blinded claim without disclosure of the Salted Disclosed Claim.

## Types of blinded claims

Salted Disclosed Claims for named claims are structured as a 128-bit salt, the name of the redacted element, and the disclosed value.
For Salted Disclosed Claims of items in an array, the name is omitted.

~~~ cddl
salted = salted-claim / salted-element / decoy
salted-claim = [
  bstr .size 16,     ; 128-bit salt
  (int / text),      ; claim name
  any                ; claim value
]
salted-element = [
  bstr .size 16,     ; 128-bit salt
  any                ; claim value
]
decoy = [
  bstr .size 16,     ; 128-bit salt
]

; a collection of Salted Disclosed Claims
salted-array = [ +bstr .cbor salted ]
~~~

When a blinded claim is a key in a map, its blinded claim hash is added to a `redacted_values` array claim in the CWT payload that is at the same level of hierarchy as the key being blinded.

When blinding an individual item in an array, the value of the item is replaced with a CBOR map containing only the special key "...".

~~~ cddl
redacted_element = { "...": any }
~~~

Blinded claims can be nested. For example, both individual keys in the `address` claim, and the entire `address` element can be separately blinded.
An example nested claim is shown in **TODO iref**.

Finally, an issuer may create "decoy digests" which look like a blinded claim hash but have only a salt.
Decoy digests are discussed in **TODO iref**.


# SD-CWT Issuance

How the Holder communicates to the Issuer to request a CWT or an SD-CWT is out-of-scope of this specification.
Likewise, how the Holder determines which claims to blind or to always disclose is a policy matter which is not discussed in this specification.
This specification defines the format of an SD-CWT communicated between an Issuer and a Holder in this section, and describes the format of an SD-CWT communicated between a Holder and a Verifier in the next section.

The unprotected header MUST contain an `sd_claims` section with a Salted Disclosed Claim for *every* blinded claim hash present anywhere in the payload.
The payload MUST also include a key confirmation element (`cnf`) {{!RFC8747}} for the Holder's public key, and an `sd_alg` claim identifying the algorithm used to hash the Salted Disclosed Claims.

## Issuer generation

The Issuer follows all the requirements of generating a valid CWT.
The Issuer MUST implement COSE_Sign1 using an appropriate asymmetric signature algorithm / curve combination (for example ES256/P-256 or EdDSA/Ed25519)

The Issuer MUST generate a unique cryptographically random salt with at least 128-bits of entropy for each Salted Disclosed Claim.
If the client communicates a client-generated nonce (`cnonce`) when requesting the SD-CWT, the Issuer SHOULD include it in the payload.

## Holder validation

Upon receiving an SD-CWT from the Issuer with the Holder as the subject, the
Holder verifies the following:

- the issuer (`iss`) and subject (`sub`) are correct;
- if an audience (`aud`) is present, it is acceptable;
- the CWT is valid according to the `nbf` and `exp` claims;
- a public key under the control of the Holder is present in the `cnf` claim;
- the hash algorithm in `sd-alg` is supported by the Holder;
- if a `cnonce` is present, it was provided by the Holder to this Issuer and is still "fresh";
- there are no unblinded claims about the subject which violate its privacy policies;
- every blinded claim hash has a corresponding Salted Disclosed Claim, and vice versa;
- all the Salted Disclosed Claims are correct in their unblinded context in the payload.

The following informative CDDL is provided to describe the syntax for an SD-CWT issuance. A complete CDDL schema is in {{cddl}}.

~~~ cddl
sd-cwt-issued = #6.18([
   protected: bstr .cbor sd-protected,
   unprotected-issued,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

sd-protected = {
   &(typ: 16) ^ => "application/sd+cwt",
   &(alg: 1) ^ => int,
   * key => any
}

unprotected-issued = {
   &(sd_claims: 17) ^ => bstr .cbor salted-array,
   * key => any
}

sd-payload = {
    ; standard claims
      &(iss: 1) ^ => tstr, ; "https://issuer.example"
      &(sub: 2) ^ => tstr, ; "https://device.example"
    ? &(aud: 3) ^ => tstr, ; "https://verifier.example/app"
    ? &(exp: 4) ^ => int,  ; 1883000000
    ? &(nbf: 5) ^ => int,  ; 1683000000
      &(iat: 6) ^ => int,  ; 1683000000
      &(cnf: 8) ^ => { * key => any }, ; key confirmation
    ? &(cnonce: 39) ^ => bstr,
    ;
    ; sd-cwt new claims
      &(sd_alg: 12) ^ => int,            ; -16 for sha-256
    ? &(redacted_keys: 65556) ^ => [ * bstr ],
    * key => any
}
~~~


# SD-CWT Presentation

When a Holder presents an SD-CWT to a Verifier, it can disclose none, some, or all of its blinded claims.
If the Holder wishes to disclose any claims, it includes those Salted Disclosed Claims in the `sd_claims` claim of the unprotected header.

~~~ cddl
sd-cwt-presentation = #6.18([
   protected: bstr .cbor sd-protected,
   unprotected-presentation,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

unprotected-presentation = {
   &(sd_kbt: 18) ^ => bstr .cbor kbt-cwt,
   ? &(sd_claims: TBD1) ^ => bstr .cbor salted-array,
   * key => any
}
~~~

As described in the CDDL above, a SD-CWT presentation to a Verifier has the same syntax as an SD-CWT issued to a Holder, except for its unprotected header.
Since the unprotected header is not included in the signature, it will contain all the Salted Disclosed Claims when sent from the Issuer to the Holder.
By comparison, the unprotected header will include a Key Binding Token and contain none, some, or all of these Claims when sent from the Holder to the Verifier.

## Creating a Key Binding Token {#kbt}

Regardless if it discloses any claims, the Holder MUST include a Holder key binding (SD_KBT) {{kbt}} in a `sd_kbt` claim in the unprotected header in every presentation of an SD-CWT by a Holder to a Verifier.
(The `sd_kbt` claim is absent when the Issuer is providing the SD-CWT to the Holder.) An SD-KBT is itself a type of CWT.
The protected header of the SD-KBT MUST include the `typ` header parameter with the value `application/sd-kbt`.

The SD-KBT provides the following assurances to the Verifier:

- the Holder of the SD-CWT controls the confirmation method chosen by the Issuer;
- the Holder's disclosures have not been tampered with since confirmation occurred;
- the Holder intended to address the SD-CWT to the Verifier specified in the audience (`aud`) claim;
- the Holder's disclosure is linked to the creation time (`iat`) of the key binding.

The SD-KBT prevents an attacker from copying and pasting disclosures, or from adding or removing disclosures without detection.
Confirmation is established according to RFC 8747, using the `cnf` claim in the payload of the SD-CWT.

Using the algorithm established in `sd_alg` in the payloads of both the SD-CWT and the SD-KBT, the Holder constructs the hash of all the Salted Disclosed Claims it will share with the Verifier.
This is the hash of the entire `sd_claims` array in the unprotected header of the SD-CWT.
This composite hash is included in the `sd_hash` claim in the payload of the SD-KBT.

The Holder signs the SD-KBT using the key specified in the `cnf` claim in the SD-CWT. This proves possession of the Holder's private key.

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
    ? &(cnonce: 39) ^ => bstr,
      ; matches the hash of sd_claims in the presentation token
      &(sd_hash: 11) ^ => bstr,
    * key => any
}
~~~

The `cnonce` is a `bstr` and MUST be treated as opaque to the Holder.


# SD-CWT Validation

The exact order of the following steps MAY be changed, as long as all checks are performed before deciding if an SD-CWT is valid.
First the Verifier must validate the SD-CWT as described in {{Section 7.2 of RFC8392}}.
After validation, the SD-KBT MUST be extracted from the unprotected header, and validated as described in {{Section 7.2 of RFC8392}}.
The Verifier MUST confirm that the `sd_alg` in the SD-KBT and the `sd_alg` in the SD-CWT are identical, and that the `sd_hash` claim of the validated SD-CWT-KBT matches the hash of the `sd_claims` member of the unprotected header, using the hash algorithm obtained from the validated `sd_alg` claim.
Next, the Verifier MUST extract and decode the disclosed claims from the `sd_claims` in the unprotected header.
The decoded `sd_claims` are converted to an intermediate data structure called a Digest To Disclosed Claim Map which is used to transform the Presented Disclosed Claimset, into a Validated Disclosed Claimset.
The Verifier MUST compute the hash of each Salted Disclosed Claim (`salted`), in order to match each disclosed value to each entry of the Presented Disclosed Claimset.
One possible concrete representation of the intermediate data structure for the Digest To Disclosed Claim Map could be:

~~~ cddl-ish
{
  &(digested-salted-disclosed-claim) => salted
}
~~~

The Verifier constructs an empty cbor map called the Validated Disclosed Claimset, and initializes it with all mandatory to disclose claims from the verified Presented Disclosed Claimset.
Next the Verifier performs a breadth first or depth first traversal of the Presented Disclosed Claimset, Validated Disclosed Claimset, using the Digest To Disclosed Claim Map to insert claims into the Validated Disclosed Claimset when they appear in the Presented Disclosed Claimset.
By performing these steps, the recipient can cryptographically verify the integrity of the protected claims and verify they have not been tampered with.
If there remain unused Digest To Disclosed Claim Map at the end of this procedure the SD-CWT MUST be considered invalid, as if the siganture had failed to verify.
Otherwise the SD-CWT is considered valid, and the Validated Disclosed Claimset is now a CWT Claimset with no claims marked for redaction.
Further validation logic can be applied to the Validated Disclosed Claimset, as it might normally be applied to a validated CWT claimset.

# Decoy Digests

**TODO**

# Credential Types

This specification defines the CWT claim vct (for verifiable credential type). The vct value MUST be a case-sensitive StringOrURI (see {{RFC7519}}) value serving as an identifier for the type of the SD-CWT claimset. The vct value MUST be a Collision-Resistant Name as defined in Section 2 of {{RFC7515}}.

This claim is defined for COSE based verifiable credentials, similar to the JOSE based verifiable credentials claim (`vct`) described in Section 3.2.2.1.1 of {{-SD-JWT-VC}}.

Profiles built on this specification are also encouraged to use more specific media types, as described in {{!RFC9596}}.


# Examples

**TODO** - Provide more examples

## Minimal spanning example

The following example contains claims needed to demonstrate redaction of key-value pairs and array elements.

~~~~~~~~~~
{::include ./sd-cwt-example.cbor-diag}
~~~~~~~~~~
{: #example-edn title="An EDN Example"}


## Nested example

**TODO**


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

Name: [github.com/transmute-industries/sd-cwt](https://github.com/transmute-industries/sd-cwt)

Description: An open source implementation of this draft.

Maturity: Prototype

Coverage: The current version ('main') implements functionality similar to that described in this document, and will be revised, with breaking changes to support the generation of example data to support this specification.

License: Apache-2.0

Implementation Experience: No interop testing has been done yet. The code works as proof of concept, but is not yet production ready.

Contact: Orie Steele (orie@transmute.industries)


# Security Considerations

Security considerations from COSE {(RFC9052)} and CWT {{RFC8392}} apply to this specificaton.

## Random Numbers

Each salt used to protect disclosed claims MUST be generated independently from the salts of other claims. The salts MUST be generated from a source of entropy that is acceptable to the issuer.
Poor choice of salts can lead to brute force attacks that can reveal redacted claims.

# IANA Considerations

## COSE Header Parameters

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).

### sd_claims

The following completed registration template per RFC8152 is provided:

Name: sd_claims
Label: TBD9 (requested assignment 17)
Value Type: bstr
Value Registry: (empty)
Description: A list of selectively disclosed claims, which were originally redacted, then later disclosed at the discretion of the sender.
Reference: RFC XXXX

### sd_kbt

The following completed registration template per RFC8152 is provided:

Name: sd_kbt
Label: TBD8 (requested assignment 18)
Value Type: bstr
Value Registry: (empty)
Description: Key binding token for disclosed claims
Reference: RFC XXXX

## CBOR Web Token (CWT) Claims

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cwt/cwt.xhtml).

<!-- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-12#name-json-web-token-claims-regis -->

### redacted_claim_keys

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_claim_keys
Claim Description: Redacted Claim Keys in a map.
JWT Claim Name: _sd
Claim Key: TBD5 (request assignment 65556)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### redacted_claim_element

The following completed registration template per RFC8392 is provided:

Claim Name: redacted_claim_element
Claim Description: Redacted element of an array
JWT Claim Name: ...
Claim Key: TBD6 (request assignment 65555)
Claim Value Type(s): array of bstr
Change Controller: IETF
Specification Document(s): RFC XXXX

### sd_alg

The following completed registration template per RFC8392 is provided:

Claim Name: sd_alg
Claim Description: Hash algorithm used for selective disclosure
JWT Claim Name: _sd_alg
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

### vct

The following completed registration template per RFC8392 is provided:

Claim Name: vct
Claim Description: Verifiable credential type
JWT Claim Name: vct
Claim Key: TBD7 (request assignment 15)
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

The COSE equivalent of `_sd` is TBD5 (requested assignment 65556).

The COSE equivalent of `...` is TBD6 (requested assignment 65555).

## Issuance

The issuance process for SD-CWT is similar to SD-JWT, with the exception that a confirmation claim is REQUIRED.

## Presentation

The presentation process for SD-CWT is similar to SD-JWT, with the exception that a Key Binding Token is REQUIRED.

## Validation

The validation process for SD-JWT is similar to SD-JWT, however, JSON Objects are replaced with CBOR Maps which can contain integer keys and CBOR Tags.

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


# Document History

-00

* Initial working group version based on draft-prorock-spice-cose-sd-cwt-01.

# Acknowledgments
{:numbered="false"}

The authors would like to thank those that have worked on similar items for
providing selective disclosure mechanisms in JSON, especially:
Brent Zundel, Roy Williams, Tobias Looker, Kristina Yasuda, Daniel Fett,
Brian Campbell, Oliver Terbu, and Michael Jones.
