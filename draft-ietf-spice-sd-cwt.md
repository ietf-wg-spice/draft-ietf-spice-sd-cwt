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

This document uses terms from CWT {{RFC8392}}, and COSE {{!RFC9052}}
{{!RFC9053}}.

This document defines the following new terms related to concepts originally described in SD-JWT {{-SD-JWT}}.

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
: When the full set of claims protected by the Issuer, is disclosed by the Holder.

Salted Disclosed Claim:
: A salted claim disclosed in the unprotected header of an SD-CWT.

Digested Salted Disclosed Claim / Blinded Claim Hash:
: A hash digest of a Salted Disclosed Claim.

Blinded Claim:
: Any Redacted key or Redacted element which has been replaced in the
CWT payload by a Blinded Claim Hash.

Redacted key:
: The hash of a claim redacted from a map data structure.

Redacted element:
: The hash of an element redacted from an array data structure.

Presented Disclosed Claimset:
: The CBOR map containing zero or more Redacted keys or Redacted elements.

Validated Disclosed Claimset:
: The CBOR map containing all mandatory to disclose claims signed by the issuer, all selectively disclosed claims presented by the holder, and ommiting all instances of redacted_keys and redacted_element claims that are present in the original sd_cwt.


# SD-CWT definition

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions
in CBOR and COSE. An SD-CWT MUST include the protected header parameter
`typ` {{!RFC9596}} with the value "application/sd-cwt" in the SD-CWT.

An SD-CWT is a CWT containing the "blinded claim hash" of
at least one blinded claim in the CWT payload. Optionally the salted claim
values (and often claim names) for the corresponding Blinded Claim Hash are
actually disclosed in the `sd_claims` claim in the unprotected header of the
CWT (the disclosures).

Any party with a Salted Disclosed Claim can generate its hash, find that
hash in the CWT payload, and unblind the content. However a Verifier with the hash cannot reconstruct the corresponding blinded claim without
disclosure of the Salted Disclosed Claim.

## Types of blinded claims

Salted Disclosed Claims for named claims are structured as a 128-bit salt, the name of the redacted element, and the disclosed value. For Salted
Disclosed Claims of items in an array, the name is omitted.

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

When blinding an individual item in an array, the value of the item is
replaced with a CBOR map containing only the special key "...".

~~~ cddl
redacted_element = { "...": any }
~~~

Blinded claims can be nested. For example, both individual keys in the
`address` claim, and the entire `address` element can be separately blinded.
An example nested claim is shown in **TODO iref**.

Finally, an issuer may create "decoy digests" which look like a blinded
claim hash but have only a salt. Decoy digests are discussed in **TODO iref**.


# SD-CWT Issuance

How the Holder communicates to the Issuer to request a CWT or an SD-CWT is
out-of-scope of this specification. Likewise, how the Holder determines
which claims to blind or to always disclose is a policy matter which is
not discussed in this specification. This specification defines the format
of an SD-CWT communicated between an Issuer and a Holder in this section, and describes the format of an SD-CWT communicated between a Holder and a
Verifier in the next section.

The unprotected header MUST contain an `sd_claims` section with a Salted
Disclosed Claim for *every* blinded claim hash present anywhere in the
payload. The payload MUST also include a key confirmation element (`cnf`) {{!RFC8747}}
for the Holder's public key, and an `sd_alg` claim identifying the
algorithm used to hash the Salted Disclosed Claims.

## Issuer generation

The Issuer follows all the requirements of generating a valid CWT.
The Issuer MUST implement COSE_Sign1 using an appropriate asymmetric
signature algorithm / curve combination (for example ES256/P-256 or
EdDSA/Ed25519)

The Issuer MUST generate a unique cryptographically random salt with at least
128-bits of entropy for each Salted Disclosed Claim. If the client
communicates a client-generated nonce (`cnonce`) when requesting the SD-CWT,
the Issuer SHOULD include it in the payload.

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

The following informative CDDL is provided to describe the syntax for an
SD-CWT issuance. A complete CDDL schema is in {{cddl}}.

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
   &(sd_claims: TBD1) ^ => bstr .cbor salted-array,
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
      # TODO: should sd_hash be included in issued?
      &(sd_hash: TBD3) ^ => bstr,
      &(sd_alg: TBD4) ^ => int,            ; -16 for sha-256
    ? &(redacted_keys: TBD5) ^ => [ * bstr ],
    * key => any
}
~~~


# SD-CWT Presentation

When a Holder presents an SD-CWT to a Verifier, it can disclose
none, some, or all of its blinded claims. If the Holder wishes to disclose any claims, it includes those Salted Disclosed Claims in the `sd_claims` claim of the unprotected header.

~~~ cddl
sd-cwt-presentation = #6.18([
   protected: bstr .cbor sd-protected,
   unprotected-presentation,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

unprotected-presentation = {
   &(sd_kbt: TBD2) ^ => bstr .cbor kbt-cwt,
   ? &(sd_claims: TBD1) ^ => bstr .cbor salted-array,
   * key => any
}
~~~

As described in the CDDL above, a SD-CWT presentation to a Verifier has the
same syntax as an SD-CWT issued to a Holder, except for its unprotected header.

## Creating a Key Binding Token {#kbt}

Regardless if it discloses any claims, the Holder MUST include a Holder key
binding (SD_KBT) {{kbt}} in a `sd_kbt` claim in the unprotected header in
every presentation of an SD-CWT by a Holder to a Verifier.
(The `sd_kbt` claim is absent when the Issuer is providing the
SD-CWT to the Holder.) An SD-KBT is itself a type of CWT. The protected header of the SD-KBT
MUST include the `typ` header parameter with the value `application/sd-kbt`.

The SD-KBT provides the following assurances to the Verifier:

- the Holder of the SD-CWT controls the confirmation method chosen by the Issuer;
- the Holder's disclosures have not been tampered with since confirmation occurred;
- the Holder intended to address the SD-CWT to the Verifier specified in the
audience (`aud`) claim;
- the Holder's disclosure is linked to the creation time (`iat`) of the key binding.

The SD-KBT prevents an attacker from copying and pasting disclosures, or from adding or removing disclosures without detection.
Confirmation is established according to RFC 8747, using the `cnf` claim in the payload of the SD-CWT.

Using the algorithm established in `sd_alg` in the payloads of both the SD-CWT and the SD-KBT, the Holder constructs the hash of all the Salted Disclosed Claims it will share with the Verifier. This is the hash of the entire `sd_claims` array in the unprotected header of the SD-CWT. This composite hash is included in the `sd_hash` claim in the payload of the SD-KBT.

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
      &(cnonce: 39) ^ => bstr,
      ; matches the hash of sd_claims in the presentation token
      &(sd_hash: TBD3) ^ => bstr,
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

This claim is defined COSE based verifiable credentials, similar to the JOSE based verifiable credentials described in Section 3.2.2.1.1 of SD-JWT-VC.

Profiles built on this specification are also encouraged to use more specific media
types, as described in {{!RFC9596}}.


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

# Acknowledgments
{:numbered="false"}

The authors would like to thank those that have worked on similar items for providing selective disclosure mechanisms in JSON, especially:
Brent Zundel, Roy Williams, Tobias Looker, Kristina Yasuda, Daniel Fett,
Oliver Terbu, and Michael Jones.
