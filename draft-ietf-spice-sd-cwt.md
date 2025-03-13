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
  I-D.draft-ietf-cbor-cde: CDE
  RFC9162: CT
  I-D.draft-ietf-keytrans-protocol: KT
  t-Closeness:
    target: https://ieeexplore.ieee.org/document/4221659
    title: "t-Closeness: Privacy Beyond k-Anonymity and l-Diversity"
    date: 2007-06-04

entity:
  SELF: "RFCthis"

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
A holder cannot send redacted claim keys to a verifier who does not understand selective disclosure at all.
However, Claim Keys and Claim Values which are not understood remain ignored as described in {{Section 3 of RFC8392}}.

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

This document uses terms from CWT {{RFC8392}}, and COSE {{RFC9052}}
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
: The CBOR map containing all mandatory to disclose claims signed by the issuer, all selectively disclosed claims presented by the holder, and omitting all undisclosed instances of Redacted Claim Keys and Redacted Claim Element claims that are present in the original SD-CWT.



# Overview of Selective Disclosure CWT

## A CWT without Selective Disclosure

Below is the payload of a standard CWT without selective disclosure.
It consists of standard CWT claims, the holder confirmation key, and five specific custom claims. The payload is shown below in CBOR Extended Diagnostic
Notation (EDN) {{!I-D.ietf-cbor-edn-literals}}. Note that some of the CWT claim map keys shown in the examples have been invented for this example and do not have registered integer keys.

~~~ cbor-diag
{
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "https://device.example",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : {
      / cose key / 1 : {
        / kty /  1: 2,  / EC2   /
        / crv / -1: 1,  / P-256 /
        / x /   -2: h'8554eb275dcd6fbd1c7ac641aa2c90d9
                      2022fd0d3024b5af18c7cc61ad527a2d',
        / y /   -3: h'4dc7ae2c677e96d0cc82597655ce92d5
                      503f54293d87875d1e79ce4770194343'
      }
    },
    /most_recent_inspection_passed/ 500: true,
    /inspector_license_number/ 501: "ABCD-123456",
    /inspection_dates/ 502 : [
        1549560720,   / 2019-02-07T17:32:00 /
        1612498440,   / 2021-02-04T20:14:00 /
        1674004740,   / 2023-01-17T17:19:00 /
    ],
    /inspection_location/ 503: {
        "country": "us",            / United States /
        "region": "ca",             / California /
        "postal_code": "94188"
    }
}
~~~

The custom claims deal with attributes of an inspection of the subject: the pass/fail result, the inspection location, the license number of the inspector, and a list of date when the subject was inspected.

## Holder gets an SD-CWT from the Issuer

Alice would like to selectively disclose some of these (custom) claims to different verifiers.
Note that some of the claims may not be selectively disclosable.
In our next example the pass/fail status of the inspection, the most recent inspection date, and the country of the inspection will be fixed claims (always present in the SD-CWT).
After the Holder requests an SD-CWT from the issuer, the issuer generates an SD-CWT as follows:

~~~ cbor-diag
{::include examples/issuer_cwt.edn}
~~~
{: #basic-issuer-cwt title="Issued SD-CWT with all disclosures"}


Some of the claims are *redacted* in the payload. The corresponding *disclosure* is communicated in the unprotected header in the `sd_claims` key.
For example, the `inspector_license_number` claim is a Salted Disclosed Claim, consisting of a per-disclosure random salt, the claim name, and claim value.

~~~ cbor-diag
{::include examples/first-disclosure.edn}
~~~
{: title="CBOR extended diagnostic notation representation of inspector_license_number disclosure"}


This is represented in CBOR pretty printed formal as follows (end of line comments and spaces inserted for clarity):

~~~ cbor-pretty
{::include examples/first-disclosure.pretty}
~~~
{: title="CBOR encoding of inspector_license_number disclosure"}


The SHA-256 hash (the hash algorithm identified in the `sd_alg` protected header field) of that bytes string is the Digested Salted Disclosed Claim (in hex).
The digest value is included in the payload in a `redacted_claim_keys` field for a Redacted Claim Key (in this example), or in a named array for a Redacted Claim Element (ex: for a redacted claim element of `inspection_dates`).

~~~
{::include examples/first-blinded-hash.txt}
~~~
{: title="SHA-256 hash of inspector_license_number disclosure"}

Finally, since this redacted claim is a map key and value, the Digested Salted Disclosed Claim is placed in a `redacted_claim_keys` array in the SD-CWT payload at the same level of hierarchy as the original claim.
Redacted claims which are array elements are handled slightly differently, as described in {{types-of-blinded-claims}}.

~~~ cbor-diag
{::include examples/first-redacted.edn}
~~~
{: title="redacted inspector_license_number claim in the issued CWT payload"}

# Holder prepares an SD-CWT for a Verifier

When the Holder wants to send an SD-CWT and disclose none, some, or all of the redacted values, it makes a list of the values to disclose and puts them in `sd_claims` in the unprotected header.

For example, Alice decides to disclose to a verifier the `inspector_license_number` claim (ABCD-123456), the `region` claim (California), and the earliest date element in the `inspection_dates` array (7-Feb-2019).

~~~ cbor-diag
{::include examples/chosen-disclosures.edn}
~~~

The Holder MAY fetch a nonce from the Verifier to prevent replay, or obtain a nonce acceptable to the verifier through a process similar to the method described in {{?I-D.ietf-httpbis-unprompted-auth}}.

Finally, the Holder generates a Selective Disclosure Key Binding Token (SD-KBT) that ties together the SD-CWT generated by the Issuer (with the disclosures the Holder chose for the Verifier in its unprotected header), the Verifier target audience and optional nonces, and proof of possession of the Holder's private key.

The issued SD-CWT is placed in the `kcwt` (Confirmation Key CWT) protected header field (defined in {{!RFC9528}}).

~~~ cbor-diag
{::include examples/elided-kbt.edn}
~~~

Together the digests in protected parts of the issued SD-CWT, and the disclosures hashed in unprotected header of the `issuer_sd_cwt` are used by the Verifier to confirm the disclosed claims.
Since the unprotected header of the included SD-CWT is covered by the signature in the SW-KBT, the Verifier has assurance the Holder included the sent list of disclosures.

# Update to the CBOR Web Token Specification {#cwt-update}

The CBOR Web Token Specification (Section 1.1 of {{RFC8392}}), uses strings, negative integers, and unsigned integers as map keys.
This specification relaxes that requirement, by also allowing CBOR tagged integers and text strings as map keys.
CBOR maps used in a CWT cannot have duplicate keys.
(An integer or string map key is distinct key from a tagged map key which wraps the corresponding integer or string value).

>When sorted, map keys in CBOR are arranged in bytewise lexicographic order of the key's deterministic encodings (see Section 4.2.1 of {{RFC8949}}).
>So an integer key of 3 is represented in hex as `03`, an integer key of -2 is represented in hex as `21`, and a tag of 60 wrapping a 3 is represented in hex as `D8 3C 03`

Note that holders presenting to a verifier that does not support this specification would need to present a CWT without tagged map keys.

Tagged keys are not registered in the CBOR Web Token Claims IANA registry.
Instead the tag provides additional information about the tagged claim key and the corresponding (untagged) value.
Multiple levels of tags in a key are not permitted.

Variability in serialization requirements impacts privacy.

See the security considerations section for more details on the privacy impact of serialization and profiling.


# SD-CWT definition

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE. An SD-CWT MUST include the protected header parameter `typ` {{!RFC9596}} with either a text value "application/sd-cwt" or an uint value of "C-F-TBD" in the SD-CWT.

An SD-CWT is a CWT that can contain blinded claims (each expressed as a Blinded Claim Hash) in the CWT payload, at the root level or in any arrays or maps inside that payload.
It is not required to contain any blinded claims.

Optionally the salted claim values (and often claim names) for the corresponding Blinded Claim Hash are actually disclosed in the `sd_claims` field in the unprotected header of the CWT (the disclosures).
If there are no disclosures (and when no Blinded Claims Hash is present in the payload) the `sd_claims` field in the unprotected header is an empty array.

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

When a blinded claim is a key in a map, its blinded claim hash is added to a `redacted_claim_keys` array claim in the CWT payload that is at the same level of hierarchy as the key being blinded.
The `redacted_claim_keys` key is the integer 0 (which is reserved for top-level CWT claim keys), wrapped with a CBOR tag (requested tag number 59).

When blinding an individual item in an array, the value of the item is replaced with the digested salted hash as a CBOR binary string, wrapped with a CBOR tag (requested tag number 60).

~~~ cddl
redacted_claim_element = #6.60( bstr .size 16 )
~~~

Blinded claims can be nested. For example, both individual keys in the `inspection_location` claim, and the entire `inspection_location` element can be separately blinded.
An example nested claim is shown in {{nesting}}.

Finally, an issuer may create "decoy digests" which look like a blinded claim hash but have only a salt.
Decoy digests are discussed in {{decoys}}.


# SD-CWT Issuance

How the Holder communicates to the Issuer to request a CWT or an SD-CWT is out-of-scope of this specification.
Likewise, how the Holder determines which claims to blind or to always disclose is a policy matter which is not discussed in this specification.
This specification defines the format of an SD-CWT communicated between an Issuer and a Holder in this section, and describes the format of a Key Binding Token containing that SD-CWT communicated between a Holder and a Verifier in {{sd-cwt-presentation}}.

The protected header MUST contain the `sd_alg` field identifying the algorithm (from the COSE Algorithms registry) used to hash the Salted Disclosed Claims.
The unprotected header MUST contain an `sd_claims` section with a Salted Disclosed Claim for *every* blinded claim hash present anywhere in the payload, and any decoys (see {{decoys}}).
If there are no disclosures, the `sd_claims` header is an empty array.
The payload MUST also include a key confirmation element (`cnf`) {{!RFC8747}} for the Holder's public key.

In an SD-CWT, either the subject `sub`/ 2 claim is present, or the redacted form of the subject is present.
The issuer `iss` / 1 standard claim SHOULD be present, unless the protected header contains a certificate or certificate-like entity which fully identifies the issuer.
All other standard CWT claims (`aud`/ 3, `exp` / 4, `nbf` / 5, `iat` / 6, and `cti` / 7) are OPTIONAL.
The `cnonce` / 39 claim is OPTIONAL.
The `cnf` claim, the `cnonce` claim, and the standard claims other than the subject MUST NOT be redacted.
Any other claims are OPTIONAL and MAY be redacted.


## Issuer generation

The Issuer follows all the requirements of generating a valid CWT as updated by {{cwt-update}}.
The Issuer MUST implement COSE_Sign1 using an appropriate asymmetric signature algorithm / curve combination (for example ES256/P-256 or EdDSA/Ed25519)

The Issuer MUST generate a unique cryptographically random salt with at least 128-bits of entropy for each Salted Disclosed Claim.
If the client communicates a client-generated nonce (`cnonce`) when requesting the SD-CWT, the Issuer SHOULD include it in the payload.

## Holder validation

Upon receiving an SD-CWT from the Issuer with the Holder as the subject, the
Holder verifies the following:

- the issuer (`iss`) and subject (`sub`) are correct;
- if an audience (`aud`) is present, it is acceptable;
- the CWT is valid according to the `nbf` and `exp` claims, if present;
- a public key under the control of the Holder is present in the `cnf` claim;
- the hash algorithm in the `sd_alg` protected header is supported by the Holder;
- if a `cnonce` is present, it was provided by the Holder to this Issuer and is still "fresh";
- there are no unblinded claims about the subject which violate its privacy policies;
- every blinded claim hash (some of which may be nested as in {{nesting}}) has a corresponding Salted Disclosed Claim, and vice versa;
- all the Salted Disclosed Claims are correct in their unblinded context in the payload.

The following informative CDDL is provided to describe the syntax for an SD-CWT issuance. A complete CDDL schema is in {{cddl}}.

~~~ cddl
sd-cwt-issued = #6.18([
   protected: bstr .cbor sd-protected,
   sd-unprotected,
   payload: bstr .cbor sd-payload,
   signature: bstr
])

sd-protected = {
   &(typ: 16) ^ => "application/sd+cwt" / TBD1,
   &(alg: 1) ^ => int,
   &(sd_alg: 18) ^= int,             ; -16 for sha-256
   * key => any
}

sd-unprotected = {
   ? &(sd_claims: 17) ^ => salted-array,
   * key => any
}

sd-payload = {
    ; standard claims
      &(iss: 1) ^ => tstr, ; "https://issuer.example"
    ? &(sub: 2) ^ => tstr, ; "https://device.example"
    ? &(aud: 3) ^ => tstr, ; "https://verifier.example/app"
    ? &(exp: 4) ^ => int,  ; 1883000000
    ? &(nbf: 5) ^ => int,  ; 1683000000
    ? &(iat: 6) ^ => int,  ; 1683000000
    ? &(cti: 7) ^ => bstr,
      &(cnf: 8) ^ => { * key => any }, ; key confirmation
    ? &(cnonce: 39) ^ => bstr,
    ;
    ? &(redacted_keys: #6.59(0)) ^ => [ * bstr ],
    * key => any
}
~~~


# SD-CWT Presentation

When a Holder presents an SD-CWT to a Verifier, it can disclose none, some, or all of its blinded claims.
If the Holder wishes to disclose any claims, it includes that subset of its Salted Disclosed Claims in the `sd_claims` claim of the unprotected header.

An SD-CWT presentation to a Verifier has the same syntax as an SD-CWT issued to a Holder, except the Holder choses the subset of disclosures included in the `sd_claims` claim.
Since the unprotected header is not included in the signature, it will contain all the Salted Disclosed Claims when sent from the Issuer to the Holder.
When sent from the Holder to the Verifier, the unprotected header will contain none, some, or all of these Claims.
Finally, the SD-CWT used for presentation to a Verifier is included in a key binding token, as discsused in the next section.

## Creating a Key Binding Token {#kbt}

Regardless if it discloses any claims, the Holder sends the Verifier a unique Holder key binding (SD-KBT) {{kbt}} for every presentation of an SD-CWT to a different Verifier.

An SD-KBT is itself a type of CWT, signed using the private key corresponding to the key in the `cnf` claim in the presented SD-CWT.
The SD-KBT contains the SD-CWT, including the Holder's choice of presented disclosures, in the `kcwt` protected header field in the SD-KBT.

The Holder is conceptually both the subject and the issuer of the Key Binding Token.
Therefore the `sub` and `iss` of an SD-KBT are implied from the `cnf` claim in the included SD-CWT, and are ignored for validation purposes if they are present.
(A profile may define additional semantics.)

The `aud` claim MUST be included and relevant to the Verifier.
The SD-KBT payload MUST contain the issued_at (`iat`) claims.
The protected header of the SD-KBT MUST include the `typ` header parameter with the value `application/sd-kbt`.

The SD-KBT provides the following assurances to the Verifier:

- the Holder of the SD-CWT controls the confirmation method chosen by the Issuer;
- the Holder's disclosures have not been tampered with since confirmation occurred;
- the Holder intended to address the SD-CWT to the Verifier specified in the audience (`aud`) claim;
- the Holder's disclosure is linked to the creation time (`iat`) of the key binding.

The SD-KBT prevents an attacker from copying and pasting disclosures, or from adding or removing disclosures without detection.
Confirmation is established according to RFC 8747, using the `cnf` claim in the payload of the SD-CWT.

The Holder signs the SD-KBT using the key specified in the `cnf` claim in the SD-CWT. This proves possession of the Holder's private key.

~~~ cddl
kbt-cwt = #6.18([
   protected: bstr .cbor kbt-protected,
   kbt-unprotected,
   payload: bstr .cbor kbt-payload,
   signature: bstr
])

kbt-protected = {
   &(typ: 16) ^ => "application/kb+cwt",
   &(alg: 1) ^ => int,
   &(kcwt: 13) ^ => sd-cwt-issued,
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
    * key => any
}
~~~

The SD-KBT payload MAY include a `cnonce` claim.
If included, the `cnonce` is a `bstr` and MUST be treated as opaque to the Holder.
All other claims are OPTIONAL in an SD-KBT.


# SD-KBT and SD-CWT Verifier Validation

The exact order of the following steps MAY be changed, as long as all checks are performed before deciding if an SD-CWT is valid.
First the Verifier must open the protected headers of the SD-KBT and find the issuer SD-CWT present in the `kcwt` field.
Next the Verifier must validate the SD-CWT as described in {{Section 7.2 of RFC8392}}.
The Verifier extract the confirmation key from the `cnf` claim in the SD-CWT payload.
Using the confirmation key, the Verifier validates the SD-KBT as described in {{Section 7.2 of RFC8392}}.

Finally, the Verifier MUST extract and decode the disclosed claims from the `sd_claims` in the unprotected header of the SD-CWT.
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
If there remain unused Digest To Disclosed Claim Map at the end of this procedure the SD-CWT MUST be considered invalid, as if the signature had failed to verify.

Otherwise the SD-CWT is considered valid, and the Validated Disclosed Claimset is now a CWT Claimset with no claims marked for redaction.
Further validation logic can be applied to the Validated Disclosed Claimset, as it might normally be applied to a validated CWT claimset.

# Decoy Digests {#decoys}

**TODO**

# Encrypted Disclosures

Some uses of SD-CWT involve verifiers which have internal structure.
In these cases, encrypted disclosures allow more fine-grained disclosure inside a single presentation.

> In the Remote Attestation Procedures (RATS) architecture {{?RFC9334}}, an SD-CWT is a RATS conceptual message that represents evidence.
> Different evidence claims could be processed by different attesters within the same Verifier.
> For example, one SD-KBT could include an SD-CWT with one set of claims about the workload, and one set of claims about the platform.
> It would be desirable to have each RATS appraiser see a different subset of disclosures in the SD-CWT / SD-KBT.

> In the Messaging Layer Security (MLS) protocol {{?RFC9420}}, an SD-CWT credential {{?I-D.mahy-mls-sd-cwt-credential}} could present one subset of its disclosures to the MLS Distribution Service, and a different subset of those disclosures to the other members of the MLS group.

Taking the first example disclosure from above:

~~~ cbor-diag
<<[
    /salt/   h'2008c50a62d9b59813318abd06df8a89',
    /claim/  501,   / inspector_license_number /
    /value/  "ABCD-123456"
]>>
~~~

The corresponding bstr is encrypted with an IANA registered Authenticated Encryption with Additional Data (AEAD) algorithm {{!RFC5116}} such as AEAD_AES_128_GCM, using the salt as the nonce.
The `salt`, the algorithm used (`alg`), and the resulting `ciphertext` and `mac` are put in an array.
The bstr encoding of the array is placed in the `sd_encrypted_claims` unprotected header field array of the SD-CWT.
The entire SD-CWT is included in the protected header of the SD-KBT, which integrity protects both encrypted and regular disclosures alike.
Neither encrypted nor regular disclosures can appear in the unprotected header of a SD-KBT.

~~~ cbor-diag
/ sd_encrypted_claims / 19 : [ / encrypted disclosures /
    <<[
        /salt/        h'2008c50a62d9b59813318abd06df8a89',
        /alg/         1, / AEAD_AES_128_GCM /
        /ciphertext/  h'b8cf6ed5905b6b0d9c1e7f274ecee4cb
                         ac8f5ad4dac6ba88e7673e70bafa87b5
                         9a61c7',
        /mac/         h'4ea90eef6b3d05d632e6f19b49aa9de5'
    ]>>,
    ...
]
~~~

> In the example above the key in hex is '1eb2d67081ee9950fb3a14c6e8896203'.

The blinded claim hash is still over the unencrypted disclosure.
The receiver of an encrypted disclosure locates the appropriate key by looking up the unique salt.
If the verifier is able to decrypt and verify an encrypted disclosure, the decrypted disclosure is then processed as if it where in the `sd_claims` unprotected header in the SD-CWT.

Details of key management are left to the specific protocols which make use of encrypted disclosures.

The CDDL for encrypted disclosures is described below.

~~~ cddl
encrypted-array = [ +bstr .cbor encrypted ]
encrypted = [
  bstr .size 16,     ; 128-bit salt
  uint16,            ; IANA AEAD Algorithm number
  bstr,              ; the ciphertext output of a bstr-encoded-salted
                     ;   with a matching salt
  bstr               ; the corresponding MAC
]
;bstr-encoded-salted = bstr .cbor salted
~~~

> **TODO**: consider moving the AEAD algorithm for all encrypted disclosures into a new protected header field.

> Note: because the algorithm is in a registry which contains only AEAD algorithms, an attacker cannot replace the algorithm or the message, without a decryption verification failure.


# Credential Types

This specification defines the CWT claim vct (for verifiable credential type). The vct value MUST be a case-sensitive StringOrURI (see {{RFC7519}}) value serving as an identifier for the type of the SD-CWT claimset. The vct value MUST be a Collision-Resistant Name as defined in Section 2 of {{RFC7515}}.

This claim is defined for COSE based verifiable credentials, similar to the JOSE based verifiable credentials claim (`vct`) described in Section 3.2.2.1.1 of {{-SD-JWT-VC}}.

Profiles built on this specification are also encouraged to use more specific media types, as described in {{!RFC9596}}.


# Examples

## Minimal spanning example

The following example contains claims needed to demonstrate redaction of key-value pairs and array elements.

~~~ cbor-diag
{::include examples/kbt.edn}
~~~
{: #example-edn title="An EDN Example"}


## Nested example {#nesting}

Instead of the structure from the previous example, imagine the payload contains an inspection history log with the following structure. It could be blinded at multiple levels of the claim set hierarchy.

~~~ cbor-diag
{
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "https://device.example",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : { ... },
    504: [                      / inspection history log /
        {
            500: True,          / inspection passed /
            502: 1549560720,    / 2019-02-07T17:32:00 /
            501: "DCBA-101777", / inspector license /
            503: {
                1: "us",        / United States /
                2: "co",        / region=Colorado /
                3: "80302"      / postcode /
            }
        },
        {
            500: True,          / inspection passed /
            502: 1612560720,    / 2021-02-04T20:14:00 /
            501: "EFGH-789012", / inspector license /
            503: {
                1: "us",        / United States /
                2: "nv",        / region=Nevada /
                3: "89155"      / postcode /
            }
        },
        {
            500: True,          / inspection passed /
            502: 17183928,      / 2023-01-17T17:19:00 /
            501: "ABCD-123456", / inspector license /
            503: {
                1: "us",        / United States /
                2: "ca",        / region=California /
                3: "94188"      / postcode /
            }
        },
    ]
}
~~~

For example, looking at the nested disclosures below, the first disclosure unblinds the entire January 2023 inspection record.
However, when the record is disclosed, the inspector license number and inspection location are redacted inside the record.
The next disclosure unblinds the inspector_license_number, and the next
disclosure unblinds the inspection location record, but the region and postcode claims inside the location record are also individually blinded.
The fourth disclosure unblinds the inspection region.

The fifth disclosure unblinds the earliest inspection record, and the last disclosure unblinds the inspector_license_number for that record.

Verifiers start unblinding claims for which they have blinded claim hashes. They continue descending until there are no blinded claim hashes at any level of the hierarchy for which they have a corresponding disclosure.

~~~ cbor-diag
/ sd_claims / 17 : [ / these are the disclosures /
    <<[
        /salt/   h'e3aa33644123fdbf819ad534653f4aaa',
        /claim/  504,   / inspection 17-Jan-2023 /
        /value/  [
                     59(h'2893a00665f1ca2cfeb7456e1eeb8eba
                          f21d5c12a73d9fbcb8902822f3ecb635'),
                     59(h'92c0262b0ed6891c6e46d6fca5554caf
                          79bd8d05c74dbb06a25c9edd304c6e22'),
                     {
                         500: True,
                         502: 17183928,
                         simple(59): [
                           h'0ad0f76dcb7fd812ca64c3ada3f543be
                              96d0e351e1e576fbab5cb659b49e599e',
                           h'f34c3ea2292d02b92bde25e68e94acd7
                             f1e011fd6eea6c490f841f09a7a01a48'
                         ]
                     }
                 ]
    ]>>,
    <<[
        /salt/   h'bae611067bb823486797da1ebbb52f83',
        /claim/  501,   / inspector_license_number /
        /value/  "ABCD-123456"
    ]>>,
    <<[
        /salt/   h'7d2505257e7850b70295a87b3c8748e5',
        /claim/  503,   / San Francisco location /
        /value/  {
                     1: "us",
                     simple(59): [
                       h'de03a7a0b4359511a7dc0edd8f4ebc00
                         b5783d8a0d36e715679e23c703011d16',
                       h'5a98ac2381cb59dee7a43daa073eab48
                         9773e2830a0b9c4e1efd55737dbb1c06'
                     ]
                 }
    ]>>,
    <<[
        /salt/   h'52da9de5dc61b33775f9348b991d3d78',
        /claim/  2,   / region=California /
        /value/  "ca"
    ]>>,
    <<[
        /salt/   h'b52272341715f2a0b476e33e55ce7501',
        /value/  {
                     500: True,
                     502: 1549560720,
                     simple(59): [
                       h'cd88763edb2485b8109613546051f606
                         e6b822456da1bf09f604b886e1def45a',
                       h'0a45eb75de44741bea78dc48b1898d40
                         09601dbf567279f3042a24cee9fdcab5'
                     ]
                 }   / inspection 7-Feb-2019 /
    ]>>,
    <<[
        /salt/   h'591eb2081b05be2dcbb6f8459cc0fe51',
        /claim/  501,   / inspector_license_number /
        /value/  "DCBA-101777"
    ]>>
]
~~~

After applying the disclosures of the nested structure above, the disclosed claim set visible to the verifier would look like the following:

~~~ cbor-diag
{
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "https://device.example",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : { ... },
    504: [                      / inspection history log /
        {
            500: True,          / inspection passed /
            502: 1549560720,    / 2019-02-07T17:32:00 /
            501: "DCBA-101777", / inspector license /
            503: {
                1: "us"         / United States /
            }
        },
        {
            500: True,          / inspection passed /
            502: 17183928,      / 2023-01-17T17:19:00 /
            501: "ABCD-123456", / inspector license /
            503: {
                1: "us",        / United States /
                2: "ca"         / region=California /
            }
        },
    ]
}
~~~


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

## Rust Prototype

Organization: SimpleLogin

Name: [github.com/beltram/esdicawt](https://github.com/beltram/esdicawt)

Description: An open source Rust implementation of this draft in Rust.

Maturity: Prototype

Coverage: The current version is close to the spec with the exception of `redacted_claim_keys` using a CBOR SimpleValue as label instead of a tagged key. Not all the verifications have been implemented yet.

License: Apache-2.0

Implementation Experience: No interop testing has been done yet. The code works as proof of concept, but is not yet production ready.

Contact: Beltram Maldant (beltram.ietf.spice@pm.me)

# Security Considerations

Security considerations from COSE {(RFC9052)} and CWT {{RFC8392}} apply to this specification.

## Transparency

Verification of an SD-CWT requires that the verifier have access to a verification key (public key) that is associated with the issuer.
Compromise of the issuer's signing key enables an attacker to forge credentials for any subject associated with the issuer.
Certificate transparency as described in {{-CT}}, or key transparency as described in {{-KT}} can enable the observation of incorrectly issued certificates or fraudulent bindings between verification keys and issuer identifiers.
Issuers choose which claims to include in an SD-CWT, and whether they are mandatory to disclose, including self asserted claims such as "iss".
All mandatory to disclose data elements are visible to the verifier as part of verification, some of these elements reveal information about the issuer, such as key or certificate thumbprints, supported digital signature algorithms, or operational windows which can be inferred from analysis of timestamps.

## Traceability

Presentations of the same SD-CWT to multiple verifiers can be correlated by matching on the signature component of the COSE_Sign1.
Signature based linkability can be mitigated by leveraging batch issuance of single use tokens, for a credential management complexity cost.
Any claim value with sufficiently low "anonymity set" can be used track the subject.
For example, a high precision issuance time might match the issuance of only a few credentials for a given issuer, and as such any presentation of a credential issued at that time can be determined to be associated with the set of credentials issued at that time, for those subjects.

## Credential Types

The mandatory and optional to disclose data elements in an SD-CWT are credential type specific.
Several distinct credential types might be applicable to a given use case.
Issuers MUST perform a privacy and confidentiality assessment regarding each credential type they intend to issue prior to issuance.

## Determinism & Augmentation

It is possible to encode additional information through the choices made during the serialization stage of producing an SD-CWT, for example, by adjusting the order of CBOR map keys, or by choosing different numeric encodings for certain data elements. {{-CDE}} provides guidance for constructing application profiles that constrain serialization optionality beyond CBOR Common Deterministic Encoding rulesets (CDE). The construction of such profiles has a significant impact on the privacy properties of a credential type.

## Threat Model

Each use case will have a unique threat model which MUST be considered before the applicability of SD-CWT based credential types can be determined.
This section provides a non exahustive list of topics to be consider when developing a threat model for applying SD-CWT to a given use case.

Has there been a t-closeness, k-anonymity and l-diverity assessment (see {{t-Closeness}}) assuming compromise of the one or more issuers, verifiers or holders, for all relevant credential types?

How many issuers exist for the credential type?
Is the size of the set of issuers growing or shrinking over time?
For a given credential type, will subjects be able to hold instances of the same credential type from multiple issuers, or just a single issuer?
Does the credential type require or offer the ability to disclose a globally unique identifier?
Does the credential type require high precision time or other claims that have sufficient entropy such that they can serve as a unique fingerprint for a specific subject.
Does the credential type contain Personally Identifiable Information (PII), or other sensitive information which might have value in a market.

How many verifiers exist for the credential type?
Is the size of the set of verifiers growing or shrinking over time?
Are the verifiers a superset, subset, or disjoint set of the issuers or subjects?
Are there any legally required reporting or disclosure requirements associated with the verifiers?
Is there reason to believe that a verifier's historic data will be aggregated and analyzed?
Assuming multiple verifiers are simultaneously compromised, what knowledge regarding subjects can be inferred from analyzing the resulting dataset?

How many subjects exist for the credential type?
Is the size of the set of subjects growing or shrinking over time?
Does the credential type require specific hardware, or algorithms that limit the set of possible subjects to owners of a specific device or subscribers to a given service.

## Random Numbers

Each salt used to protect disclosed claims MUST be generated independently from the salts of other claims. The salts MUST be generated from a source of entropy that is acceptable to the issuer.
Poor choice of salts can lead to brute force attacks that can reveal redacted claims.

## Binding the KBT and the CWT

The issuer claim in the SD-CWT is self-asserted by the issuer.

Because confirmation is mandatory, the subject claim of an SD-CWT, when present, is always related directly to the confirmation claim.
There might be many subject claims and many confirmation keys that identify the same entity or that are controlled by the same entity, while the identifiers and keys are distinct values.
Reusing an identifier or key enables traceability, but MUST be evaluated in terms of the confidential and privacy constraints associated with the credential type.
Conceptually, the Holder is both the issuer and the subject of the SD-KBT, even if the issuer or subject claims are not present.
If they are present, they are self-asserted by the Holder.
All three are represented by the confirmation (public) key in the SD-CWT.

As with any self-assigned identifiers, Verifiers need to take care to verify that the SD-KBT issuer and subject claims match the subject in the SD-KBT, and are a valid representation of the Holder and correspond to the Holder's confirmation key.
Extra care should be taken in case the SD-CWT subject claim is redacted.
Likewise, Holders and Verifiers need to verify that the issuer claim of the SD-CWT corresponds to the Issuer and the key described in the protected header of the SD-CWT.


# IANA Considerations

## COSE Header Parameters

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).

### sd_claims

The following completed registration template per RFC8152 is provided:

* Name: sd_claims
* Label: TBD1 (requested assignment 17)
* Value Type: bstr
* Value Registry: (empty)
* Description: A list of selectively disclosed claims, which were originally redacted, then later disclosed at the discretion of the sender.
* Reference: RFC XXXX

### sd_alg

The following completed registration template per RFC8152 is provided:

* Name: sd_alg
* Label: TBD2 (requested assignment 18)
* Value Type: int
* Value Registry: COSE Algorithms
* Description: The hash algorithm used for redacting disclosures.
* Reference: RFC XXXX

### sd_encrypted_claims

The following completed registration template per RFC8152 is provided:

* Name: sd_encrypted claims
* Label: TBD6 (requested assignment 19)
* Value Type: bstr
* Value Registry: (empty)
* Description: A list of encrypted selectively disclosed claims, which were originally redacted, then later disclosed at the discretion of the sender.
* Reference: RFC XXXX


## CBOR Tags

### To be redacted tag

The array claim element, or map key and value inside the "To be redacted" tag is intended to be redacted using selective disclosure.

* Tag: TBD3 (requested assignment 58)
* Data Item: (any)
* Semantics: An array claim element, or map key and value intended to be redacted.
* Specification Document(s): RFC XXXX

### Redacted claim keys tag

This tag encloses the integer claim key 0 (reserved as a CWT claim key). It indicates that the claim value is an array of redacted claim keys at the same level.

* Tag: TBD4 (requested assignment 59)
* Data Item: unsigned integer 0
* Semantics: Tags the claim key 0. The value of the key is an array of selective disclosure redacted claim keys.
* Specification Document(s): RFC XXXX

### Redacted claim element tag

The binary string inside the tag is a selective disclosure redacted claim element of an array.

* Tag: TBD5 (requested assignment 60)
* Data Item: byte string
* Semantics: A selective disclosure redacted (array) claim element.
* Specification Document(s): RFC XXXX

## CBOR Web Token (CWT) Claims

IANA is requested to add the following entries to the CWT claims registry (https://www.iana.org/assignments/cwt/cwt.xhtml).

<!-- https://datatracker.ietf.org/doc/html/draft-ietf-oauth-selective-disclosure-jwt-12#name-json-web-token-claims-regis -->

### vct

The following completed registration template per RFC8392 is provided:

* Claim Name: vct
* Claim Description: Verifiable credential type
* JWT Claim Name: vct
* Claim Key: TBD6 (request assignment 11)
* Claim Value Type(s): bstr
* Change Controller: IETF
* Specification Document(s): RFC XXXX

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
    - Magic number(s): n/a
    - File extension(s): n/a
    - Macintosh file type code(s): n/a
* Person & email address to contact for further information:
    SPICE WG mailing list (spice@ietf.org) or
    IETF Security Area (saag@ietf.org)
* Intended usage: COMMON
* Restrictions on usage: none
* Author: See Author's Addresses section
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
     - Magic number(s): n/a
     - File extension(s): n/a
     - Macintosh file type code(s): n/a
* Person & email address to contact for further information:
    SPICE WG mailing list (spice@ietf.org) or
    IETF Security Area (saag@ietf.org)
* Intended usage: COMMON
* Restrictions on usage: none
* Author: See Author's Addresses section
* Change controller: IETF
* Provisional registration?  No

## Content-Formats

[^rfced] Please replace "{{&SELF}}" with the RFC number assigned to this document.

[^rfced] IANA is requested to register the following Content-Format numbers in the "CoAP Content-Formats" registry, within the "Constrained RESTful Environments (CoRE) Parameters" registry group {{!IANA.core-parameters}}:

| Content-Type | Content Coding | ID | Reference |
| application/sd+cwt | - | TBD1 | {{&SELF}} |
| application/kb+cwt | - | TBD2 | {{&SELF}} |
{: align="left" title="New CoAP Content Formats"}

If possible, TBD1 and TBD2 should be assigned in the 256..9999 range.

--- back

# Complete CDDL Schema {#cddl}

~~~~~~~~~~ cddl
{::include ./sd-cwts.cddl}
~~~~~~~~~~
{: #cddl-schema title="A complete CDDL description of SD-CWT"}

# Comparison to SD-JWT

SD-CWT is modeled after SD-JWT, with adjustments to align with conventions in CBOR and COSE.

## Media Types

The COSE equivalent of `application/sd-jwt` is `application/sd+cwt`.

THe COSE equivalent of `application/kb+jwt` is `application/kb+cwt`.

## Redaction Claims

The COSE equivalent of `_sd` is a CBOR tag (requested assignment 59) of the claim key 0. The corresponding claim value is an array of the redacted claim keys.

The COSE equivalent of `...` is a CBOR tag (requested assignment 60) of the digested salted claim.

## Issuance

The issuance process for SD-CWT is similar to SD-JWT, with the exception that a confirmation claim is REQUIRED.

## Presentation

The presentation process for SD-CWT is similar to SD-JWT, except that a Key Binding Token is REQUIRED.
The Key Binding Token then includes the issued SD-CWT, including the Holder-selected disclosures.
Because the entire SD-CWT is included as a claim in the SD-KBT, the disclosures are covered by the Holder's signature in the SD-KBT, but not by the Issuer's signature in the SD-CWT.

## Validation

The validation process for SD-CWT is similar to SD-JWT, however, JSON Objects are replaced with CBOR Maps which can contain integer keys and CBOR Tags.

# Keys used in the examples

## Subject / Holder

Holder COSE key pair in EDN format

~~~ cbor-diag
{
  /kty/  1 : 2, /EC/
  /alg/  3 : -7, /ES256/
  /crv/ -1 : 1, /P-256/
  /x/   -2 : h'8554eb275dcd6fbd1c7ac641aa2c90d9
               2022fd0d3024b5af18c7cc61ad527a2d',
  /y/   -3 : h'4dc7ae2c677e96d0cc82597655ce92d5
               503f54293d87875d1e79ce4770194343',
  /d/   -4 : h'5759a86e59bb3b002dde467da4b52f3d
               06e6c2cd439456cf0485b9b864294ce5'
}
~~~

The fields necessary for the COSE Key Thumbprint {{!RFC9679}}
in EDN format:

~~~ cbor-diag
{
  /kty/  1 : 2, /EC/
  /crv/ -1 : 1, /P-256/
  /x/   -2 : h'8554eb275dcd6fbd1c7ac641aa2c90d9
               2022fd0d3024b5af18c7cc61ad527a2d',
  /y/   -3 : h'4dc7ae2c677e96d0cc82597655ce92d5
               503f54293d87875d1e79ce4770194343'
}
~~~

The same map in CBOR pretty printing

~~~ cbor-pretty
A4                                      # map(4)
   01                                   # unsigned(1)
   02                                   # unsigned(2)
   20                                   # negative(0)
   01                                   # unsigned(1)
   21                                   # negative(1)
   58 20                                # bytes(32)
      8554EB275DCD6FBD1C7AC641AA2C90D92022FD0D3024B5AF18C7CC61AD527A2D
   22                                   # negative(2)
   58 20                                # bytes(32)
      4DC7AE2C677E96D0CC82597655CE92D5503F54293D87875D1E79CE4770194343
~~~

The COSE thumbprint (in hexadecimal)--SHA256 hash of the thumbprint fields:

~~~
8343d73cdfcb81f2c7cd11a5f317be8eb34e4807ec8c9ceb282495cffdf037e0
~~~

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

Holder private key in PEM format

~~~
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgV1moblm7OwAt3kZ9
pLUvPQbmws1DlFbPBIW5uGQpTOWhRANCAASFVOsnXc1vvRx6xkGqLJDZICL9DTAk
ta8Yx8xhrVJ6LU3HrixnfpbQzIJZdlXOktVQP1QpPYeHXR55zkdwGUND
-----END PRIVATE KEY-----
~~~

## Issuer

Issuer COSE key pair in Extended Diagnostic Notation (EDN)

~~~ cbor-diag
{
  /kty/  1 : 2, /EC/
  /kid/  2 : "https://issuer.example/cwk3.cbor",
  /alg/  3 : -35, /ES384/
  /crv/ -1 : 2, /P-384/
  /x/   -2 : h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307
               b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf',
  /y/   -3 : h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e
               84a055a31fb7f9214b27509522c159e764f8711e11609554',
  /d/   -4 : h'71c54d2221937ea612db1221f0d3ddf771c9381c4e3be41d
               5aa0a89d685f09cfef74c4bbf104783fd57e87ab227d074c'
}
~~~

The fields necessary for the COSE Key Thumbprint {{!RFC9679}}
in EDN format:

~~~ cbor-diag
{
  /kty/  1 : 2, /EC/
  /crv/ -1 : 2, /P-384/
  /x/   -2 : h'c31798b0c7885fa3528fbf877e5b4c3a6dc67a5a5dc6b307
               b728c3725926f2abe5fb4964cd91e3948a5493f6ebb6cbbf',
  /y/   -3 : h'8f6c7ec761691cad374c4daa9387453f18058ece58eb0a8e
               84a055a31fb7f9214b27509522c159e764f8711e11609554'
}
~~~

The same map in CBOR pretty printing

~~~ cbor-pretty
A4                                      # map(5)
   01                                   # unsigned(1)
   02                                   # unsigned(2)
   20                                   # negative(0)
   02                                   # unsigned(2)
   21                                   # negative(1)
   58 30                                # bytes(48)
      C31798B0C7885FA3528FBF877E5B4C3A6DC67A5A5DC6B307
      B728C3725926F2ABE5FB4964CD91E3948A5493F6EBB6CBBF
   22                                   # negative(2)
   58 30                                # bytes(48)
      8F6C7EC761691CAD374C4DAA9387453F18058ECE58EB0A8E
      84A055A31FB7F9214B27509522C159E764F8711E11609554
~~~

The COSE thumbprint (in hexadecimal)--SHA256 hash of the thumbprint fields:

~~~
554550a611c9807b3462cfec4a690a1119bc43b571da1219782133f5fd6dbcb0
~~~

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

Note: RFC Editor, please remove this entire section on publication.

## draft-ietf-spice-sd-cwt-03

- remove bstr encoding from sd_claims array (but not the individual disclosures)
- clarify which claims are optional/mandatory
- correct that an SD-CWT may have zero redacted claims
- improve the walkthrough of computing a disclosure
- clarify that duplicate map keys are not allowed, and how tagged keys are represented.
- added security considerations section (#42) and text about privacy and linkability risks (#43)
- register SD-CWT and SD-KBT as content formats in CoAP registry (#39)
- updated media types registrations to have more useful contacts (#44)
- build most of the values (signatures/salts/hashes/dates) in the examples automatically using a script that implements SD-CWT
- regenerate all examples with correct signatures
- add nested example
- add optional encrypted disclosures
- add description of decoy digests **TODO**
- provide test vectors **TODO**

## draft-ietf-spice-sd-cwt-02

- KBT now includes the entire SD-CWT in the Confirmation Key CWT (`kcwt`) existing COSE protected header. Has algorithm now specified in new `sd_alg` COSE protected header. No more `sd_hash` claim. (PR #34, 32)
- Introduced tags for redacted and to-be-redacted claim keys and elements. (PR#31, 28)
- Updated example to be a generic inspection certificate. (PR#33)
- Add section saying SD-CWT updates the CWT spec (RFC8392). (PR#29)

## draft-ietf-spice-sd-cwt-01

- Added Overview section
- Rewrote the main normative section
- Made redaacted_claim_keys use an unlikely to collide claim key integer
- Make cnonce optional (it now says SHOULD)
- Made most standard claims optional.
- Consistently avoid use of bare term "key" - to make crypto keys and map keys clear
- Make clear issued SD-CWT can contain zero or more redactions; presented SD-CWT can disclose zero, some, or all redacted claims.
- Clarified use of sd_hash for issuer to holder case._
- Lots of editorial cleanup
- Added Rohan as an author and Brian Campbell to Acknowledgements
- Updated implementation status section to be BCP205-compatible
- Updated draft metadata

## draft-ietf-spice-sd-cwt-00

* Initial working group version based on draft-prorock-spice-cose-sd-cwt-01.

# Acknowledgments
{:numbered="false"}

The authors would like to thank those that have worked on similar items for
providing selective disclosure mechanisms in JSON, especially:
Brent Zundel, Roy Williams, Tobias Looker, Kristina Yasuda, Daniel Fett,
Brian Campbell, Oliver Terbu, and Michael Jones.

[^rfced]: RFC Editor:
