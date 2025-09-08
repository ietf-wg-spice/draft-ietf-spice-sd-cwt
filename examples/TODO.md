
TODO

- break up CDDL into 4 main sections, the `redacted_claim_element`, a prelude, and postlude. construct the sd-cwts.cddl by concatenating the pieces
  - prelude `sd-cwt-types = sd-cwt-issued / kbt-cwt`
  - sd-cwt.cddl
  - kbt.cddl
  - salted-claims.cddl
  - encrypted-claims.cddl
  - postlude
  - redacted_claim_element (add ';' before it is included in the main sd-cwts.cddl)
- write some tooling??
- figure out why nested example cbor and edn don't match
- rename first-disclosure.cbor to first-disclosure.cborseq
- try CDDL validation against all CBOR files
