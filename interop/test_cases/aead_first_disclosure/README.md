# aead_first_disclosure

The draft's worked example, presented with one disclosure AEAD encrypted.

| File | What it is |
|---|---|
| `issued.cbor` | `examples/issuer_cwt.cbor`, unmodified |
| `issuer_pub.pem` | Appendix C Issuer public key (P-384), from `issuer_privkey.pem` |
| `holder_priv.pem` | Appendix C Holder private key (P-256), a copy of `holder_privkey.pem` |
| `disclosure_list.cbor` | Salts of the two disclosures sent in plaintext: `1549560720` and `region`. `kbt.cbor` presents the same three disclosures, all in plaintext |
| `encrypt_list.cbor` | Salt of the disclosure sent encrypted: `501` (`examples/first-disclosure.edn`) |
| `aead_key.hex` | The draft's AEAD key (`examples/aead-key.txt`) |
| `wrong_aead_key.hex` | Sixteen zero bytes |
| `aead_nonces.csv` | Pins the nonce for `501` to the draft's, so the output is a test vector |
| `expected_aead_claims.cbor` | The `sd_aead_encrypted_claims` array the Holder must produce: `aead-claim-array.edn` |

`run_aead.py` checks, for every Holder x Verifier pair:

1. `present` succeeds.
2. The presented SD-CWT's 171 equals `expected_aead_claims.cbor` byte for byte. This pins the plaintext to the full `bstr .cbor salted-entry` encoding, header included, and the associated data to empty.
3. `501` is not in `sd_claims`.
4. `verify --aead-key aead_key.hex` succeeds and its claims contain `501: "ABCD-123456"`.
5. `verify` with no key succeeds and its claims do not contain `501`.
6. `verify --aead-key wrong_aead_key.hex` fails.
