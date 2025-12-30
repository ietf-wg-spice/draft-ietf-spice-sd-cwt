#!/usr/bin/env python3
import cbor2
from pycose.keys import CoseKey

TO_BE_REDACTED_TAG = 58
#TO_BE_DECOY = 61
SD_CLAIMS = 17

from sd-cwt import *

from enum import Enum
class Role(Enum):
    Issuer = 1
    Holder = 2
    Verifier = 3

def convert_privkey_dict(privkey_dict):
    from pycose.keys import CoseKey
    from cbor2
    pubkey_dict = dict(privkey_dict)
    del(pubkey_dict[-4])
    priv_cosekey = CoseKey.from_dict(privkey_dict)
    pub_cosekey = CoseKey.from_dict(pubkey_dict)
    # dictionary needs to be in deterministic order
    #sorted_dict = sort_keys(pubkey_dict)
    thumb = sha256(cbor2.dumps(pubkey_dict))
    return (priv_cosekey, pub_cosekey, pubkey_dict, thumb)

def ckt2uri(ckt):
    if type(ckt) is not bytes or len(ckt) == 0:
        raise Exception("Expected ckt to be a bytes")
    return "urn:ietf:params:oauth:ckt:" + bytes_to_b64u(ckt)

def key2alg(cosekey):
    from pycose.keys import CoseKey
    crv2alg = {
        1: -7,  # P-256   ==> ES256
        2: -35, # P-384   ==> ES384
        3: -36, # P-521   ==> ES512
        6: -8,  # Ed25519 ==> EdDSA
        7: -8   # Ed448   ==> EdDSA
    }
    return crv2alg[cosekey.crv.identifier]

def bytes_to_b64u(b):
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b'=')

def b64u_to_bytes(b64):
    import base64
    if not isinstance(b64, str):
        raise Exception("Expected base64 string")
    return base64.urlsafe_b64decode(b64.rstrip() + '==')



##### functions for participating in interop. need to split these out

def claimset2sdcwt(payload_map,        # need to have cnf already in payload
                   holder_cnf_claim,
                   issuer_privkey,
                   time_claims={},
                   salt_map=None):
    from pycose.keys import CoseKey
    
    (payload, disclosures) = redact_map(payload_map)
    payload |= time_claims | holder_cnf_claim
    
    unprotected = {}
    unprotected[SD_CLAIMS] = disclosures
    
    protected = {
        1 : key2alg(issuer_privkey),             # alg
        4 : b'https://issuer.example/cose-key3', # kid
        16: "application/sd-cwt",                # typ
        18: -16,                                 # sd_alg = SHA256
    }
    
    issuer_cwt = sign(protected, unprotected)

def sdcwt2kbt(sdcwt, holder_privkey, disclosure_indexes, kbt_claims):
    from pycose.keys import CoseKey


def kbt2claimset(kbt):
    from pycose.keys import CoseKey
    from pycose.messages import Sign1Message
    
    kbt_msg = Sign1Message.decode(kbt)
    
    
    
    if kbt_msg.verify_signature():
        


#### this is the interop section that loads and saves test results


def load_test_params(testname, target_role):
    #params = {}
    match target_role:
        case Role.Issuer:
            # (redactable_claimset or
            # (unredacted_claimset and redaction_list)),
            # (issuer_private_pem_key or
            #  issuer_private_cose_key)
            # (holder_public_cose_key or
            #  (holder_cwk and holder_public_pem_key)),
            #  (iat, exp_duration, nbf_leeway)
            # (optional) deterministic salts
            redactable_claimset =
              bytes_from_file(testname + '/input/readactable.cbor')
            issuer_priv =
              bytes_from_file(testname + '/input/issuer_priv.pem')
            holder_pub =
              bytes_from_file(testname + '/input/holder_pub.cbor')
            time_claims = list_from_csv(testname + '/input/sd-cwt-time.csv')
            # if deterministic salts (including decoys) are available, load them
            # TODO load deterministic salts
            return (redactable_claimset, issuer_priv, holder_pub, time_claims)
        case Role.Holder:
            issued_cwt =
              bytes_from_file(testname + '/input/issued_cwt.cbor')
            issuer_pub =
              bytes_from_file(testname + '/input/issuer_pub.pem')
            holder_priv =
              bytes_from_file(testname + '/input/holder_priv.pem')
            disclosure_list =
              list_from_csv(testname + '/input/disclosure-list.csv')
            # standard KBT clams are aud, (opt) exp/nbf/iat, and (opt) cnonce
            kbt_std_claims =
              list_from_csv(testname + 'input/std-kbt-claims.csv')
            #other_claims =
            #  bytes_from_file(testname + '/input/additional-kbt-claims.cbor')
            return (issued_cwt, issuer_pub, holder_priv, disclosure_list)
        case Role.Verifier:
            kbt = bytes_from_file(testname + '/input/kbt.cbor')
            issuer_pub =
              bytes_from_file(testname + '/input/issuer_pub.pem')
            # get the verifier's "current" time (or use actual time if empty)
            now = list_from_csv(testname + 'input/kbt-verify-time.csv')
            return (kbt, now)


def save_test_results(testname, role, error_list, cbor=None, det_nonces=None):
    match target_role:
        case Role.Issuer:
            # write any errors (could be multiple) in CSV
            # write issued CWT if successful
            # optionally write deterministic nonces
        case Role.Holder:
            # write any errors (could be multiple) in CSV
            # write KBT
        case Role.Verifier:
            # write any errors (could be multiple) in CSV
            # write resulting claim set



#### here there could be a separate program to generate some initial tests



if __name__ = "__main__":
    from pycose.keys import CoseKey

    # -----BEGIN PUBLIC KEY-----
    # MCowBQYDK2VwAyEAD4ikAgUJlb6Ha36CjVFM7Pm3vAwzILiCSXvzZsq9ACg=
    # -----END PUBLIC KEY-----
    #
    # -----BEGIN PRIVATE KEY-----
    # MC4CAQAwBQYDK2VwBCIEIIH8hgdx3FUamo7y5AdYpE2kMc+MgTllf+zDZ6zf6Naa
    # -----END PRIVATE KEY-----
    #
    holder_privkey_dict = {
      1: 1,   # kty = OKP
      -1: 6,  # crv = Ed25519
      -2: b64u_to_bytes("D4ikAgUJlb6Ha36CjVFM7Pm3vAwzILiCSXvzZsq9ACg"),
      -4: b64u_to_bytes("gfyGB3HcVRqajvLkB1ikTaQxz4yBOWV_7MNnrN_o1po")
    }
    (holder_priv_cosekey, holder_pubkey_dict, holder_pub_cosekey, holder_ckt) = convert_privkey_dict(holder_privkey_dict)

    # -----BEGIN PUBLIC KEY-----
    # MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMsiGbouPzmMXugPNJ5bxTYMrDGaV
    # e0AvwLhSdXxICc3oRfiL2yzLZhtdQiFpXwR2olVUKzrRx639/n20+ai74A==
    # -----END PUBLIC KEY-----
    #
    # -----BEGIN PRIVATE KEY-----
    # MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYAj02mMgOd2kjHGV
    # zxq+Kqy8QN2mLTWwJOqbzuoAerKhRANCAAQyyIZui4/OYxe6A80nlvFNgysMZpV7
    # QC/AuFJ1fEgJzehF+IvbLMtmG11CIWlfBHaiVVQrOtHHrf3+fbT5qLvg
    # -----END PRIVATE KEY-----
    issuer_privkey_dict = {
      1: 2,   # kty = EC2
      -1: 1,  # crv = P-256
      -2: b64u_to_bytes("MsiGbouPzmMXugPNJ5bxTYMrDGaVe0AvwLhSdXxICc0"),
      -3: b64u_to_bytes("6EX4i9ssy2YbXUIhaV8EdqJVVCs60cet_f59tPmou-A"),
      -4: b64u_to_bytes("YAj02mMgOd2kjHGVzxq-Kqy8QN2mLTWwJOqbzuoAerI")
    }
    (issuer_priv_cosekey, issuer_pubkey_dict, issuer_pub_cosekey, issuer_ckt) = convert_privkey_dict(holder_privkey_dict)

    # TODO: do the same thing here for the holder key. maybe easier to use PEM

    payload_boolean = {
        1  : "https://issuer.example",
        2  : ckt2uri(holder_ckt),
        98 : [cbor2.CBORTag(58, "it"), cbor2.CBORTag(58, null)],
        cbor2.CBORTag(58,99) : True 
    }

    payload_manifest = {
        1  : "https://issuer.example",
        2  : "https://device.example/manifests/ap8GhizU0",
        cbor2.CBORTag(58,300): [                       # Manifest
          cbor2.CBORTag(58,{
            1 : 144,                                   # quantity
            2: cbor2.CBORTag(58,[15.78, "EUR"]),       # unit value
            3: "de",                                   # country of origin
            4: [0.790, "kg"],                          # unit mass
            5: [12.5, 4.8, 2.0, "cm"]                  # unit dimensions
          }),
          cbor2.CBORTag(58,{
            1 : 6,
            2: cbor2.CBORTag(58,[25.80, "EUR"]),
            3: "nl",
            4: [9.2, "kg"],
            5: [14.5, 21.8, 30.0, "cm"]
          }),
          cbor2.CBORTag(61, 1)                         # 1st decoy
        ],
        cbor2.CBORTag(58,301): "EXW",                  # Incoterms EXWorks
        cbor2.CBORTag(58,302): [51.949564, 4.147359],  # Rotterdam port
        cbor2.CBORTag(58,303): 1760449111              # 14-Oct-2025 09:28:31Z
        cbor2.CBORTag(61, 2)                           # 2nd decoy
    }



    
    cbor_input
    
    
    
    cbor_output = 
    write_to_file(cbor_output, )
    
    ## for pure interop tests we care about a few things:
    ## - signatures, hashes, time validations, etc., all work as expected
    ## - resulting claim set matches expected claim set
    ## - for pure interop we don't care about deterministic salts, nonces,
    ##   exact time claims, order of disclosures, order of redacted claims,
    ##   or even order of claims in the resulting claim set.

