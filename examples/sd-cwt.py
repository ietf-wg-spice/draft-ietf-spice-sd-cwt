#!/usr/bin/env python3
import cbor2

TO_BE_REDACTED_TAG = 58
SD_CLAIMS = 17

def bytes2hex(bytes):
    import binascii
    return binascii.hexlify(bytes)

def hex2bytes(string):
    return bytes.fromhex(string)

def new_redacted_entry_tag(value):
    REDACTED_ENTRY_TAG = 59
    return cbor2.CBORTag(REDACTED_ENTRY_TAG, value)

def new_salt():
    import secrets
    return secrets.token_bytes(16)

def sha256(bytes):
    import hashlib
    return hashlib.sha256(bytes).digest()

def make_time_claims(expiration, leeway=300, now=None):
    # all values should be in seconds
    if now is None:
        import time
        now = int(time.time())
    newdict = {}
    newdict[4] = now + expiration   # exp
    newdict[5] = now - leeway       # nbf
    newdict[6] = now
    return newdict


def make_disclosure(salt=None, key=None, value=None):
    if salt is None:
        salt = new_salt()
    if key is None:
        if value is None:
            # decoy digest
            disclosure_array = [salt]
        else:
            # array entry
            disclosure_array = [salt, value]
    else:
        if value is None:
            raise Exception("Value must be specified is a key is present")
        else:
            # map claim
            disclosure_array = [salt, key, value]
    # double encode to add bstr type and bstr length
    return cbor2.dumps(cbor2.dumps(disclosure_array))


def parse_disclosures(disclosures):
    # takes an array of bstr and returns an array of parsed disclosures
    import cbor2
    new_array = []
    for bstr in disclosures:
        new_array += cbor2.loads(bstr)
    return new_array


def redact_map(map, level):
    REDACTED_KEYS_ARRAY = cbor2.CBORSimpleValue(59)
    # REDACTED_KEYS_ARRAY = cbor2.CBORTag(59, 0)
    # REDACTED_KEYS_ARRAY = -65536
    #
    if type(map) is not dict:
        raise Exception("Called redact_map on an object other than a dict")
    if type(level) is not int or level < 1 or level > 16:
        raise Exception("level is out of range: ", level)
    
    disclosures = []
    newmap = {}
    
    for key in map:
        value = map[key]
        if type(key) is cbor2.CBORTag and key.tag == TO_BE_REDACTED_TAG:
            if type(value) is list:
                (n, d) = redact_array(value, level+1)
                disclosures += d
                disclosure = make_disclosure(key=key.value, value=n)
            elif type(value) is dict:
                (n, d) = redact_map(value, level+1)
                disclosures += d
                disclosure = make_disclosure(key=key.value, value=n)
            else:
                disclosure = make_disclosure(key=key.value, value=value)
            disclosures.append(disclosure)
            redacted = sha256(cbor2.dumps(disclosure))
            if REDACTED_KEYS_ARRAY not in newmap:
                newmap[REDACTED_KEYS_ARRAY] = []
            newmap[REDACTED_KEYS_ARRAY].append(redacted)
        elif type(value) is list:
            (n, d) = redact_array(value, level+1)
            newmap[key] = n
            disclosures += d
        elif type(value) is dict:
            (n, d) = redact_map(value, level+1)
            newmap[key] = n
            disclosures += d
        else:
            newmap[key] = value
    
    return (newmap, disclosures)


def redact_array(array, level):
    if type(array) is not list:
        raise Exception("Called redact_array on an object other than a list")
    if type(level) is not int or level < 1 or level > 16:
        raise Exception("level is out of range: ", level)
    
    disclosures = []
    newarray = []
    
    for entry in array:
        if type(entry) is cbor2.CBORTag and entry.tag == TO_BE_REDACTED_TAG:
            if type(entry.value) is list:
                (n, d) = redact_array(entry.value, level+1)
                disclosures += d
                disclosure = make_disclosure(value=n)
            elif type(entry.value) is dict:
                (n, d) = redact_map(entry.value, level+1)
                disclosures += d
                disclosure = make_disclosure(value=n)
            else:
                disclosure = make_disclosure(value=entry.value)
            disclosures.append(disclosure)
            redacted = sha256(cbor2.dumps(disclosure))
            newarray.append(new_redacted_entry_tag(redacted))
        elif type(entry) is list:
            (n, d) = redact_array(entry, level+1)
            newarray.append(n)
            disclosures += d
        elif type(entry) is dict:
            (n, d) = redact_map(entry, level+1)
            newarray.append(n)
            disclosures += d
        else:
            newarray.append(entry)
    
    return (newarray, disclosures)


def cnf_from_key(cosekey):
    # cnf is 8
        # cose key is 1
            # alg is 3
                # EdDSA is -8
                # ES256 is -7
                # ES384 is -35
                # ES512 is -36
            # kty is 1
                # OKP is 1
                # EC2 is 2
            # crv is -1
                # Ed25519 is 6
                # Ed448 is 7
                # P-256 is 1
                # P-384 is 2
                # P-521 is 3  (Note: 521 is correct, not 512)
            # x is -2
            # y is -3 (EC2 only)
    from pycose.keys import EC2Key, CoseKey, OKPKey
    import pycose.keys.curves
    cosekey_dict = {}
    if type(cosekey) is pycose.keys.okp.OKPKey:
        cosekey_dict[1] = 1    # kty = OKP
        #cosekey_dict[3] = -8   # alg = EdDSA
        cosekey_dict[-2] = cosekey.x
        if cosekey.crv is pycose.keys.curves.Ed25519:
            cosekey_dict[-1] = 6
        elif cosekey.crv is pycose.keys.curves.Ed448:
            cosekey_dict[-1] = 7
        else:
            raise Exception("Unknown curve")
    elif type(cosekey) is pycose.keys.ec2.EC2Key:
        cosekey_dict[1] = 2    # kty = EC2
        cosekey_dict[-2] = cosekey.x
        cosekey_dict[-3] = cosekey.y
        if cosekey.crv is pycose.keys.curves.P256:
            cosekey_dict[-1] = 1
            #cosekey_dict[3] = -7
        elif cosekey.crv is pycose.keys.curves.P384:
            cosekey_dict[-1] = 2
            #cosekey_dict[3] = -35
        elif cosekey.crv is pycose.keys.curves.P521:
            cosekey_dict[-1] = 3
            #cosekey_dict[3] = -36
        else:
            raise Exception("Unknown curve")
    else:
        raise Exception("Unsupported key type")
    return {8: {1: cosekey_dict}}


def sign(phdr, uhdr, payload, key):
    # unlike pycose Sign1Message, the payload is not bstr encoded yet
    from pycose.messages import Sign1Message
    cwt_object = pycose.messages.sign1message.Sign1Message(
      phdr=phdr,
      uhdr=uhdr,
      payload=cbor.dumps(payload),
      key=key
    )
    return cwt_object.encode()


if __name__ == "__main__":
    print("Generating examples for SD-CWT draft.")
    from pycose.keys import CoseKey
    
    # constants for the draft
    CWT_IAT = 1725244200    # CWT issued at 01-Sep-2024 19:30 UTC
    KBT_IAT = CWT_IAT + 37  # KBT issued 37 seconds later
    
    to_be_redacted_payload = {
      1   : "https://issuer.example",
      2   : "mimi://example.com/d/asljc9sihSJI/08823ab2",
      500 : True,
      cbor2.CBORTag(58,501) : "ABCD-123456",
      502 : [
        cbor2.CBORTag(58, 1549560720),
        cbor2.CBORTag(58, 1612560720),
        17183928
      ],
      503 : {
        1: "us",
        cbor2.CBORTag(58, 2): "ca",
        cbor2.CBORTag(58, 3): "94188"
      }
    }
    
    tbr_nested_payload = {
      1   : "https://issuer.example",
      2   : "mimi://example.com/d/asljc9sihSJI/08823ab2",
      500 : True,
      cbor2.CBORTag(58,501) : "ABCD-123456",
      502 : [
        cbor2.CBORTag(58, 1549560720),
        cbor2.CBORTag(58, 1612560720),
        17183928
      ],
      cbor2.CBORTag(58, 503) : {
        1: "us",
        cbor2.CBORTag(58, 2): "ca",
        cbor2.CBORTag(58, 3): "94188",
        cbor2.CBORTag(58, 6): {
            1: "one",
            cbor2.CBORTag(58, 2): "two",
            cbor2.CBORTag(58, 3): "three"
        },
        cbor2.CBORTag(58, 7): [
            "A", 
            cbor2.CBORTag(58, "B"), 
            cbor2.CBORTag(58, "C")
        ]
      }
    }
    
    # load keys from files
    with open('issuer_privkey.pem', 'r') as file:
        issuer_priv_pem = file.read()
    with open('holder_privkey.pem', 'r') as file:
        holder_priv_pem = file.read()
    #issuer_priv_pem = '''-----BEGIN PRIVATE KEY-----
    #MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBxxU0iIZN+phLbEiHw
    #0933cck4HE475B1aoKidaF8Jz+90xLvxBHg/1X6HqyJ9B0yhZANiAATDF5iwx4hf
    #o1KPv4d+W0w6bcZ6Wl3Gswe3KMNyWSbyq+X7SWTNkeOUilST9uu2y7+PbH7HYWkc
    #rTdMTaqTh0U/GAWOzljrCo6EoFWjH7f5IUsnUJUiwVnnZPhxHhFglVQ=
    #-----END PRIVATE KEY-----'''
    
    #holder_priv_pem = '''-----BEGIN PRIVATE KEY-----
    #MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgV1moblm7OwAt3kZ9
    #pLUvPQbmws1DlFbPBIW5uGQpTOWhRANCAASFVOsnXc1vvRx6xkGqLJDZICL9DTAk
    #ta8Yx8xhrVJ6LU3HrixnfpbQzIJZdlXOktVQP1QpPYeHXR55zkdwGUND
    #-----END PRIVATE KEY-----'''
    issuer_priv_key = CoseKey.from_pem_private_key(issuer_priv_pem)
    holder_priv_key = CoseKey.from_pem_private_key(holder_priv_pem)
    
    # create common claims
    holder_cnf = cnf_from_key(holder_priv_key)
    cwt_time_claims = make_time_claims(3600*24, CWT_IAT) # one day expiration
    
    # redact payload for primary example
    (payload, disclosures) = redact_map(to_be_redacted_payload, 1)
    
    # generate/save pretty-printed disclosures from primary example
    decoded_disclosures = parse_disclosures(disclosures)
    TBC
    
    # make issued CWT for primary example
    payload |= holder_cnf | cwt_time_claims
    
    cwt_full_unprotected = {}
    cwt_full_unprotected[SD_CLAIMS] = disclosures
    
    cwt_protected = {
      1 : -35,                                 # alg = ES384
      4 : b'https://issuer.example/cwt-key3',  # kid
      16: "application/sd+cwt"                 # typ
      18: -16,                                 # sd_alg = SHA256
    }
    issuer_cwt = sign(cwt_protected,
                       cwt_full_unprotected,
                       payload,
                       issuer_priv_key)
    with open('issuer_cwt.cbor', 'wb') as file:
        file.write(issuer_cwt)
    
    # make KBT for primary example
    holder_unprotected = {
      SD_CLAIMS: [
        disclosures[0],
        disclosures[1],
        disclosures[3]
      ]}
    presentation_cwt = sign(cwt_protected,
                       holder_unprotected,
                       payload,
                       issuer_priv_key)
    # TODO: check the signatures for issuer_cwt and presentation_cwt are equal
    
    kbt_protected = {
        1  : -7,                        # alg = ES256
        16 : "application/kb+cwt",      # typ
        13 : presentation_cwt           # kcwt
    }
    
    kbt_payload = {
        3: "https://verifier.example",  # aud
        6: KBT_IAT                      # iat
    }
    
    kbt = sign(kbt_protected, {}, kbt_payload, holder_priv_key)
    with open('kbt.cbor', 'wb') as file:
        file.write(kbt)
    
    # save files related to primary example
    TBC
    
    # redact payload for nested example
    (payload, disclosures) = redact_map(tbr_nested_payload, 1)
    
    # generate/save pretty-printed disclosures from nested example
    payload |= holder_cnf | cwt_time_claims
    
    # which disclosures to include?
    nested_unprotected = {
      SD_CLAIMS: [
        disclosures[0]
      ]
    }
    nested_cwt = sign(cwt_protected,
                      nested_unprotected,
                      payload,
                      issuer_priv_key)
    kbt_protected[13] = nested_cwt
    nested_kbt = sign(kbt_protected, {}, kbt_payload, holder_priv_key)
    with open('nested_kbt.cbor', 'wb') as file:
        file.write(nested_kbt)
    
    # save files related to nested example
    TBC
