#!/usr/bin/env python3
import cbor2

TO_BE_REDACTED_TAG = 58
SD_CLAIMS = 17

# ****** Generically useful functions

def bytes2hex(bytes):
    import binascii
    return binascii.hexlify(bytes).decode("utf-8")

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

def write_to_file(value, filename):
    if isinstance(value, bytes):
        mode = 'wb'
    elif isinstance(value, str):
        mode = 'w'
    else:
        raise Exception("Can only write a bytes or str")
    with open(filename, mode) as f:
        f.write(value)

def pretty_hex(hex_str, indent=0):
    # takes a string of hex digits and returns an h'' EDN string
    # with at most 32 hex digits per line/row, indented `indent` spaces 
    l = len(hex_str)
    if l % 2 == 1:
        raise Exception("Odd number of hex digits")
    if l == 0:
        return "h''"
    # zero-indexed last row of hex chars
    last_row = (l - 1) // 32
    pretty = "h'"
    for row in range(last_row + 1):
        start = row*32
        if row != last_row:
            pretty += hex_str[start:start+32] + '\n' + ' '*(indent+2)
        else:
            pretty += hex_str[start:] + "'"
    return pretty

def iso_date(secs_since_epoch):
    import datetime
    t = datetime.datetime.fromtimestamp(secs_since_epoch, datetime.UTC)
    return t.isoformat() + 'Z'

def indent(string, num_spaces=4):
    # take a multi-line string and add `num_spaces` spaces (if positive)
    # TBC: or remove (if negative)
    new_string = ""
    if num_spaces > 0:
        for line in string.splitlines():
            new_string += (' '*num_spaces + line + '\n')
        return new_string
    #elif spaces < 0:
        # trimming not yet supported
    else:
        return string


# ****** Functions specific to SD-CWTs

def make_time_claims(expiration, now=None, leeway=300):
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
            raise Exception("Value must be specified if a key is present")
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
        new_array.append(cbor2.loads(bstr))
    return new_array


# TBC add decoy digests
def redact_map(map, level=1, num_decoys=0):
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
    
    # add num_decoys here
    #for i in range(num_decoys):
    #    disclosure = make_disclosure()
    #    disclosures.append(disclosure)
    #    redacted = sha256(cbor2.dumps(disclosure))
    #    if REDACTED_KEYS_ARRAY not in newmap:
    #        newmap[REDACTED_KEYS_ARRAY] = []
    #    newmap[REDACTED_KEYS_ARRAY].append(redacted)
    
    return (newmap, disclosures)


# TBC add decoy digests
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
    # return/generate a confirmation key object AND
    # its EDN thumbprint representation
    # from the corresponding cosekey
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
    edn = ""
    crv = ""
    alg = ""
    if type(cosekey) is pycose.keys.okp.OKPKey:
        cosekey_dict[1] = 1    # kty = OKP
        #cosekey_dict[3] = -8   # alg = EdDSA
        cosekey_dict[-2] = cosekey.x
        if cosekey.crv is pycose.keys.curves.Ed25519:
            cosekey_dict[-1] = 6
            crv = "Ed25519"
        elif cosekey.crv is pycose.keys.curves.Ed448:
            cosekey_dict[-1] = 7
            crv = "Ed448"
        else:
            raise Exception("Unknown curve")
        #        / alg /  3: -8, / EdDSA /
        edn = f'''        / kty /  1: 1,  / OKP   /
        / crv / -1: {cosekey_dict[-1]},  / {crv} /
        / x /   -2: {pretty_hex(bytes2hex(cosekey_dict[-2]), 20)}
'''
    elif type(cosekey) is pycose.keys.ec2.EC2Key:
        cosekey_dict[1] = 2    # kty = EC2
        cosekey_dict[-2] = cosekey.x
        cosekey_dict[-3] = cosekey.y
        if cosekey.crv is pycose.keys.curves.P256:
            cosekey_dict[-1] = 1
            crv = "P-256"
            #cosekey_dict[3] = -7
            alg = "ES256"
        elif cosekey.crv is pycose.keys.curves.P384:
            cosekey_dict[-1] = 2
            crv = "P-284"
            #cosekey_dict[3] = -35
            alg = "ES384"
        elif cosekey.crv is pycose.keys.curves.P521:
            cosekey_dict[-1] = 3
            crv = "P-521"
            #cosekey_dict[3] = -36
            alg = "ES512"
        else:
            raise Exception("Unknown curve")
        #        / alg /  3: {cosekey_dict[3]}, / {alg} /
        edn = f'''        / kty /  1: 2,  / EC2   /
        / crv / -1: {cosekey_dict[-1]},  / {crv} /
        / x /   -2: {pretty_hex(bytes2hex(cosekey_dict[-2]), 20)},
        / y /   -3: {pretty_hex(bytes2hex(cosekey_dict[-3]), 20)}
'''
    else:
        raise Exception("Unsupported key type")
    return ( {8: {1: cosekey_dict}}, edn )


def sign(phdr, uhdr, payload, key):
    # unlike pycose Sign1Message, the payload is not bstr encoded yet
    from pycose.messages import Sign1Message
    cwt_object = Sign1Message(
      phdr=phdr,
      uhdr=uhdr,
      payload=cbor2.dumps(payload),
      key=key
    )
    return cwt_object.encode()


def edn_one_disclosure(disclosure, comment=None):
    def val(value):
        # get pretty printing to work correctly for unnested values 
        if isinstance(value, str):
            return '"' + value + '"'
        elif isinstance(value, bytes):
            return "h'" + bytes2hex(value) + "'"
        elif isinstance(value, bool):
            return "true" if value is True else "false"
        else:
            return value

    if len(disclosure) == 0 or len(disclosure) > 3:
        raise Exception("Too many/few elements in disclosure")
    cmt = ""
    if comment != None:
        cmt = "   / " + comment + " /"
    edn = '        <<[\n'
    edn += f"            /salt/   h'{bytes2hex(disclosure[0])}',\n"
    if len(disclosure) == 3:
        edn += f"            /claim/  {val(disclosure[1])},{cmt}\n"
        edn += f"            /value/  {val(disclosure[2])}\n"
    elif len(disclosure) == 2:
        edn += f"            /value/  {val(disclosure[1])}{cmt}\n"
    edn += '        ]>>,\n'
    return edn


def edn_decoded_disclosures(disclosures, comments=[]):
    edn = '    / sd_claims / 17 : [ / these are all the disclosures /\n'
    i = 0
    for d in disclosures:
        cmt = None
        if i < len(comments):
            cmt = comments[i]
        disc_array = cbor2.loads(d)
        edn += edn_one_disclosure(disc_array, comment=cmt)
        i += 1
    edn += '    ]\n'
    return edn


def redacted_hashes_from_disclosures(disclosures):
    # an array of the redacted SHA hex strings in same order as the disclosures
    redacted = []
    for d in disclosures:
        redacted.append(bytes2hex(sha256(cbor2.dumps(d))))
    return redacted


# ****** Functions to generate the *examples* in the SD-CWT draft

# TODO: eventually put all under build_draft_examples
#def build_draft_examples():
def generate_basic_issuer_cwt_edn(edn_disclosures, exp, nbf, iat,
                                  thumb_fields, redacted, sig):
    # use this function twice to generate two versions of this EDN:
    #   - one for holder with all disclosures,
    #   - one for verifier with holder-selected disclosures
    return f'''/ cose-sign1 / 18([  / issuer SD-CWT /
  / CWT protected / << {{
    / alg /    1  : -35, / ES384 /
    / typ /    16 : "application/sd+cwt",
    / kid /    4  : 'https://issuer.example/cwt-key3',
    / sd_alg / 18 : -16  / SHA256 /
  }} >>,
  / CWT unprotected / {{
{edn_disclosures}  }}
  / CWT payload / << {{
    / iss / 1   : "https://issuer.example",
    / sub / 2   : "https://device.example",
    / exp / 4   : {exp},  /{iso_date(exp)}/
    / nbf / 5   : {nbf},  /{iso_date(nbf)}/
    / iat / 6   : {iat},  /{iso_date(iat)}/
    / cnf / 8   : {{
      / cose key / 1 : {{
{thumb_fields}      }}
    }},
    /most_recent_inspection_passed/ 500: true,
    / redacted_claim_keys / 59(0) : [
        / redacted inspector_license_number /
        {pretty_hex(redacted[0], 8)}
    ],
    /inspection_dates/ 502 : [
        / redacted inspection date 7-Feb-2019 /
        60({pretty_hex(redacted[1], 11)}),
        / redacted inspection date 4-Feb-2021 /
        60({pretty_hex(redacted[2], 11)}),
        1674004740,   / 2023-01-17T17:19:00 /
    ],
    / inspection_location / 503 : {{
        "country" : "us",            / United States /
        / redacted_claim_keys / 59(0) : [
            / redacted region /
            {pretty_hex(redacted[3], 12)}
            / redacted postal_code /
            {pretty_hex(redacted[4], 12)}
      ]
    }}
  }} >>,
  / CWT signature / {pretty_hex(bytes2hex(sig), 20)}
])'''


def generate_basic_holder_kbt_edn(issuer_cwt, iat, sig):
    cwt = indent(issuer_cwt, 4) # indent 4 spaces
    # trim the / cose-sign1 / and extra indent from first line
    cwt = cwt[18:]
    #print(cwt)
    return f'''/ cose-sign1 / 18( / sd_kbt / [
  / KBT protected / << {{
    / alg /    1:  -7, / ES256 /
    / typ /   16:  "application/kb+cwt",
    / kcwt /  13:  {cwt}     / end of issuer SD-CWT /
  }} >>,     / end of KBT protected header /
  / KBT unprotected / {{}},
  / KBT payload / << {{
    / cnonce / 39    : h'8c0f5f523b95bea44a9a48c649240803',
    / aud    /  3    : "https://verifier.example/app",
    / iat    /  6    : {iat}, / {iso_date(iat)} /
  }} >>,      / end of KBT payload /
  / KBT signature / {pretty_hex(bytes2hex(sig), 20)}
])   / end of kbt /'''


#def make_basic_example():
#    from pycose.keys import CoseKey


if __name__ == "__main__":
    print("Generating examples for SD-CWT draft.")
    from pycose.keys import CoseKey
    
    # constants for the draft
    CWT_IAT = 1725244200    # CWT issued at 01-Sep-2024 19:30 UTC
    KBT_IAT = CWT_IAT + 37  # KBT issued 37 seconds later
    
    to_be_redacted_payload = {
      1   : "https://issuer.example",
      2   : "https://device.example",
      500 : True,
      cbor2.CBORTag(58,501) : "ABCD-123456",
      502 : [
        cbor2.CBORTag(58, 1549560720),
        cbor2.CBORTag(58, 1612560720),
        17183928
      ],
      503 : {
        "country": "us",
        cbor2.CBORTag(58, "region"): "ca",
        cbor2.CBORTag(58, "postal_code"): "94188"
      }
    }
    
    # load keys from files
    with open('../issuer_privkey.pem', 'r') as file:
        issuer_priv_pem = file.read()
    with open('../holder_privkey.pem', 'r') as file:
        holder_priv_pem = file.read()
    issuer_priv_key = CoseKey.from_pem_private_key(issuer_priv_pem)
    holder_priv_key = CoseKey.from_pem_private_key(holder_priv_pem)
    
    # create common claims
    (holder_cnf, holder_thumb_edn) = cnf_from_key(holder_priv_key)
    cwt_time_claims = make_time_claims(3600*24, CWT_IAT) # one day expiration
    
    # redact payload for primary example
    (payload, disclosures) = redact_map(to_be_redacted_payload)
    
    # generate/save pretty-printed disclosures from primary example
    example_comments=[
        "inspector_license_number",
        "inspected 7-Feb-2019",
        "inspected 4-Feb-2021",
        "region=California"
    ]
    decoded_disclosures = parse_disclosures(disclosures)
    edn_disclosures = edn_decoded_disclosures(decoded_disclosures, 
                                      comments=example_comments)
    redacted = redacted_hashes_from_disclosures(disclosures)
    with open('disclosures.edn', 'w') as file:
        print(edn_disclosures, file=file)
    
    # write first disclosure becoming blinded claim
    first_disc_array = cbor2.loads(decoded_disclosures[0])
    with open('first-disclosure.edn', 'w') as file:
        print(edn_one_disclosure(first_disc_array, comment=example_comments[0]),
            file=file)
    first_bstr = decoded_disclosures[0]
    with open('first-disclosure.cbor', 'wb') as file:
        file.write(first_bstr)
    first_redacted = bytes2hex(sha256(first_bstr))
    with open('first-blinded-hash.txt', 'w') as file:
        file.write(first_redacted)
    with open('first-redacted.edn', 'w') as file:
        print( "  / redacted_claim_keys / 59(0) : [", file=file)
        print( "      / redacted inspector_license_number /", file=file)
        print(f"      h'{first_redacted[0:32]}", file=file)
        print(f"        {first_redacted[32:64]}',", file=file)
        print( "      / ... next redacted claim at the same level would go here /", file=file)
        print( "  ],", file=file)
    
    # make issued CWT for primary example
    payload |= holder_cnf | cwt_time_claims
    
    cwt_full_unprotected = {}
    cwt_full_unprotected[SD_CLAIMS] = disclosures
    
    cwt_protected = {
      1 : -35,                                 # alg = ES384
      4 : b'https://issuer.example/cose-key3', # kid
      16: "application/sd+cwt",                # typ
      18: -16,                                 # sd_alg = SHA256
    }
    issuer_cwt = sign(cwt_protected,
                       cwt_full_unprotected,
                       payload,
                       issuer_priv_key)
    with open('issuer_cwt.cbor', 'wb') as file:
        file.write(issuer_cwt)
    
    # write issuer CWT EDN from template
    
    basic_issued_edn = generate_basic_issuer_cwt_edn(edn_disclosures, 
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_cwt[-96:])
    with open('issuer_cwt.edn', 'w') as file:
        file.write(basic_issued_edn)

    
    # make KBT for primary example
    presented_disclosures = [
        decoded_disclosures[0],
        decoded_disclosures[1],
        decoded_disclosures[3]
    ]
    presented_comments=[
        example_comments[0],
        example_comments[1],
        example_comments[3]
    ]

    edn_disclosures = edn_decoded_disclosures(
        presented_disclosures, comments=presented_comments)
    #redacted = redacted_hashes_from_disclosures(presented_disclosures)
    basic_presented_edn = generate_basic_issuer_cwt_edn(edn_disclosures, 
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_cwt[-96:])
    
    holder_unprotected = {SD_CLAIMS: presented_disclosures}
    presentation_cwt = sign(cwt_protected,
                       holder_unprotected,
                       payload,
                       issuer_priv_key)
    if issuer_cwt[-96:] != presentation_cwt[-96:]:
        print("oops the issuer signatures don't match ")
    
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
    
    basic_kbt_edn = generate_basic_holder_kbt_edn(
        basic_presented_edn, iat=KBT_IAT, sig=kbt[-64:])
    with open('kbt.edn', 'w') as file:
        file.write(basic_kbt_edn)

    # **** TODO: finish nested example
    
    tbr_nested_payload = {
      1   : "https://issuer.example",
      2   : "https://device.example",
      cbor2.CBORTag(58,504) : [    # inspection history log
          cbor2.CBORTag(58, {
              500 : True,
              502 : 1549560720,
              cbor2.CBORTag(58,501) : "ABCD-101777",
              cbor2.CBORTag(58, 503) : {
                  1: "us",
                  cbor2.CBORTag(58, 2): "ca",
                  cbor2.CBORTag(58, 3): "94188",
              }
          }),
          cbor2.CBORTag(58, {
              500 : True,
              502 : 1612560720,
              cbor2.CBORTag(58,501) : "EFGH-789012",
              cbor2.CBORTag(58, 503) : {
                  1: "us",
                  cbor2.CBORTag(58, 2): "nv",
                  cbor2.CBORTag(58, 3): "89155",
              }
          }),
          {
              500 : True,
              502 : 17183928,
              cbor2.CBORTag(58,501) : "ABCD-123456",
              cbor2.CBORTag(58, 503) : {
                  1: "us",
                  cbor2.CBORTag(58, 2): "ca",
                  cbor2.CBORTag(58, 3): "94188",
              }
          },
      ]
    }
    
    # redact payload for nested example
    #(payload, disclosures) = redact_map(tbr_nested_payload, 1)
    
    # generate issued nested example?
    
    # generate/save pretty-printed disclosures from nested example
    #payload |= holder_cnf | cwt_time_claims
    
    # which disclosures to include?
    #nested_unprotected = {
    #  SD_CLAIMS: [
    #    disclosures[0]
    #  ]
    #}
    #nested_cwt = sign(cwt_protected,
    #                  nested_unprotected,
    #                  payload,
    #                  issuer_priv_key)
    #kbt_protected[13] = nested_cwt
    #nested_kbt = sign(kbt_protected, {}, kbt_payload, holder_priv_key)
    #with open('nested_kbt.cbor', 'wb') as file:
    #    file.write(nested_kbt)

