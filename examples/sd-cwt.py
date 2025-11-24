#!/usr/bin/env python3
import cbor2

TO_BE_REDACTED_TAG = 58
TO_BE_DECOY_TAG = 61
SD_CLAIMS = 17

# ****** Generically useful functions

def hex2bytes(string):
    return bytes.fromhex(string)

def bytes2hex(bstr):
    import binascii
    return binascii.hexlify(bstr).decode("utf-8")

def b64u_to_bytes(b64):
    import base64
    return base64.urlsafe_b64decode(b64 + '==')

def bytes_to_b64u(bstr):
    import base64
    b = base64.urlsafe_b64encode(bstr).rstrip(b'=')
    return b.decode('ascii')

def b64u_to_hex(b64):
    import base64
    return base64.urlsafe_b64decode(b64 + '==').hex()

def read_salts():
    import csv
    salt_map = {}
    with open('salt_list.csv', 'r') as f:
        salts = csv.reader(f)
        for row in salts:
            salt_map[hex2bytes(row[0])] = hex2bytes(row[1])
    return salt_map

def write_new_salts(salt_map):
    import csv
    with open('salt_list.csv', 'a') as f:
        csvwriter = csv.writer(f)
        for k in salt_map:
            csvwriter.writerow(list((bytes2hex(k), bytes2hex(salt_map[k]))))

def read_decoy_salts():
    import csv
    decoy_map = {}
    with open('decoy_list.csv', 'r') as f:
        salts = csv.reader(f)
        for row in salts:
            decoy_map[int(row[0])] = hex2bytes(row[1])
    return decoy_map

def write_new_decoy_salts(decoy_map):
    import csv
    with open('decoy_list.csv', 'a') as f:
        csvwriter = csv.writer(f)
        for i in decoy_map:
            csvwriter.writerow(list((i, bytes2hex(decoy_map[i]))))

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

def bytes_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

def indent(string, num_spaces=4):
    # take a multi-line string and add `num_spaces` spaces (if positive)
    # TBC: or remove (if negative)
    if type(string) != str or len(string) == 0:
        return ''
    new_string = ""
    if num_spaces > 0:
        for line in string.splitlines():
            new_string += (' '*num_spaces + line + '\n')
        return new_string[:-1]  #trim final \n
    #elif spaces < 0:
        # trimming not yet supported
    else:
        return string

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

def pretty_by_type(thing, indent=0, newline=True):
  def pretty(string, indent, ending):
    return ' '*indent + string + ending

  if newline:
    ending = '\n'
  else:
    ending = ''
  if type(thing) is bool:
    if thing == True:
      return pretty("true", indent, ending)
    else:
      return pretty("false", indent, ending)
  if thing is None:
    return pretty("null"), indent, ending
  match thing:
    case int():
      return pretty(f'{thing}', indent, ending)
    case float():
      return pretty(f'{thing}', indent, ending)
    case str():
      return pretty(f'"{thing}"', indent, ending)
    case bytes():
      return pretty(pretty_hex(bytes2hex(thing), indent),
                    indent, ending)
    case list():
      p = pretty('[', indent, '\n')
      c = 0
      for i in thing:
        c += 1
        p += pretty_by_type(i, indent=indent+4, newline=False)
        if c != len(thing):
            p += ',\n'
        else:
            p += '\n'
      p += pretty(']', indent, ending)
      return p
    case dict():
      p = pretty('{', indent, '\n')
      c = 0
      for i in thing:
        c += 1
        p += pretty_by_type(i, indent=indent+4, newline=False)
        p += ': '
        p += pretty_by_type(thing[i], newline=False)
        if c != len(thing):
            p += ',\n'
        else:
            p += '\n'
      p += pretty('}', indent, ending)
      return p
    case _:
      if thing.__class__ == cbor2.CBORSimpleValue:
        return pretty(f'simple({thing.value})', indent, ending)
      elif thing.__class__ == cbor2.CBORTag:
        p = pretty(f'{thing.tag}', indent, ending)
        p += '('
        p += pretty_by_type(thing.value, newline=False)
        p += ')' + ending
        return p

def iso_date(secs_since_epoch):
    import datetime
    t = datetime.datetime.fromtimestamp(secs_since_epoch, datetime.UTC)
    return t.isoformat() + 'Z'

def sort_keys(unsorted_dict, rfc7049=False):
    # note: does not sort into keys which are themselves maps
    def walk_array(array):
        if array == []:
            return []
        temp_array = []
        for item in array:
            if type(item) == dict:
                temp_array.append(sort_keys(item))
            elif type(item) == list:
                temp_array.append(walk_array(item))
            else:
                temp_array.append(item)
        return temp_array
    if rfc7049 is True:
        raise Exception("RFC7049 ordering not yet supported")
    if type(unsorted_dict) == list:
        # actually an array
        return walk_array(unsorted_dict)
    elif type(unsorted_dict) != dict:
        # some scalar type
        return unsorted_dict
    if len(unsorted_dict) == 0:
        return {}
    new_dict = {}
    cbor_key_encoding = {}
    for k in unsorted_dict:
        cbor_key_encoding[cbor2.dumps(k)] = k
    sorted_keys = dict(sorted(cbor_key_encoding.items()))
    for encoded_key in sorted_keys:
        original_key = cbor_key_encoding[encoded_key]
        val = unsorted_dict[original_key]
        if type(val) == dict:
            new_dict[original_key] = sort_keys(val)
        elif type(val) == list:
            new_dict[original_key] = walk_array(val)
        else:
            new_dict[original_key] = val
    return new_dict


# ****** Functions specific to SD-CWTs

def new_redacted_entry_tag(value):
    REDACTED_ENTRY_TAG = 60
    return cbor2.CBORTag(REDACTED_ENTRY_TAG, value)

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

# needs global salts and append_salts dicts
def find_salt(value, key=None):
    # find an existing salt or generate one if not in "salts" dict
    salt_index = sha256(cbor2.dumps([key, value]))
    if salt_index not in salts:
        s = new_salt()
        salts[salt_index] = s
        append_salts[salt_index] = s
        print(f'Added new salt {bytes2hex(salts[salt_index])} for {bytes2hex(salt_index)}')
    return salts[salt_index]

# needs global decoy_salts and append_decoy_salts dicts
def find_decoy_salt(decoy_index):
    if type(decoy_index) != int:
        raise Exception("decoy_index needs to be an int")
    if decoy_index not in decoy_salts:
        s = new_salt()
        decoy_salts[decoy_index] = s
        append_decoy_salts[decoy_index] = s
    return decoy_salts[decoy_index]

# needs global aes_keys and append_aes_keys dicts
#def find_aes_key(salt)
#    import secrets
#    if type(salt) != bytes:
#        raise Exception("salt needs to be a bytes")
#    if salt not in aes_keys:
#        nonce = secrets.token_bytes(16)
#        key = secrets.token_bytes(32)
#    return (nonce, key)

def make_disclosure(salt=None, key=None, value=None, decoy_index=None):
    if decoy_index == None and value == None:
        raise Exception("can't make disclosure with no value nor decoy_index ")
    if salt is None:
        if decoy_index == None:
            salt = find_salt(value=value, key=key)
        else:
            salt = find_decoy_salt(decoy_index)
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
            disclosure_array = [salt, value, key]
    # double encode to add bstr type and bstr length
    return cbor2.dumps(sort_keys(disclosure_array))


def parse_disclosures(disclosures):
    # takes an array of bstr and returns an array of parsed disclosures
    import cbor2
    new_array = []
    for bstr in disclosures:
        new_array.append(cbor2.loads(bstr))
    return new_array


def redact_level(item, level, map_value=False):
    # return redacted_item, disclosures
    REDACTED_KEYS_ARRAY = cbor2.CBORSimpleValue(59)
    redacted = None
    disclosures = []
    if type(item) is list:
        redacted=[]
        for element in item:
            # replace one tagged element for another
            (new_item, disc) = redact_level(element, level+1)
            redacted.append(new_item)
            disclosures += disc
    elif type(item) is dict:
        redacted = {}
        redacted_keys = []  #redacted keys array at this level
        for key in item:
            if type(key) is cbor2.CBORTag:
                if key.tag == TO_BE_REDACTED_TAG:
                    # redact the value of this key
                    (new_value, disc) = redact_level(item[key], level+1, True)
                    disclosure = make_disclosure(key=key.value, value=new_value)
                    disclosures += disc
                    disclosures.append(disclosure)
                    h = sha256(cbor2.dumps(disclosure))
                    redacted_keys.append(h)
                elif key.tag == TO_BE_DECOY_TAG:
                    disclosure = make_disclosure(decoy_index=key.value)
                    disclosures.append(disclosure)
                    h = sha256(cbor2.dumps(disclosure))
                    redacted_keys.append(h)
                else:
                    raise Exception("other tagged map keys not allowed in CWT")
            elif type(key) in (int, str):
                (new_value, disc) = redact_level(item[key], level+1)
                disclosures += disc
                redacted[key] = new_value
            else:
                raise Exception("map keys must be int or tstr")
        if len(redacted_keys) > 0:
            redacted[REDACTED_KEYS_ARRAY] = redacted_keys
    elif type(item) is cbor2.CBORTag:
        if item.tag not in (TO_BE_REDACTED_TAG, TO_BE_DECOY_TAG):
            (new_item, disc) = redact_level(item.value, level+1)
            redacted = cbor2.CBORTag(item.tag, new_item)
            disclosures += disc
        elif item.tag == TO_BE_REDACTED_TAG:
            if map_value:
                raise Exception("to be redacted tag not allowed in map values")
            (new_item, disc) = redact_level(item.value, level+1)
            d = make_disclosure(value=new_item)
            disclosures += disc
            disclosures.append(d)
            h = sha256(cbor2.dumps(d))
            redacted = new_redacted_entry_tag(h)
        else: # TO_BE_DECOY_TAG
            if map_value:
                raise Exception("to be decoy tag not allow in map values")
            if type(item.value) is not int:
                raise Exception("decoy tag: integer index expected")
            disclosure = make_disclosure(decoy_index=item.value)
            disclosures.append(disclosure)
            h = sha256(cbor2.dumps(disclosure))
            redacted = new_redacted_entry_tag(h)
    else:
        redacted = item
    return (redacted, disclosures)


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
      payload=cbor2.dumps(sort_keys(payload)),
      key=key
    )
    return cwt_object.encode()


def edn_one_disclosure(disclosure, comment=None):
    def val(value):
        # get pretty printing to work correctly for unnested values 
        #if isinstance(value, str):
        #    return '"' + value + '"'
        #elif isinstance(value, bytes):
        #    return "h'" + bytes2hex(value) + "'"
        #elif isinstance(value, bool):
        #    return "true" if value is True else "false"
        #elif
        #else:
        #    return value
        return indent(pretty_by_type(value, newline=False), num_spaces=21)[21:]

    if len(disclosure) == 0 or len(disclosure) > 3:
        raise Exception("Too many/few elements in disclosure")
    cmt = ""
    if comment != None:
        cmt = "   / " + comment + " /"
    edn = '        <<[\n'
    edn += f"            /salt/   h'{bytes2hex(disclosure[0])}',\n"
    if len(disclosure) == 3:
        if disclosure[2] == 500:
            print(disclosure[1])
            print(type(disclosure[1]))
        edn += f"            /value/  {val(disclosure[1])},\n"
        edn += f"            /claim/  {val(disclosure[2])}{cmt}\n"
    elif len(disclosure) == 2:
        edn += f"            /value/  {val(disclosure[1])}{cmt}\n"
    #else len == 1 (decoy) - so do nothing else
    edn += '        ]>>,\n'
    return edn


def edn_decoded_disclosures(disclosures, comments=[], all=False):
    edn = f'    / sd_claims / 17 : [ / these are {"all " if all else ""}the disclosures /\n'
    i = 0
    for d in disclosures:
        cmt = None
        if i < len(comments):
            cmt = comments[i]
        edn += edn_one_disclosure(d, comment=cmt)
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
    / kid /    4  : 'https://issuer.example/cose-key3',
    / typ /    16 : "application/sd-cwt",
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
    /inspection_dates/ 502 : [
        / redacted inspection date 7-Feb-2019 /
        60({pretty_hex(redacted[1], 11)}),
        / redacted inspection date 4-Feb-2021 /
        60({pretty_hex(redacted[2], 11)}),
        1674004740,   / 2023-01-17T17:19:00 /
    ],
    / inspection_location / 503 : {{
        "country" : "us",            / United States /
        / redacted_claim_keys / simple(59) : [
            / redacted region /
            {pretty_hex(redacted[3], 12)}
            / redacted postal_code /
            {pretty_hex(redacted[4], 12)}
      ]
    }},
    / redacted_claim_keys / simple(59) : [
        / redacted inspector_license_number /
        {pretty_hex(redacted[0], 8)}
    ]
  }} >>,
  / CWT signature / {pretty_hex(bytes2hex(sig), 20)}
])'''

def generate_nested_cwt_edn(edn_disclosures, exp, nbf, iat,
                            thumb_fields, redacted, sig, comments):
    # use this function twice to generate two versions of this EDN:
    #   - one for holder with all disclosures,
    #   - one for verifier with holder-selected disclosures
    return f'''/ cose-sign1 / 18([  / issuer SD-CWT /
  / CWT protected / << {{
    / alg /    1  : -35, / ES384 /
    / kid /    4  : 'https://issuer.example/cose-key3',
    / typ /    16 : "application/sd-cwt",
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
    /inspection history log/ 504: [
      / {comments[4]} /
      60({pretty_hex(redacted[4], 9)}),
      / {comments[9]} /
      60({pretty_hex(redacted[9], 9)}),
      / {comments[14]} /
      60({pretty_hex(redacted[14], 9)})
    ]
  }} >>,
  / CWT signature / {pretty_hex(bytes2hex(sig), 20)}
])'''

def generate_basic_holder_kbt_edn(issuer_cwt, iat, sig):
    cwt = indent(issuer_cwt, 4) # indent 4 spaces
    # trim the / cose-sign1 / and extra indent from first line
    cwt = cwt[19:]
    #print(cwt)
    return f'''/ cose-sign1 / 18( / sd_kbt / [
  / KBT protected / << {{
    / alg /    1:  -7, / ES256 /
    / kcwt /  13:  {cwt},\n    / end of issuer SD-CWT /
    / typ /   16:  "application/kb+cwt",
  }} >>,     / end of KBT protected header /
  / KBT unprotected / {{}},
  / KBT payload / << {{
    / aud    /  3    : "https://verifier.example/app",
    / iat    /  6    : {iat}, / {iso_date(iat)} /
    / cnonce / 39    : h'8c0f5f523b95bea44a9a48c649240803'
  }} >>,      / end of KBT payload /
  / KBT signature / {pretty_hex(bytes2hex(sig), 20)}
])   / end of kbt /'''

def generate_decoy_cwt_edn(edn_disclosures, exp, nbf, iat,
                                  thumb_fields, redacted, sig):
    return f'''/ cose-sign1 / 18([  / issuer SD-CWT /
  / CWT protected / << {{
    / alg /    1  : -35, / ES384 /
    / kid /    4  : 'https://issuer.example/cose-key3',
    / typ /    16 : "application/sd-cwt",
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
    /countries array/ 98: [
        /redacted country == "fr" /
        {pretty_hex(redacted[0], 8)}
        /decoy country #1 /
        {pretty_hex(redacted[1], 8)}
    ],
    / redacted_claim_keys / simple(59) : [
        / redacted claim 500 (== true) /
        {pretty_hex(redacted[2], 8)}
        / decoy claim #2 /
        {pretty_hex(redacted[3], 8)}
    ]
  }} >>,
  / CWT signature / {pretty_hex(bytes2hex(sig), 20)}
])'''


#def make_basic_example():
#    from pycose.keys import CoseKey


if __name__ == "__main__":
    print("Generating examples for SD-CWT draft.")
    from pycose.keys import CoseKey

    # constants for the draft
    CWT_IAT = 1725244200    # CWT issued at 01-Sep-2024 19:30 UTC
    KBT_IAT = CWT_IAT + 37  # KBT issued 37 seconds later

    salts = read_salts()
    append_salts = {}
    decoy_salts = read_decoy_salts()
    append_decoy_salts = {}

    to_be_redacted_payload = {
      1   : "https://issuer.example",
      2   : "https://device.example",
      500 : True,
      cbor2.CBORTag(58,501) : "ABCD-123456",
      502 : [
        cbor2.CBORTag(58, 1549560720),
        cbor2.CBORTag(58, 1612560720),
        1674004740
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
    (payload, disclosures) = redact_level(to_be_redacted_payload, level=1)
    
    # generate/save pretty-printed disclosures from primary example
    example_comments=[
        "inspector_license_number",
        "inspected 7-Feb-2019",
        "inspected 4-Feb-2021",
        "region=California"
    ]
    decoded_disclosures = parse_disclosures(disclosures)
    edn_disclosures = edn_decoded_disclosures(decoded_disclosures, 
                            comments=example_comments, all=True)
    redacted = redacted_hashes_from_disclosures(disclosures)
    
    # write first disclosure becoming blinded claim
    first_disc_array = decoded_disclosures[0]
    with open('first-disclosure.edn', 'w') as file:
        print(edn_one_disclosure(first_disc_array, comment=example_comments[0])[:-1],
            file=file, end='')
    first_bstr = cbor2.dumps(decoded_disclosures[0])
    with open('first-disclosure.cborseq', 'wb') as file:
        file.write(first_bstr)
    first_redacted = bytes2hex(sha256(first_bstr))
    with open('first-blinded-hash.txt', 'w') as file:
        file.write(first_redacted)
    with open('first-redacted.edn', 'w') as file:
        print( "  / redacted_claim_keys / simple(59) : [", file=file)
        print( "      / redacted inspector_license_number /", file=file)
        print(f"      h'{first_redacted[0:32]}", file=file)
        print(f"        {first_redacted[32:64]}',", file=file)
        print( "      / ... next redacted claim at the same level would go here /", file=file, end='')
        print( "  ],", file=file)
    
    # make issued CWT for primary example
    payload |= holder_cnf | cwt_time_claims
    
    cwt_full_unprotected = {}
    cwt_full_unprotected[SD_CLAIMS] = disclosures
    
    cwt_protected = {
      1 : -35,                                 # alg = ES384
      4 : b'https://issuer.example/cose-key3', # kid
      16: "application/sd-cwt",                # typ
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
    write_to_file(edn_disclosures, 'chosen-disclosures.edn')
    
    basic_presented_edn = generate_basic_issuer_cwt_edn(edn_disclosures, 
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_cwt[-96:])
    
    encoded_presented_disclosures = []
    for d in presented_disclosures:
        encoded_presented_disclosures.append(cbor2.dumps(d))
    
    holder_unprotected = {SD_CLAIMS: encoded_presented_disclosures}
    presentation_cwt = sign(cwt_protected,
                       holder_unprotected,
                       payload,
                       issuer_priv_key)
    if issuer_cwt[-96:] != presentation_cwt[-96:]:
        print("oops the issuer signatures don't match ")
    
    kbt_protected = {
        1  : -7,                                  # alg = ES256
        13 : cbor2.loads(presentation_cwt),       # kcwt
        16 : "application/kb+cwt"                 # typ
    }
    
    kbt_payload = {
        3: "https://verifier.example/app",                # aud
        6: KBT_IAT,                                       # iat
        39: hex2bytes('8c0f5f523b95bea44a9a48c649240803') # cnonce
    }
    
    kbt = sign(kbt_protected, {}, kbt_payload, holder_priv_key)
    with open('kbt.cbor', 'wb') as file:
        file.write(kbt)
    
    basic_kbt_edn = generate_basic_holder_kbt_edn(
        basic_presented_edn, iat=KBT_IAT, sig=kbt[-64:])
    with open('kbt.edn', 'w') as file:
        file.write(basic_kbt_edn)
    
    elision_message = ' '*15 + '''...
       /  *** SD-CWT from Issuer goes here      /
       /  with Holder's choice of disclosures   /
       /  in the SD-CWT unprotected header  *** /'''
    elided_kbt_edn = generate_basic_holder_kbt_edn(
        elision_message , iat=KBT_IAT, sig=kbt[-64:])
    write_to_file(elided_kbt_edn, 'elided-kbt.edn')
    
    
    # ***** Nested example
    
    tbr_nested_payload = {
      1   : "https://issuer.example",
      2   : "https://device.example",
      504 : [    # inspection history log
          cbor2.CBORTag(58, {
              500 : True,
              502 : 1549560720,
              cbor2.CBORTag(58,501) : "DCBA-101777",
              cbor2.CBORTag(58, 503) : {
                  1: "us",
                  cbor2.CBORTag(58, 2): "co",
                  cbor2.CBORTag(58, 3): "80302",
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
          cbor2.CBORTag(58, {
              500 : True,
              502 : 1674004740,
              cbor2.CBORTag(58,501) : "ABCD-123456",
              cbor2.CBORTag(58, 503) : {
                  1: "us",
                  cbor2.CBORTag(58, 2): "ca",
                  cbor2.CBORTag(58, 3): "94188",
              }
          }),
      ]
    }
    
    # redact payload for nested example
    (payload, disclosures) = redact_level(tbr_nested_payload, level=1)
        
    # make nested-cwt
    payload |= holder_cnf | cwt_time_claims
    
    # help figure out which disclosures to include
    for d in disclosures:
        disc_array = cbor2.loads(d)
        print(f'''
{disc_array}
''')

    full_nested_unprotected = {
      SD_CLAIMS: disclosures
    }
    issuer_nested_cwt = sign(cwt_protected,
                      full_nested_unprotected,
                      payload,
                      issuer_priv_key)
    write_to_file(issuer_nested_cwt, "nested_issuer_cwt.cbor")

    # generate/save pretty-printed disclosures from nested example
    example_comments=[
        "inspector_license_number",  # 0
        "region=Colorado",           # 1
        "postcode=80302",            # 2
        "Denver location",           # 3
        "inspection 7-Feb-2019",     # 4
        "inspector_license_number",  # 5
        "region=Nevada",             # 6
        "postcode=89155",            # 7
        "Las Vegas location",        # 8
        "inspection 4-Feb-2021",     # 9
        "inspector_license_number",  # 10
        "region=California",         # 11
        "postcode=94188",            # 12
        "San Francisco location",    # 13
        "inspection 17-Jan-2023"     # 14
    ]
    decoded_disclosures = parse_disclosures(disclosures)
    edn_disclosures = edn_decoded_disclosures(decoded_disclosures, 
                            comments=example_comments, all=True)

    # generate nested issuer EDN
    redacted = redacted_hashes_from_disclosures(disclosures)
    nested_issued_edn = generate_nested_cwt_edn(edn_disclosures,
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_nested_cwt[-96:],
        comments=example_comments)
    write_to_file(nested_issued_edn, "nested_issuer_cwt.edn")

    chosen_nested_disclosures = [
        disclosures[14],
        disclosures[10],
        disclosures[13],
        disclosures[11],
        disclosures[4],
        disclosures[0],
        disclosures[3]
    ]
    chosen_nested_unprotected = {
        SD_CLAIMS: chosen_nested_disclosures
    }

    nested_cwt = sign(cwt_protected,
                      chosen_nested_unprotected,
                      payload,
                      issuer_priv_key)
    write_to_file(nested_cwt, "nested_cwt.cbor")

    kbt_protected[13] = cbor2.loads(nested_cwt)
    nested_kbt = sign(kbt_protected, {}, kbt_payload, holder_priv_key)
    write_to_file(nested_kbt, "nested_kbt.cbor")

    chosen_comments = [
        example_comments[14],
        example_comments[10],
        example_comments[13],
        example_comments[11],
        example_comments[4],
        example_comments[0],
        example_comments[3]
    ]
    decoded_disclosures = parse_disclosures(chosen_nested_disclosures)
    edn_disclosures = edn_decoded_disclosures(decoded_disclosures,
                            comments=chosen_comments)
    write_to_file(edn_disclosures, 'chosen-nested-disclosures.edn')

    nested_presented_edn = generate_nested_cwt_edn(edn_disclosures,
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_nested_cwt[-96:],
        comments=example_comments)
    write_to_file(nested_presented_edn, "nested_cwt.edn")

    nested_kbt_edn = generate_basic_holder_kbt_edn(
        nested_presented_edn, iat=KBT_IAT, sig=nested_kbt[-64:])
    write_to_file(nested_kbt_edn, 'nested_kbt.edn')

    # example for decoy digests
    tbr_decoy_payload = {
      1   : "https://issuer.example",
      2   : "https://device.example",
      98: [
        cbor2.CBORTag(58, "fr"),
        cbor2.CBORTag(61, 1)
      ],
      cbor2.CBORTag(58, 500) : True,
      cbor2.CBORTag(61,2) : None
    }
    (payload, disclosures) = redact_level(tbr_decoy_payload, level=1)
    decoy_payload = sort_keys(payload | holder_cnf | cwt_time_claims)

    full_decoy_unprotected = {
      SD_CLAIMS: disclosures
    }

    issuer_decoy_cwt = sign(cwt_protected,
                     full_decoy_unprotected,
                     decoy_payload,
                     issuer_priv_key)
    write_to_file(issuer_decoy_cwt, "decoy.cbor")

    # write decoy EDN
    decoy_comments=[
        "France",
        "decoy country",
        "inspection result",
        "decoy claim"
    ]
    decoded_disclosures = parse_disclosures(disclosures)
    edn_disclosures = edn_decoded_disclosures(decoded_disclosures,
                          comments=decoy_comments, all=True)
    redacted = redacted_hashes_from_disclosures(disclosures)
    decoy_edn = generate_decoy_cwt_edn(edn_disclosures,
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_decoy_cwt[-96:])
    write_to_file(decoy_edn, "decoy.edn")

    # write deterministic salts
    write_new_salts(append_salts)
    write_new_decoy_salts(append_decoy_salts)

