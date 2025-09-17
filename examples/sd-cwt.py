#!/usr/bin/env python3
import cbor2

TO_BE_REDACTED_TAG = 58
SD_CLAIMS = 17

def hex2bytes(string):
    return bytes.fromhex(string)

# pre-used salts so the values can stay the same when the data is the same
# hashes the rest of the disclosure (minus the salt) as the dict key
salts = {
    hex2bytes('e46eb069cb1b453700c8199c9431931dad9f7dac76098999b802e03dc8d0db2e'):
    hex2bytes('cd99b3858f1d659f9d16039abf8c5fba'),

    hex2bytes('84e6023a698dea8d7eaefeda3ec51a50a89ec6def850703720f171550e106aca'):
    hex2bytes('c23a4d192be75dbd583be570482de8dd'),

    hex2bytes('d2a4ef4cbcc59b1a9574213bfff2f63fd5f804caf8c8229e4ddbd7155dfcfa88'):
    hex2bytes('2df7d2c105b5bf3acf9c698f3658552f'),

    hex2bytes('c6fcdd752637e315c81aa612209c7f592a8238014b2f0b41eb6f69cae5bd5c04'):
    hex2bytes('c225607427e01072bbafcce7e48049e3'),

    hex2bytes('d7b86b369f670a6333e03b12071b4a6361ad3b92d51ef3187dc15d74c7c98f87'):
    hex2bytes('1b248d469cf00b8dfa896f069f04697b'),

    hex2bytes('25baa45374593ff558152aaf85b9c483667f620be3984852b6558a63a927af2f'):
    hex2bytes('483e4b3c194df6073a9c41ca9f274067'),

    hex2bytes('0ce809ed234b06848d02c6adaa8435d2b6ddb803bf161b326f40f45ff48f9c1b'):
    hex2bytes('c4057d22ba56c3513af4c94f6c21826d'),

    hex2bytes('d3870bfc39a2fbd377de1c529ab2b45078506c6c53eb0d35d4b8ddc56b1b67cd'):
    hex2bytes('414915421ae4b3cdb2f04521a8ec8475'),

    hex2bytes('15f1c68ea20b62af0ec924f62b8355e674cd254b6cbea184823dc70c573eb091'):
    hex2bytes('29d880f7bdc161b98a6b27f7f523be51'),

    hex2bytes('24e2d75288c7409cb1e803f20a2e59253dd62ccd8bde930aa50a7016d6cb62e7'):
    hex2bytes('41c7a3cd57b26ce28049301838b5f1c4'),

    hex2bytes('7abbfcaff1ce239e350f4c1dde880da50bbecf5218f0e9c67d16b5291a566dcc'):
    hex2bytes('42423c7e05c8273dda2be4d4ec11c62c'),

    hex2bytes('5af839c0c65d6eb6c59b59a9255cafd11d8d05190af123067ff733098c6df080'):
    hex2bytes('10cc82ab0554cde23c7ec67d3237eb8a'),

    hex2bytes('0159388947ab60e445baa6aee63226fa7508d428c239aa7c8b67a74c98b2d746'):
    hex2bytes('a6c5b334512af02a0de1c83f74f81fe8'),


    # first disclosure
    hex2bytes('47abe6e8bfe75077c60b7941cec72a900773c75075b8229a36a550b78bd1d8cc'):
    hex2bytes('bae611067bb823486797da1ebbb52f83'),

    # second disclosures
    hex2bytes('03b4b1f0584e3bd8e3de9c15eea95b415403989627fb0a1e22d7ebda5e20ea5e'):
    hex2bytes('8de86a012b3043ae6e4457b9e1aaab80'),

    # third disclosure
    hex2bytes('96505eb290a053098c50f1690fff48b551e9e1cad32c7f387afcc460474de805'):
    hex2bytes('7af7084b50badeb57d49ea34627c7a52'),

    # fourth disclosure
    hex2bytes('a4498ed1fc2e628b563428a8cbd28c164c51b0f26ed6dcc8b072cf3baf25653b'):
    hex2bytes('ec615c3035d5a4ff2f5ae29ded683c8e'),

    # fifth disclosure
    hex2bytes('fd0d674ae67041df0ef0a1e81dda7fb5462dc7ce88c2d47c051bb73b8a7fc51b'):
    hex2bytes('37c23d4ec4db0806601e6b6dc6670df9'),

    # nested disclosure 1
    hex2bytes('f6b0f3f2a36a4e51799cfa1a0b496c45294f155817407889345b8197827e7d4e'):
    hex2bytes('ff220dbc9b033e5086f6d382e0760ddf'),

    # nested disclosure 2
    hex2bytes('f489a265621aa70a006e75b0579156ab5ad4893119b8a055f68bba27e19aca48'):
    hex2bytes('52da9de5dc61b33775f9348b991d3d78'),

    # nested disclosure 3
    hex2bytes('92407c932a1254b3137f3e38ff5e9be22f5ecdb54a598d788e25f74169ad8289'):
    hex2bytes('a965de35aa599d603fe1b7aa89490eb0'),

    # nested disclosure 4
    hex2bytes('f4f090d4ecc12ac2d96763259487ff9b93823bd6d966805d77290efc07c5058c'):
    hex2bytes('7d2505257e7850b70295a87b3c8748e5'),

    # nested disclosure 5
    hex2bytes('90d525ff80cfbf7e2cece7bd57ca41e14a929c112cf4213de4950e2ee5993bae'):
    hex2bytes('78b8a19cc53f1ed43f5e2751398d2704'),

    # nested disclosure 6
    hex2bytes('301837e17b8ac94bb78eea2cfb660d5329d1d5205a8da67cd9aea487a2b54066'):
    hex2bytes('9a3bc899090435650b377199450c1fa1'),

    # nested disclosure 7
    hex2bytes('0b3ee5a4a933e652d26de80b4aa1873cdf6ddb958b1ec871faf0750db7295291'):
    hex2bytes('5e852d2eef59c0ebeab8c08fca252cc5'),

    # nested disclosure 8
    hex2bytes('0a8c5194f17353cee813bf5379f6f6f6e4906a0a428d63c3241e28a696b7c7f3'):
    hex2bytes('3dd46bd7dea09c9ee7dfe4e0d510129b'),

    # nested disclosure 9
    hex2bytes('a044cd2cbeb18e28b7c99c8dc9cf26014060a346a0de6be458eeafbdfed5c86b'):
    hex2bytes('a1658ffb2a45e2684ac664bcce00c92c'),

    # nested disclosure 10
    hex2bytes('252cccd551b4b71043dfe750f51709cecca0f7dad01700cb774bf951340d7ba3'):
    hex2bytes('2715ebca1d42af16a6d4560dc231c448'),

    # nested disclosure 11
    hex2bytes('e8053bef82eb7beec078a5af997d1b9d83c89d0209cea84901a6fa4f6f3dd64e'):
    hex2bytes('b492ab1cfb415a31821138648c7a559a'),

    # A
    hex2bytes('0870fb80316bb20c95c7150814ffb747b09cd2944ce20888f135c98d9a4e8c3c'):
    hex2bytes('591eb2081b05be2dcbb6f8459cc0fe51'),

    # B
    hex2bytes('c76675e719488855257e4f083dfb069ad2e8e0e367777329a5067c0c97619a39'):
    hex2bytes('e70e23e77176fa59beb0b2559943a079'),

    # C
    hex2bytes('f3243e018b967baa332dd79489e23d33821f15fac52582d8dba3dc4fd30fe0db'):
    hex2bytes('cbbf1cd3d1a5da83e1d92c08d566a481'),

    # D
    hex2bytes('8155d253658325854728a0a90b4eb9fec8d09d486fed92ff0146829509e43e2b'):
    hex2bytes('d7abeb9016448caeb018b5bdbaee17de'),

    # E
    hex2bytes('76bfbc495fe772c1517e6e82949db90bb370e67349ed9c790098022a880117e2'):
    hex2bytes('b52272341715f2a0b476e33e55ce7501'),

    # F
    hex2bytes('378e5117da83fcc15c480479b4e0851b4f6a6db433104393b3562b49418eec7c'):
    hex2bytes('e3aa33644123fdbf819ad534653f4aaa'),

    # G

    hex2bytes('7955612dcba5d69d79643dec1a62a3c83b1d05727e45701107e7d7a5ea2503ed'):
    hex2bytes('d2be8cc99c185ef10e3f91a61d2d9bf9')
}



# ****** Generically useful functions

def bytes2hex(bytes):
    import binascii
    return binascii.hexlify(bytes).decode("utf-8")

def new_redacted_entry_tag(value):
    REDACTED_ENTRY_TAG = 60
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


def find_salt(key=None, value=None, decoy_level=0, decoy_num=0):
    # find an existing salt or generate one if not in "salts" dict
    salt_index = None
    if decoy_level == 0:
        salt_index = sha256(cbor2.dumps([key, value]))
    else:
        salt_index = sha256(cbor2.dumps([decoy_level, decoy_num]))
    if salt_index not in salts:
        salts[salt_index] = new_salt()
        print(f'Added new salt {bytes2hex(salts[salt_index])} for {bytes2hex(salt_index)}')
    return salts[salt_index]


def make_disclosure(salt=None, key=None, value=None):
    if salt is None:
        salt = find_salt(key=key, value=value)
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
                (n, d) = redact_array(value, level+1) #num_decoys=num_decoys//2)
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
            (n, d) = redact_map(value, level+1)  # , num_decoys=num_decoys//2)
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
                (n, d) = redact_array(entry.value, level+1) #num_decoys//2
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
            (n, d) = redact_map(entry, level+1) #, num_decoys=num_decoys//2)
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
                            comments=example_comments, all=True)
    redacted = redacted_hashes_from_disclosures(disclosures)
    
    # write first disclosure becoming blinded claim
    first_disc_array = decoded_disclosures[0]
    with open('first-disclosure.edn', 'w') as file:
        print(edn_one_disclosure(first_disc_array, comment=example_comments[0])[:-1],
            file=file, end='')
    first_bstr = cbor2.dumps(decoded_disclosures[0])
    with open('first-disclosure.cbor', 'wb') as file:
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
    (payload, disclosures) = redact_map(tbr_nested_payload, 1)
    
    # generate issued nested example?
    
    # make nested-cwt
    payload |= holder_cnf | cwt_time_claims
    
    # which disclosures to include?
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
    
    nested_unprotected = {
      SD_CLAIMS: [
        disclosures[14],
        disclosures[10],
        disclosures[13],
        disclosures[11],
        disclosures[4],
        disclosures[0],
        disclosures[3]
      ]
    }
    
    nested_sd_claims = []
    for d in nested_unprotected[SD_CLAIMS]:
        nested_sd_claims.append(cbor2.dumps(d))
    encoded_nested_unprotected = {
        SD_CLAIMS: nested_sd_claims
    }

    nested_cwt = sign(cwt_protected,
                      encoded_nested_unprotected,
                      payload,
                      issuer_priv_key)
    write_to_file(nested_cwt, "nested_cwt.cbor")

    kbt_protected[13] = nested_cwt
    nested_kbt = sign(kbt_protected, {}, kbt_payload, holder_priv_key)
    write_to_file(nested_kbt, "nested_kbt.cbor")

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

    presented_disclosures = [
        decoded_disclosures[14],
        decoded_disclosures[10],
        decoded_disclosures[13],
        decoded_disclosures[11],
        decoded_disclosures[4],
        decoded_disclosures[0],
        decoded_disclosures[3]
    ]
    presented_comments = [
        example_comments[14],
        example_comments[10],
        example_comments[13],
        example_comments[11],
        example_comments[4],
        example_comments[0],
        example_comments[3]
    ]
    edn_disclosures = edn_decoded_disclosures(
        presented_disclosures, comments=presented_comments)
    write_to_file(edn_disclosures, 'chosen-nested-disclosures.edn')

    nested_presented_edn = generate_basic_issuer_cwt_edn(
        encoded_nested_unprotected,
        exp=cwt_time_claims[4], nbf=cwt_time_claims[5], iat=cwt_time_claims[6],
        thumb_fields=holder_thumb_edn,
        redacted=redacted,
        sig=issuer_nested_cwt[-96:])
    write_to_file(nested_presented_edn, "nested_cwt.edn")

#    holder_unprotected = {SD_CLAIMS: presented_disclosures}
#    nested_presentation_cwt = sign(cwt_protected,
#                       holder_unprotected,
#                       payload,
#                       issuer_priv_key)

    nested_kbt_edn = generate_basic_holder_kbt_edn(
        nested_presented_edn, iat=KBT_IAT, sig=nested_kbt[-64:])
    write_to_file(nested_kbt_edn, 'nested_kbt.edn')

#    for s in salts:
#        print(f'''*** Hash: {bytes2hex(s)}
#Salt: {bytes2hex(salts[s])}
#
#''')
#
#    print('\n')
#    print(salts)

