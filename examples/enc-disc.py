#!/usr/bin/env python3

# proof of concept

import cbor2

def bytes2hex(bytes):
    import binascii
    return binascii.hexlify(bytes).decode("utf-8")

def hex2bytes(string):
    return bytes.fromhex(string)

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

def new_salt():
    import secrets
    return secrets.token_bytes(16)

def encrypt_disclosure(key, nonce, plaintext):
    from Crypto.Cipher import AES
    # uses default mac_len of 16
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # returns (ciphertext, mac)
    return cipher.encrypt_and_digest(plaintext)

def decrypt_disclosure(key, nonce, ciphertext, mac):
    from Crypto.Cipher import AES
    decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    out = bytearray(len(ciphertext))
    decipher.decrypt_and_verify(ciphertext, mac, output=out)
    return bytes(out)

nonce = hex2bytes('95d0040fe650e5baf51c907c31be15dc')
key = hex2bytes('a061c27a3273721e210d031863ad81b6')
salt = hex2bytes('bae611067bb823486797da1ebbb52f83')
salted_array = [salt, "ABCD-123456", 501]
plaintext = cbor2.dumps(cbor2.dumps(salted_array))
(ciphertext, mac) = encrypt_disclosure(key, nonce, plaintext)

encrypted_array = [nonce, ciphertext, mac]
enc_disclosure = cbor2.dumps(cbor2.dumps(encrypted_array))
print(f'''key = {pretty_hex(bytes2hex(key), 6)}

encrypted_array = [
    / nonce /      {pretty_hex(bytes2hex(nonce), 19)},
    / ciphertext / {pretty_hex(bytes2hex(ciphertext), 19)},
    / mac /        {pretty_hex(bytes2hex(mac), 19)}
]

encrypted_disclosure = {bytes2hex(enc_disclosure)}
''')

test_plaintext = decrypt_disclosure(key, nonce, ciphertext, mac)
if test_plaintext == plaintext:
    print("OK")
else:
    print("FAIL")

