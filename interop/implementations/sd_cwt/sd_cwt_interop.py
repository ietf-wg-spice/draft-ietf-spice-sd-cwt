#!/usr/bin/env python3
"""INTEROP.md wrapper for tradeverifyd/sd-cwt (python).

Run with a python that has sd-cwt installed; set SD_CWT_PYTHON to choose it.
"""

import argparse
import csv
import sys
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from sd_cwt import cbor_utils, decrypt_sd_cwt_disclosures, encrypt_sd_cwt_disclosures
from sd_cwt.holder_binding import create_sd_kbt, kcwt_to_bytes
from sd_cwt.signers import PresentationSigner
from sd_cwt.simple_api import SDCWTVerifier
from sd_cwt.thumbprint import CoseKeyThumbprint
from sd_cwt.verifiers import CredentialVerifier

CRV = {"secp256r1": (1, -7), "secp384r1": (2, -35), "secp521r1": (3, -36)}
DEFAULT_AUDIENCE = "https://verifier.example/app"


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def cose_key(pem_path: str) -> dict[int, Any]:
    data = open(pem_path, "rb").read()
    if b"PRIVATE KEY" in data:
        private: Optional[Any] = serialization.load_pem_private_key(data, None)
        public = private.public_key()
    else:
        private, public = None, serialization.load_pem_public_key(data)
    if not isinstance(public, ec.EllipticCurvePublicKey):
        raise SystemExit("only EC2 keys are supported")
    crv, alg = CRV[public.curve.name]
    size = (public.curve.key_size + 7) // 8
    numbers = public.public_numbers()
    key = {1: 2, 3: alg, -1: crv, -2: numbers.x.to_bytes(size, "big"), -3: numbers.y.to_bytes(size, "big")}
    if private is not None:
        key[-4] = private.private_numbers().private_value.to_bytes(size, "big")
    return key


def read_hex(path: str) -> bytes:
    return bytes.fromhex(open(path).read().strip())


def salt_of(disclosure: bytes) -> bytes:
    return cbor_utils.decode(disclosure)[0]


def unprotected_of(token: bytes) -> dict[Any, Any]:
    return cbor_utils.get_tag_value(cbor_utils.decode(token))[1]


def present(args: argparse.Namespace) -> int:
    sd_cwt = sys.stdin.buffer.read()
    if args.issuer_key != "ignore":
        if not args.issuer:
            log("no --issuer key and --issuer-key is not 'ignore'")
            return 2
        issuer_key = cose_key(args.issuer)
        if not CredentialVerifier(lambda kid: issuer_key).verify(sd_cwt)[0]:
            log("Issuer signature did not verify")
            return 1

    available = list(unprotected_of(sd_cwt).get(17, []))
    by_salt = {salt_of(d): d for d in available}

    def pick(path: Optional[str]) -> list[bytes]:
        if not path:
            return []
        salts = cbor_utils.decode(open(path, "rb").read())
        missing = [s.hex() for s in salts if s not in by_salt]
        if missing:
            raise SystemExit(f"no disclosure with salt {missing}")
        return [by_salt[s] for s in salts]

    to_encrypt = pick(args.encrypt_list)
    plaintext = available if args.disclose_all else pick(args.disclosure_list)
    plaintext = [d for d in plaintext if d not in to_encrypt]

    nonces = None
    if args.aead_nonces:
        table = {bytes.fromhex(r[0]): bytes.fromhex(r[1]) for r in csv.reader(open(args.aead_nonces)) if r}
        nonces = [table[salt_of(d)] for d in to_encrypt]
    if to_encrypt and not args.aead_key:
        log("--encrypt_list needs --aead-key")
        return 2
    context = args.aead_key_context
    if context is not None and context.isdigit():
        context = int(context)

    with_disclosures = encrypt_sd_cwt_disclosures(
        sd_cwt,
        plaintext,
        to_encrypt,
        read_hex(args.aead_key) if args.aead_key else b"",
        key_context=context,
        nonces=nonces,
    )
    holder_key = cose_key(args.holder_priv)
    kbt = create_sd_kbt(
        sd_cwt_with_disclosures=with_disclosures,
        holder_signer=PresentationSigner(holder_key),
        audience=args.audience,
        issued_at=args.time if args.time is not None else int(__import__("time").time()),
        key_id=CoseKeyThumbprint.compute(holder_key, "sha256"),
    )
    log(f"presented {len(plaintext)} plaintext, {len(to_encrypt)} encrypted disclosures")
    sys.stdout.buffer.write(kbt)
    return 0


def verify(args: argparse.Namespace) -> int:
    kbt = sys.stdin.buffer.read()
    arr = cbor_utils.get_tag_value(cbor_utils.decode(kbt))
    audience = args.audience or cbor_utils.decode(arr[2]).get(3)

    if args.issuer_key == "ignore":
        log("--issuer-key ignore is not supported by this verifier")
        return 2
    if not args.issuer:
        log("no --issuer key")
        return 2
    issuer_key = cose_key(args.issuer)

    keys = [read_hex(p) for p in args.aead_key or []]
    resolver = (lambda ctx: keys) if keys else None

    embedded = kcwt_to_bytes(cbor_utils.decode(arr[0])[13])
    try:
        _, undecrypted = decrypt_sd_cwt_disclosures(embedded, resolver)
    except ValueError as e:
        log(f"encrypted disclosures rejected: {e}")
        return 1
    if undecrypted:
        log(f"{len(undecrypted)} encrypted disclosure(s) left undecrypted")

    valid, claims, _ = SDCWTVerifier(lambda kid: issuer_key).verify_presentation(
        kbt, audience, aead_key_resolver=resolver
    )
    if not valid or claims is None:
        log("presentation did not verify")
        return 1
    names = {"iss": 1, "sub": 2, "iat": 6}
    out = {names.get(k, k): v for k, v in claims.items()}
    sys.stdout.buffer.write(cbor_utils.encode(out))
    return 0


def main() -> int:
    role = sys.argv[1]
    if role == "target":
        sys.stdout.write("sd_cwt")
        return 0
    p = argparse.ArgumentParser(prog=role)
    if role == "present":
        p.add_argument("holder_priv")
        p.add_argument("--disclosure_list")
        p.add_argument("--disclose_all", action="store_true")
        p.add_argument("--encrypt_list")
        p.add_argument("--aead-key-context")
        p.add_argument("--aead-nonces")
        p.add_argument("--aead-key")
        p.add_argument("--audience", default=DEFAULT_AUDIENCE)
    else:
        p.add_argument("--aead-key", action="append")
        p.add_argument("--audience")
    p.add_argument("--issuer")
    p.add_argument("--issuer-key", choices=["ignore", "fetch", "cache"])
    p.add_argument("--time", type=int)
    args = p.parse_args(sys.argv[2:])
    return present(args) if role == "present" else verify(args)


if __name__ == "__main__":
    sys.exit(main())
