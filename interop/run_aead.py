#!/usr/bin/env python3
"""Run the AEAD encrypted disclosure test case across every Holder x Verifier pair.

    ./run_aead.py [--impl NAME ...]

Each implementation directory under implementations/ that has `present` and
`verify` takes part. The Issuer is the draft itself: the test case presents
examples/issuer_cwt.cbor, so no implementation has to issue.
Results go to tests/I=draft_H={holder}_V={verifier}/{timestamp}/.
"""

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone

import cbor2

BASE = os.path.dirname(os.path.abspath(__file__))
CASE = "aead_first_disclosure"
CASE_DIR = os.path.join(BASE, "test_cases", CASE)
SD_CLAIMS, SD_AEAD_ENCRYPTED_CLAIMS, KCWT = 17, 171, 13
CLAIM, VALUE = 501, "ABCD-123456"


def impls(names):
    root = os.path.join(BASE, "implementations")
    found = []
    for name in sorted(names or os.listdir(root)):
        d = os.path.join(root, name)
        if all(os.access(os.path.join(d, r), os.X_OK) for r in ("present", "verify")):
            found.append(name)
        elif names:
            sys.exit(f"{name}: needs executable present and verify")
    return found


def run(impl, role, args, stdin, out_dir, label):
    exe = os.path.join(BASE, "implementations", impl, role)
    with open(os.path.join(out_dir, f"{CASE}-{label}.log"), "w") as log:
        p = subprocess.run([exe, *args], input=stdin, stdout=subprocess.PIPE, stderr=log,
                           cwd=CASE_DIR, timeout=60)
    return p.returncode, p.stdout


def embedded_unprotected(kbt):
    protected = cbor2.loads(cbor2.loads(kbt).value[0])
    kcwt = protected[KCWT]
    kcwt = cbor2.loads(kcwt) if isinstance(kcwt, bytes) else kcwt
    return kcwt.value[1]


def check_pair(holder, verifier, stamp):
    out_dir = os.path.join(BASE, "tests", f"I=draft_H={holder}_V={verifier}", stamp)
    os.makedirs(out_dir, exist_ok=True)
    issued = open(os.path.join(CASE_DIR, "issued.cbor"), "rb").read()
    expected = open(os.path.join(CASE_DIR, "expected_aead_claims.cbor"), "rb").read()
    results = []

    def record(name, ok, detail=""):
        results.append((name, ok, detail))

    code, kbt = run(holder, "present", [
        "holder_priv.pem", "--issuer", "issuer_pub.pem",
        "--disclosure_list", "disclosure_list.cbor",
        "--encrypt_list", "encrypt_list.cbor",
        "--aead-key", "aead_key.hex", "--aead-nonces", "aead_nonces.csv",
    ], issued, out_dir, "present")
    record("present", code == 0, f"exit {code}")
    if code != 0:
        return results
    open(os.path.join(out_dir, f"{CASE}.kbt.cbor"), "wb").write(kbt)

    try:
        unprotected = embedded_unprotected(kbt)
        entries = unprotected.get(SD_AEAD_ENCRYPTED_CLAIMS)
        record("171 matches the draft example",
               entries is not None and cbor2.dumps(entries) == expected)
        record("501 not in sd_claims",
               all(cbor2.loads(d)[-1] != CLAIM for d in unprotected.get(SD_CLAIMS, [])))
    except Exception as e:
        record("decode presentation", False, str(e))

    def verify(label, key):
        args = ["--issuer", "issuer_pub.pem"] + (["--aead-key", key] if key else [])
        code, out = run(verifier, "verify", args, kbt, out_dir, f"verify-{label}")
        if out:
            open(os.path.join(out_dir, f"{CASE}.{label}.claims.cbor"), "wb").write(out)
        claims = cbor2.loads(out) if code == 0 and out else None
        return code, claims

    code, claims = verify("key", "aead_key.hex")
    record("verify with key discloses 501", code == 0 and claims and claims.get(CLAIM) == VALUE,
           f"exit {code}")
    code, claims = verify("nokey", None)
    record("verify without key passes, 501 withheld",
           code == 0 and claims is not None and CLAIM not in claims, f"exit {code}")
    code, _ = verify("wrongkey", "wrong_aead_key.hex")
    record("verify with wrong key rejects", code != 0, f"exit {code}")

    with open(os.path.join(out_dir, "results.csv"), "w") as f:
        for name, ok, detail in results:
            f.write(f"{name},{'pass' if ok else 'fail'},{detail}\n")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl", action="append")
    names = impls(ap.parse_args().impl)
    if not names:
        sys.exit("no implementation has both present and verify")
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    failures = 0
    for holder in names:
        for verifier in names:
            results = check_pair(holder, verifier, stamp)
            passed = sum(ok for _, ok, _ in results)
            print(f"H={holder:<12} V={verifier:<12} {passed}/{len(results)}")
            for name, ok, detail in results:
                if not ok:
                    failures += 1
                    print(f"    FAIL {name} {detail}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
