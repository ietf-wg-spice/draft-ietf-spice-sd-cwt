#!/usr/bin/env python3
"""Cross-implementation AEAD probes. See ENCRYPTED-INTEROP.md for scope.

Requires cbor2 and cryptography. Does not import any SD-CWT implementation.
All negative disclosure probes are freshly holder-signed; rejection cannot be
attributed to a stale KBT signature. Positive controls gate rejection results.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from run_aead import impls

BASE = Path(__file__).resolve().parent
CASE = BASE / 'test_cases/aead_first_disclosure'
ISSUED = (CASE / 'issued.cbor').read_bytes()
KEY = bytes.fromhex((CASE / 'aead_key.hex').read_text().strip())
DISCLOSURE = cbor2.loads(ISSUED).value[1][17][0]
EXPECTED = cbor2.loads((CASE / 'expected_aead_claims.cbor').read_bytes())
CLAIM, VALUE = 501, 'ABCD-123456'


def sign(token, pem):
    """Re-sign test fixtures using Appendix C keys, without an implementation API."""
    arr = list(token.value)
    key = serialization.load_pem_private_key(pem.read_bytes(), None)
    algorithm = cbor2.loads(arr[0])[1]
    digest = {-7: hashes.SHA256, -35: hashes.SHA384}[algorithm]()
    data = cbor2.dumps(['Signature1', arr[0], b'', arr[2]])
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(digest)))
    size = (key.curve.key_size + 7) // 8
    arr[3] = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
    return cbor2.dumps(cbor2.CBORTag(18, arr))


def embedded(token):
    protected = cbor2.loads(cbor2.loads(token).value[0])
    inner = protected[13]
    return cbor2.loads(inner) if isinstance(inner, bytes) else inner


def mutate(token, change):
    outer = list(cbor2.loads(token).value)
    protected = cbor2.loads(outer[0])
    was_bytes = isinstance(protected[13], bytes)
    inner = embedded(token)
    change(inner.value[1])
    protected[13] = cbor2.dumps(inner) if was_bytes else inner
    outer[0] = cbor2.dumps(protected)
    return sign(cbor2.CBORTag(18, outer), CASE / 'holder_priv.pem')


def seal(plaintext, key=KEY):
    # Test vectors only: this fixed nonce must never be used with production keys.
    nonce = bytes(range(12))
    out = AESGCM(key).encrypt(nonce, plaintext, b'')
    return [nonce, out[:-16], out[-16:]]


def git_state(path):
    if not path:
        return None
    def git(*args):
        return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()
    return {'commit': git('rev-parse', 'HEAD'), 'status': git('status', '--short'),
            'diff_sha256': hashlib.sha256(subprocess.check_output(
                ['git', '-C', str(path), 'diff', '--binary'])).hexdigest()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--impl', action='append')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--python-repo', type=Path)
    ap.add_argument('--js-repo', type=Path)
    ap.add_argument('--rust-repo', type=Path)
    args = ap.parse_args()
    names = impls(args.impl)
    if not names:
        ap.error('no implementations selected')
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    rows = []

    def record(group, holder, verifier, check, passed, detail=''):
        rows.append(dict(group=group, holder=holder, verifier=verifier, check=check,
                         status='pass' if passed else 'fail', detail=detail))

    def invoke(impl, role, argv, data, label):
        executable = BASE / 'implementations' / impl / role
        argv = [*argv, '--time', '1725244300']
        prefix = out / label
        prefix.parent.mkdir(parents=True, exist_ok=True)
        try:
            p = subprocess.run([str(executable), *argv], input=data, capture_output=True,
                               cwd=CASE, timeout=60)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except (OSError, subprocess.TimeoutExpired) as e:
            code, stdout, stderr = -1, b'', str(e).encode()
        prefix.with_suffix('.input.cbor').write_bytes(data)
        prefix.with_suffix('.log').write_bytes(stderr)
        prefix.with_suffix('.cbor').write_bytes(stdout)
        prefix.with_suffix('.command.json').write_text(json.dumps(
            {'implementation': impl, 'role': role, 'args': argv, 'exit': code,
             'input_sha256': hashlib.sha256(data).hexdigest()}, indent=2) + '\n')
        return code, stdout

    def verify(holder, verifier, name, token, expected, key=True, extra=(), group='interop', control=True):
        argv = ['--issuer', 'issuer_pub.pem', '--audience', 'https://verifier.example/app']
        if key:
            argv += ['--aead-key', str(key) if isinstance(key, Path) else 'aead_key.hex']
        if '--audience' in extra:
            i = argv.index('--audience')
            del argv[i:i + 2]
        argv += list(extra)
        code, raw = invoke(verifier, 'verify', argv, token, f'{holder}/{verifier}/{name}')
        try:
            claims = cbor2.loads(raw) if code == 0 else None
            valid = code == 0 and isinstance(claims, dict)
            if expected == 'reject':
                passed = control and code == 1
            elif expected == 'disclose':
                passed = valid and claims.get(CLAIM) == VALUE
            elif expected == 'withhold':
                passed = valid and CLAIM not in claims
            else:
                passed = valid
        except Exception:
            passed = False
        detail = f'exit {code}' + ('; positive control failed' if not control else '')
        record(group, holder, verifier, name, passed, detail)
        return passed

    for holder in names:
        argv = ['holder_priv.pem', '--issuer', 'issuer_pub.pem', '--disclosure_list',
                'disclosure_list.cbor', '--encrypt_list', 'encrypt_list.cbor',
                '--aead-key', 'aead_key.hex', '--aead-nonces', 'aead_nonces.csv']
        code, token = invoke(holder, 'present', argv, ISSUED, f'{holder}/present')
        record('interop', holder, None, 'present', code == 0, f'exit {code}')
        if code:
            continue
        try:
            inner = embedded(token)
            hdr = inner.value[1]
            record('interop', holder, None, 'draft ciphertext bytes', hdr.get(171) == EXPECTED)
            record('interop', holder, None, 'encrypted disclosure absent from plaintext',
                   DISCLOSURE not in hdr.get(17, []))
            record('spec', holder, None, '172 absent from unprotected header', 172 not in hdr)
        except Exception as e:
            record('interop', holder, None, 'decode presentation', False, str(e))
            continue

        variants = {'resigned-control': (lambda h: None, 'disclose', True),
                    'empty-encrypted': (lambda h: h.update({171: []}), 'reject', True),
                    'empty-plaintext': (lambda h: h.update({17: []}), 'reject', True),
                    'duplicate-encrypted': (lambda h: h[171].append(copy.deepcopy(h[171][0])), 'reject', True),
                    'duplicate-plaintext-encrypted': (lambda h: h.setdefault(17, []).append(DISCLOSURE), 'reject', True),
                    'orphan-disclosure': (lambda h: h.update({171: [seal(cbor2.dumps(cbor2.dumps([b'0'*16, 'other', 999])))]}), 'reject', True),
                    'unwrapped-plaintext': (lambda h: h.update({171: [seal(DISCLOSURE)]}), 'reject', True),
                    'no-key-empty-encrypted': (lambda h: h.update({171: []}), 'reject', False)}
        for field, idx in [('nonce', 0), ('ciphertext', 1), ('tag', 2)]:
            def corrupt(h, idx=idx):
                b = h[171][0][idx]
                h[171][0][idx] = bytes([b[0] ^ 1]) + b[1:]
            variants['corrupt-' + field] = (corrupt, 'reject', True)
        for context in [0, 'verifier-key']:
            def add_context(h, context=context):
                h[171][0] = h[171][0][:3] + [context]
            variants['context-' + str(context)] = (add_context, 'disclose', True)
            variants['no-key-context-' + str(context)] = (add_context, 'withhold', False)
        tokens = {name: mutate(token, change) for name, (change, _, _) in variants.items()}
        for name, data in tokens.items():
            (out / holder / (name + '.kbt.cbor')).write_bytes(data)
        for verifier in names:
            positive = verify(holder, verifier, 'correct-key', token, 'disclose')
            verify(holder, verifier, 'no-key', token, 'withhold', key=False)
            verify(holder, verifier, 'wrong-key', token, 'reject', key=CASE / 'wrong_aead_key.hex', control=positive)
            resigned = verify(holder, verifier, 'resigned-control', tokens['resigned-control'], 'disclose')
            for name, (_, expected, key) in variants.items():
                if name == 'resigned-control':
                    continue
                extra = ()
                if name.startswith('context-') and verifier == 'esdicawt_aead':
                    extra = ('--aead-key-context', name[len('context-'):])
                verify(holder, verifier, name, tokens[name], expected, key=key,
                       extra=extra, control=resigned, group='spec' if expected == 'reject' else 'interop')
            verify(holder, verifier, 'wrong-audience', token, 'reject',
                   extra=('--audience', 'https://wrong.example'), control=positive, group='spec')
            broken = list(cbor2.loads(token).value)
            broken[3] = bytes([broken[3][0] ^ 1]) + broken[3][1:]
            verify(holder, verifier, 'invalid-holder-signature', cbor2.dumps(cbor2.CBORTag(18, broken)),
                   'reject', control=positive, group='spec')

        # Exercise the library's context production and fresh nonce generation too.
        for context in ['0', 'verifier-key']:
            code, contextual = invoke(holder, 'present', argv + ['--aead-key-context', context], ISSUED,
                                      f'{holder}/present-context-{context}')
            record('interop', holder, None, 'present-context-' + context, code == 0)
            if code == 0:
                for verifier in names:
                    extra = ('--aead-key-context', context) if verifier == 'esdicawt_aead' else ()
                    verify(holder, verifier, 'native-context-' + context, contextual, 'disclose', extra=extra)
        random_argv = argv[:-2]
        code, random_token = invoke(holder, 'present', random_argv, ISSUED, f'{holder}/present-random')
        code2, random_token2 = invoke(holder, 'present', random_argv, ISSUED, f'{holder}/present-random-2')
        fresh = code == code2 == 0 and embedded(random_token).value[1][171][0][0] != embedded(random_token2).value[1][171][0][0]
        record('interop', holder, None, 'fresh nonce on two presentations', fresh)
        if fresh:
            for verifier in names:
                verify(holder, verifier, 'random-nonce', random_token, 'disclose')
        only_argv = argv[:3] + argv[5:]
        code, only_token = invoke(holder, 'present', only_argv, ISSUED, f'{holder}/present-encrypted-only')
        record('interop', holder, None, 'encrypted-only omits header 17',
               code == 0 and 17 not in embedded(only_token).value[1])
        if code == 0:
            for verifier in names:
                verify(holder, verifier, 'encrypted-only', only_token, 'disclose')
                verify(holder, verifier, 'encrypted-only-no-key', only_token, 'withhold', key=False)

    # Explicit protected algorithm probes use independently encrypted and issuer-signed
    # fixtures. The positive AES-128 control establishes these are valid presentations.
    reference = next((out / n / 'present.cbor' for n in names if (out / n / 'present.cbor').stat().st_size), None)
    if reference:
        for alg, aead_key in [(1, KEY), (2, bytes(range(32)))]:
            base = reference.read_bytes()
            outer = list(cbor2.loads(base).value)
            protected = cbor2.loads(outer[0])
            inner = list(embedded(base).value)
            ip = cbor2.loads(inner[0]); ip[172] = alg
            inner[0] = cbor2.dumps(ip)
            inner[1].pop(172, None)
            inner[1][171] = [seal(cbor2.dumps(DISCLOSURE), aead_key)]
            signed = sign(cbor2.CBORTag(18, inner), BASE.parent / 'issuer_privkey.pem')
            protected[13] = signed if isinstance(protected[13], bytes) else cbor2.loads(signed)
            outer[0] = cbor2.dumps(protected)
            token = sign(cbor2.CBORTag(18, outer), CASE / 'holder_priv.pem')
            keyfile = out / f'algorithm-{alg}.key.hex'; keyfile.write_text(aead_key.hex() + '\n')
            (out / f'algorithm-{alg}.kbt.cbor').write_bytes(token)
            for verifier in names:
                verify('reference', verifier, f'protected-algorithm-{alg}', token, 'disclose', key=keyfile, group='algorithm')
                verify('reference', verifier, f'protected-algorithm-{alg}-no-key', token, 'withhold', key=False, group='algorithm')

    metadata = {'timestamp': datetime.now(timezone.utc).isoformat(),
                'draft': git_state(BASE.parent), 'python': git_state(args.python_repo),
                'javascript': git_state(args.js_repo), 'rust': git_state(args.rust_repo),
                'implementations': names, 'python_runtime': sys.version,
                'fixture_sha256': hashlib.sha256(ISSUED).hexdigest(),
                'source_sha256': {
                    str(p.relative_to(BASE)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [Path(__file__).resolve(), BASE / 'run_aead.py',
                              *sorted((BASE / 'implementations').rglob('*'))]
                    if p.is_file() and '__pycache__' not in str(p)
                }}
    files = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(out.rglob('*')) if p.is_file()}
    report = {'metadata': metadata, 'passed': sum(r['status'] == 'pass' for r in rows),
              'total': len(rows), 'checks': rows, 'artifacts_sha256': files}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{report['passed']}/{report['total']} checks passed; {out / 'results.json'}")
    for row in rows:
        if row['status'] != 'pass':
            print(f"{row['status'].upper()} {row['group']} H={row['holder']} V={row['verifier']} {row['check']}: {row['detail']}")
    return int(report['passed'] != report['total'])


if __name__ == '__main__':
    sys.exit(main())
