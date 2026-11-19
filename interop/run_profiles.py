#!/usr/bin/env python3
"""Check complete application-claim reconstruction across encrypted profiles.

Uses draft keys and independently issuer-signed fixtures. Python/JS/Rust produce
and verify AES-128/AES-256 profiles; ChaCha20 remains scoped to Python/JS.
All algorithm headers follow draft-09. Negative cases whose positive
control fails are blocked, never counted as successful rejection tests.
"""
from spec_revision import spec_manifest

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import cbor2
from run_encrypted import BASE, CASE, ISSUED, KEY, sign, embedded, mutate, git_state

REDACTED = cbor2.CBORSimpleValue(59)
NAMES = ['sd_cwt', 'sd_cwt_js']


def digest(d):
    return hashlib.sha256(cbor2.dumps(d)).digest()


def fixture(algorithm, nested=False):
    original = list(cbor2.loads(ISSUED).value)
    protected = cbor2.loads(original[0])
    protected.pop(172, None)  # AEAD selection belongs to the Holder in draft-09
    original[0] = cbor2.dumps(protected)
    payload = cbor2.loads(original[2])
    if nested:
        child = cbor2.dumps([b'c'*16, 'private city', 'city'])
        parent = cbor2.dumps([b'p'*16, {'public': True, REDACTED: [digest(child)]}, 'profile'])
        element = cbor2.dumps([b'e'*16, {'kind': 'secret'}])
        ds = [child, parent, element]  # child before parent deliberately
        payload = {1: payload[1], 2: payload[2], 8: payload[8], 500: True,
                   'items': ['public', cbor2.CBORTag(60, digest(element))],
                   REDACTED: [digest(parent)]}
        wanted = {1: payload[1], 2: payload[2], 500: True,
                  'profile': {'public': True, 'city': 'private city'},
                  'items': ['public', {'kind': 'secret'}]}
        hidden = {1: payload[1], 2: payload[2], 500: True, 'items': ['public']}
    else:
        ds = original[1][17]
        wanted = {k: v for k, v in payload.items() if k in (1, 2, 4, 5, 6, 500)}
        wanted.update({501: 'ABCD-123456', 502: [1549560720, 1612560720, 1674004740],
                       503: {'country': 'us', 'region': 'ca', 'postal_code': '94188'}})
        hidden = {k: v for k, v in wanted.items() if k not in (501, 502, 503)}
        hidden.update({502: [1674004740], 503: {'country': 'us'}})
    original[1] = {17: ds}
    original[2] = cbor2.dumps(payload)
    return sign(cbor2.CBORTag(18, original), BASE.parent / 'issuer_privkey.pem'), ds, wanted, hidden


def main():
    specification = spec_manifest()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--rust', action='store_true')
    ap.add_argument('--python-repo', type=Path)
    ap.add_argument('--js-repo', type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    results = []

    def record(name, ok, detail=''):
        results.append({'check': name, 'status': 'pass' if ok else 'fail', 'detail': detail})

    def run(impl, role, argv, data, label):
        argv = [*argv, '--time', '1725244300']
        prefix = out / label
        prefix.parent.mkdir(parents=True, exist_ok=True)
        try:
            p = subprocess.run([str(BASE / 'implementations' / impl / role), *argv],
                               input=data, capture_output=True, cwd=CASE, timeout=60)
            code, raw, err = p.returncode, p.stdout, p.stderr
        except (OSError, subprocess.TimeoutExpired) as e:
            code, raw, err = -1, b'', str(e).encode()
        prefix.with_suffix('.input.cbor').write_bytes(data)
        prefix.with_suffix('.cbor').write_bytes(raw)
        prefix.with_suffix('.log').write_bytes(err)
        prefix.with_suffix('.command.json').write_text(json.dumps({'args': argv, 'exit': code})+'\n')
        return code, raw

    def verify(impl, token, wanted, key, label, extra=(), reject=False, control=True):
        argv = ['--issuer', 'issuer_pub.pem', '--audience', 'https://verifier.example/app']
        if key:
            argv += ['--aead-key', str(key)]
        code, raw = run(impl, 'verify', argv + list(extra), token, label)
        actual = None
        try:
            actual = cbor2.loads(raw) if code == 0 else None
            # Simple Python API intentionally omits cnf; it was used to verify the
            # holder signature. All other claims must match exactly, including shape.
            if isinstance(actual, dict):
                actual.pop(8, None)
            ok = control and (code == 1 if reject else code == 0 and actual == wanted)
        except Exception:
            ok = False
        record(label, ok, f'exit {code}; actual={actual!r}' if not ok else '')
        if not control and reject:
            results[-1]['status'] = 'blocked'
            results[-1]['detail'] = 'positive control failed; rejection is not evidence'
        return ok

    for alg in [1, 2, 29]:
        key = KEY if alg == 1 else bytes(range(32))
        keyfile = out / f'key-{alg}.hex'; keyfile.write_text(key.hex())
        for nested in [False, True]:
            issued, disclosures, wanted, hidden = fixture(alg, nested)
            profile = f'alg-{alg}-' + ('nested' if nested else 'draft')
            salts = out / f'{profile}-salts.cbor'
            salts.write_bytes(cbor2.dumps([cbor2.loads(d)[0] for d in disclosures]))
            (out / f'{profile}-issued.cbor').write_bytes(issued)
            (out / f'{profile}-expected.cbor').write_bytes(cbor2.dumps(wanted))
            for holder in NAMES + (['esdicawt_aead'] if args.rust and alg in (1, 2) else []):
                for mode in ['plaintext', 'encrypted']:
                    label = f'{profile}/{holder}/{mode}'
                    argv = ['holder_priv.pem', '--issuer', 'issuer_pub.pem']
                    argv += ['--disclose_all'] if mode == 'plaintext' else ['--encrypt_list', str(salts), '--aead-key', str(keyfile)]
                    if mode == 'encrypted' and holder in NAMES:
                        argv += ['--aead-algorithm', str(alg)]
                    code, token = run(holder, 'present', argv, issued, label + '/present')
                    record(label + '/present', code == 0, f'exit {code}')
                    if code:
                        continue
                    for verifier in NAMES + (['esdicawt_aead'] if args.rust and alg in (1, 2) else []):
                        prefix = f'{label}/{verifier}'
                        good = verify(verifier, token, wanted, keyfile, prefix+'/full')
                        verify(verifier, token, hidden if mode == 'encrypted' else wanted, None, prefix+'/no-key')
                        header = 171 if mode == 'encrypted' else 17
                        reordered = mutate(token, lambda h: h[header].reverse())
                        verify(verifier, reordered, wanted, keyfile, prefix+'/reordered', control=good)
                        if mode == 'encrypted':
                            corrupt = mutate(token, lambda h: h[171][-1].__setitem__(2, bytes(16)))
                            verify(verifier, corrupt, None, keyfile, prefix+'/one-bad-tag', reject=True, control=good)

    # Partial encryption across a parent/descendant relationship. An encrypted
    # parent carries its disclosed child encrypted too, so no-key forwarding
    # does not leave an orphan plaintext disclosure. The independent array stays public.
    issued, ds, wanted, _ = fixture(1, nested=True)
    keyfile = out/'mixed-key.hex'; keyfile.write_text(KEY.hex())
    for mode, selection in [('child-only', [ds[0]]), ('parent-and-child', ds[:2])]:
        salts = out/f'mixed-{mode}.cbor'
        salts.write_bytes(cbor2.dumps([cbor2.loads(d)[0] for d in selection]))
        hidden = cbor2.loads(cbor2.dumps(wanted))
        if mode == 'child-only': del hidden['profile']['city']
        else: del hidden['profile']
        for holder in NAMES:
            label = f'mixed-{mode}/{holder}'
            code, token = run(holder, 'present', ['holder_priv.pem', '--issuer', 'issuer_pub.pem',
                '--disclose_all', '--encrypt_list', str(salts), '--aead-key', str(keyfile)],
                issued, label+'/present')
            record(label+'/present', code == 0)
            if code: continue
            for verifier in NAMES + (['esdicawt_aead'] if args.rust else []):
                prefix = label+'/'+verifier
                good = verify(verifier, token, wanted, keyfile, prefix+'/full')
                verify(verifier, token, hidden, None, prefix+'/no-key')
                bad = mutate(token, lambda h: h[171][-1].__setitem__(2, bytes(16)))
                verify(verifier, bad, None, keyfile, prefix+'/bad-tag', reject=True, control=good)

    # Exercise native Holder production of byte-string key contexts and actual
    # context routing in the verifier API, including key rotation candidates.
    issued, ds, wanted, hidden = fixture(1)
    salts = out / 'context-salts.cbor'
    salts.write_bytes(cbor2.dumps([cbor2.loads(d)[0] for d in ds]))
    keyfile = out / 'context-key.hex'; keyfile.write_text(KEY.hex())
    for holder in NAMES + (['esdicawt_aead'] if args.rust else []):
        for size in [32, 48, 64]:
            context = bytes(range(size))
            ctxfile = out / f'context-{size}.cbor'; ctxfile.write_bytes(cbor2.dumps(context))
            label = f'context-{size}/{holder}'
            argv = ['holder_priv.pem', '--issuer', 'issuer_pub.pem', '--encrypt_list', str(salts),
                    '--aead-key', str(keyfile), '--aead-key-context-cbor', str(ctxfile)]
            code, token = run(holder, 'present', argv, issued, label+'/present')
            record(label+'/present', code == 0)
            if code:
                continue
            record(label+'/wire-context', all(e[3] == context for e in embedded(token).value[1][171]))
            if args.rust:
                prefix = label+'/esdicawt_aead'
                good = verify('esdicawt_aead', token, wanted, keyfile, prefix+'/correct',
                              extra=('--aead-key-context-cbor', str(ctxfile)))
                other = out / 'unknown-context.cbor'; other.write_bytes(cbor2.dumps('unknown'))
                verify('esdicawt_aead', token, hidden, keyfile, prefix+'/unknown',
                       extra=('--aead-key-context-cbor', str(other)))
                badkey = out / 'wrong-context-key.hex'; badkey.write_text(bytes(16).hex())
                verify('esdicawt_aead', token, None, badkey, prefix+'/wrong',
                       extra=('--aead-key-context-cbor', str(ctxfile)), reject=True, control=good)

            for kind, mapping, expected, reject in [
                ('correct', {context: KEY}, wanted, False),
                ('unknown', {b'unknown': KEY}, hidden, False),
                ('rotation', {context: [bytes(16), KEY]}, wanted, False),
                ('wrong', {context: bytes(16)}, None, True),
            ]:
                path = out/f'context-{size}-{kind}.keys.cbor'; path.write_bytes(cbor2.dumps(mapping))
                for verifier in NAMES:
                    control = True
                    if reject:
                        control = verify(verifier, token, wanted, keyfile, label+'/'+verifier+'/control')
                    verify(verifier, token, expected, None, label+'/'+verifier+'/'+kind,
                           extra=('--aead-key-map', str(path)), reject=reject, control=control)

        if holder == 'esdicawt_aead':
            continue  # adapter exposes a single key, not the Python/JS resolver API

        # Compose independently produced entries for two recipient keys into one
        # holder-signed KBT. This tests verifier routing, not a new Holder API.
        first = next(d for d in ds if cbor2.loads(d)[-1] == 501)
        second = next(d for d in ds if cbor2.loads(d)[-1] == 'region')
        tokens = []
        contexts = [bytes(range(32)), 'recipient-b']
        keys = [KEY, bytes(range(16))]
        for i, d in enumerate([first, second]):
            selection = out/f'two-key-{i}-salts.cbor'; selection.write_bytes(cbor2.dumps([cbor2.loads(d)[0]]))
            ctx = out/f'two-key-{i}-context.cbor'; ctx.write_bytes(cbor2.dumps(contexts[i]))
            keypath = out/f'two-key-{i}.hex'; keypath.write_text(keys[i].hex())
            code, token = run(holder, 'present', [
                'holder_priv.pem', '--issuer', 'issuer_pub.pem', '--disclose_all',
                '--encrypt_list', str(selection), '--aead-key', str(keypath),
                '--aead-key-context-cbor', str(ctx)], issued, f'two-key/{holder}/part-{i}')
            record(f'two-key/{holder}/part-{i}', code == 0)
            if code == 0: tokens.append(token)
        if len(tokens) != 2:
            continue
        def combine(h):
            h[17] = [d for d in h[17] if d != second]
            h[171].extend(embedded(tokens[1]).value[1][171])
        combined = mutate(tokens[0], combine)
        only_a = cbor2.loads(cbor2.dumps(wanted)); del only_a[503]['region']
        only_b = cbor2.loads(cbor2.dumps(wanted)); del only_b[501]
        neither = cbor2.loads(cbor2.dumps(only_a)); del neither[501]
        for verifier in NAMES:
            prefix = f'two-key/{holder}/{verifier}'
            allkeys = out/'two-key-both.cbor'; allkeys.write_bytes(cbor2.dumps(dict(zip(contexts, keys))))
            good = verify(verifier, combined, wanted, None, prefix+'/both', extra=('--aead-key-map', str(allkeys)))
            for kind, mapping, expected, reject in [
                ('only-a', {contexts[0]: keys[0]}, only_a, False),
                ('only-b', {contexts[1]: keys[1]}, only_b, False),
                ('neither', {}, neither, False),
                ('one-wrong', {contexts[0]: bytes(16), contexts[1]: keys[1]}, None, True),
            ]:
                path = out/f'two-key-{kind}.cbor'; path.write_bytes(cbor2.dumps(mapping))
                verify(verifier, combined, expected, None, prefix+'/'+kind,
                       extra=('--aead-key-map', str(path)), reject=reject, control=good)

    metadata = {'specification': specification, 'python': git_state(args.python_repo), 'javascript': git_state(args.js_repo),
                'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'rust_adapter': 'c6eb0e4 + cli.patch; AES-128/AES-256, all-disclosure selection, typed contexts' if args.rust else None,
                'source_sha256': {str(p.relative_to(BASE)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in [BASE/'run_profiles.py', BASE/'run_encrypted.py', BASE/'run_aead.py', BASE/'spec_revision.py', BASE/'spec-version.json',
                              BASE/'implementations/sd_cwt/sd_cwt_interop.py',
                              BASE/'implementations/sd_cwt_js/sd_cwt_interop.mjs',
                              BASE/'implementations/esdicawt_aead/cli.patch']}}
    artifacts = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in out.rglob('*') if p.is_file()}
    report = {'metadata': metadata, 'passed': sum(r['status']=='pass' for r in results),
              'failed': sum(r['status']=='fail' for r in results),
              'blocked': sum(r['status']=='blocked' for r in results),
              'total': len(results), 'checks': results, 'artifacts_sha256': artifacts}
    (out/'results.json').write_text(json.dumps(report, indent=2)+'\n')
    print(f"{report['passed']}/{report['total']} passed; {report['failed']} failed; {report['blocked']} blocked")
    for r in results:
        if r['status']=='fail': print('FAIL', r['check'], r['detail'])
    return int(report['passed'] != report['total'])


if __name__ == '__main__':
    sys.exit(main())
