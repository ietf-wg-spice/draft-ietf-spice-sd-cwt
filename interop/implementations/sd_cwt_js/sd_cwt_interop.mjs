// INTEROP.md wrapper for tradeverifyd/sd-cwt-js.
// Set SD_CWT_JS_DIR to a checkout of sd-cwt-js with `npm install` done.

import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFileSync, writeSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const dir = process.env.SD_CWT_JS_DIR;
if (!dir) {
  console.error('set SD_CWT_JS_DIR to an sd-cwt-js checkout');
  process.exit(2);
}
const load = p => import(pathToFileURL(join(dir, p)).href);
const { Holder, Verifier } = await load('src/api.js');
const coseSign1 = await load('src/cose-sign1.js');
const sdCwt = await load('src/sd-cwt.js');
const cbor = await load('node_modules/cbor2/lib/index.js');

const DEFAULT_AUDIENCE = 'https://verifier.example/app';
const ES = { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' };
const b64u = s => new Uint8Array(Buffer.from(s, 'base64url'));
const hex = s => new Uint8Array(Buffer.from(s.trim(), 'hex'));
const toHex = b => Buffer.from(b).toString('hex');
const readStdin = () => new Uint8Array(readFileSync(0));
const out = bytes => writeSync(1, bytes);
const decode = b => cbor.decode(b, sdCwt.cborDecodeOptions);
// cbor2 encodes a Node Buffer as a {type, data} map, not a bstr.
const plain = v =>
  Buffer.isBuffer(v) ? new Uint8Array(v)
  : v instanceof Map ? new Map([...v].map(([k, x]) => [plain(k), plain(x)]))
  : Array.isArray(v) ? v.map(plain)
  : v;

function jwkFromPem(path) {
  const pem = readFileSync(path, 'utf8');
  const key = pem.includes('PRIVATE KEY') ? createPrivateKey(pem) : createPublicKey(pem);
  const jwk = key.export({ format: 'jwk' });
  const k = { x: b64u(jwk.x), y: b64u(jwk.y) };
  if (jwk.d) k.d = b64u(jwk.d);
  return { key: k, alg: ES[jwk.crv] };
}

function pick(path, bySalt) {
  if (!path) return [];
  return decode(new Uint8Array(readFileSync(path))).map(salt => {
    const d = bySalt.get(toHex(salt));
    if (!d) throw new Error(`no disclosure with salt ${toHex(salt)}`);
    return d;
  });
}

async function present(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      issuer: { type: 'string' },
      'issuer-key': { type: 'string' },
      time: { type: 'string' },
      disclosure_list: { type: 'string' },
      disclose_all: { type: 'boolean' },
      encrypt_list: { type: 'string' },
      'aead-key': { type: 'string' },
      'aead-key-context': { type: 'string' },
      'aead-nonces': { type: 'string' },
      audience: { type: 'string', default: DEFAULT_AUDIENCE },
    },
  });
  const token = readStdin();
  if (values['issuer-key'] !== 'ignore') {
    if (!values.issuer) throw new Error("no --issuer key and --issuer-key is not 'ignore'");
    await Verifier.verifyWithoutKeyBinding({ token, disclosures: [], publicKey: jwkFromPem(values.issuer).key });
  }
  const available = coseSign1.getHeaders(token).unprotectedHeaders.get(17) ?? [];
  const bySalt = new Map(available.map(d => [toHex(decode(d)[0]), d]));
  const toEncrypt = pick(values.encrypt_list, bySalt);
  const plaintext = (values.disclose_all ? available : pick(values.disclosure_list, bySalt))
    .filter(d => !toEncrypt.includes(d));
  if (toEncrypt.length && !values['aead-key']) throw new Error('--encrypt_list needs --aead-key');

  const nonces = new Map();
  if (values['aead-nonces']) {
    for (const line of readFileSync(values['aead-nonces'], 'utf8').split('\n')) {
      const [salt, nonce] = line.split(',');
      if (salt && nonce) nonces.set(salt.trim(), hex(nonce));
    }
  }
  let keyContext = values['aead-key-context'];
  if (keyContext !== undefined && /^\d+$/.test(keyContext)) keyContext = Number(keyContext);
  const aeadKey = values['aead-key'] ? hex(readFileSync(values['aead-key'], 'utf8')) : undefined;

  const holder = jwkFromPem(positionals[0]);
  const kbt = await Holder.present({
    token,
    selectedDisclosures: plaintext,
    encryptedDisclosures: toEncrypt.map(disclosure => ({
      disclosure,
      key: aeadKey,
      keyContext,
      nonce: nonces.get(toHex(decode(disclosure)[0])),
    })),
    holderPrivateKey: holder.key,
    audience: values.audience,
    algorithm: holder.alg,
  });
  console.error(`presented ${plaintext.length} plaintext, ${toEncrypt.length} encrypted disclosures`);
  out(kbt);
}

async function verify(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      issuer: { type: 'string' },
      'issuer-key': { type: 'string' },
      time: { type: 'string' },
      audience: { type: 'string' },
      'aead-key': { type: 'string', multiple: true },
    },
  });
  if (!values.issuer) throw new Error('no --issuer key');
  const presentation = readStdin();
  const audience = values.audience ?? decode(decode(presentation).contents[2]).get(3);
  const keys = (values['aead-key'] ?? []).map(p => hex(readFileSync(p, 'utf8')));
  const result = await Verifier.verify({
    presentation,
    issuerPublicKey: jwkFromPem(values.issuer).key,
    expectedAudience: audience,
    aeadKeyResolver: keys.length ? () => keys : undefined,
  });
  if (result.undecryptedDisclosures?.length) {
    console.error(`${result.undecryptedDisclosures.length} encrypted disclosure(s) left undecrypted`);
  }
  out(cbor.encode(plain(result.claims)));
}

const [role, ...argv] = process.argv.slice(2);
try {
  if (role === 'target') process.stdout.write('sd_cwt_js');
  else if (role === 'present') await present(argv);
  else if (role === 'verify') await verify(argv);
  else throw new Error(`unknown role ${role}`);
} catch (e) {
  console.error(e.message);
  process.exit(1);
}
