// © 2026 sun-dive.
//
// SLIP-0010 for Ed25519: a seed to a hardened chain of keys. Hardened only, which is not a choice here
// but the scheme's own rule: SLIP-0010 defines no non-hardened derivation for Ed25519, so one leaked
// child can never rebuild its parent. Graded by the specification's two test vectors in
// tools/verify-key.mjs. The public key comes from WebCrypto, which is the only place the private key
// ever goes.

import { hmac } from '@noble/hashes/hmac.js'
import { sha512 } from '@noble/hashes/sha2.js'

const HARDENED = 0x80000000
const enc = new TextEncoder()

/** The master node: HMAC-SHA512 keyed with "ed25519 seed" over the seed. */
export function master(seed) {
  const I = hmac(sha512, enc.encode('ed25519 seed'), seed)
  return { key: I.slice(0, 32), chain: I.slice(32) }
}

/** A hardened child. `index` is the plain index (0, 1, ...) or an already-hardened one; both are accepted. */
export function child(node, index) {
  const i = index >= HARDENED ? index : index + HARDENED
  const data = new Uint8Array(1 + 32 + 4)
  data[0] = 0
  data.set(node.key, 1)
  data[33] = (i >>> 24) & 255; data[34] = (i >>> 16) & 255; data[35] = (i >>> 8) & 255; data[36] = i & 255
  const I = hmac(sha512, node.chain, data)
  return { key: I.slice(0, 32), chain: I.slice(32) }
}

/** `m/44'/1'/0'` or `m/44H/1H/0H`. Every step must be marked hardened; an unmarked step is refused. */
export function derive(seed, path) {
  const parts = path.trim().split('/')
  if (parts[0] !== 'm') throw new Error('a path starts with m')
  let node = master(seed)
  for (const p of parts.slice(1)) {
    const m = /^(\d+)(['Hh])$/.exec(p)
    if (!m) throw new Error(`SLIP-0010 Ed25519 derives hardened children only: "${p}" is not marked`)
    const n = Number(m[1])
    if (n >= HARDENED) throw new Error('index out of range')
    node = child(node, n)
  }
  return node
}

/** PKCS#8 wrapping of a raw 32-byte Ed25519 private key (RFC 8410), for WebCrypto import. */
export function pkcs8(key32) {
  const prefix = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]
  return Uint8Array.from([...prefix, ...key32])
}

const b64url = s => { const b = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')); return Uint8Array.from(b, c => c.charCodeAt(0)) }

/** The 32-byte public key for a raw private key. The import is extractable only for this export. */
export async function publicKey(key32) {
  const k = await crypto.subtle.importKey('pkcs8', pkcs8(key32), { name: 'Ed25519' }, true, ['sign'])
  const jwk = await crypto.subtle.exportKey('jwk', k)
  return b64url(jwk.x)
}
