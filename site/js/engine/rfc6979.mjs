// © 2026 sun-dive — Business Source License 1.1 (see LICENSE).
/**
 * RFC 6979 — deterministic `k`.
 *
 * ★ CURVE-AGNOSTIC ON PURPOSE, and that is what makes it gradeable. `k` depends only on the group
 *   order, the private key and the digest — **never on the curve's points** — so RFC 6979 §A.2.5's
 *   published **P-256** vectors grade this algorithm exactly, and secp256k1 then uses the same
 *   function. ⇒ An external oracle exists for the hard part.
 *
 * ⚠⚠ TWO SILENT-FAILURE TRAPS, both of which verify fine while disagreeing with everyone else:
 *   1. **`bits2int` must SHIFT RIGHT** when the input is wider than the order, never truncate bytes.
 *      Identical when both are 32 bytes; wrong the moment a digest is wider than the curve.
 *   2. **`int2octets` is fixed width**, and `bits2octets` reduces **mod q FIRST**.
 *
 * ⚠ The HMAC used to be injected, so that a browser build could supply its own. That is no longer
 *   needed: `@noble/hashes` is synchronous and bundles for a browser, which was the whole reason for
 *   the parameter. ⇒ Removed rather than left as an unused hook.
 */
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concat, toBigBE } from './bytes.mjs'

const hmac256 = (key, msg) => hmac(sha256, key, msg)

/** big-endian bytes → BigInt, SHIFTED RIGHT if wider than the order. ⚠ Not truncated. */
function bits2int(b, qlen) {
  const v = toBigBE(b)
  const blen = b.length * 8
  return blen > qlen ? v >> BigInt(blen - qlen) : v
}

function int2octets(x, rlen) {
  const out = new Uint8Array(rlen)
  for (let i = rlen - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n }
  if (x !== 0n) throw new RangeError('int2octets: value wider than the order')
  return out
}

const bitlen = n => (n === 0n ? 0 : n.toString(2).length)

/**
 * @param {bigint} q the group order
 * @param {bigint} x the private key
 * @param {Uint8Array} h1 the message digest
 * @param {number} attempt ★ retry steps the generator FORWARD — never a fresh random k, which would
 *   reintroduce the very RNG this file exists to remove.
 */
export function rfc6979k(q, x, h1, attempt = 0) {
  const qlen = bitlen(q)
  const rlen = Math.ceil(qlen / 8)
  // ⚠ bits2octets: reduce mod q FIRST, then fix the width.
  const h1int = bits2int(h1, qlen)
  const z2 = int2octets(h1int >= q ? h1int - q : h1int, rlen)
  const x2 = int2octets(x, rlen)

  let V = new Uint8Array(32).fill(0x01)
  let K = new Uint8Array(32).fill(0x00)
  K = hmac256(K, concat(V, Uint8Array.of(0x00), x2, z2)); V = hmac256(K, V)
  K = hmac256(K, concat(V, Uint8Array.of(0x01), x2, z2)); V = hmac256(K, V)

  for (let skipped = 0; ;) {
    let T = new Uint8Array(0)
    while (T.length * 8 < qlen) { V = hmac256(K, V); T = concat(T, V) }
    const cand = bits2int(T, qlen)
    if (cand >= 1n && cand < q) {
      if (skipped === attempt) return cand
      skipped++
    }
    K = hmac256(K, concat(V, Uint8Array.of(0x00))); V = hmac256(K, V)
  }
}
