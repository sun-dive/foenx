// © 2026 sun-dive — Business Source License 1.1 (see LICENSE).
/**
 * ECDSA over secp256k1 — signing, verification, and STRICT DER.
 *
 * ★ THIS FILE OWNS THE SIGNING PATH. `secp256k1.mjs` was written for BIP-32 derivation and did not sign
 *   at all; signing happens here, and nowhere else.
 *
 * ⛔⛔ STRICT DER, AND THE RULE THAT IS EASIEST TO MISS:
 *   A DER INTEGER is SIGNED. One whose top bit is set REQUIRES a leading `0x00`, or the value reads as
 *   negative. ⇒ Omit that byte and you have **two different byte strings for one signature** — the
 *   classic malleability. **BIP-66 has made the unpadded form invalid on the network since 2015**, so a
 *   parser that accepts it is MORE PERMISSIVE THAN CONSENSUS: it can call a transaction good that no
 *   node would accept. `decodeDer` refuses it, along with BER long-form lengths, trailing bytes and
 *   non-minimal leading zeros.
 *
 * ⚠⚠ NOT CONSTANT TIME, and cannot be. That is a property of JavaScript rather than of any particular
 *   implementation: JIT compilation and garbage collection put it out of reach in a scripting language.
 *   ⇒ The two secrets on this path are BLINDED instead — the nonce through `mulBlinded`, its inverse
 *     through `invNBlinded`, both in `secp256k1.mjs` where `mulRaw` guarantees the blinding is not
 *     reduced away. That RAISES THE COST of a timing attack; it does not remove it.
 *   **For anything material, sign air-gapped.**
 */
import { N, P, G, mul, mulBlinded, add, serP, mod, modPow, invN, invNBlinded } from './secp256k1.mjs'
import { rfc6979k } from './rfc6979.mjs'
import { concat, beBytes, toBigBE } from './bytes.mjs'

// ⚠ mod, modPow and invN come from the curve module — they were duplicated here.

/* ⚠ `beBytes` and `toBigBE` live in bytes.mjs — one copy of the left-padding rule, not three. */
const toBig = toBigBE

/* ⚠ `mulBlinded` USED TO LIVE HERE, and it did nothing: it called `mul`, which reduces mod N and so
   erased the blinding. It now lives in the curve module next to `mulRaw`, the only multiply that does
   not reduce — so the two cannot drift apart again. See the note at the top of `secp256k1.mjs`. */

export function publicKey(d, compressed = true) {
  const pt = mulBlinded(mod(d, N), G)           // ⚠ d is SECRET — never the plain `mul` here
  if (pt === null) throw new Error('private key out of range')
  return compressed ? serP(pt) : concat(Uint8Array.of(0x04), beBytes(pt.x, 32), beBytes(pt.y, 32))
}

/** ⚠ DER INTEGERs are SIGNED: a high top bit needs a `0x00` in front or the value reads negative. */
function derInt(v) {
  let b = beBytes(v, 32)
  const first = b.findIndex(x => x !== 0)
  b = b.subarray(first === -1 ? 31 : first)
  if (b[0] & 0x80) b = concat(Uint8Array.of(0x00), b)      // ⚠ DER INTEGERs are SIGNED
  return concat(Uint8Array.of(0x02, b.length), b)
}

export function encodeDer(r, s) {
  const body = concat(derInt(r), derInt(s))
  return concat(Uint8Array.of(0x30, body.length), body)
}

/**
 * STRICT by default. `allowTrailing` permits ONE thing — bytes after the sequence, which is where
 * Bitcoin's sighash byte lives. ⚠ It does NOT relax the integer rules.
 * @returns {[bigint, bigint] | null}
 */
export function decodeDer(sig, allowTrailing = false) {
  const b = sig
  if (b.length < 8 || b[0] !== 0x30) return null
  const len = b[1]
  if (len & 0x80) return null                                  // ⛔ long-form length is BER, not DER
  if (!allowTrailing && 2 + len !== b.length) return null       // ⛔ trailing bytes
  if (2 + len > b.length) return null
  let p = 2
  const readInt = () => {
    if (b[p++] !== 0x02) return null
    const l = b[p++]
    if (l === 0 || l > 33 || p + l > b.length) return null
    const v = b.subarray(p, p + l); p += l
    if (v[0] & 0x80) return null                                // ⛔ NEGATIVE — see the module note
    if (v[0] === 0x00 && !(v[1] & 0x80)) return null            // ⛔ non-minimal leading zero
    return toBig(v)
  }
  const r = readInt(); if (r === null) return null
  const s = readInt(); if (s === null) return null
  if (p !== 2 + len) return null
  if (r <= 0n || s <= 0n || r >= N || s >= N) return null
  return [r, s]
}

/**
 * Sign a 32-byte DIGEST. ⚠ Not a message — ECDSA cannot consume bytes, only a digest, so the hash is
 * the caller's explicit responsibility.
 * @param {bigint} d
 * @param {Uint8Array} digest32
 * @param {{lowS?: boolean, rand?: Function}} opts
 * ⚠ The HMAC used to be injected. `@noble/hashes` is synchronous and bundles for a browser, so the
 *   hook had no remaining purpose and is gone rather than left unused.
 */
export function sign(d, digest32, { lowS = false, rand } = {}) {
  if (digest32.length !== 32) throw new Error('a digest is 32 bytes')
  const z = toBig(digest32)
  for (let attempt = 0; attempt < 64; attempt++) {
    const k = rfc6979k(N, mod(d, N), digest32, attempt)
    const pt = mulBlinded(k, G, rand)
    if (pt === null) continue
    const r = mod(pt.x, N)
    if (r === 0n) continue                       // ★ retry steps the generator forward, never randomly
    /* ⚠ `invNBlinded`, not `invN`: `k` is the secret nonce, and `modPow`'s work depends on its base.
       Verification below uses the plain `invN` because `s` there is public. */
    let s = mod(invNBlinded(k, rand) * (z + r * mod(d, N)), N)
    if (s === 0n) continue
    /* ⚠⚠ LOW-S IS NOT A PROTOCOL RULE, AND HAS NOT BEEN SINCE APRIL 2026.
       It is a BIP-62 malleability rule from 2015. **Chronicle removed it** — mainnet block 943,816,
       7 April 2026, opt-in via transaction version > 1 — along with the rest of that 2015 set.

       ⛔ ONE MAJOR PROCESSOR STILL ENFORCES IT. Measured on mainnet 2026-08-12: of 20 covenant spends,
       ARC refused exactly the 7 whose signature was high-s — `error 461: Non-canonical signature: S
       value is unnecessarily high` — while WhatsOnChain accepted all 20. ★ And the chain settled it:
       one of the refused transactions was MINED, in block 961,975. ⇒ **ARC is the non-conformant
       party, not the signature.**

       ⇒ SO WHY NORMALISE HERE? Because for KEY-BASED signing it is free: the signer holds the key and
       simply negates s, which is deterministic, so reproducibility survives and no fee is paid.
       ⇒ ⚠ THE COVENANT CASE IS DIFFERENT AND THE ANSWER THERE IS THE OPPOSITE. In an OP_PUSH_TX
       covenant `s` is DERIVED in-script from fixed constants and cannot be conditionally negated, so
       low-s costs a builder-side GRIND. That was decided against (2026-08-12): bending transactions
       to satisfy a processor that has not caught up is the wrong default on a chain whose premise is
       restoring the original protocol. **Do not bake low-s into a covenant.** */
    if (lowS && s > N / 2n) s = N - s
    return encodeDer(r, s)
  }
  throw new Error('no valid signature after 64 attempts — statistically impossible; something is wrong')
}

/** Verify a DER signature over a 32-byte digest. */
export function verifyDigest(sig, pub, digest32, allowTrailing = false) {
  const parsed = decodeDer(sig, allowTrailing)
  if (parsed === null) return false
  const [r, s] = parsed
  const Q = decodePoint(pub)
  if (Q === null) return false
  const z = toBig(digest32)
  const w = invN(s)
  const p1 = mul(mod(z * w, N), G)
  const p2 = mul(mod(r * w, N), Q)
  const R = add(p1, p2)
  return R !== null && mod(R.x, N) === r
}

/** SEC1 point decoding, compressed or uncompressed. */
export function decodePoint(pub) {
  const b = pub
  if (b.length === 33 && (b[0] === 0x02 || b[0] === 0x03)) {
    const x = toBig(b.subarray(1))
    if (x >= P) return null
    const y2 = mod(x * x % P * x + 7n, P)
    let y = modPow(y2, (P + 1n) / 4n, P)
    if (modPow(y, 2n, P) !== y2) return null       // ⛔ not on the curve
    if ((y & 1n) !== BigInt(b[0] & 1)) y = P - y
    return { x, y }
  }
  if (b.length === 65 && b[0] === 0x04) {
    const x = toBig(b.subarray(1, 33)), y = toBig(b.subarray(33))
    if (x >= P || y >= P) return null
    if (mod(y * y, P) !== mod(x * x % P * x + 7n, P)) return null
    return { x, y }
  }
  return null
}
