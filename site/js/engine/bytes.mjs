// © 2026 sun-dive — Business Source License 1.1 (see LICENSE).
/**
 * Byte primitives — what `Uint8Array` does not give you and `Buffer` did.
 *
 * ★★★ WHY `Uint8Array` AND NOT `Buffer`. **The wallet is browser-only.** `Buffer` does not exist in a
 *   browser: code using it BUNDLES CLEANLY and then fails at runtime on a user's machine, which is a
 *   worse failure than one that refuses to build. ⇒ `test/browser-safe.mjs` now catches both.
 *
 * ★★ AND `Uint8Array` IS THE BETTER TYPE ANYWAY, not merely the available one:
 *   | it **enforces bytes** | assign 256 and you get 0; a `number[]` holds `-1` or `999` and says nothing |
 *   | every browser API speaks it | `crypto.getRandomValues`, `TextEncoder`, `Blob`, `File.arrayBuffer()` |
 *   | `subarray()` is a **view** | not a copy, unlike `slice()` on an array |
 *   | one byte per element | rather than eight |
 *
 * ⚠ Multi-byte reads and writes go through `DataView`, which takes an explicit endianness argument on
 *   every call. Bitcoin is little-endian almost everywhere and big-endian in a few places, and having to
 *   name it each time is a feature: `readU32LE` cannot be misread as its big-endian cousin.
 */

/** ⚠ Refuses malformed hex rather than guessing — see `src/bytes.ts` for the two implementations that
 *  disagreed about odd-length input, producing different bytes for the same string. */
export function fromHex(hex) {
  if (hex.length === 0) return new Uint8Array(0)
  if (hex.length % 2 !== 0) throw new Error(`hex string has an odd length (${hex.length})`)
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error(`not a hex string: "${hex.slice(0, 24)}…"`)
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  return out
}

/** ⚠ `padStart` is not cosmetic: a byte is always two characters. */
export function toHex(b) {
  let s = ''
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0')
  return s
}

export function concat(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}

/** ⚠ Compares CONTENT. `a === b` on two Uint8Arrays compares identity and is always false. */
export function equals(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

/** ★ Constant-time content comparison, for anything derived from a secret. */
export function timingSafeEquals(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** ⚠ Reverses a COPY. Bitcoin displays hashes reversed; mutating the original in place is a classic bug. */
export const reversed = b => new Uint8Array(b).reverse()

export const fromUtf8 = s => new TextEncoder().encode(s)
export const toUtf8 = b => new TextDecoder().decode(b)

// ── multi-byte integers ─────────────────────────────────────────────────────────────────────────────
// ⚠ Endianness is named in every function, because Bitcoin uses both and the wrong one is silent.
const dv = b => new DataView(b.buffer, b.byteOffset, b.byteLength)

export const readU16LE = (b, o = 0) => dv(b).getUint16(o, true)
export const readU32LE = (b, o = 0) => dv(b).getUint32(o, true)
export const readU64LE = (b, o = 0) => dv(b).getBigUint64(o, true)

export function u16LE(n) { const b = new Uint8Array(2); dv(b).setUint16(0, n, true); return b }
export function u32LE(n) { const b = new Uint8Array(4); dv(b).setUint32(0, n, true); return b }
/** ⚠ 8 bytes, and it takes a BigInt: a satoshi amount above 2^53 is not safe as a JS number. */
export function u64LE(n) { const b = new Uint8Array(8); dv(b).setBigUint64(0, BigInt(n), true); return b }

/** big-endian, LEFT-PADDED. ⚠ The padding is the point — see BIP-32's "retention of leading zeros". */
export function beBytes(n, len) {
  const out = new Uint8Array(len)
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n }
  if (n !== 0n) throw new RangeError(`does not fit in ${len} bytes`)
  return out
}

export const toBigBE = b => (b.length === 0 ? 0n : BigInt('0x' + toHex(b)))
