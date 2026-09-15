// © 2026 sun-dive.
//
// A foen thread IS a jetmora covenant thread: "a tip, ticked forward, only valid links".
//
// Every tick is a jetmora ENTRY (spec §3: an entry is a transaction), built exactly as
// jetmora/server/wallet/jetmora/thread.php builds one:
//   input 0   spends the tip: prevEntry = the previous entry's hash (the genesis id for the first tick),
//             index 0, sequence = the tick index, unlocking = <sig> <pub> as two jetForth direct pushes
//   output 0  the successor tip, locked to the same key, in jetForth (family JF, revision 3):
//               $<call id> 2DROP  2DUP 1000 HASH160  1000 20 $<h160(pub)> BYTES=  >R
//               2000 PREIMAGE 3000 HASH256  3000 32 ED25519-CHECKSIG  R> AND
//             the call id is carried and dropped; the key must hash to the committed hash; the signature
//             must verify over HASH256 of the preimage the verifier supplies. Both flags are ANDed, so
//             the lock has no branches and reads the same whichever check fails.
//   output 1  the tick's payload:  STR16 <payload> ABORT  (never spendable, and says so)
//   locktime 0 · value 0 (§3: an application quantity, MAY be zero)
// The key is Ed25519 (32 bytes), held non-extractable in WebCrypto (key.mjs): the signature is 64 raw
// bytes over SHA256d(preimage), the preimage being the BIP143 layout of input 0 against the previous
// tip's lock (spec §3, type 0x01). ED25519-CHECKSIG takes the message as given, so the digest is pushed
// explicitly and the word signs exactly what the script says.
//
// The genesis is native and derived (§2): SHA256d( LP(source_hash) ‖ LP(script) ‖ LP(state) ‖ LP(authorised) ),
// with authorised = 0x02 ‖ k ‖ n ‖ (32 ‖ sha256(pub)) — hashes, never keys in the clear (his rule, 7 Sept).

import { sha256 } from './jetmora/sha256.mjs'
import { serializeEntry, parseEntry, varint } from './jetmora/entry.mjs'
import { preimage } from './jetmora/preimage.mjs'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { sign, verify, keyHasNumber } from './key.mjs'
import { toHex, fromHex } from './engine/bytes.mjs'

export const VERSION_JF3 = ((0x46 << 24) | (0x4a << 16) | 3) >>> 0      // family 'JF', revision 3: sections by category, crypto last
const SOURCE_HASH = sha256([...new TextEncoder().encode('foen thread v2 (jetForth): state 2DROP, key hash check, ED25519-CHECKSIG over HASH256 of PREIMAGE, ANDed; one STR16 data output per tick')])
// jetForth bytes (jetmora/server/ops-jf.php, revision 3): a direct push is its own length (1..72);
// LIT8/LIT16 carry integers; STR16/STR32 carry long strings. Words by number.
const JF = { PUSH_MAX: 0x48, SMALL0: 0x49, LIT8: 0x53, LIT16: 0x54, STR16: 0x59, STR32: 0x5a,
  '2DROP': 0x5c, '2DUP': 0x5d, '>R': 0x62, 'R>': 0x6a, AND: 0x86, ABORT: 0xaf,
  'BYTES=': 0xbf, 'ED25519-CHECKSIG': 0xd8, HASH160: 0xda, HASH256: 0xdb, PREIMAGE: 0xcb }

const dsha256 = b => sha256(sha256(b))
const hash160 = pub => [...ripemd160(Uint8Array.from(sha256([...pub])))]
const lp = b => [(b.length >>> 24) & 255, (b.length >>> 16) & 255, (b.length >>> 8) & 255, b.length & 255, ...b]
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

/** A jetForth direct push: the opcode is the length (1..72 bytes). */
export function push(data) {
  if (data.length < 1 || data.length > JF.PUSH_MAX) throw new Error(`direct push must be 1..${JF.PUSH_MAX} bytes`)
  return [data.length, ...data]
}
/** A jetForth integer literal in its smallest form, as jf_asm emits it. */
export function lit(v) {
  if (v >= 0 && v <= 8) return [JF.SMALL0 + v]
  if (v >= -128 && v <= 127) return [JF.LIT8, v & 255]
  if (v >= -32768 && v <= 32767) return [JF.LIT16, v & 255, (v >> 8) & 255]
  throw new Error('literal out of range for this lock')
}
/** Read the direct pushes of a script; null if it holds anything else. */
export function pushes(script) {
  const out = []
  for (let p = 0; p < script.length;) {
    const n = script[p++]
    if (n < 1 || n > JF.PUSH_MAX || p + n > script.length) return null
    out.push(script.slice(p, p + n)); p += n
  }
  return out
}

/** The tip's lock in jetForth for a key in a call (see the header). Byte-identical to jf_asm of the source. */
export const lockFor = (state, pub) => [
  ...push(state), JF['2DROP'],
  JF['2DUP'], ...lit(1000), JF.HASH160,
  ...lit(1000), ...lit(20), ...push(hash160(pub)), JF['BYTES='], JF['>R'],
  ...lit(2000), JF.PREIMAGE, ...lit(3000), JF.HASH256,
  ...lit(3000), ...lit(32), JF['ED25519-CHECKSIG'],
  JF['R>'], JF.AND,
]
/** The payload output: STR16 (or STR32) <payload> ABORT. Never spendable, and says so. */
export const dataOutput = payload => {
  const n = payload.length
  return n <= 0xffff ? [JF.STR16, n & 255, n >> 8, ...payload, JF.ABORT]
                     : [JF.STR32, n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255, ...payload, JF.ABORT]
}
/** Read a payload output back; null if it is not one. */
export function readData(script) {
  if (script.length < 4 || script[script.length - 1] !== JF.ABORT) return null
  let n, p
  if (script[0] === JF.STR16) { n = script[1] | (script[2] << 8); p = 3 }
  else if (script[0] === JF.STR32) { n = (script[1] | (script[2] << 8) | (script[3] << 16) | (script[4] << 24)) >>> 0; p = 5 }
  else return null
  if (p + n + 1 !== script.length) return null
  return script.slice(p, p + n)
}
export const authorisedHashes = (pubs, k = 1) => {
  const hs = pubs.map(p => sha256([...p])).sort((a, b) => toHex(a) < toHex(b) ? -1 : 1)
  return [0x02, k, hs.length, ...hs.flatMap(h => [h.length, ...h])]
}
/** Genesis id (§2): SHA256d of the four length-prefixed fields. */
export function genesisId(state, pub) {
  const commitment = [...lp(SOURCE_HASH), ...lp(lockFor(state, pub)), ...lp(state), ...lp(authorisedHashes([pub]))]
  return dsha256(commitment)
}

/** One direction of a call: this key's thread, ticked forward per chunk. */
export class Sender {
  /** @param wallet {pub, priv} from key.mjs: the public key and the non-extractable signing key */
  constructor(wallet, callId) {
    this.wallet = wallet
    this.pub = [...wallet.pub]
    this.state = [...fromHex(callId)]
    this.lock = lockFor(this.state, this.pub)
    this.genesis = genesisId(this.state, this.pub)
    this.tip = this.genesis
    this.seq = 1
  }
  /** Tick: spend the tip, produce the successor and the payload. Resolves { seq, bytes } (bytes: Uint8Array). */
  async entry(payload) {
    const seq = this.seq++
    const skeleton = { version: VERSION_JF3, inputs: [{ prevEntry: this.tip, index: 0, unlocking: [], sequence: seq }],
                       outputs: [{ value: 0n, locking: this.lock }, { value: 0n, locking: dataOutput(payload) }], locktime: 0 }
    const pre = preimage({ entry: skeleton, inputIndex: 0, scriptCode: this.lock, value: 0n })
    const sig = [...await sign(this.wallet, Uint8Array.from(dsha256(pre)))]   // 64 raw bytes over the digest the script names
    const entry = { ...skeleton, inputs: [{ ...skeleton.inputs[0], unlocking: [...push(sig), ...push(this.pub)] }] }
    const bytes = serializeEntry(entry)
    this.tip = dsha256(bytes)
    return { seq, bytes: Uint8Array.from(bytes) }
  }
}

/** The other direction: verifies each tick on its own, tracks the tip, reports gaps. */
export class Receiver {
  /**
   * @param peerPub     the peer's 32-byte key, when known (an invite carries it)
   * @param peerNumber  the peer's number, when only that is known (a link, a book listing): the first
   *                    tick's key must carry it, and is pinned from then on
   */
  constructor(callId, peerPub = null, peerNumber = null) {
    this.state = [...fromHex(callId)]
    this.peerPub = peerPub ? [...peerPub] : null
    this.peerNumber = peerNumber
    this.lock = this.peerPub ? lockFor(this.state, this.peerPub) : null
    this.tip = this.peerPub ? genesisId(this.state, this.peerPub) : null
    this.seq = 0
    this.stats = { received: 0, verified: 0, badSig: 0, badFormat: 0, stale: 0, gaps: 0, missed: 0, bytes: 0 }
  }
  /** Resolves { seq, linked, payload } for a good tick, or null (and counts why). */
  async accept(bytes) {
    const s = this.stats
    s.received++
    const b = [...bytes]
    let e
    try { e = parseEntry(b) } catch { s.badFormat++; return null }
    if (e.version !== VERSION_JF3 || e.inputs.length !== 1 || e.outputs.length < 2 || e.locktime !== 0) { s.badFormat++; return null }
    const inp = e.inputs[0]
    const ul = pushes(inp.unlocking)
    if (!ul || ul.length !== 2 || ul[1].length !== 32 || ul[0].length !== 64) { s.badFormat++; return null }
    const sig = ul[0], pub = ul[1]
    const payload = readData(e.outputs[1].locking)
    if (!payload) { s.badFormat++; return null }
    if (inp.sequence <= this.seq) { s.stale++; return null }

    // A call is between the two keys that speak on it: the first verified tick fixes the peer's key,
    // which must match the key the invitation named, or carry the number that was dialled. The lock
    // carries the call id, so a tick signed by this key for another call fails here.
    const lock = this.peerPub ? this.lock : lockFor(this.state, pub)
    if (this.peerPub && !same(pub, this.peerPub)) { s.badSig++; return null }
    if (!this.peerPub && this.peerNumber && !keyHasNumber(Uint8Array.from(pub), this.peerNumber)) { s.badSig++; return null }
    if (!same(e.outputs[0].locking, lock)) { s.badSig++; return null }
    const digest = dsha256(preimage({ entry: e, inputIndex: 0, scriptCode: lock, value: 0n }))
    if (!await verify(Uint8Array.from(pub), Uint8Array.from(sig), Uint8Array.from(digest))) { s.badSig++; return null }
    if (!this.peerPub) { this.peerPub = pub; this.lock = lock; this.tip = genesisId(this.state, pub) }

    const linked = same(inp.prevEntry, this.tip)
    if (!linked) { s.gaps++; s.missed += inp.sequence - this.seq - 1 }
    this.tip = dsha256(b)
    this.seq = inp.sequence
    s.verified++; s.bytes += b.length
    return { seq: inp.sequence, linked, payload: Uint8Array.from(payload) }
  }
}
