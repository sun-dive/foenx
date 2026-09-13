// © 2026 sun-dive.
//
// A foen thread IS a jetmora covenant thread: "a tip, ticked forward, only valid links".
//
// Every tick is a jetmora ENTRY (spec §3: an entry is a transaction), built exactly as
// jetmora/server/wallet/jetmora/thread.php builds one:
//   input 0   spends the tip: prevEntry = the previous entry's hash (the genesis id for the first tick),
//             index 0, sequence = the tick index, unlocking = <sig‖0x01> <pub>
//   output 0  the successor tip, locked to the same key:  <state> OP_DROP OP_DUP OP_HASH160 <h160(pub)> OP_EQUALVERIFY OP_CHECKSIG
//   output 1  the tick's payload:  OP_FALSE OP_RETURN <payload>
//   version   family SV revision 1 · locktime 0 · value 0 (§3: an application quantity, MAY be zero)
// The covenant signature is over SHA256d of the BIP143-layout preimage of input 0 against the previous
// tip's locking script (spec §3, sighash 0x01, no FORKID). The state carried in the lock is the call id,
// so a tick from another call fails the lock check even when signed by the same key.
//
// The genesis is native and derived (§2): SHA256d( LP(source_hash) ‖ LP(script) ‖ LP(state) ‖ LP(authorised) ),
// with authorised = 0x02 ‖ k ‖ n ‖ (32 ‖ sha256(pub)) — hashes, never keys in the clear (his rule, 7 Sept).

import { sha256 } from './jetmora/sha256.mjs'
import { serializeEntry, parseEntry, varint } from './jetmora/entry.mjs'
import { preimage } from './jetmora/preimage.mjs'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { sign, verifyDigest, publicKey } from './engine/ecdsa.mjs'
import { toHex, fromHex } from './engine/bytes.mjs'

export const VERSION_SV1 = ((0x56 << 24) | (0x53 << 16) | 1) >>> 0      // family 'SV', revision 1
const SOURCE_HASH = sha256([...new TextEncoder().encode('foen thread v1: <state> DROP then P2PKH, one data output per tick')])
const OP = { FALSE: 0x00, RETURN: 0x6a, DROP: 0x75, DUP: 0x76, HASH160: 0xa9, EQUALVERIFY: 0x88, CHECKSIG: 0xac, PUSHDATA1: 0x4c, PUSHDATA2: 0x4d, PUSHDATA4: 0x4e }

const dsha256 = b => sha256(sha256(b))
const hash160 = pub => [...ripemd160(Uint8Array.from(sha256([...pub])))]
const lp = b => [(b.length >>> 24) & 255, (b.length >>> 16) & 255, (b.length >>> 8) & 255, b.length & 255, ...b]
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

/** Minimal push of `data` (Bitcoin script encoding). */
export function push(data) {
  const n = data.length
  if (n === 0) return [OP.FALSE]
  if (n <= 75) return [n, ...data]
  if (n <= 0xff) return [OP.PUSHDATA1, n, ...data]
  if (n <= 0xffff) return [OP.PUSHDATA2, n & 255, n >> 8, ...data]
  return [OP.PUSHDATA4, n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255, ...data]
}
/** Read the pushes of a script; null if it is not purely pushes. */
export function pushes(script) {
  const out = []
  for (let p = 0; p < script.length;) {
    const op = script[p++]; let n
    if (op === OP.FALSE) { out.push([]); continue }
    if (op <= 75) n = op
    else if (op === OP.PUSHDATA1) { n = script[p]; p += 1 }
    else if (op === OP.PUSHDATA2) { n = script[p] | (script[p + 1] << 8); p += 2 }
    else if (op === OP.PUSHDATA4) { n = (script[p] | (script[p + 1] << 8) | (script[p + 2] << 16) | (script[p + 3] << 24)) >>> 0; p += 4 }
    else return null
    if (p + n > script.length) return null
    out.push(script.slice(p, p + n)); p += n
  }
  return out
}

/** The tip's locking script for a key in a given call: <state> OP_DROP OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG */
export const lockFor = (state, pub) => [...push(state), OP.DROP, OP.DUP, OP.HASH160, ...push(hash160(pub)), OP.EQUALVERIFY, OP.CHECKSIG]
export const dataOutput = payload => [OP.FALSE, OP.RETURN, ...push([...payload])]
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
  constructor(d, callId) {
    this.d = d
    this.pub = [...publicKey(d)]
    this.state = [...fromHex(callId)]
    this.lock = lockFor(this.state, this.pub)
    this.genesis = genesisId(this.state, this.pub)
    this.tip = this.genesis
    this.seq = 1
  }
  /** Tick: spend the tip, produce the successor and the payload. Returns { seq, bytes } (bytes: Uint8Array). */
  entry(payload) {
    const seq = this.seq++
    const skeleton = { version: VERSION_SV1, inputs: [{ prevEntry: this.tip, index: 0, unlocking: [], sequence: seq }],
                       outputs: [{ value: 0n, locking: this.lock }, { value: 0n, locking: dataOutput(payload) }], locktime: 0 }
    const pre = preimage({ entry: skeleton, inputIndex: 0, scriptCode: this.lock, value: 0n })
    const sig = [...sign(this.d, Uint8Array.from(dsha256(pre)), { lowS: true }), 0x01]
    const entry = { ...skeleton, inputs: [{ ...skeleton.inputs[0], unlocking: [...push(sig), ...push(this.pub)] }] }
    const bytes = serializeEntry(entry)
    this.tip = dsha256(bytes)
    return { seq, bytes: Uint8Array.from(bytes) }
  }
}

/** The other direction: verifies each tick on its own, tracks the tip, reports gaps. */
export class Receiver {
  constructor(callId, peerPub = null) {
    this.state = [...fromHex(callId)]
    this.peerPub = peerPub ? [...peerPub] : null
    this.lock = this.peerPub ? lockFor(this.state, this.peerPub) : null
    this.tip = this.peerPub ? genesisId(this.state, this.peerPub) : null
    this.seq = 0
    this.stats = { received: 0, verified: 0, badSig: 0, badFormat: 0, stale: 0, gaps: 0, missed: 0, bytes: 0 }
  }
  /** Returns { seq, linked, payload } for a good tick, or null (and counts why). */
  accept(bytes) {
    const s = this.stats
    s.received++
    const b = [...bytes]
    let e
    try { e = parseEntry(b) } catch { s.badFormat++; return null }
    if (e.version !== VERSION_SV1 || e.inputs.length !== 1 || e.outputs.length < 2 || e.locktime !== 0) { s.badFormat++; return null }
    const inp = e.inputs[0]
    const ul = pushes(inp.unlocking)
    if (!ul || ul.length !== 2 || ul[1].length !== 33 || ul[0].length < 9 || ul[0][ul[0].length - 1] !== 0x01) { s.badFormat++; return null }
    const sig = ul[0].slice(0, -1), pub = ul[1]
    const data = e.outputs[1].locking
    if (data[0] !== OP.FALSE || data[1] !== OP.RETURN) { s.badFormat++; return null }
    const dp = pushes(data.slice(2))
    if (!dp || dp.length !== 1) { s.badFormat++; return null }
    if (inp.sequence <= this.seq) { s.stale++; return null }

    // A call is between the two keys that speak on it: the first verified tick fixes the peer's key
    // (or it must match the key the invitation named). The lock carries the call id, so a tick signed
    // by this key for another call fails here.
    const lock = this.peerPub ? this.lock : lockFor(this.state, pub)
    if (this.peerPub && !same(pub, this.peerPub)) { s.badSig++; return null }
    if (!same(e.outputs[0].locking, lock)) { s.badSig++; return null }
    const digest = dsha256(preimage({ entry: e, inputIndex: 0, scriptCode: lock, value: 0n }))
    if (!verifyDigest(Uint8Array.from(sig), Uint8Array.from(pub), Uint8Array.from(digest))) { s.badSig++; return null }
    if (!this.peerPub) { this.peerPub = pub; this.lock = lock; this.tip = genesisId(this.state, pub) }

    const linked = same(inp.prevEntry, this.tip)
    if (!linked) { s.gaps++; s.missed += inp.sequence - this.seq - 1 }
    this.tip = dsha256(b)
    this.seq = inp.sequence
    s.verified++; s.bytes += b.length
    return { seq: inp.sequence, linked, payload: Uint8Array.from(dp[0]) }
  }
}
