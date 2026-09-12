// © 2026 sun-dive.
//
// foen - a call as a covenant chain tip with no chain behind it.
//
// Each side signs every chunk it sends over the previous tip; the receiver verifies, plays, keeps only
// the new tip and drops the chunk. The relay holds one tip per direction and validates nothing.
//
// Entry layout (binary):
//   [0]       version = 1
//   [1..5)    seq, u32 big-endian
//   [5..37)   previous tip (32)
//   [37..69)  sha256 of the payload (32)
//   [69..102) sender's public key (33) - every entry verifies on its own; a tip-only relay may drop any
//   [102]     signature length L
//   [103..103+L) DER signature over sha256(genesis ‖ header[0..102))
//   [103+L..) payload
// tip = sha256(header[0..102)) · genesis = sha256("foen-call-v1" ‖ callId ‖ senderPub)

import { sha256 } from '@noble/hashes/sha2.js'
import { N } from './engine/secp256k1.mjs'
import { sign, verifyDigest, publicKey } from './engine/ecdsa.mjs'
import { concat, toHex, fromHex, fromUtf8, toBigBE, beBytes } from './engine/bytes.mjs'

const VERSION = 1
const HEADER = 102
const MAX_IN_FLIGHT = 8

export function newKey() {
  for (;;) {
    const d = toBigBE(crypto.getRandomValues(new Uint8Array(32)))
    if (d > 0n && d < N) return d
  }
}
export function loadKey() {
  let hex = null
  try { hex = localStorage.getItem('foen:key') } catch {}
  if (hex) return BigInt('0x' + hex)
  const d = newKey()
  try { localStorage.setItem('foen:key', d.toString(16).padStart(64, '0')) } catch {}
  return d
}
export const newCallId = () => toHex(crypto.getRandomValues(new Uint8Array(16)))
export const genesisOf = (callId, pub) => sha256(concat(fromUtf8('foen-call-v1'), fromHex(callId), pub))

const u32be = n => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255)
const readU32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0

/** The sending side of one direction: signs each chunk over the previous tip. */
export class Sender {
  constructor(d, callId) {
    this.d = d
    this.pub = publicKey(d)
    this.genesis = genesisOf(callId, this.pub)
    this.tip = this.genesis
    this.seq = 0
  }
  /** Build the next entry. */
  entry(payload) {
    const header = concat(Uint8Array.of(VERSION), u32be(this.seq), this.tip, sha256(payload), this.pub)
    const sig = sign(this.d, sha256(concat(this.genesis, header)), { lowS: true })
    const e = concat(header, Uint8Array.of(sig.length), sig, payload)
    this.tip = sha256(header)
    const seq = this.seq++
    return { seq, bytes: e }
  }
}

/** The receiving side of one direction: verifies each entry, tracks the tip, reports gaps. */
export class Receiver {
  constructor(callId, peerPub = null) {
    this.callId = callId
    this.peerPub = peerPub
    this.genesis = peerPub ? genesisOf(callId, peerPub) : null
    this.tip = this.genesis
    this.seq = -1
    this.stats = { received: 0, verified: 0, badSig: 0, badFormat: 0, stale: 0, gaps: 0, missed: 0, bytes: 0 }
  }
  /** Returns { seq, linked, payload } for a good entry, or null (and counts why). */
  accept(bytes) {
    const s = this.stats
    s.received++
    if (bytes.length < HEADER + 1 || bytes[0] !== VERSION) { s.badFormat++; return null }
    const seq = readU32be(bytes, 1)
    const prev = bytes.subarray(5, 37)
    const payloadHash = bytes.subarray(37, 69)
    const pub = bytes.subarray(69, 102)
    const L = bytes[102]
    if (bytes.length < HEADER + 1 + L) { s.badFormat++; return null }
    const sig = bytes.subarray(103, 103 + L)
    const payload = bytes.subarray(103 + L)
    if (toHex(sha256(payload)) !== toHex(payloadHash)) { s.badFormat++; return null }
    if (seq <= this.seq) { s.stale++; return null }
    const header = bytes.subarray(0, HEADER)

    // A call is between the two keys that speak on it: the first verified entry fixes the peer's key
    // for the call (or it must match the key the invitation named); every later entry must carry it.
    if (this.peerPub === null) {
      const g = genesisOf(this.callId, pub)
      if (!verifyDigest(sig, pub, sha256(concat(g, header)))) { s.badSig++; return null }
      this.peerPub = new Uint8Array(pub); this.genesis = g; this.tip = g
    } else {
      if (toHex(pub) !== toHex(this.peerPub)) { s.badSig++; return null }
      if (!verifyDigest(sig, this.peerPub, sha256(concat(this.genesis, header)))) { s.badSig++; return null }
    }

    const linked = toHex(prev) === toHex(this.tip)
    if (!linked) { s.gaps++; s.missed += seq - this.seq - 1 }
    this.tip = sha256(header)
    this.seq = seq
    s.verified++; s.bytes += bytes.length
    return { seq, linked, payload }
  }
}

/** Talks to relay.php for one call. `mine`/`theirs` are the two direction letters. */
export class Relay {
  constructor(url, callId, role) {
    this.url = url; this.callId = callId
    this.mine = role; this.theirs = role === 'a' ? 'b' : 'a'
    this.stats = { posts: 0, postFail: 0, polls: 0, pollEmpty: 0, pollFail: 0, inFlight: 0, maxInFlight: 0 }
  }
  /** Fire a post without waiting for it; the caller bounds how many are in flight. */
  postAsync(seq, bytes) {
    this.stats.inFlight++; this.stats.maxInFlight = Math.max(this.stats.maxInFlight, this.stats.inFlight)
    return this.post(seq, bytes).catch(() => null).finally(() => { this.stats.inFlight-- })
  }
  async post(seq, bytes) {
    this.stats.posts++
    const r = await fetch(`${this.url}?c=${this.callId}&d=${this.mine}&s=${seq}`, { method: 'POST', body: bytes, headers: { 'Content-Type': 'application/octet-stream' } })
    if (!r.ok) { this.stats.postFail++; throw new Error(`post ${r.status}`) }
    return r.json()
  }
  /** One long-poll. Returns { seq, entries } - every entry newer than `after` still in the relay's ring,
   *  oldest first - or null when nothing newer arrived in `wait` ms. */
  async poll(after, wait = 20000) {
    this.stats.polls++
    const r = await fetch(`${this.url}?c=${this.callId}&d=${this.theirs}&after=${after}&wait=${wait}`, { cache: 'no-store' })
    if (r.status === 204) { this.stats.pollEmpty++; return null }
    if (!r.ok) { this.stats.pollFail++; throw new Error(`poll ${r.status}`) }
    const seq = Number(r.headers.get('X-Seq'))
    const body = new Uint8Array(await r.arrayBuffer())
    const entries = []
    for (let o = 0; o + 4 <= body.length;) {
      const n = readU32be(body, o); o += 4
      if (o + n > body.length) break
      entries.push(body.subarray(o, o + n)); o += n
    }
    return { seq, entries }
  }
}

/**
 * The measurement: push signed dummy chunks at call rate through the relay, verify what comes back,
 * and report. Each payload starts with the highest peer seq seen so far, so the other side can measure
 * the ack round trip without shared clocks.
 */
export class Test {
  constructor({ relay, sender, receiver, chunkBytes = 16384, intervalMs = 100, seconds = 30, onUpdate = () => {} }) {
    Object.assign(this, { relay, sender, receiver, chunkBytes, intervalMs, seconds, onUpdate })
    this.sendTimes = new Map()
    this.rtts = []
    this.running = false
    this.peerSeqSeen = -1
    this.startedAt = 0
  }
  summary() {
    const r = this.receiver.stats, l = this.relay.stats
    const sorted = [...this.rtts].sort((a, b) => a - b)
    const q = p => sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))] : null
    const elapsed = this.startedAt ? (performance.now() - this.startedAt) / 1000 : 0
    return {
      elapsedS: Math.round(elapsed), sent: this.sender.seq, ...r, posts: l.posts, postFail: l.postFail,
      polls: l.polls, pollEmpty: l.pollEmpty, pollFail: l.pollFail, maxInFlight: l.maxInFlight,
      ackRttMs: { n: sorted.length, median: q(0.5), p90: q(0.9), max: sorted.at(-1) ?? null },
      kbps: elapsed > 0 ? Math.round(r.bytes * 8 / 1000 / elapsed) : 0,
    }
  }
  async run() {
    this.running = true
    this.startedAt = performance.now()
    const stopAt = this.startedAt + this.seconds * 1000

    const pollLoop = (async () => {
      let after = -1
      while (this.running) {
        try {
          const got = await this.relay.poll(after, 20000)
          if (!got) continue
          after = Math.max(after, got.seq)
          for (const bytes of got.entries) {
            const ok = this.receiver.accept(bytes)
            if (!ok) continue
            this.peerSeqSeen = ok.seq
            if (ok.payload.length >= 4) {
              const acked = readU32be(ok.payload, 0)
              const t = this.sendTimes.get(acked)
              if (t !== undefined) { this.rtts.push(performance.now() - t); this.sendTimes.delete(acked) }
            }
          }
          this.onUpdate(this.summary())
        } catch (e) { await new Promise(r => setTimeout(r, 250)) }
      }
    })()

    const sendLoop = (async () => {
      while (this.running && performance.now() < stopAt) {
        const payload = new Uint8Array(this.chunkBytes)
        payload.set(u32be(this.peerSeqSeen >>> 0), 0)
        crypto.getRandomValues(payload.subarray(4, Math.min(this.chunkBytes, 4 + 1024)))
        const e = this.sender.entry(payload)
        this.sendTimes.set(e.seq, performance.now())
        if (this.sendTimes.size > 200) this.sendTimes.delete(this.sendTimes.keys().next().value)
        // Pipelined: up to MAX_IN_FLIGHT posts on the wire at once; the cadence is the interval, not the RTT.
        while (this.relay.stats.inFlight >= MAX_IN_FLIGHT) await new Promise(r => setTimeout(r, 5))
        this.relay.postAsync(e.seq, e.bytes)
        this.onUpdate(this.summary())
        await new Promise(r => setTimeout(r, this.intervalMs))
      }
      // let the last acks arrive, then stop
      await new Promise(r => setTimeout(r, 2000))
      this.running = false
    })()

    await sendLoop
    await Promise.race([pollLoop, new Promise(r => setTimeout(r, 21000))])
    return this.summary()
  }
}

export { toHex, fromHex, beBytes }
