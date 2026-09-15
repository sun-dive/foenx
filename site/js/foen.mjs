// © 2026 sun-dive.
//
// foen - a call as a covenant chain tip with no chain behind it.
//
// Each side signs every chunk it sends over the previous tip; the receiver verifies, plays, keeps only
// the new tip and drops the chunk. The relay holds a short ring per direction and validates nothing.
// The entry is a jetmora covenant entry (thread.mjs); the key is the wallet in key.mjs.

import { toHex, fromHex, beBytes } from './engine/bytes.mjs'

const MAX_IN_FLIGHT = 8

export const newCallId = () => toHex(crypto.getRandomValues(new Uint8Array(16)))

const u32be = n => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255)
const readU32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0

// The entry format is jetmora's: see thread.mjs. Sender and Receiver are re-exported from there.
export { Sender, Receiver } from './thread.mjs'

/** Talks to relay.php for one call. `mine`/`theirs` are the two direction letters. */
export class Relay {
  constructor(url, callId, role) {
    this.url = url; this.callId = callId
    this.mine = role; this.theirs = role === 'a' ? 'b' : 'a'
    this.stats = { posts: 0, postFail: 0, polls: 0, pollEmpty: 0, pollFail: 0, streams: 0, inFlight: 0, maxInFlight: 0 }
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
  /** Streaming receive: one connection the relay keeps open for `wait` ms, calling onEntry(bytes) for
   *  each framed entry as it arrives. Resolves when the relay closes it; the caller reconnects. */
  async stream(after, wait, onEntry) {
    this.stats.streams++
    const r = await fetch(`${this.url}?c=${this.callId}&d=${this.theirs}&after=${after}&wait=${wait}&stream=1`, { cache: 'no-store' })
    if (!r.ok || !r.body) { this.stats.pollFail++; throw new Error(`stream ${r.status}`) }
    const reader = r.body.getReader()
    let buf = new Uint8Array(0)
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      const nb = new Uint8Array(buf.length + value.length); nb.set(buf); nb.set(value, buf.length); buf = nb
      let o = 0
      while (o + 4 <= buf.length) {
        const n = readU32be(buf, o)
        if (o + 4 + n > buf.length) break
        onEntry(buf.subarray(o + 4, o + 4 + n)); o += 4 + n
      }
      buf = buf.subarray(o)
    }
  }
}

/**
 * The measurement: push signed dummy chunks at call rate through the relay, verify what comes back,
 * and report. Each payload starts with the highest peer seq seen so far, so the other side can measure
 * the ack round trip without shared clocks.
 */
export class Test {
  constructor({ relay, sender, receiver, chunkBytes = 16384, intervalMs = 100, seconds = 30, stream = true, onUpdate = () => {} }) {
    Object.assign(this, { relay, sender, receiver, chunkBytes, intervalMs, seconds, stream, onUpdate })
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
      elapsedS: Math.round(elapsed), sent: this.sender.seq - 1, ...r, posts: l.posts, postFail: l.postFail,
      polls: l.polls, pollEmpty: l.pollEmpty, pollFail: l.pollFail, streams: l.streams, maxInFlight: l.maxInFlight, mode: this.stream ? 'stream' : 'poll',
      ackRttMs: { n: sorted.length, median: q(0.5), p90: q(0.9), max: sorted.at(-1) ?? null },
      kbps: elapsed > 0 ? Math.round(r.bytes * 8 / 1000 / elapsed) : 0,
    }
  }
  async run() {
    this.running = true
    this.startedAt = performance.now()
    const stopAt = this.startedAt + this.seconds * 1000

    const take = async bytes => {
      const ok = await this.receiver.accept(bytes)
      if (!ok) return
      this.peerSeqSeen = ok.seq
      if (ok.payload.length >= 4) {
        const acked = readU32be(ok.payload, 0)
        const t = this.sendTimes.get(acked)
        if (t !== undefined) { this.rtts.push(performance.now() - t); this.sendTimes.delete(acked) }
      }
    }
    const pollLoop = (async () => {
      let after = -1
      while (this.running) {
        try {
          if (this.stream) {
            let chain = Promise.resolve()
            await this.relay.stream(after, 20000, bytes => { chain = chain.then(() => take(bytes)).then(() => { after = Math.max(after, this.receiver.seq); this.onUpdate(this.summary()) }) })
            await chain
          } else {
            const got = await this.relay.poll(after, 20000)
            if (!got) continue
            after = Math.max(after, got.seq)
            for (const bytes of got.entries) await take(bytes)
            this.onUpdate(this.summary())
          }
        } catch (e) { await new Promise(r => setTimeout(r, 250)) }
      }
    })()

    const sendLoop = (async () => {
      while (this.running && performance.now() < stopAt) {
        const payload = new Uint8Array(this.chunkBytes)
        payload.set(u32be(this.peerSeqSeen >>> 0), 0)
        crypto.getRandomValues(payload.subarray(4, Math.min(this.chunkBytes, 4 + 1024)))
        const e = await this.sender.entry(payload)
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
