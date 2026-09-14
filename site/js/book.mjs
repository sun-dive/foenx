// © 2026 sun-dive.
//
// The phone book and the inbox.
//   listing  = a signed entry (foen.mjs format) with payload JSON {name, pub}, on a fixed "book" call id
//   inbox    = a relay call whose id is derived from the callee's key; invites are signed entries on its
//              direction 'a' with payload JSON {t:'invite', call, from}
// The host stores and lists blobs; every page verifies the signatures itself.

import { sha256 } from '@noble/hashes/sha2.js'
import { Sender, Receiver, Relay, toHex, fromHex } from './foen.mjs'
import { concat, fromUtf8 } from './engine/bytes.mjs'

const enc = new TextEncoder(), dec = new TextDecoder()
const idOf = (label, extra = new Uint8Array(0)) => toHex(sha256(concat(fromUtf8(label), extra)).subarray(0, 16))
export const BOOK_ID = idOf('foen-book-v1')
export const inboxOf = pub => idOf('foen-inbox-v1', pub)
const STALE_S = 45   // longer than the page rings for (30 s), so a page opened while it rings still rings

const readU32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0
function frames(body) {
  const out = []
  for (let o = 0; o + 4 <= body.length;) { const n = readU32be(body, o); o += 4; if (o + n > body.length) break; out.push(body.subarray(o, o + n)); o += n }
  return out
}
/** Verify one signed entry on its own: returns { pub, payload, seq } or null. */
function verifyAlone(callId, bytes) {
  const r = new Receiver(callId)
  const ok = r.accept(bytes)
  return ok ? { pub: r.peerPub, payload: ok.payload, seq: ok.seq } : null
}

export class Book {
  constructor(baseUrl, d, bookName = '') { this.url = new URL('book.php' + (bookName ? '?b=' + encodeURIComponent(bookName) : ''), baseUrl).href; this.d = d }
  /** List yourself under a name. The signed listing carries the key it is signed with. */
  async register(name, pub) {
    const s = new Sender(this.d, BOOK_ID)
    s.seq = Math.floor(Date.now() / 1000)   // newer listings win on the reader side
    const e = s.entry(enc.encode(JSON.stringify({ name: String(name).slice(0, 40), pub: toHex(pub) })))
    const r = await fetch(this.url, { method: 'POST', body: e.bytes, headers: { 'Content-Type': 'application/octet-stream' } })
    if (!r.ok) throw new Error(`book ${r.status}`)
  }
  /** Every listing whose signature verifies and whose payload names the signing key. */
  async list() {
    const r = await fetch(this.url, { cache: 'no-store' })
    if (!r.ok) throw new Error(`book ${r.status}`)
    const out = []
    for (const bytes of frames(new Uint8Array(await r.arrayBuffer()))) {
      const v = verifyAlone(BOOK_ID, bytes)
      if (!v) continue
      let p; try { p = JSON.parse(dec.decode(v.payload)) } catch { continue }
      if (typeof p.name !== 'string' || p.pub !== toHex(v.pub)) continue
      out.push({ name: p.name, pub: v.pub, pubHex: p.pub })
    }
    return out
  }
}

export class Inbox {
  /** Watch my inbox for invites; onInvite({ callId, from, pub }) for each verified one. */
  constructor(baseUrl, myPub) {
    this.relay = new Relay(new URL('relay.php', baseUrl).href, inboxOf(myPub), 'b')   // I read direction 'a'
    this.running = false
  }
  start(onInvite) {
    this.running = true
    const loop = async () => {
      let after = -1
      while (this.running) {
        try {
          const got = await this.relay.poll(after, 20000)
          if (!got) continue
          after = Math.max(after, got.seq)
          for (const bytes of got.entries) {
            const v = verifyAlone(this.relay.callId, bytes)
            if (!v) continue
            let p; try { p = JSON.parse(dec.decode(v.payload)) } catch { continue }
            // An invite's seq is the second it was sent. The ring replays on every page load, so anything
            // older than a ring's length is a call that has already been missed, not a new one.
            if (Math.floor(Date.now() / 1000) - v.seq > STALE_S) continue
            if ((p.t === 'invite' || p.t === 'cancel') && /^[0-9a-f]{32}$/.test(p.call)) onInvite({ t: p.t, callId: p.call, from: String(p.from ?? '').slice(0, 40), pub: v.pub, seq: v.seq })
          }
        } catch { await new Promise(r => setTimeout(r, 500)) }
      }
    }
    loop()
  }
  stop() { this.running = false }
}

/** Drop a signed invite (or a cancel of one) into someone's inbox. Returns the call id. */
export async function invite(baseUrl, d, myName, theirPub, callId, t = 'invite') {
  const inboxId = inboxOf(theirPub)
  const s = new Sender(d, inboxId)
  s.seq = Math.floor(Date.now() / 1000) + (t === 'cancel' ? 1 : 0)   // a cancel in the same second still sorts after
  const e = s.entry(enc.encode(JSON.stringify({ t, call: callId, from: String(myName).slice(0, 40) })))
  const relay = new Relay(new URL('relay.php', baseUrl).href, inboxId, 'a')
  await relay.post(e.seq, e.bytes)
  return callId
}

export { fromHex }
