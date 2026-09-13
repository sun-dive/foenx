// © 2026 sun-dive.
//
// A call: camera and microphone in, signed ticks out, the other side's ticks decoded and played.
//
// A TICK is one entry per 100 ms. Its payload:
//   [0..4)  ack: the highest peer seq seen (u32 BE), for round-trip measurement without shared clocks
//   then records, each  [type u8][timestamp ms u32 BE][length u32 BE][data]
//   type 1 = video key frame · 2 = video delta frame · 3 = audio packet · 4 = bye (the sender is hanging up)
// Video is VP8, audio is Opus, both from WebCodecs. A key frame every KEY_EVERY ticks, so a late joiner
// or a lost tick recovers inside the relay's ring.

import { Sender, Receiver, Relay } from './foen.mjs'

const TICK_MS = 100
const KEY_EVERY = 10          // a key frame every second: skipping ahead costs at most that
const VIDEO = { width: 320, height: 240, fps: 10, bitrate: 250_000 }
const AUDIO_BITRATE = 24_000
const JITTER_S = 0.15
const MAX_LAG_S = 0.25         // audio queued beyond jitter + this is dropped rather than played late
const START_BEHIND = 2         // on join, take at most this many of the ring's newest ticks
const SILENCE_S = 10           // nothing verified from the other side for this long: they are gone
const MAX_IN_FLIGHT = 8

const u32be = n => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255)
const readU32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0

export const supported = () =>
  typeof VideoEncoder !== 'undefined' && typeof VideoDecoder !== 'undefined' && typeof MediaStreamTrackProcessor !== 'undefined'

/** Packs records into one tick payload. */
function packTick(ack, records) {
  let n = 4
  for (const r of records) n += 9 + r.data.length
  const out = new Uint8Array(n)
  out.set(u32be(ack >>> 0), 0)
  let o = 4
  for (const r of records) {
    out[o] = r.type; out.set(u32be(r.ts), o + 1); out.set(u32be(r.data.length), o + 5); out.set(r.data, o + 9)
    o += 9 + r.data.length
  }
  return out
}
function unpackTick(p) {
  if (p.length < 4) return null
  const ack = readU32be(p, 0)
  const records = []
  for (let o = 4; o + 9 <= p.length;) {
    const type = p[o], ts = readU32be(p, o + 1), n = readU32be(p, o + 5)
    if (o + 9 + n > p.length) break
    records.push({ type, ts, data: p.subarray(o + 9, o + 9 + n) }); o += 9 + n
  }
  return { ack, records }
}

export class Call {
  /**
   * @param {object} o  { d, callId, role, relayUrl, peerPub, localVideo (<video>), remoteCanvas (<canvas>),
   *                      stream (bool: streaming receive), onUpdate(stats) }
   */
  constructor(o) {
    Object.assign(this, o)
    this.relay = new Relay(o.relayUrl, o.callId, o.role)
    this.sender = new Sender(o.d, o.callId)
    this.receiver = new Receiver(o.callId, o.peerPub ?? null)
    this.stats = { framesIn: 0, framesEncoded: 0, audioEncoded: 0, ticksSent: 0, ticksGot: 0, framesDecoded: 0, audioDecoded: 0,
                   keyWaits: 0, decodeErrors: 0, videoBytes: 0, audioBytes: 0, startedAt: 0, rtts: [], audioDropped: 0, audioLagMs: 0, videoSkipped: 0, drawWaits: [] }
    this.arrivals = new Map()
    this.pendingVideo = null
    this.pendingAudio = []
    this.peerSeqSeen = -1
    this.sendTimes = new Map()
    this.running = false
    this.haveKey = false
  }

  summary() {
    const s = this.stats, r = this.receiver.stats, l = this.relay.stats
    const sorted = [...s.rtts].sort((a, b) => a - b)
    const q = p => sorted.length ? Math.round(sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]) : null
    const el = s.startedAt ? (performance.now() - s.startedAt) / 1000 : 0
    return {
      elapsedS: Math.round(el), ticksSent: s.ticksSent, ticksGot: s.ticksGot, framesEncoded: s.framesEncoded, framesDecoded: s.framesDecoded,
      audioEncoded: s.audioEncoded, audioDecoded: s.audioDecoded, keyWaits: s.keyWaits, decodeErrors: s.decodeErrors,
      audioDropped: s.audioDropped, audioLagMs: s.audioLagMs, videoSkipped: s.videoSkipped, decodeQueue: this.vDec?.decodeQueueSize ?? 0,
      drawWaitMs: s.drawWaits.length ? Math.round([...s.drawWaits].sort((a, b) => a - b)[Math.floor(s.drawWaits.length / 2)]) : null,
      verified: r.verified, badSig: r.badSig, badFormat: r.badFormat, stale: r.stale, gaps: r.gaps, missed: r.missed,
      posts: l.posts, postFail: l.postFail, polls: l.polls, pollFail: l.pollFail, maxInFlight: l.maxInFlight,
      rtt: { n: sorted.length, median: q(0.5), p90: q(0.9), max: sorted.length ? Math.round(sorted.at(-1)) : null },
      sendKbps: el > 0 ? Math.round((s.videoBytes + s.audioBytes) * 8 / 1000 / el) : 0,
      recvKbps: el > 0 ? Math.round(r.bytes * 8 / 1000 / el) : 0,
    }
  }

  async start() {
    if (!supported()) throw new Error('this browser has no WebCodecs (Chrome, Edge or Android Chrome do)')
    this.running = true
    this.stats.startedAt = performance.now()
    // Take what the device has: camera and microphone, or either alone, or neither (watch and listen only).
    const video = { width: { ideal: VIDEO.width }, height: { ideal: VIDEO.height }, frameRate: { ideal: VIDEO.fps } }
    const audio = { channelCount: 1, echoCancellation: true, noiseSuppression: true }
    this.media = null; this.have = { video: false, audio: false }
    for (const c of [{ video, audio }, { audio }, { video }]) {
      try { this.media = await navigator.mediaDevices.getUserMedia(c); break } catch (e) { this.mediaError = e.name + ': ' + e.message }
    }
    if (this.media) {
      this.have.video = this.media.getVideoTracks().length > 0
      this.have.audio = this.media.getAudioTracks().length > 0
      if (this.localVideo && this.have.video) { this.localVideo.srcObject = this.media; this.localVideo.muted = true; this.localVideo.play().catch(() => {}) }
    }
    this.audioCtx = new AudioContext({ sampleRate: 48000 })
    this.playhead = 0
    if (this.have.video) this.startVideoOut()
    if (this.have.audio) this.startAudioOut().catch(e => { this.audioError = String(e) })
    this.startDecoders()
    this.tickLoop()
    this.receiveLoop()
  }

  /** Hang up: tell the other side, then stop. */
  stop(reason = 'hung up') {
    if (!this.running) return
    try { const e = this.sender.entry(packTick(this.peerSeqSeen, [{ type: 4, ts: 0, data: new Uint8Array(0) }])); this.relay.postAsync(e.seq, e.bytes) } catch {}
    this.endReason = reason
    this.running = false
    try { this.media?.getTracks().forEach(t => t.stop()) } catch {}
    try { this.vEnc?.close(); this.aEnc?.close(); this.vDec?.close(); this.aDec?.close() } catch {}
    try { this.audioCtx?.close() } catch {}
  }

  // ── outbound ──
  startVideoOut() {
    const track = this.media.getVideoTracks()[0]
    const settings = track.getSettings()
    const width = settings.width || VIDEO.width, height = settings.height || VIDEO.height
    this.vEnc = new VideoEncoder({
      output: chunk => {
        const data = new Uint8Array(chunk.byteLength); chunk.copyTo(data)
        this.pendingVideo = { type: chunk.type === 'key' ? 1 : 2, ts: Math.round(chunk.timestamp / 1000) >>> 0, data }
        this.stats.framesEncoded++
      },
      error: e => { this.videoError = String(e) },
    })
    this.vEnc.configure({ codec: 'vp8', width, height, bitrate: VIDEO.bitrate, framerate: VIDEO.fps, latencyMode: 'realtime' })
    const reader = new MediaStreamTrackProcessor({ track }).readable.getReader()
    let n = 0, last = 0
    const pump = async () => {
      while (this.running) {
        const { value: frame, done } = await reader.read()
        if (done) break
        this.stats.framesIn++
        const now = performance.now()
        if (now - last >= 1000 / VIDEO.fps - 5 && this.vEnc.encodeQueueSize < 2) {
          last = now
          this.vEnc.encode(frame, { keyFrame: n % KEY_EVERY === 0 }); n++
        }
        frame.close()
      }
    }
    pump().catch(e => { this.videoError = String(e) })
  }

  async startAudioOut() {
    const track = this.media.getAudioTracks()[0]
    if (!track || typeof AudioEncoder === 'undefined') return
    const reader = new MediaStreamTrackProcessor({ track }).readable.getReader()
    const first = await reader.read()
    if (first.done) return
    const { sampleRate, numberOfChannels } = first.value
    this.aEnc = new AudioEncoder({
      output: chunk => {
        const data = new Uint8Array(chunk.byteLength); chunk.copyTo(data)
        this.pendingAudio.push({ type: 3, ts: Math.round(chunk.timestamp / 1000) >>> 0, data })
        this.stats.audioEncoded++
      },
      error: e => { this.audioError = String(e) },
    })
    this.aEnc.configure({ codec: 'opus', sampleRate, numberOfChannels, bitrate: AUDIO_BITRATE })
    this.audioFormat = { sampleRate, numberOfChannels }
    this.aEnc.encode(first.value); first.value.close()
    while (this.running) {
      const { value, done } = await reader.read()
      if (done) break
      if (this.aEnc.encodeQueueSize < 4) this.aEnc.encode(value)
      value.close()
    }
  }

  tickLoop() {
    const loop = async () => {
      while (this.running) {
        const records = []
        if (this.pendingVideo) { records.push(this.pendingVideo); this.stats.videoBytes += this.pendingVideo.data.length; this.pendingVideo = null }
        if (this.pendingAudio.length) { for (const a of this.pendingAudio) { records.push(a); this.stats.audioBytes += a.data.length }; this.pendingAudio = [] }
        if (records.length) {
          const e = this.sender.entry(packTick(this.peerSeqSeen, records))
          this.sendTimes.set(e.seq, performance.now())
          if (this.sendTimes.size > 200) this.sendTimes.delete(this.sendTimes.keys().next().value)
          while (this.relay.stats.inFlight >= MAX_IN_FLIGHT && this.running) await new Promise(r => setTimeout(r, 5))
          this.relay.postAsync(e.seq, e.bytes)
          this.stats.ticksSent++
        }
        this.onUpdate?.(this.summary())
        if (this.lastHeard && performance.now() - this.lastHeard > SILENCE_S * 1000) { this.stop('the other side stopped answering'); this.onEnded?.(this.endReason); break }
        await new Promise(r => setTimeout(r, TICK_MS))
      }
    }
    loop()
  }

  // ── inbound ──
  startDecoders() {
    const canvas = this.remoteCanvas, ctx = canvas?.getContext('2d')
    this.vDec = new VideoDecoder({
      output: frame => {
        this.stats.framesDecoded++
        const t = this.arrivals.get(frame.timestamp)
        if (t !== undefined) { this.stats.drawWaits.push(performance.now() - t); this.arrivals.delete(frame.timestamp); if (this.stats.drawWaits.length > 300) this.stats.drawWaits.shift() }
        if (ctx) {
          if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) { canvas.width = frame.displayWidth; canvas.height = frame.displayHeight }
          ctx.drawImage(frame, 0, 0)
        }
        frame.close()
      },
      error: e => { this.stats.decodeErrors++; this.haveKey = false; try { this.vDec.reset(); this.vDec.configure({ codec: 'vp8' }) } catch {} },
    })
    this.vDec.configure({ codec: 'vp8' })
  }
  ensureAudioDecoder(sampleRate = 48000, numberOfChannels = 1) {
    if (this.aDec || typeof AudioDecoder === 'undefined') return
    this.aDec = new AudioDecoder({
      output: data => {
        this.stats.audioDecoded++
        try {
          const ch = data.numberOfChannels, frames = data.numberOfFrames
          const buf = this.audioCtx.createBuffer(ch, frames, data.sampleRate)
          for (let c = 0; c < ch; c++) { const f32 = new Float32Array(frames); data.copyTo(f32, { planeIndex: c, format: 'f32-planar' }); buf.copyToChannel(f32, c) }
          const now = this.audioCtx.currentTime
          // Bounded jitter buffer: fall behind by more than the budget and the backlog is dropped, never queued.
          if (this.playhead < now + 0.02) this.playhead = now + JITTER_S
          if (this.playhead - now > JITTER_S + MAX_LAG_S) { this.stats.audioDropped++; data.close(); return }
          const src = this.audioCtx.createBufferSource(); src.buffer = buf; src.connect(this.audioCtx.destination)
          src.start(this.playhead); this.playhead += buf.duration
          this.stats.audioLagMs = Math.round((this.playhead - now) * 1000)
        } catch {}
        data.close()
      },
      error: () => { this.stats.decodeErrors++ },
    })
    this.aDec.configure({ codec: 'opus', sampleRate, numberOfChannels })
  }
  takeTick(payload, seq) {
    const t = unpackTick(payload)
    if (!t) return
    this.stats.ticksGot++
    this.lastHeard = performance.now()
    if (t.records.some(r => r.type === 4)) { this.stop('the other side hung up'); this.onEnded?.(this.endReason); return }
    const st = this.sendTimes.get(t.ack)
    if (st !== undefined) { this.stats.rtts.push(performance.now() - st); this.sendTimes.delete(t.ack) }
    for (const r of t.records) {
      if (r.type === 1 || r.type === 2) {
        if (r.type === 1) this.haveKey = true
        if (!this.haveKey) { this.stats.keyWaits++; continue }
        if (this.vDec.decodeQueueSize > 3 && r.type === 2) { this.stats.videoSkipped++; this.haveKey = false; continue }
        this.arrivals.set(r.ts * 1000, performance.now()); if (this.arrivals.size > 100) this.arrivals.delete(this.arrivals.keys().next().value)
        try { this.vDec.decode(new EncodedVideoChunk({ type: r.type === 1 ? 'key' : 'delta', timestamp: r.ts * 1000, data: r.data })) }
        catch { this.stats.decodeErrors++; this.haveKey = false }
      } else if (r.type === 3) {
        this.ensureAudioDecoder()
        try { this.aDec?.decode(new EncodedAudioChunk({ type: 'key', timestamp: r.ts * 1000, data: r.data })) } catch { this.stats.decodeErrors++ }
      }
    }
  }
  receiveLoop() {
    const take = bytes => {
      const ok = this.receiver.accept(bytes)
      if (!ok) return
      this.peerSeqSeen = ok.seq
      this.takeTick(ok.payload, ok.seq)
    }
    const loop = async () => {
      let after = -1
      // Join at the newest tick: a probe with no wait shows how far the other side has got, and we start
      // START_BEHIND ticks before it rather than swallowing the whole ring as a backlog.
      try { const probe = await this.relay.poll(-1, 0); if (probe) after = Math.max(-1, probe.seq - START_BEHIND) } catch {}
      while (this.running) {
        try {
          if (this.stream) {
            await this.relay.stream(after, 20000, bytes => { take(bytes); after = Math.max(after, this.receiver.seq) })
          } else {
            const got = await this.relay.poll(after, 20000)
            if (!got) continue
            after = Math.max(after, got.seq)
            for (const bytes of got.entries) take(bytes)
          }
        } catch { await new Promise(r => setTimeout(r, 250)) }
      }
    }
    loop()
  }
}
