// © 2026 sun-dive.
//
// Call tones, synthesised: ported from SVphone (mvp/SVphone_v09_05/src/phone-ui.js). No files.
//   incoming   a mechanical bell, two strikes per cycle, every six seconds
//   outgoing   the standard 440 + 480 Hz ringback, two seconds on, four off
//   connecting a short 440 Hz pulse once a second
//   failed     three descending beeps
// Browsers refuse sound until the page has been touched once, so unlock() runs on the first click or
// tap; a page that has never been touched shows the banner and, on Android, vibrates instead.

let ctx = null
const timers = {}, playing = {}

export function unlock() {
  try { ctx ??= new AudioContext(); ctx.resume() } catch {}
}
const ready = () => { try { ctx ??= new AudioContext(); return ctx.resume().then(() => ctx) } catch { return Promise.reject() } }

function bellStrike(c, t) {
  const partials = [[550, 0.40], [554, 0.30], [1100, 0.20], [1654, 0.12], [2750, 0.06]]
  const master = c.createGain()
  master.gain.setValueAtTime(0.7, t); master.gain.exponentialRampToValueAtTime(0.001, t + 0.8)
  master.connect(c.destination)
  for (const [freq, vol] of partials) {
    const o = c.createOscillator(), g = c.createGain()
    g.gain.value = vol; o.type = 'sine'; o.frequency.value = freq
    o.connect(g); g.connect(master); o.start(t); o.stop(t + 0.85)
  }
}
function cycle(key) {
  if (!playing[key]) return
  const now = ctx.currentTime
  if (key === 'incoming') { bellStrike(ctx, now); bellStrike(ctx, now + 0.7) }
  else {
    const g = ctx.createGain(); g.gain.value = 0.25; g.connect(ctx.destination)
    for (const f of [440, 480]) { const o = ctx.createOscillator(); o.frequency.value = f; o.connect(g); o.start(now); o.stop(now + 2) }
  }
  timers[key] = setTimeout(() => cycle(key), 6000)
}
/** Start the incoming bell or the outgoing ringback; harmless if already ringing. */
export function ring(key) {
  if (playing[key]) return
  ready().then(() => { if (playing[key]) return; playing[key] = true; cycle(key) }).catch(() => {})
}
export function stop(key) {
  playing[key] = false
  if (timers[key]) { clearTimeout(timers[key]); timers[key] = null }
}
export function stopAll() { for (const k of ['incoming', 'outgoing', 'connecting']) stop(k) }

export function connecting() {
  if (playing.connecting) return
  ready().then(() => {
    playing.connecting = true
    const pulse = () => {
      if (!playing.connecting) return
      const g = ctx.createGain(); g.gain.value = 0.15; g.connect(ctx.destination)
      const o = ctx.createOscillator(); o.frequency.value = 440; o.connect(g); o.start(ctx.currentTime); o.stop(ctx.currentTime + 0.15)
      timers.connecting = setTimeout(pulse, 1000)
    }
    pulse()
  }).catch(() => {})
}
export function failed() {
  ready().then(() => {
    const now = ctx.currentTime
    ;[480, 400, 320].forEach((f, i) => {
      const g = ctx.createGain(); g.gain.value = 0.25; g.connect(ctx.destination)
      const o = ctx.createOscillator(); o.frequency.value = f; o.connect(g); o.start(now + i * 0.25); o.stop(now + i * 0.25 + 0.2)
    })
  }).catch(() => {})
}
export const isRinging = key => !!playing[key]
