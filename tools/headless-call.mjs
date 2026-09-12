// A real call between two headless Chromium profiles with synthetic camera and microphone, through one
// relay. Prints what each side encoded, sent, verified and decoded.
//   node tools/headless-call.mjs http://127.0.0.1:8088/ 30 [stream 0|1]
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [base = 'http://127.0.0.1:8088/', seconds = '30', stream = '0'] = process.argv.slice(2)
const CHROME = process.env.CHROME || 'chromium'

async function launch(port) {
  const dir = mkdtempSync(join(tmpdir(), 'foen-call-'))
  const p = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`, '--no-first-run', '--no-sandbox',
    '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required', 'about:blank'], { stdio: 'ignore' })
  for (let i = 0; i < 50; i++) {
    try { const v = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); return { p, dir, ws: v.webSocketDebuggerUrl } } catch { await new Promise(r => setTimeout(r, 200)) }
  }
  throw new Error('chromium did not start')
}
class Cdp {
  constructor(url) { this.ws = new WebSocket(url); this.id = 0; this.pending = new Map(); this.ws.onmessage = e => { const m = JSON.parse(e.data); const w = this.pending.get(m.id); if (w) { this.pending.delete(m.id); m.error ? w.rej(new Error(m.error.message)) : w.res(m.result) } } }
  open() { return new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = rej }) }
  send(method, params = {}, sessionId) { const id = ++this.id; this.ws.send(JSON.stringify({ id, method, params, sessionId })); return new Promise((res, rej) => this.pending.set(id, { res, rej })) }
}
async function page(b, url) {
  const cdp = new Cdp(b.ws); await cdp.open()
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' })
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true })
  await cdp.send('Page.enable', {}, sessionId); await cdp.send('Runtime.enable', {}, sessionId)
  await cdp.send('Page.navigate', { url }, sessionId)
  return { evalJs: async expr => (await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId)).result.value }
}
const wait = ms => new Promise(r => setTimeout(r, ms))

const A = await launch(9311), B = await launch(9312)
try {
  const auto = `?auto=1&stream=${stream}`
  const a = await page(A, base + auto)
  let invite = null
  for (let i = 0; i < 50 && !invite; i++) { invite = await a.evalJs('window.__foenInvite || null'); if (!invite) await wait(200) }
  if (!invite) throw new Error('no invite link from page A')
  const b = await page(B, invite.replace('#', auto + '#'))
  const t0 = Date.now()
  let sa = null, sb = null
  while (Date.now() - t0 < +seconds * 1000) {
    await wait(1000)
    sa = await a.evalJs('window.__foenStats || null'); sb = await b.evalJs('window.__foenStats || null')
    if (sa && sb) process.stdout.write(`\r  A enc ${sa.framesEncoded} dec ${sa.framesDecoded} · B enc ${sb.framesEncoded} dec ${sb.framesDecoded} · rtt ${sa.rtt.median ?? '-'}/${sb.rtt.median ?? '-'}   `)
  }
  const ea = await a.evalJs('document.getElementById("errors").textContent'), eb = await b.evalJs('document.getElementById("errors").textContent')
  const stA = await a.evalJs('document.getElementById("state").textContent'), stB = await b.evalJs('document.getElementById("state").textContent')
  console.log('\n')
  for (const [name, s, err, st] of [['A', sa, ea, stA], ['B', sb, eb, stB]]) {
    if (!s) { console.log(`${name}: no stats · state "${st}"`); continue }
    console.log(`${name}: ${s.elapsedS}s · ticks sent ${s.ticksSent} got ${s.ticksGot} · video enc ${s.framesEncoded} dec ${s.framesDecoded} · audio enc ${s.audioEncoded} dec ${s.audioDecoded} · keyWaits ${s.keyWaits} decodeErr ${s.decodeErrors} · verified ${s.verified} badSig ${s.badSig} badFormat ${s.badFormat} stale ${s.stale} gaps ${s.gaps}/${s.missed} · posts ${s.posts}/${s.postFail} polls ${s.polls}/${s.pollFail} · rtt med ${s.rtt.median} p90 ${s.rtt.p90} max ${s.rtt.max} (n=${s.rtt.n}) · send ${s.sendKbps} recv ${s.recvKbps} kbit/s${err ? ' · ERR ' + err : ''}`)
  }
} finally {
  A.p.kill(); B.p.kill(); await wait(1000)
  for (const d of [A.dir, B.dir]) rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 })
}
