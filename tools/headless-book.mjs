// A call placed through the phone book: A lists itself, B lists itself, B calls A by name, A answers
// automatically. Both have a synthetic camera and microphone. Prints what each side encoded and decoded.
//   node tools/headless-book.mjs http://127.0.0.1:8088/ 30
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [base = 'http://127.0.0.1:8088/', seconds = '30'] = process.argv.slice(2)
const CHROME = process.env.CHROME || 'chromium'

async function launch(port) {
  const dir = mkdtempSync(join(tmpdir(), 'foen-book-'))
  const p = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`, '--no-first-run', '--no-sandbox',
    '--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--ignore-certificate-errors', '--autoplay-policy=no-user-gesture-required', 'about:blank'], { stdio: 'ignore' })
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
  return { evalJs: async expr => { const r = await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId); if (r.exceptionDetails) throw new Error(r.exceptionDetails.text + ' ' + (r.exceptionDetails.exception?.description ?? '')); return r.result.value } }
}
const wait = ms => new Promise(r => setTimeout(r, ms))

const A = await launch(9321), B = await launch(9322)
try {
  const tag = Math.random().toString(36).slice(2, 6)
  const a = await page(A, `${base}?book=test&name=Alice-${tag}&auto=answer`)
  const b = await page(B, `${base}?book=test&name=Bob-${tag}`)
  await wait(2500)
  await b.evalJs(`window.__foenCallName('Alice-${tag}')`)
  const t0 = Date.now()
  let sa = null, sb = null, rang = null, hungUp = false
  while (Date.now() - t0 < +seconds * 1000) {
    await wait(1000)
    if (!hungUp && Date.now() - t0 > (+seconds - 6) * 1000) { hungUp = true; await b.evalJs('document.getElementById("call").click()'); console.log('\n  B pressed Hang up') }
    rang = rang || await a.evalJs('window.__foenIncoming || null')
    sa = await a.evalJs('window.__foenStats || null'); sb = await b.evalJs('window.__foenStats || null')
    if (sa && sb) process.stdout.write(`\r  A dec ${sa.framesDecoded} · B dec ${sb.framesDecoded} · rtt ${sa.rtt.median ?? '-'}/${sb.rtt.median ?? '-'}   `)
  }
  console.log('\n')
  console.log(rang ? `A was rung by "${rang.from}" on call ${rang.callId.slice(0, 8)}… · incoming bell ${rang.ringing ? 'rang' : 'silent (page untouched)'}` : 'A was never rung')
  console.log('after B hung up, A says: "' + await a.evalJs('document.getElementById("state").textContent') + '" · B says: "' + await b.evalJs('document.getElementById("state").textContent') + '"')
  for (const [name, s] of [['A (answered)', sa], ['B (called by name)', sb]]) {
    if (!s) { console.log(`${name}: no stats`); continue }
    console.log(`${name}: ${s.elapsedS}s · ticks ${s.ticksSent}/${s.ticksGot} · video ${s.framesEncoded}→${s.framesDecoded} · audio ${s.audioEncoded}→${s.audioDecoded} · audio buffer ${s.audioLagMs} ms dropped ${s.audioDropped} · video skipped ${s.videoSkipped} draw-wait ${s.drawWaitMs} ms · errors ${s.decodeErrors} · badSig ${s.badSig} · gaps ${s.gaps} · rtt med ${s.rtt.median} p90 ${s.rtt.p90} · send ${s.sendKbps} recv ${s.recvKbps} kbit/s`)
  }
} finally {
  A.p.kill(); B.p.kill(); await wait(1000)
  for (const d of [A.dir, B.dir]) rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 })
}
