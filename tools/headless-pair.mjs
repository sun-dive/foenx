// Drive two headless Chromium profiles through one relay and print the numbers both sides measured.
//   node tools/headless-pair.mjs http://127.0.0.1:8088/ 30 16384 100
// Uses the Chrome DevTools Protocol over Node's built-in WebSocket; no packages.
import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const [base = 'http://127.0.0.1:8088/', seconds = '30', chunk = '16384', every = '100'] = process.argv.slice(2)
const CHROME = process.env.CHROME || 'chromium'

async function launch(port) {
  const dir = mkdtempSync(join(tmpdir(), 'foen-'))
  const p = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${dir}`, '--no-first-run', '--no-sandbox', '--disable-gpu', 'about:blank'], { stdio: 'ignore' })
  for (let i = 0; i < 50; i++) {
    try { const v = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); return { p, dir, ws: v.webSocketDebuggerUrl, port } } catch { await new Promise(r => setTimeout(r, 200)) }
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
  const evalJs = async expr => (await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, sessionId)).result.value
  return { evalJs, close: () => cdp.send('Target.closeTarget', { targetId }) }
}
const wait = ms => new Promise(r => setTimeout(r, ms))

const A = await launch(9301), B = await launch(9302)
try {
  const auto = `?auto=${seconds}&chunk=${chunk}&every=${every}`
  const a2 = await page(A, base + auto)            // A: no call in the hash ⇒ role a, starts at once
  let invite = null
  for (let i = 0; i < 50 && !invite; i++) { invite = await a2.evalJs('window.__foenInvite || null'); if (!invite) await wait(200) }
  if (!invite) throw new Error('no invite link from page A')
  const b = await page(B, invite.replace('#', auto + '#'))   // B: opens the invite ⇒ role b
  const t0 = Date.now()
  let da = null, db = null
  while ((!da || !db) && Date.now() - t0 < (+seconds + 40) * 1000) {
    await wait(1000)
    da = da || await a2.evalJs('window.__foenDone || null')
    db = db || await b.evalJs('window.__foenDone || null')
    const sa = await a2.evalJs('window.__foenStats || null'), sb = await b.evalJs('window.__foenStats || null')
    if (sa && sb) process.stdout.write(`\r  A sent ${sa.sent} verified ${sa.verified} gaps ${sa.gaps} · B sent ${sb.sent} verified ${sb.verified} gaps ${sb.gaps}   `)
  }
  console.log('\n')
  for (const [name, s] of [['A', da], ['B', db]]) {
    if (!s) { console.log(`${name}: did not finish`); continue }
    console.log(`${name}: ${s.elapsedS}s · sent ${s.sent} · received ${s.received} · verified ${s.verified} · badSig ${s.badSig} · badFormat ${s.badFormat} · stale ${s.stale} · gaps ${s.gaps} (missed ${s.missed}) · posts ${s.posts}/${s.postFail} fail · polls ${s.polls}/${s.pollEmpty} empty/${s.pollFail} fail · ack RTT median ${Math.round(s.ackRttMs.median ?? -1)} p90 ${Math.round(s.ackRttMs.p90 ?? -1)} max ${Math.round(s.ackRttMs.max ?? -1)} (n=${s.ackRttMs.n}) · ${s.kbps} kbit/s`)
  }
} finally {
  A.p.kill(); B.p.kill(); await wait(1000)
  for (const d of [A.dir, B.dir]) rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 })
}
