// How long a tick costs to make and to check, in this engine, on this machine.
//   node --import ./tools/node-importmap.mjs tools/bench-ticks.mjs [ticks]
import { Sender, Receiver } from '../site/js/thread.mjs'
import { keyFromWords } from '../site/js/key.mjs'

const n = Number(process.argv[2] || 200)
const wallet = await keyFromWords('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
const pub = wallet.pub
const callId = '00112233445566778899aabbccddeeff'
const s = new Sender(wallet, callId), r = new Receiver(callId, pub)
const payload = new Uint8Array(1600).fill(7)

const entries = []
let t = performance.now()
for (let i = 0; i < n; i++) entries.push((await s.entry(payload)).bytes)
const sign = (performance.now() - t) / n
t = performance.now()
let ok = 0
for (const e of entries) if (await r.accept(e)) ok++
const verify = (performance.now() - t) / n
console.log(`${n} ticks of ${payload.length} B: sign ${sign.toFixed(2)} ms, verify ${verify.toFixed(2)} ms, ${ok}/${n} accepted, ${r.stats.badSig} bad`)
