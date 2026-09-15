// Emit one tick from the page's own Sender, for tools/crosscheck-jf.php:
//   node --import ./tools/node-importmap.mjs tools/emit-tick.mjs
// Prints three hex lines: the entry, the previous tip (the genesis id), the call id.
import { Sender } from '../site/js/thread.mjs'
import { keyFromWords } from '../site/js/key.mjs'
import { toHex } from '../site/js/engine/bytes.mjs'

const wallet = await keyFromWords('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
const callId = '00112233445566778899aabbccddeeff'
const s = new Sender(wallet, callId)
const prev = toHex(s.tip)
const e = await s.entry(new Uint8Array([1, 2, 3, 4]))
console.log(toHex(e.bytes)); console.log(prev); console.log(callId)
