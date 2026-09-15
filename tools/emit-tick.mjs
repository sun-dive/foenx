// Emit one tick from the page's own Sender, for tools/crosscheck-jf.php:
//   node --import ./tools/node-importmap.mjs tools/emit-tick.mjs
// Prints three hex lines: the entry, the previous tip (the genesis id), the call id.
import { Sender } from '../site/js/thread.mjs'
import { toHex } from '../site/js/engine/bytes.mjs'

const d = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdefn
const callId = '00112233445566778899aabbccddeeff'
const s = new Sender(d, callId)
const prev = toHex(s.tip)
const e = s.entry(new Uint8Array([1, 2, 3, 4]))
console.log(toHex(e.bytes)); console.log(prev); console.log(callId)
