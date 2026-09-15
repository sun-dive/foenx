// The call key, graded: both sides derive the same key, a sealed tick opens only with that key, the
// nonce and the additional data are bound, and a fresh call has a fresh key.
//   node tools/verify-seal.mjs
import { newAgreement, callKey, nonceFor, aadFor, seal, open } from '../site/js/secret.mjs'

let pass = 0, fail = 0
const ok = (c, w) => { c ? pass++ : (fail++, console.log('  ✗ ' + w)) }
const callId = Uint8Array.from({ length: 16 }, (_, i) => i)
const A = 0x61, B = 0x62

const a = await newAgreement(), b = await newAgreement()
ok(a.pub.length === 32 && b.pub.length === 32, 'public halves are 32 bytes')
const ka = await callKey(a.priv, b.pub, callId), kb = await callKey(b.priv, a.pub, callId)
const plain = new Uint8Array(1600).map((_, i) => i & 255)
const sealed = await seal(ka, nonceFor(A, 7), aadFor(callId, A), plain)
ok(sealed.length === plain.length + 16, 'ciphertext is the plaintext plus a 16-byte tag')
const opened = await open(kb, nonceFor(A, 7), aadFor(callId, A), sealed)
ok(opened && opened.every((x, i) => x === plain[i]), 'the other side opens it with its own derivation of the key')
ok((await open(kb, nonceFor(A, 8), aadFor(callId, A), sealed)) === null, 'a different sequence does not open it')
ok((await open(kb, nonceFor(B, 7), aadFor(callId, A), sealed)) === null, 'a different role byte does not open it')
ok((await open(kb, nonceFor(A, 7), aadFor(callId, B), sealed)) === null, 'a different additional data does not open it')
const bad = Uint8Array.from(sealed); bad[100] ^= 1
ok((await open(kb, nonceFor(A, 7), aadFor(callId, A), bad)) === null, 'a flipped byte does not open')
const c = await newAgreement()
const kc = await callKey(c.priv, a.pub, callId)
ok((await open(kc, nonceFor(A, 7), aadFor(callId, A), sealed)) === null, 'a third party with a fresh pair cannot open it')
const otherCall = await callKey(b.priv, a.pub, Uint8Array.from({ length: 16 }, () => 9))
ok((await open(otherCall, nonceFor(A, 7), aadFor(callId, A), sealed)) === null, 'the same pairs on another call id give another key')
let exportable = null
try { await crypto.subtle.exportKey('raw', ka) } catch (e) { exportable = e.name }
ok(exportable !== null, `the call key cannot be exported (${exportable})`)
try { await crypto.subtle.exportKey('raw', a.priv); exportable = null } catch (e) { exportable = e.name }
ok(exportable !== null, `the agreement private half cannot be exported (${exportable})`)

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed · ${fail} failed   [call key · X25519 + HKDF + AES-GCM through WebCrypto]`)
process.exit(fail === 0 ? 0 : 1)
