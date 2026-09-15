// © 2026 sun-dive.
//
// The call key. Each side makes a fresh X25519 pair for every call and sends its public half in its
// first ticks, signed like every tick by the number's key. Once both halves are held, both sides derive
// the same AES-GCM key and every tick after that is ciphertext. The relay carries who is talking and
// when; it cannot read what is said, and a copy of the traffic is useless after the call, because the
// agreement key exists only in this page's memory and only for this call.
//
// All of it is the browser's own WebCrypto: X25519, HKDF-SHA256, AES-GCM-256. Nothing is stored.

const enc = new TextEncoder()

/** A fresh, non-extractable agreement pair. `pub` (32 bytes) goes to the other side. */
export async function newAgreement() {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])
  return { priv: kp.privateKey, pub: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) }
}

/** The call key from my private half, their public half and the call id. Non-extractable. */
export async function callKey(priv, theirPub32, callIdBytes) {
  const theirs = await crypto.subtle.importKey('raw', theirPub32, { name: 'X25519' }, false, [])
  const shared = await crypto.subtle.deriveBits({ name: 'X25519', public: theirs }, priv, 256)
  const ikm = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: callIdBytes, info: enc.encode('foen call v2') },
                                 ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
}

/** The nonce for one tick: the sender's role byte and the tick's sequence. Never repeats within a call. */
export const nonceFor = (roleByte, seq) =>
  Uint8Array.of(roleByte, (seq >>> 24) & 255, (seq >>> 16) & 255, (seq >>> 8) & 255, seq & 255, 0, 0, 0, 0, 0, 0, 0)

/** Additional data bound into every ciphertext: the call and the sender's role. */
export const aadFor = (callIdBytes, roleByte) => Uint8Array.of(...callIdBytes, roleByte)

export async function seal(key, nonce, aad, plain) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, plain))
}
/** Null when the ciphertext, the nonce or the additional data has been touched. */
export async function open(key, nonce, aad, sealed) {
  try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad }, key, sealed)) }
  catch { return null }
}

export const supported = async () => {
  try { await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']); return true } catch { return false }
}
