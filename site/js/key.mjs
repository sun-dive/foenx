// © 2026 sun-dive.
//
// The wallet: twelve words, a number, and a key that signs and is never seen.
//
//   words   BIP-39, twelve English words. The portable root: written down once, they rebuild the number
//           on any device. Never stored here.
//   key     SLIP-0010 hardened derivation from the words, then an Ed25519 key held NON-EXTRACTABLE in
//           WebCrypto and kept in IndexedDB. A script on the page can ask it to sign; nothing can read it.
//           The private bytes exist in JavaScript only for the moment of import.
//   number  from hash160(public key): 20 digits plus a check digit. Anyone may
//           know it. It is what the book lists, what the inbox id is derived from, and what a caller
//           checks the first tick's key against.

import * as bip39 from './engine/bip39.mjs'
import { derive, publicKey, pkcs8 } from './slip10.mjs'
import { sha256 } from '@noble/hashes/sha2.js'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { toHex } from './engine/bytes.mjs'

/** The same path jetmora's PHP signer uses (server/wallet/jetmora/signer.php), so the same twelve words
 *  are the same identity in both wallets. Hardened at every level, as SLIP-0010 requires. */
export const PATH = "m/44'/0'/0'"

export const supported = () => typeof crypto !== 'undefined' && !!crypto.subtle && typeof indexedDB !== 'undefined'

export const newWords = () => bip39.fromEntropy(crypto.getRandomValues(new Uint8Array(16)))
export const validWords = w => bip39.isValid(w)

/** Words to a wallet {pub, priv}. Throws on a bad word or checksum. */
export async function keyFromWords(words) {
  bip39.toEntropy(words)                                    // ⚠ checks the checksum; toSeed alone would not
  const node = derive(bip39.toSeed(words), PATH)
  const pub = await publicKey(node.key)
  const priv = await crypto.subtle.importKey('pkcs8', pkcs8(node.key), { name: 'Ed25519' }, false, ['sign'])
  node.key.fill(0)
  return { pub, priv }
}

export const hash160 = b => ripemd160(sha256(b))

// The number: hash160 of the public key, first 80 bits, reduced modulo 10^20, so it fits 20 digits with
// a Luhn check digit as the 21st (his call, 15 Sept). About 66 bits of the hash survive, which is what a
// caller pins the first tick's key against: forging a number is out of reach, and the number is short
// enough to read out, type, or write on a card. Digits only, in threes, like a long international number.
const NUMBER_DIGITS = 20
const MOD = 10n ** BigInt(NUMBER_DIGITS)
function luhn(digits) {
  let sum = 0
  for (let i = digits.length - 1, dbl = true; i >= 0; i--, dbl = !dbl) {
    let d = Number(digits[i]); if (dbl) { d *= 2; if (d > 9) d -= 9 }
    sum += d
  }
  return String((10 - (sum % 10)) % 10)
}
/** The canonical 21-digit number for a public key. */
export function numberOf(pub) {
  let n = 0n
  for (const b of hash160(pub).slice(0, 10)) n = (n << 8n) | BigInt(b)
  const digits = (n % MOD).toString().padStart(NUMBER_DIGITS, '0')
  return digits + luhn(digits)
}
/** "123 456 789 012 345 678 901" for people. */
export const formatNumber = digits => digits.replace(/(\d{3})(?=\d)/g, '$1 ')
/** Back from what a person typed: the canonical 21 digits, or null if it is not a well-formed number. */
export function parseNumber(text) {
  const digits = String(text).replace(/\D/g, '')
  if (digits.length !== NUMBER_DIGITS + 1 || luhn(digits.slice(0, NUMBER_DIGITS)) !== digits[NUMBER_DIGITS]) return null
  return digits
}
/** Does this public key carry this number? */
export const keyHasNumber = (pub, number) => numberOf(pub) === number

/** Sign a message with the device key. 64 bytes. */
export async function sign(wallet, msg) {
  return new Uint8Array(await crypto.subtle.sign('Ed25519', wallet.priv, msg))
}
const pubCache = new Map()
/** Verify an Ed25519 signature under a 32-byte public key. */
export async function verify(pub32, sig64, msg) {
  if (pub32.length !== 32 || sig64.length !== 64) return false
  const hex = toHex(pub32)
  let k = pubCache.get(hex)
  if (!k) {
    try { k = await crypto.subtle.importKey('raw', pub32, { name: 'Ed25519' }, false, ['verify']) } catch { return false }
    if (pubCache.size > 64) pubCache.clear()
    pubCache.set(hex, k)
  }
  try { return await crypto.subtle.verify('Ed25519', k, sig64, msg) } catch { return false }
}

// ── the store: IndexedDB, because a CryptoKey object can live there and nowhere else ──
const DB = 'foen', STORE = 'wallet', ID = 'device'
function openDb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1)
    r.onupgradeneeded = () => { if (!r.result.objectStoreNames.contains(STORE)) r.result.createObjectStore(STORE) }
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error)
  })
}
async function idb(mode, fn) {
  const db = await openDb()
  try {
    return await new Promise((res, rej) => {
      const tx = db.transaction(STORE, mode), req = fn(tx.objectStore(STORE))
      req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error)
    })
  } finally { db.close() }
}
/** The wallet on this device, or null. */
export async function loadWallet() {
  const w = await idb('readonly', s => s.get(ID))
  return w && w.pub && w.priv ? { pub: new Uint8Array(w.pub), priv: w.priv } : null
}
export const saveWallet = w => idb('readwrite', s => s.put({ pub: w.pub, priv: w.priv, created: Date.now() }, ID))
export const forgetWallet = () => idb('readwrite', s => s.delete(ID))

/** A new wallet on this device. Returns the words ONCE; they are not kept. */
export async function createWallet() {
  const words = newWords()
  const w = await keyFromWords(words)
  await saveWallet(w)
  return { words, wallet: w }
}
/** The same number on another device, from its words. */
export async function restoreWallet(words) {
  const w = await keyFromWords(words)
  await saveWallet(w)
  return w
}
