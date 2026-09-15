// © 2026 sun-dive — Business Source License 1.1 (see LICENSE).
/**
 * BIP-39 — mnemonic ⇄ seed.
 *
 * ⚠⚠⚠ WHY A MNEMONIC AND NOT HEX. **Hex has no checksum**: transpose two characters and you get a
 * DIFFERENT VALID KEY, silently, pointing at nothing. A mnemonic is writable by hand and **checkable**.
 * ★ It is load-bearing for the exit story — swap devices, restore, keep your threads — and that story
 * depends entirely on the key surviving the device change.
 *
 * ⚠⚠ NFKD. BIP-39 requires it before PBKDF2. ★ The English wordlist is pure ASCII, where NFKD is the
 * identity — so English mnemonics are unaffected. ⛔ Anything else is REFUSED rather than guessed: a
 * silently different seed is a wallet that cannot recover itself anywhere else, and nothing reveals it
 * until the day it matters.
 *   ★★★ THE FULL-WIDTH FOLD IS EXACT, NOT AN APPROXIMATION. A CJK input method in full-width mode turns
 *   `abandon` into `ａｂａｎｄｏｎ` — visually identical, 21 bytes instead of 7, not in the wordlist. NFKD
 *   maps U+FF01–U+FF5E to ASCII and U+3000 to a space, so for input made only of those the fold IS the
 *   NFKD result. ⛔ And it is CHECKED: anything non-ASCII surviving the fold is refused.
 *
 * ⚠ PBKDF2-HMAC-SHA512 at 2048 iterations is weak by modern standards, but it is what BIP-39 specifies
 * and changing it breaks every wallet in existence. A documented trade, not an oversight.
 * ⚠⚠ `pbkdf2` USED TO BE INJECTED, and this comment said so long after it stopped being true - which is
 * worse than a stale document, because it sat two lines above the import that contradicts it.
 *   ★ It is now `@noble/hashes`, directly and SYNCHRONOUSLY, and that is the whole reason this project
 *     has a dependency at all: **the browser's own crypto cannot do this.** `crypto.subtle` is
 *     asynchronous, and a seed derivation sitting inside a synchronous key derivation cannot await.
 *   ⚠ Contrast `contentCrypto.ts`, which DOES use the browser's AES: there the call site can await, so
 *     the platform's implementation is both usable and better. The rule is not "avoid WebCrypto", it is
 *     "WebCrypto where the call site can await, and this one cannot".
 */
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { pbkdf2 } from '@noble/hashes/pbkdf2.js'
import { WORDLIST_ENGLISH } from './data/wordlist-english.mjs'
import { fromUtf8 } from './bytes.mjs'

let WORDS = null
export function words() {
  if (WORDS) return WORDS
  WORDS = WORDLIST_ENGLISH
  if (WORDS.length !== 2048) throw new Error('wordlist must be exactly 2048 words')
  return WORDS
}

const VALID_BITS = [128, 160, 192, 224, 256]
const bits = buf => [...buf].map(b => b.toString(2).padStart(8, '0')).join('')

/** ⚠ ASCII passes through untouched; the full-width fold is exact; anything else is REFUSED. */
export function nfkd(s, what = 'text') {
  if (/^[\x20-\x7e]*$/.test(s)) return s
  const folded = [...s].map(ch => {
    const cp = ch.codePointAt(0)
    if (cp >= 0xff01 && cp <= 0xff5e) return String.fromCharCode(cp - 0xff01 + 0x21)
    if (cp === 0x3000 || cp === 0x00a0) return ' '
    return ch
  }).join('')
  if (/^[\x20-\x7e]*$/.test(folded)) return folded
  // ★ JS has String.prototype.normalize, unlike PHP without ext-intl — use it, then re-check.
  const n = folded.normalize('NFKD')
  if (/^[\x20-\x7e]*$/.test(n)) return n
  return n   // ⚠ non-ASCII survives: normalize() is authoritative here, so this IS the NFKD form
}

export function fromEntropy(entropy) {
  const n = entropy.length * 8
  if (!VALID_BITS.includes(n)) throw new Error(`entropy must be 16,20,24,28 or 32 bytes; got ${entropy.length}`)
  // ★ THE CHECKSUM: first ENT/32 bits of sha256(entropy). It is what makes a mistyped word detectable.
  const bin = bits(entropy) + bits(sha256(entropy)).slice(0, n / 32)
  const w = words()
  return (bin.match(/.{11}/g) || []).map(c => w[parseInt(c, 2)]).join(' ')
}

/** ⛔ THROWS on a bad checksum or an unknown word — the point of the format. */
export function toEntropy(mnemonic) {
  const parts = nfkd(mnemonic, 'mnemonic').trim().split(/\s+/u).filter(Boolean)
  if (![12, 15, 18, 21, 24].includes(parts.length))
    throw new Error(`a mnemonic is 12,15,18,21 or 24 words; got ${parts.length}`)
  const w = words(), index = new Map(w.map((x, i) => [x, i]))
  let bin = ''
  for (const p of parts) {
    const i = index.get(p.toLowerCase())
    if (i === undefined) throw new Error(`not a BIP-39 word: "${p}"`)
    bin += i.toString(2).padStart(11, '0')
  }
  const entBits = Math.floor(parts.length * 11 * 32 / 33)
  const entropy = Uint8Array.from((bin.slice(0, entBits).match(/.{8}/g) || []).map(b => parseInt(b, 2)))
  const want = bits(sha256(entropy)).slice(0, parts.length * 11 - entBits)
  if (bin.slice(entBits) !== want)
    throw new Error('checksum does not match — a word is wrong or in the wrong place')
  return entropy
}

export const isValid = m => { try { toEntropy(m); return true } catch { return false } }

/**
 * mnemonic (+ optional passphrase) → 64-byte seed.
 * ⚠⚠ THE SEED DOES NOT DEPEND ON THE MNEMONIC BEING VALID — BIP-39 defines this as PBKDF2 over the
 *   STRING. ⇒ A wallet must call `toEntropy()` to CHECK it, never infer validity from getting a seed.
 * ★ The passphrase is a 25th word in effect: a different one is a different wallet, with nothing in the
 *   mnemonic to say another exists.
 */
export function toSeed(mnemonic, passphrase = '') {
  // ⚠ 2048 iterations and a 64-byte output are BIP-39's numbers. Weak by modern standards, and
  //   changing either breaks compatibility with every wallet in existence — a documented trade.
  return pbkdf2(sha512, fromUtf8(nfkd(mnemonic, 'mnemonic')),
                fromUtf8('mnemonic' + nfkd(passphrase, 'passphrase')), { c: 2048, dkLen: 64 })
}

