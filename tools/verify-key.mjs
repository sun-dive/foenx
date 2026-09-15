// The wallet, graded: SLIP-0010's own Ed25519 vectors, a BIP-39 vector, the number's round trip and
// check digit, and a sign/verify/tamper cycle through WebCrypto.
//   node --import ./tools/node-importmap.mjs tools/verify-key.mjs
import { master, derive, publicKey } from '../site/js/slip10.mjs'
import { keyFromWords, numberOf, formatNumber, parseNumber, keyHasNumber, sign, verify, PATH } from '../site/js/key.mjs'
import * as bip39 from '../site/js/engine/bip39.mjs'
import { toHex, fromHex } from '../site/js/engine/bytes.mjs'

let pass = 0, fail = 0
const ok = (c, w) => { c ? pass++ : (fail++, console.log('  ✗ ' + w)) }

// ── SLIP-0010 §test vectors (Ed25519): chain code, private key, public key, every chain ──
const VECTORS = [
 ['000102030405060708090a0b0c0d0e0f', [
  ['m', '90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb', '2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7', 'a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed'],
  ['m/0H', '8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69', '68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3', '8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c'],
  ['m/0H/1H', 'a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14', 'b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2', '1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187'],
  ['m/0H/1H/2H', '2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c', '92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9', 'ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1'],
  ['m/0H/1H/2H/2H', '8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc', '30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662', '8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c'],
  ['m/0H/1H/2H/2H/1000000000H', '68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230', '8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793', '3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a']]],
 ['fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542', [
  ['m', 'ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b', '171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012', '8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a'],
  ['m/0H', '0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d', '1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635', '86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037'],
  ['m/0H/2147483647H', '138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f', 'ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4', '5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d'],
  ['m/0H/2147483647H/1H', '73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90', '3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c', '2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45'],
  ['m/0H/2147483647H/1H/2147483646H', '0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a', '5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72', 'e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b'],
  ['m/0H/2147483647H/1H/2147483646H/2H', '5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4', '551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d', '47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0']]],
]
for (const [seedHex, chains] of VECTORS) {
  const seed = fromHex(seedHex)
  for (const [path, chain, key, pub] of chains) {
    const node = derive(seed, path)
    ok(toHex(node.chain) === chain, `${path} chain code`)
    ok(toHex(node.key) === key, `${path} private key`)
    ok(toHex(await publicKey(node.key)) === pub, `${path} public key (WebCrypto)`)
  }
}
let refused = false
try { derive(fromHex(VECTORS[0][0]), 'm/0') } catch (e) { refused = /hardened/.test(e.message) }
ok(refused, 'an unhardened step is refused, not silently hardened')

// ── BIP-39: the published vector for the all-zero mnemonic with passphrase TREZOR ──
const M = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
ok(bip39.isValid(M), 'vector mnemonic is valid')
ok(toHex(bip39.toSeed(M, 'TREZOR')).startsWith('c55257c360c07c72029aebc1b53c05ed'), 'seed matches the BIP-39 vector')
ok(!bip39.isValid(M.replace('about', 'abandon')), 'a wrong last word fails the checksum')

// ── the number ──
const w = await keyFromWords(M)
ok(w.pub.length === 32, `wallet public key is 32 bytes (path ${PATH})`)
const num = numberOf(w.pub)
ok(/^\d{21}$/.test(num), `number is 21 digits: ${formatNumber(num)}`)
ok(parseNumber(formatNumber(num)) === num, 'the formatted number parses back to the canonical digits')
ok(parseNumber(num.slice(0, 20) + String((Number(num[20]) + 1) % 10)) === null, 'a wrong check digit is rejected')
const swapped = num.slice(0, 3) + num[4] + num[3] + num.slice(5)
ok(swapped === num || parseNumber(swapped) === null, 'a transposed pair is rejected')
ok(parseNumber('1234') === null, 'a short number is rejected')
ok(keyHasNumber(w.pub, num), 'the key carries its own number')
ok(!keyHasNumber(w.pub, num.slice(0, 20) + '0') || num[20] === '0', 'another number is not this key')

// ── sign, verify, tamper ──
const msg = new Uint8Array(32).fill(7)
const sig = await sign(w, msg)
ok(sig.length === 64, 'signature is 64 bytes')
ok(await verify(w.pub, sig, msg), 'verifies')
ok(!(await verify(w.pub, sig, new Uint8Array(32).fill(8))), 'fails under another message')
const bad = Uint8Array.from(sig); bad[10] ^= 1
ok(!(await verify(w.pub, bad, msg)), 'fails when tampered')
const w2 = await keyFromWords(M.replace(/about$/, 'about') === M ? 'legal winner thank year wave sausage worth useful legal winner thank yellow' : M)
ok(!(await verify(w2.pub, sig, msg)), 'fails under another key')
ok(!(await verify(w.pub.slice(0, 31), sig, msg)), 'a 31-byte key is a failed check, not an error')
let extractable = null
try { await crypto.subtle.exportKey('jwk', w.priv) } catch (e) { extractable = e.name }
ok(extractable !== null, `the device key cannot be exported (${extractable})`)
ok(toHex((await keyFromWords(M)).pub) === toHex(w.pub), 'the same words give the same number')

console.log(`\n${fail === 0 ? '✅' : '⚠'}  ${pass} passed · ${fail} failed   [wallet · SLIP-0010 + BIP-39 vectors, number, WebCrypto Ed25519]`)
process.exit(fail === 0 ? 0 : 1)
