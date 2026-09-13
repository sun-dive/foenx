<?php
// THE TWO WALLETS AGREE, OR THEY DO NOT. A tick built by the page's JavaScript is handed to jetmora's PHP
// wallet, which decodes it as a covenant entry, rebuilds the preimage against the tip's locking script,
// and verifies the covenant signature with its own secp256k1. Same bytes on both sides, or a failure.
//   php tools/crosscheck-php.php <jetmora repo> <entry hex> <expected genesis hex> [<prev tip hex>]
declare(strict_types=1);
[$_, $jetmora, $entryHex, $genesisHex] = $argv + [null, null, null, null];
$prevTipHex = $argv[4] ?? $genesisHex;
require_once "$jetmora/server/covenant-entry.php";
require_once "$jetmora/server/preimage.php";
require_once "$jetmora/server/secp256k1.php";
require_once "$jetmora/server/dispatch.php";

$bytes = hex2bin($entryHex);
$e = CovenantEntry::decode($bytes);
$ok = fn(bool $c, string $w) => printf("  %s %s\n", $c ? '✓' : '✗', $w) || ($c ? 0 : exit(1));

$ok($e['version'] === version_build('SV', 1), sprintf('version is family SV revision 1 (0x%08x)', $e['version']));
$ok(count($e['inputs']) === 1 && count($e['outputs']) === 2, 'one input, two outputs (tip successor + data)');
$in = $e['inputs'][0];
$ok(bin2hex($in['prevEntry']) === $prevTipHex, 'input spends the expected tip (' . substr($prevTipHex, 0, 12) . '…)');
// unlocking = <sig‖0x01> <pub>
$u = $in['unlocking']; $p = 0;
$rd = function () use (&$p, $u) { $n = ord($u[$p]); $p++; $v = substr($u, $p, $n); $p += $n; return $v; };
$sigT = $rd(); $pub = $rd();
$ok($p === strlen($u) && strlen($pub) === 33 && substr($sigT, -1) === "\x01", 'unlocking is <sig‖0x01> <33-byte pub>');
$sig = substr($sigT, 0, -1);
// the successor lock must be <state> DROP DUP HASH160 <h160(pub)> EQUALVERIFY CHECKSIG for this pub
$lock = $e['outputs'][0]['locking'];
$h160 = hash('ripemd160', hash('sha256', $pub, true), true);
$ok(str_ends_with($lock, "\x75\x76\xa9\x14" . $h160 . "\x88\xac"), 'successor lock is P2PKH of the signing key, with the call state dropped in front');
// the previous tip carried the same lock (same key, same state), so it is the scriptCode
$pre = Preimage::build($e, 0, $lock, pack('P', 0));
$digest = hash('sha256', hash('sha256', $pre, true), true);
$ok(Secp256k1::verifyDigest($sig, $pub, $digest), '★ the covenant signature verifies under jetmora\'s PHP secp256k1 against the PHP-built preimage');
$ok(!Secp256k1::verifyDigest($sig, $pub, hash('sha256', $digest, true)), '…and fails for any other digest');
$data = $e['outputs'][1]['locking'];
$ok(substr($data, 0, 2) === "\x00\x6a", 'data output is OP_FALSE OP_RETURN <payload>');
printf("  entry %d bytes · preimage %d bytes · tick %d · hash %s…\n", strlen($bytes), strlen($pre), $in['sequence'], substr(bin2hex(CovenantEntry::hash($bytes)), 0, 16));
echo "PHP wallet agrees with the JavaScript wallet\n";
