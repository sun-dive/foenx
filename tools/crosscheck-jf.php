<?php
// THE NATIVE LOCK, RUN. A tick built by the page's JavaScript is handed to jetmora's PHP: the entry is
// decoded, the lock is re-assembled from the same jetForth source with jf_asm and must match byte for
// byte, and then the jetForth INTERPRETER executes unlocking ‖ locking with the preimage in context.
// The covenant admits the tick only if that run leaves TRUE.
//   php tools/crosscheck-jf.php <jetmora repo> <entry hex> <prev tip hex> <call id hex>
declare(strict_types=1);
[$_, $jetmora, $entryHex, $prevTipHex, $callId] = $argv + [null, null, null, null, null];
require_once "$jetmora/server/covenant-entry.php";
require_once "$jetmora/server/preimage.php";
require_once "$jetmora/server/dispatch.php";
require_once "$jetmora/server/jf-asm.php";
require_once "$jetmora/server/interpreter-jf.php";

$bytes = hex2bin($entryHex);
$e = CovenantEntry::decode($bytes);
$ok = fn(bool $c, string $w) => printf("  %s %s\n", $c ? '✓' : '✗', $w) || ($c ? 0 : exit(1));

$ok($e['version'] === version_build('JF', 3), sprintf('version is family JF revision 3 (0x%08x)', $e['version']));
$in = $e['inputs'][0];
$ok(bin2hex($in['prevEntry']) === $prevTipHex, 'input spends the expected tip');
// unlocking = <sig> <pub> as two direct pushes
$u = $in['unlocking']; $p = 0;
$rd = function () use (&$p, $u) { $n = ord($u[$p]); $p++; $v = substr($u, $p, $n); $p += $n; return $v; };
$sig = $rd(); $pub = $rd();
$ok($p === strlen($u) && strlen($pub) === 32 && strlen($sig) === 64 && ord($u[0]) <= JF_PUSH_MAX, 'unlocking is two direct pushes: <64-byte sig> <32-byte Ed25519 pub>');

// the lock, re-assembled from the same source the page uses
$h160 = hash('ripemd160', hash('sha256', $pub, true), true);
$src = "\$$callId 2DROP 2DUP 1000 HASH160 1000 20 \$" . bin2hex($h160) . " BYTES= >R 2000 PREIMAGE 3000 HASH256 3000 32 ED25519-CHECKSIG R> AND";
$lock = jf_asm($src);
$ok($lock === $e['outputs'][0]['locking'], sprintf('★ the successor lock equals jf_asm of the same source, byte for byte (%d B)', strlen($lock)));

// the previous tip carried the same lock: it is the scriptCode
$pre = Preimage::build($e, 0, $lock, pack('P', 0));
$vm = new InterpreterJF();
$vm->setPreimage($pre);
$stack = $vm->run($u . $lock);
$ok(count($stack) === 1 && gmp_cmp($stack[0], -1) === 0, '★★ the jetForth interpreter runs unlocking ‖ locking with the preimage and leaves TRUE');
// and refuses the same tick under a different preimage (another entry's context)
$vm2 = new InterpreterJF(); $vm2->setPreimage($pre . "\x00");
$stack2 = $vm2->run($u . $lock);
$ok(count($stack2) === 1 && gmp_cmp($stack2[0], 0) === 0, '…and leaves FALSE under a different preimage');
// the data output: STR16 <payload> ABORT
$data = $e['outputs'][1]['locking'];
$ok(ord($data[0]) === JF_LIT['STR16'] && ord($data[strlen($data) - 1]) === JF_WORD['ABORT'], 'data output is STR16 <payload> ABORT: never spendable, says so');
printf("  entry %d bytes · lock %d bytes · preimage %d bytes · tick %d\n", strlen($bytes), strlen($lock), strlen($pre), $in['sequence']);
echo "PHP interpreter admits the JavaScript wallet's tick\n";
