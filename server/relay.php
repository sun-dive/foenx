<?php
// © 2026 sun-dive.
//
// THE RELAY. One file, and it holds ONE thing per direction of a call: the newest tip. It does not
// parse, verify or keep entries. Both parties connect out over HTTPS; this is where the two
// connections meet, and it is replaceable without either party noticing.
//
//   POST relay.php?c=<call>&d=<a|b>&s=<seq>   body = the entry (binary)   → {"ok":true,"seq":N}
//   GET  relay.php?c=<call>&d=<a|b>&after=<n>&wait=<ms>                   → the newest entry with
//        seq > n, as the body, with X-Seq; 204 when nothing newer arrived within `wait`.
//
// ⚠ A call's data lives OUTSIDE the docroot when a sibling directory exists (as jetmora-data does),
//   else in ./data for local development. Whatever happens, an answer carries a body or a 204.
declare(strict_types=1);

const MAX_ENTRY = 262144;   // bytes; a video chunk is tens of KB
const MAX_WAIT  = 25000;    // ms; under the host's request time limit
const TTL       = 3600;     // s; a call directory untouched this long is removed

function out(array $body, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES), "\n";
    exit;
}

$dataRoot = (static function (): string {
    $root = $_SERVER['DOCUMENT_ROOT'] ?? '';
    if ($root !== '') {
        $sibling = dirname(rtrim($root, '/')) . '/foen-data';
        if (is_dir($sibling)) return $sibling;
    }
    $local = __DIR__ . '/data';
    if (!is_dir($local)) @mkdir($local, 0700, true);
    return $local;
})();

$call = $_GET['c'] ?? '';
$dir  = $_GET['d'] ?? '';
if (!preg_match('/^[0-9a-f]{32}$/', $call)) out(['error' => 'bad call id'], 400);
if ($dir !== 'a' && $dir !== 'b') out(['error' => 'bad direction'], 400);

$callDir = "$dataRoot/$call";
$bin = "$callDir/$dir.bin";
$seqFile = "$callDir/$dir.seq";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $seq = (int)($_GET['s'] ?? -1);
    if ($seq < 0) out(['error' => 'bad seq'], 400);
    $body = file_get_contents('php://input', false, null, 0, MAX_ENTRY + 1);
    if ($body === false || $body === '') out(['error' => 'empty entry'], 400);
    if (strlen($body) > MAX_ENTRY) out(['error' => 'entry too large'], 413);
    if (!is_dir($callDir) && !@mkdir($callDir, 0700, true) && !is_dir($callDir)) out(['error' => 'cannot create call'], 500);

    // Only ever move forward: a late POST must not overwrite a newer tip.
    $cur = @file_get_contents($seqFile);
    if ($cur !== false && (int)$cur >= $seq) out(['ok' => true, 'seq' => $seq, 'stale' => true]);

    // tmp + rename: readers see the old tip or the new one, never a torn file.
    $tmp = "$bin.$seq.tmp";
    if (file_put_contents($tmp, $body) !== strlen($body)) { @unlink($tmp); out(['error' => 'write failed'], 500); }
    if (!rename($tmp, $bin)) { @unlink($tmp); out(['error' => 'rename failed'], 500); }
    $tmpS = "$seqFile.$seq.tmp";
    file_put_contents($tmpS, (string)$seq);
    rename($tmpS, $seqFile);
    touch($callDir);

    // Housekeeping, rarely: drop calls nobody has touched for TTL.
    if (random_int(0, 99) === 0) {
        $now = time();
        foreach (glob("$dataRoot/*", GLOB_ONLYDIR) ?: [] as $d) {
            if ($now - filemtime($d) > TTL) { foreach (glob("$d/*") ?: [] as $f) @unlink($f); @rmdir($d); }
        }
    }
    out(['ok' => true, 'seq' => $seq]);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $after = (int)($_GET['after'] ?? -1);
    $wait  = min(MAX_WAIT, max(0, (int)($_GET['wait'] ?? 0)));
    $deadline = microtime(true) + $wait / 1000;
    ignore_user_abort(false);
    while (true) {
        clearstatcache(true, $seqFile);
        $cur = @file_get_contents($seqFile);
        if ($cur !== false && (int)$cur > $after) {
            $data = @file_get_contents($bin);
            if ($data !== false && $data !== '') {
                http_response_code(200);
                header('Content-Type: application/octet-stream');
                header('X-Seq: ' . (int)$cur);
                header('Cache-Control: no-store');
                echo $data;
                exit;
            }
        }
        if (microtime(true) >= $deadline || connection_aborted()) break;
        usleep(15000);
    }
    http_response_code(204);
    header('Cache-Control: no-store');
    exit;
}

out(['error' => 'method'], 405);
