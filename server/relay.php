<?php
// © 2026 sun-dive.
//
// THE RELAY. Per direction of a call it keeps a SHORT RING of the newest entries (RING of them, a few
// seconds of a call) and nothing else. It does not parse, verify or retain entries. Both parties connect
// out over HTTPS; this is where the two connections meet, and it is replaceable without either noticing.
//
//   POST relay.php?c=<call>&d=<a|b>&s=<seq>    body = the entry (binary)  → {"ok":true,"seq":N}
//   GET  relay.php?c=<call>&d=<a|b>&after=<n>&wait=<ms>
//        → every entry with seq > n still in the ring, oldest first, framed as [u32 BE length][entry]...
//          with X-Seq = the newest seq and X-Count = how many; 204 when nothing newer arrived in `wait`.
//   GET  relay.php?c=<call>&d=<a|b>&after=<n>&wait=<ms>&stream=1
//        → the same framing, but the connection stays open for `wait` ms and each entry is written and
//          flushed the moment it arrives. The client reconnects with the last seq it saw when it closes.
//
// ⚠ A call's data lives OUTSIDE the docroot when a sibling directory exists (as jetmora-data does),
//   else in ./data for local development. Whatever happens, an answer carries a body or a 204.
declare(strict_types=1);

const MAX_ENTRY = 262144;   // bytes; a video chunk is tens of KB
const MAX_WAIT  = 25000;    // ms; under the host's request time limit
const TTL       = 3600;     // s; a call directory untouched this long is removed
const RING      = 64;       // entries kept per direction; older ones are unlinked as new ones arrive

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
$seqFile = "$callDir/$dir.seq";
$entryFile = static fn (int $n): string => "$callDir/$dir.$n.e";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $seq = (int)($_GET['s'] ?? -1);
    if ($seq < 0) out(['error' => 'bad seq'], 400);
    $body = file_get_contents('php://input', false, null, 0, MAX_ENTRY + 1);
    if ($body === false || $body === '') out(['error' => 'empty entry'], 400);
    if (strlen($body) > MAX_ENTRY) out(['error' => 'entry too large'], 413);
    if (!is_dir($callDir) && !@mkdir($callDir, 0700, true) && !is_dir($callDir)) out(['error' => 'cannot create call'], 500);

    $cur = (int)(@file_get_contents($seqFile) ?: -1);
    // Below the ring's floor there is nothing to keep: the receiver has moved on.
    if ($seq <= $cur - RING) out(['ok' => true, 'seq' => $seq, 'dropped' => true]);

    // tmp + rename: a reader sees a whole entry or none.
    $tmp = $entryFile($seq) . '.tmp';
    if (file_put_contents($tmp, $body) !== strlen($body)) { @unlink($tmp); out(['error' => 'write failed'], 500); }
    if (!rename($tmp, $entryFile($seq))) { @unlink($tmp); out(['error' => 'rename failed'], 500); }
    if ($seq > $cur) {
        $tmpS = "$seqFile.$seq.tmp";
        file_put_contents($tmpS, (string)$seq);
        rename($tmpS, $seqFile);
        @unlink($entryFile($seq - RING));   // the one that just fell off the ring
    }
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

/** The entries newer than $after still in the ring, framed, oldest first. */
function framesSince(int $after, int $cur, callable $entryFile): array {
    $frames = []; $count = 0;
    for ($n = max($after + 1, $cur - RING + 1); $n <= $cur; $n++) {
        $data = @file_get_contents($entryFile($n));
        if ($data === false || $data === '') continue;   // never posted, or already rotated out
        $frames[] = pack('N', strlen($data)) . $data; $count++;
    }
    return [$frames, $count];
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && ($_GET['stream'] ?? '') === '1') {
    // Streaming: headers now, then write-and-flush each batch as it arrives until the deadline.
    $after = (int)($_GET['after'] ?? -1);
    $wait  = min(MAX_WAIT, max(0, (int)($_GET['wait'] ?? 0)));
    $deadline = microtime(true) + $wait / 1000;
    ignore_user_abort(false);
    @ini_set('zlib.output_compression', '0');
    @ini_set('output_buffering', '0');
    while (ob_get_level() > 0) ob_end_flush();
    http_response_code(200);
    header('Content-Type: application/octet-stream');
    header('Cache-Control: no-store');
    header('X-Accel-Buffering: no');
    header('X-LiteSpeed-Cache-Control: no-cache');
    flush();
    while (true) {
        clearstatcache(true, $seqFile);
        $cur = (int)(@file_get_contents($seqFile) ?: -1);
        if ($cur > $after) {
            [$frames, $count] = framesSince($after, $cur, $entryFile);
            if ($count > 0) { echo implode('', $frames); flush(); }
            $after = $cur;
        }
        if (microtime(true) >= $deadline || connection_aborted()) break;
        usleep(15000);
    }
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $after = (int)($_GET['after'] ?? -1);
    $wait  = min(MAX_WAIT, max(0, (int)($_GET['wait'] ?? 0)));
    $deadline = microtime(true) + $wait / 1000;
    ignore_user_abort(false);
    while (true) {
        clearstatcache(true, $seqFile);
        $cur = (int)(@file_get_contents($seqFile) ?: -1);
        if ($cur > $after) {
            [$frames, $count] = framesSince($after, $cur, $entryFile);
            if ($count > 0) {
                http_response_code(200);
                header('Content-Type: application/octet-stream');
                header('X-Seq: ' . $cur);
                header('X-Count: ' . $count);
                header('Cache-Control: no-store');
                echo implode('', $frames);
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
