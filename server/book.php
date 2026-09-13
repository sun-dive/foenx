<?php
// © 2026 sun-dive.
//
// THE PHONE BOOK. A listing is a signed entry (foen.mjs entry format) whose payload is JSON
// {"name": "...", "pub": "<33-byte hex>"} signed by that very key. The host keeps one blob per key and
// hands them all out; every page verifies the signatures itself. Nothing here is trusted.
//
//   POST book.php            body = the signed entry           → {"ok":true}
//   GET  book.php            → all listings, newest first, framed as [u32 BE length][entry]...
// Listings untouched for TTL days are removed.
declare(strict_types=1);

const MAX_ENTRY = 4096;
const MAX_LIST  = 200;
const TTL_DAYS  = 30;

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
        if (is_dir($sibling)) return $sibling . '/book';
    }
    return __DIR__ . '/data/book';
})();
// Separate books by name (?b=test), so test runs never appear in the real one.
$bookName = $_GET['b'] ?? '';
if ($bookName !== '') {
    if (!preg_match('/^[a-z0-9-]{1,16}$/', $bookName)) out(['error' => 'bad book name'], 400);
    $dataRoot .= "-$bookName";
}
if (!is_dir($dataRoot)) @mkdir($dataRoot, 0700, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = file_get_contents('php://input', false, null, 0, MAX_ENTRY + 1);
    if ($body === false || strlen($body) < 104) out(['error' => 'not an entry'], 400);
    if (strlen($body) > MAX_ENTRY) out(['error' => 'too large'], 413);
    // A listing is a jetmora entry: version(4) varint(1) prevEntry(32) index(4) varint(unlocking) then the
    // unlocking script <sig‖0x01> <pub>. The file is named by the key, so one listing per key.
    $p = 41;
    $ulen = ord($body[$p] ?? "\0"); $p++;                       // unlocking length (one-byte varint here)
    $slen = ord($body[$p] ?? "\0"); $p++;                       // push of the signature
    $p += $slen;
    if (($body[$p] ?? '') !== "\x21") out(['error' => 'bad key'], 400);  // push of a 33-byte key
    $pub = bin2hex(substr($body, $p + 1, 33));
    if (!preg_match('/^0[23][0-9a-f]{64}$/', $pub) || $ulen !== $slen + 35) out(['error' => 'bad key'], 400);
    $tmp = "$dataRoot/$pub.tmp";
    if (file_put_contents($tmp, $body) !== strlen($body)) { @unlink($tmp); out(['error' => 'write failed'], 500); }
    rename($tmp, "$dataRoot/$pub.e");
    out(['ok' => true]);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $files = glob("$dataRoot/*.e") ?: [];
    $now = time();
    usort($files, static fn ($a, $b) => filemtime($b) <=> filemtime($a));
    http_response_code(200);
    header('Content-Type: application/octet-stream');
    header('Cache-Control: no-store');
    $n = 0;
    foreach ($files as $f) {
        if ($now - filemtime($f) > TTL_DAYS * 86400) { @unlink($f); continue; }
        if ($n++ >= MAX_LIST) break;
        $data = file_get_contents($f);
        if ($data === false || $data === '') continue;
        echo pack('N', strlen($data)), $data;
    }
    exit;
}

out(['error' => 'method'], 405);
