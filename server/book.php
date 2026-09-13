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
if (!is_dir($dataRoot)) @mkdir($dataRoot, 0700, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = file_get_contents('php://input', false, null, 0, MAX_ENTRY + 1);
    if ($body === false || strlen($body) < 104) out(['error' => 'not an entry'], 400);
    if (strlen($body) > MAX_ENTRY) out(['error' => 'too large'], 413);
    // The sender's key sits at bytes 69..102 of the header; the file is named by it, so one listing per key.
    $pub = bin2hex(substr($body, 69, 33));
    if (!preg_match('/^0[23][0-9a-f]{64}$/', $pub)) out(['error' => 'bad key'], 400);
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
