<?php
// © 2026 sun-dive.
//
// THE CONTACT FORM. A message is written to a file outside the docroot for the operator to read; no
// email is involved anywhere. No address is stored with a message. A per-address budget of a few
// messages an hour is kept as a salted hash that lives for an hour, and a honeypot field catches the
// bots that fill every box.
//
//   POST contact.php   fields: message (required), reply (optional: a foen number or whatever they
//                      want to be reached on), website (honeypot: must be empty)   → {"ok":true}
declare(strict_types=1);

const MAX_MESSAGE = 4000;
const MAX_REPLY   = 200;
const PER_HOUR    = 5;

function out(array $body, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES), "\n";
    exit;
}
if ($_SERVER['REQUEST_METHOD'] !== 'POST') out(['error' => 'method'], 405);

$dataRoot = (static function (): string {
    $root = $_SERVER['DOCUMENT_ROOT'] ?? '';
    if ($root !== '') {
        $sibling = dirname(rtrim($root, '/')) . '/foen-data';
        if (is_dir($sibling)) return $sibling . '/contact';
    }
    return __DIR__ . '/data/contact';
})();
if (!is_dir($dataRoot)) @mkdir($dataRoot, 0700, true);
if (!is_dir("$dataRoot/.rate")) @mkdir("$dataRoot/.rate", 0700, true);

$message = trim((string)($_POST['message'] ?? ''));
$reply   = trim((string)($_POST['reply'] ?? ''));
$trap    = (string)($_POST['website'] ?? '');
// A bot that fills the honeypot is told "ok" and nothing is kept: same answer as a real message.
if ($trap !== '') out(['ok' => true]);
if ($message === '' || strlen($message) > MAX_MESSAGE) out(['error' => 'a message is one to four thousand characters'], 400);
if (strlen($reply) > MAX_REPLY) out(['error' => 'the reply line is too long'], 400);

// The budget: a salted hash of the address, five messages an hour. The salt is per boot, so the hash
// cannot be turned back into an address later, and the file is gone within an hour anyway.
$saltFile = "$dataRoot/.rate/salt";
$salt = @file_get_contents($saltFile);
if ($salt === false || strlen($salt) < 16) { $salt = bin2hex(random_bytes(16)); @file_put_contents($saltFile, $salt); }
$h = hash('sha256', $salt . ($_SERVER['REMOTE_ADDR'] ?? ''));
$rateFile = "$dataRoot/.rate/$h";
$now = time();
$stamps = array_filter(array_map('intval', explode("\n", (string)@file_get_contents($rateFile))), static fn ($t) => $t > $now - 3600);
// Over budget: say ok, keep nothing. The sender learns nothing about where the edge is.
if (count($stamps) >= PER_HOUR) out(['ok' => true]);
$stamps[] = $now;
@file_put_contents($rateFile, implode("\n", $stamps));
foreach (glob("$dataRoot/.rate/*") ?: [] as $f) { if ($f !== $saltFile && $now - (int)filemtime($f) > 3600) @unlink($f); }

$name = gmdate('Y-m-d\TH-i-s\Z') . '-' . bin2hex(random_bytes(3)) . '.txt';
$body = "when: " . gmdate('c') . "\nreply: " . str_replace(["\r", "\n"], ' ', $reply) . "\n\n" . $message . "\n";
if (@file_put_contents("$dataRoot/$name", $body) === false) out(['error' => 'could not keep the message'], 500);
out(['ok' => true]);
