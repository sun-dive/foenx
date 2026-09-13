<?php
// Development router for `php -S`: serves site/ and maps /relay.php to server/relay.php, the same
// layout the deploy produces (relay.php beside index.html).
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/relay.php') { require __DIR__ . '/../server/relay.php'; return true; }
if ($path === '/book.php') { require __DIR__ . '/../server/book.php'; return true; }
return false; // let the built-in server serve site/ statically
