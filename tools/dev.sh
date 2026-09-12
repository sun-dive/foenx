#!/bin/sh
# Serve the page and the relay locally: http://127.0.0.1:8088/
# ⚠ Workers matter: with one, every post queues behind a long-poll and the call crawls.
cd "$(dirname "$0")/.." && PHP_CLI_SERVER_WORKERS=8 exec php -S 127.0.0.1:${1:-8088} -t site tools/router.php
