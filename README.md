# foen

A video call as a covenant chain tip with no chain behind it. Each side signs every chunk it sends over
the previous tip; the other side verifies, plays, keeps only the new tip and drops the chunk. Both sides
connect out over HTTPS to a relay that holds one tip per direction and validates nothing.

Design: https://jetmora.org/light-speed-transfers.html

## What is here

| path | what |
|---|---|
| `site/index.html` | the page. Today it measures the relay with signed dummy chunks; the camera comes next |
| `site/js/foen.mjs` | entry format, signer, verifier, relay client, the measurement |
| `site/js/engine/` | unmodified copies of the Phar Lap 2 wallet engine (secp256k1, ECDSA, RFC 6979, bytes) |
| `site/js/vendor/noble-hashes/` | @noble/hashes 2.4.0 (MIT), the subset the engine imports |
| `server/relay.php` | the relay: POST a tip, long-poll for the other side's |
| `tools/dev.sh` | serve it locally with PHP's built-in server |
| `tools/headless-pair.mjs` | two headless Chromium profiles through one relay, numbers from both |

No build step. The page loads ES modules directly; an import map resolves the hashing library.

## Run

```sh
sh tools/dev.sh                                  # http://127.0.0.1:8088/
node tools/headless-pair.mjs http://127.0.0.1:8088/ 30 16384 100   # seconds, chunk bytes, interval ms
```

Or open the page in two browsers on two machines: the first shows a link, the second opens it, both
press Start.
