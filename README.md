# foen

A video call as a covenant chain tip with no chain behind it. Each side signs every chunk it sends over
the previous tip; the other side verifies, plays, keeps only the new tip and drops the chunk. Both sides
connect out over HTTPS to a relay that holds one tip per direction and validates nothing.

Design: https://jetmora.org/light-speed-transfers.html

## What is here

| path | what |
|---|---|
| `site/index.html` | the call: one button, camera and microphone as signed ticks |
| `site/test.html` | the relay measurement page: signed dummy chunks at call rate |
| `site/js/foen.mjs` | entry format, signer, verifier, relay client, the measurement |
| `site/js/call.mjs` | capture, WebCodecs VP8 + Opus, one signed tick per 100 ms, decode and play |
| `site/js/engine/` | unmodified copies of the Phar Lap 2 wallet engine (secp256k1, ECDSA, RFC 6979, bytes) |
| `site/js/vendor/noble-hashes/` | @noble/hashes 2.4.0 (MIT), the subset the engine imports |
| `server/relay.php` | the relay: POST a tip, long-poll for the other side's |
| `tools/dev.sh` | serve it locally with PHP's built-in server |
| `tools/headless-pair.mjs` | two headless Chromium profiles through one relay, numbers from both |
| `tools/headless-call.mjs` | a real call between two headless profiles with a synthetic camera and microphone |
| `tools/host.sh` | serve the page and the relay from this machine over HTTPS: the device is the server |

No build step. The page loads ES modules directly; an import map resolves the hashing library.

## The device is the server

Shared hosting cannot carry a call: its anti-bot layer rate-limits per address, and a call is ten requests
a second for minutes. So the relay runs on one of the two devices, and the other connects out to it, the
way any browser connects to any site. No third party, no STUN, no punch-through.

```sh
sh tools/host.sh call.foen.xyz     # a name whose A record points at this connection's public IPv4
```

Once, outside the script: forward TCP 80 to this machine's 8080 and TCP 443 to 8443 on the router. Caddy
(`tools/bin/caddy`, a single binary from github.com/caddyserver/caddy/releases) listens on the high ports
so nothing needs root, gets the certificate from Let's Encrypt through the forwards, and proxies to PHP's
built-in server with flushing on, so the streaming receive works as designed.

## Run locally

```sh
sh tools/dev.sh                                  # http://127.0.0.1:8088/
node tools/headless-pair.mjs http://127.0.0.1:8088/ 30 16384 100   # seconds, chunk bytes, interval ms
```

Or open the page in two browsers on two machines: the first shows a link, the second opens it, both
press Start.
