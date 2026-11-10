# TLS gateway

`gateway/gateway.js` accepts TLS HTTP/2 from clients and opens TLS to a loopback Lore server. It preserves the gRPC path, forwards data with backpressure, and forwards trailers. An allow list is a network boundary. It is not a repository grant.

`scripts/gen-certs.py` builds a CA and two server certificates. The CA extensions are written explicitly, including basic constraints and authority key identifier. The default lifetime is 1825 days for the CA and 825 days for server certificates. Do not commit the generated private keys.

On Windows, the Lore 0.10.1 CLI used in the lab did not trust a CA installed only in the current-user root store. Point `ca_file` in the lore-mono config at the CA file. lore-mono sets `SSL_CERT_FILE` for the Lore child process only.

An independent Linux machine has not run this path. That check is NOT_RUN.
