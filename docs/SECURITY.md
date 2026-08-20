# ThreadLink security posture

What you get today, what you do not, and where the trust layer grows.

## What is defended now

- **Encryption is not optional.** There is no plaintext QUIC; every connection
  is TLS 1.3. A passive observer on the path sees UDP datagrams and nothing
  else. ALPN (`threadlink/1`) makes a ThreadLink peer and any other QUIC
  application refuse each other during the handshake.
- **Framing is hostile-input safe.** Bad magic, oversized bodies (> 4 MiB),
  and undecodable JSON are rejected per-stream (`WireError` → stream reset),
  never crashing the connection or allocating attacker-chosen amounts.
- **A crashing handler is contained.** Application handler exceptions come
  back to the peer as an `ERROR` frame; the connection survives.
- **Keys are generated locally** (`ensure_cert`), written `0600`, and the repo
  `.gitignore` refuses the whole `certs/` directory so they cannot be
  committed by accident.

## What is NOT defended yet — read this before leaving a trusted network

- **Peer authentication is off by default.** `client_config(verify=False)` is
  the sprint default because agents on a LAN use self-signed certificates.
  The connection is still encrypted, but an *active* man-in-the-middle on the
  path is not prevented. This is a stated trade-off, not an oversight.
- **Any peer that completes a handshake may speak.** There is no authorization
  layer: reachability currently implies permission to send frames.

## The hooks the trust layer grows into

- `client_config(verify=True, cafile=...)` — point every agent at a shared CA
  and the MITM gap closes with no API change.
- `spki_pin(cert)` — a stable base64 pin of a peer's public key. Agents already
  exchange pins in application HELLOs (see ThreadHello); enforcing
  pin-on-first-use at dial time is the designed next step.
- **Application-layer provenance.** ThreadLink deliberately does not vouch for
  message *content*. Protocols above it (ThreadHello marks every route
  observation with its `origin` and discounts second-hand evidence) must treat
  a peer's claims as claims. Transport trust and content trust are different
  problems, and keeping them separate is what lets each mature independently.

## Reporting

This is sprint-stage software. If you find a hole, open a GitHub issue —
honest bug reports are worth more to this project than polish.
