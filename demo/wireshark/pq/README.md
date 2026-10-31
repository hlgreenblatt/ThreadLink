# Post-quantum ThreadLink, on the wire

`threadlink-pq.dsb.pcapng` is one real handshake plus one ThreadChat letter between two ThreadLink
nodes (loopback, udp/4433), with the TLS secrets embedded so Wireshark decrypts it on open.
Tested with Wireshark 4.6.4, which names the hybrid group and the ML-DSA signatures; load `wireshark/threadlink.lua` to see the ThreadLink frames.

| what | where to look | value |
|---|---|---|
| key agreement | ClientHello / ServerHello, key_share | `X25519MLKEM768` (0x11ec): ML-KEM-768 + X25519, 1216 B / 1120 B shares |
| identities | Certificate (both directions) | ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204), OID 2.16.840.1.101.3.4.3.18, 5,560 B |
| proof of possession | CertificateVerify (both directions) | `mldsa65` (0x0905), 3,309-byte signatures |
| record protection | ServerHello | TLS_CHACHA20_POLY1305_SHA256 |
| application | stream 4 | ThreadChat `CHAT_MSG node-a -> node-b`, decrypted |

Wireshark 4.6 prints the ML-DSA-65 certificate OID as `sigAlgs.18`; that OID is id-ml-dsa-65.
Regenerate with `pq_handshake.py` (see its docstring). The identities are throwaway.
