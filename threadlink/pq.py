"""
Post-quantum TLS 1.3 for ThreadLink (Captain's order 2026-10-31: "please do it again").

Two things change in the handshake, both standard code points that Wireshark
and OpenSSL 3.5+ already know:

  KEY AGREEMENT  X25519MLKEM768 (0x11EC, draft-ietf-tls-ecdhe-mlkem): a hybrid of
                 ML-KEM-768 (FIPS 203, the standardised CRYSTALS-Kyber) and X25519.
                 Client share = ML-KEM encapsulation key (1184 B) || X25519 (32 B);
                 server share = ML-KEM ciphertext (1088 B) || X25519 (32 B);
                 shared secret = ML-KEM secret || X25519 secret. An attacker has
                 to break BOTH to read the traffic, now or after recording it.

  SIGNATURES     ML-DSA-44/65/87 (0x0904/0x0905/0x0906, draft-ietf-tls-mldsa):
                 FIPS 204, the standardised CRYSTALS-Dilithium, in the certificate
                 and in CertificateVerify, for BOTH sides (ThreadLink is mutual).

aioquic 1.3.0 knows neither (its groups are X25519/X448/P-curves; upstream PR
#634 adds ML-KEM only, no ML-DSA, still open). This module teaches it, using the
ML-KEM and ML-DSA that `cryptography` >= 47 exposes from OpenSSL 3.5+.

How: three aioquic Context methods are replaced by copies of their 1.3.0 source
with the hybrid group added (marked "ThreadLink PQ" below); three small helpers
are wrapped. Every replaced/wrapped piece is fingerprinted - if the installed
aioquic is not the exact code we copied, NOTHING is patched and `status()` says
why (classical TLS keeps working; the link never breaks on an upgrade).

Compatibility during a rollout: a PQ client still offers its classical shares
after the hybrid one, so it can dial an old peer; a PQ server answers an old
client classically. ML-DSA certificates are the one hard edge: a peer that does
not advertise ML-DSA cannot verify one, so swap certificates only after every
node runs this code.

Switches (environment): THREADLINK_PQ=off -> patch nothing (rollback);
THREADLINK_PQ=require -> refuse any handshake that did not use X25519MLKEM768.

The copied methods are from aioquic 1.3.0, Copyright (c) Jeremy Lainé, BSD-3-Clause;
the full licence text is in LICENSE.aioquic beside this file.
"""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import logging
import os
from typing import Any, Optional, Union

log = logging.getLogger("threadlink.pq")

X25519MLKEM768 = 0x11EC
MLDSA44, MLDSA65, MLDSA87 = 0x0904, 0x0905, 0x0906

GROUP_NAMES = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
               0x001D: "x25519", 0x001E: "x448", X25519MLKEM768: "X25519MLKEM768"}
SIGALG_NAMES = {0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
                0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256",
                0x0807: "ed25519", 0x0808: "ed448",
                MLDSA44: "mldsa44", MLDSA65: "mldsa65", MLDSA87: "mldsa87"}

_MLKEM_EK, _MLKEM_CT, _X25519 = 1184, 1088, 32

# sha256[:16] of inspect.getsource() for what we replace or wrap, aioquic 1.3.0.
_EXPECTED = {
    "Context.__init__": "ad7c126ec299fb1b",
    "Context._client_send_hello": "6da001916fd666e1",
    "Context._client_handle_hello": "f510c85f7cd28de3",
    "Context._server_handle_hello": "2e069f962495392e",
    "Context._signature_algorithms_for_private_key": "19f832b37086fbc5",
    "Context._check_certificate_verify_signature": "ce203126c7387869",
    "signature_algorithm_params": "461545a95110aefd",
}

_state: dict[str, Any] = {"installed": False, "reason": "not installed yet"}


def mode() -> str:
    """'on' (default), 'off' or 'require' - from THREADLINK_PQ."""
    m = os.environ.get("THREADLINK_PQ", "on").strip().lower()
    return m if m in ("on", "off", "require") else "on"


def status() -> dict[str, Any]:
    """Whether the post-quantum patch is live in this process, and why not if not."""
    return {"post_quantum": _state["installed"], "mode": mode(), "reason": _state["reason"],
            "group": "X25519MLKEM768", "signatures": ["mldsa65", "mldsa87", "mldsa44"]}


def describe(tls: Any) -> dict[str, Any]:
    """What one finished handshake actually used, read from the aioquic Context."""
    if tls is None:
        return {}
    ks = getattr(tls, "key_schedule", None)
    suite = getattr(ks, "cipher_suite", None)
    g = getattr(tls, "threadlink_group", None)
    ours = getattr(tls, "threadlink_sigalg", None)
    theirs = getattr(tls, "threadlink_peer_sigalg", None)
    return {
        "key_exchange": GROUP_NAMES.get(g, None if g is None else f"0x{g:04x}"),
        "post_quantum_kex": g == X25519MLKEM768,
        "cipher": getattr(suite, "name", None),
        "our_signature": SIGALG_NAMES.get(ours, ours),
        "peer_signature": SIGALG_NAMES.get(theirs, theirs),
        "post_quantum_auth": (ours in (MLDSA44, MLDSA65, MLDSA87)
                              and theirs in (MLDSA44, MLDSA65, MLDSA87)),
    }


def _fingerprint(obj: Any) -> str:
    return hashlib.sha256(inspect.getsource(obj).encode()).hexdigest()[:16]


def install() -> dict[str, Any]:
    """Patch aioquic.tls once per process. Safe to call repeatedly."""
    if _state["installed"]:
        return status()
    if mode() == "off":
        _state["reason"] = "THREADLINK_PQ=off"
        return status()
    try:
        import aioquic
        from aioquic import tls as T
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
    except Exception as e:  # cryptography too old for ML-KEM / ML-DSA
        _state["reason"] = f"post-quantum primitives unavailable: {e}"
        log.warning("ThreadLink PQ OFF: %s", _state["reason"])
        return status()
    if not (backend.mlkem_supported() and backend.mldsa_supported()):
        _state["reason"] = "OpenSSL in cryptography lacks ML-KEM/ML-DSA (needs 3.5+)"
        log.warning("ThreadLink PQ OFF: %s", _state["reason"])
        return status()
    seen = {
        "Context.__init__": T.Context.__init__,
        "Context._client_send_hello": T.Context._client_send_hello,
        "Context._client_handle_hello": T.Context._client_handle_hello,
        "Context._server_handle_hello": T.Context._server_handle_hello,
        "Context._signature_algorithms_for_private_key": T.Context._signature_algorithms_for_private_key,
        "Context._check_certificate_verify_signature": T.Context._check_certificate_verify_signature,
        "signature_algorithm_params": T.signature_algorithm_params,
    }
    changed = [k for k, f in seen.items() if _fingerprint(f) != _EXPECTED[k]]
    if changed:
        _state["reason"] = (f"aioquic {aioquic.__version__} differs from the 1.3.0 code this patch "
                            f"was written against ({', '.join(changed)}); left classical")
        log.error("ThreadLink PQ OFF: %s", _state["reason"])
        return status()
    _patch(T)
    _state["installed"] = True
    _state["reason"] = f"aioquic {aioquic.__version__} patched"
    log.info("ThreadLink PQ ON: X25519MLKEM768 + ML-DSA (mode %s)", mode())
    return status()


def _patch(T: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric import ec, mldsa, mlkem, x448, x25519
    from aioquic.buffer import Buffer
    from aioquic.tls import (
        AlertHandshakeFailure, AlertIllegalParameter, AlertProtocolVersion,
        Certificate, CertificateRequest, CertificateVerify, ClientHello, Direction,
        EncryptedExtensions, Epoch, Finished, GROUP_TO_CURVE, Group, KeySchedule,
        KeyScheduleProxy, KeyShareEntry, OfferedPsks, ServerHello, State,
        SERVER_CONTEXT_STRING, Encoding,
        decode_public_key, encode_public_key, negotiate, push_certificate,
        push_certificate_request, push_certificate_verify, push_client_hello,
        push_encrypted_extensions, push_finished, push_message, push_server_hello,
        pull_client_hello, pull_server_hello,
    )

    mldsa_alg = {mldsa.MLDSA44PrivateKey: MLDSA44, mldsa.MLDSA65PrivateKey: MLDSA65,
                 mldsa.MLDSA87PrivateKey: MLDSA87}

    # ---- small wrappers ---------------------------------------------------
    orig_init = T.Context.__init__

    def __init__(self, *a: Any, **kw: Any) -> None:
        orig_init(self, *a, **kw)
        # ThreadLink PQ: hybrid first, classical shares still offered behind it.
        self._supported_groups.insert(0, X25519MLKEM768)
        self._signature_algorithms[:0] = [MLDSA65, MLDSA87, MLDSA44]
        self._tl_mlkem_key = None
        self._tl_x25519_key = None
        self.threadlink_group = None
        self.threadlink_sigalg = None
        self.threadlink_peer_sigalg = None

    orig_sap = T.signature_algorithm_params

    def signature_algorithm_params(signature_algorithm: int) -> tuple:
        if signature_algorithm in (MLDSA44, MLDSA65, MLDSA87):
            return tuple()          # pure ML-DSA, empty context (draft-ietf-tls-mldsa)
        return orig_sap(signature_algorithm)

    orig_for_key = T.Context._signature_algorithms_for_private_key

    def _signature_algorithms_for_private_key(self) -> list:
        for cls, alg in mldsa_alg.items():
            if isinstance(self.certificate_private_key, cls):
                return [alg]
        return orig_for_key(self)

    orig_check = T.Context._check_certificate_verify_signature

    def _check_certificate_verify_signature(self, verify: Any) -> None:
        orig_check(self, verify)
        self.threadlink_peer_sigalg = int(verify.algorithm)

    # ---- hybrid helpers ---------------------------------------------------
    def _hybrid_client_share(self) -> KeyShareEntry:
        self._tl_mlkem_key = mlkem.MLKEM768PrivateKey.generate()
        self._tl_x25519_key = x25519.X25519PrivateKey.generate()
        return (X25519MLKEM768, self._tl_mlkem_key.public_key().public_bytes_raw()
                + self._tl_x25519_key.public_key().public_bytes_raw())

    def _hybrid_client_secret(self, server_share: bytes) -> bytes:
        if len(server_share) != _MLKEM_CT + _X25519:
            raise AlertIllegalParameter("bad X25519MLKEM768 server share")
        ct, xpub = server_share[:_MLKEM_CT], server_share[_MLKEM_CT:]
        return (self._tl_mlkem_key.decapsulate(ct)
                + self._tl_x25519_key.exchange(x25519.X25519PublicKey.from_public_bytes(xpub)))

    def _hybrid_server(client_share: bytes) -> tuple[bytes, bytes]:
        if len(client_share) != _MLKEM_EK + _X25519:
            raise AlertIllegalParameter("bad X25519MLKEM768 client share")
        ek, xpub = client_share[:_MLKEM_EK], client_share[_MLKEM_EK:]
        secret, ct = mlkem.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
        xk = x25519.X25519PrivateKey.generate()
        shared = secret + xk.exchange(x25519.X25519PublicKey.from_public_bytes(xpub))
        return ct + xk.public_key().public_bytes_raw(), shared

    # ---- copies of aioquic 1.3.0 with the hybrid group added -------------
    def _client_send_hello(self, output_buf: Buffer) -> None:
        key_share: list[KeyShareEntry] = []
        supported_groups: list[int] = []

        for group in self._supported_groups:
            if group == X25519MLKEM768:                       # ThreadLink PQ
                key_share.append(_hybrid_client_share(self))
                supported_groups.append(X25519MLKEM768)
            elif group == Group.X25519:
                self._x25519_private_key = x25519.X25519PrivateKey.generate()
                key_share.append(
                    encode_public_key(self._x25519_private_key.public_key())
                )
                supported_groups.append(Group.X25519)
            elif group == Group.X448:
                self._x448_private_key = x448.X448PrivateKey.generate()
                key_share.append(encode_public_key(self._x448_private_key.public_key()))
                supported_groups.append(Group.X448)
            elif group == Group.GREASE:
                key_share.append((Group.GREASE, b"\x00"))
                supported_groups.append(Group.GREASE)
            elif group in GROUP_TO_CURVE:
                ec_private_key = ec.generate_private_key(GROUP_TO_CURVE[group]())
                self._ec_private_keys.append(ec_private_key)
                key_share.append(encode_public_key(ec_private_key.public_key()))
                supported_groups.append(group)

        assert len(key_share), "no key share entries"

        # Literal IPv4 and IPv6 addresses are not permitted in
        # Server Name Indication (SNI) hostname.
        try:
            ipaddress.ip_address(self._server_name)
        except ValueError:
            server_name = self._server_name
        else:
            server_name = None

        hello = ClientHello(
            random=self.client_random,
            legacy_session_id=self.legacy_session_id,
            cipher_suites=[int(x) for x in self._cipher_suites],
            legacy_compression_methods=self._legacy_compression_methods,
            alpn_protocols=self._alpn_protocols,
            key_share=key_share,
            psk_key_exchange_modes=(
                self._psk_key_exchange_modes
                if (self.session_ticket or self.new_session_ticket_cb is not None)
                else None
            ),
            server_name=server_name,
            signature_algorithms=self._signature_algorithms,
            supported_groups=supported_groups,
            supported_versions=self._supported_versions,
            other_extensions=self.handshake_extensions,
        )

        # PSK
        if self.session_ticket and self.session_ticket.is_valid:
            self._key_schedule_psk = KeySchedule(self.session_ticket.cipher_suite)
            self._key_schedule_psk.extract(self.session_ticket.resumption_secret)
            binder_key = self._key_schedule_psk.derive_secret(b"res binder")
            binder_length = self._key_schedule_psk.algorithm.digest_size

            # update hello
            if self.session_ticket.max_early_data_size is not None:
                hello.early_data = True
            hello.pre_shared_key = OfferedPsks(
                identities=[
                    (self.session_ticket.ticket, self.session_ticket.obfuscated_age)
                ],
                binders=[bytes(binder_length)],
            )

            # serialize hello without binder
            # ThreadLink PQ: 1024 held a classical hello; the hybrid share alone is 1216 B.
            tmp_buf = Buffer(capacity=8192)
            push_client_hello(tmp_buf, hello)

            # calculate binder
            hash_offset = tmp_buf.tell() - binder_length - 3
            self._key_schedule_psk.update_hash(tmp_buf.data_slice(0, hash_offset))
            binder = self._key_schedule_psk.finished_verify_data(binder_key)
            hello.pre_shared_key.binders[0] = binder
            self._key_schedule_psk.update_hash(
                tmp_buf.data_slice(hash_offset, hash_offset + 3) + binder
            )

            # calculate early data key
            if hello.early_data:
                early_key = self._key_schedule_psk.derive_secret(b"c e traffic")
                self.update_traffic_key_cb(
                    Direction.ENCRYPT,
                    Epoch.ZERO_RTT,
                    self._key_schedule_psk.cipher_suite,
                    early_key,
                )

        self._key_schedule_proxy = KeyScheduleProxy(self._cipher_suites)
        self._key_schedule_proxy.extract(None)

        with push_message(self._key_schedule_proxy, output_buf):
            push_client_hello(output_buf, hello)

        self._set_state(State.CLIENT_EXPECT_SERVER_HELLO)

    def _client_handle_hello(self, input_buf: Buffer, output_buf: Buffer) -> None:
        peer_hello = pull_server_hello(input_buf)

        cipher_suite = negotiate(
            self._cipher_suites,
            [peer_hello.cipher_suite],
            AlertHandshakeFailure("Unsupported cipher suite"),
        )
        if peer_hello.compression_method not in self._legacy_compression_methods:
            raise AlertIllegalParameter(
                "ServerHello has a compression method we did not advertise"
            )
        if peer_hello.supported_version not in self._supported_versions:
            raise AlertIllegalParameter(
                "ServerHello has a version we did not advertise"
            )

        # select key schedule
        if peer_hello.pre_shared_key is not None:
            if (
                self._key_schedule_psk is None
                or peer_hello.pre_shared_key != 0
                or cipher_suite != self._key_schedule_psk.cipher_suite
            ):
                raise AlertIllegalParameter
            self.key_schedule = self._key_schedule_psk
            self._session_resumed = True
        else:
            self.key_schedule = self._key_schedule_proxy.select(cipher_suite)
        self._key_schedule_psk = None
        self._key_schedule_proxy = None

        # perform key exchange
        shared_key: Optional[bytes] = None
        group = peer_hello.key_share[0]
        if group == X25519MLKEM768 and self._tl_mlkem_key is not None:   # ThreadLink PQ
            shared_key = _hybrid_client_secret(self, peer_hello.key_share[1])
        else:
            if mode() == "require":
                raise AlertHandshakeFailure("THREADLINK_PQ=require: peer did not use X25519MLKEM768")
            peer_public_key = decode_public_key(peer_hello.key_share)
            if (
                isinstance(peer_public_key, x25519.X25519PublicKey)
                and self._x25519_private_key is not None
            ):
                shared_key = self._x25519_private_key.exchange(peer_public_key)
            elif (
                isinstance(peer_public_key, x448.X448PublicKey)
                and self._x448_private_key is not None
            ):
                shared_key = self._x448_private_key.exchange(peer_public_key)
            elif isinstance(peer_public_key, ec.EllipticCurvePublicKey):
                for ec_private_key in self._ec_private_keys:
                    if (
                        ec_private_key.public_key().curve.__class__
                        == peer_public_key.curve.__class__
                    ):
                        shared_key = ec_private_key.exchange(ec.ECDH(), peer_public_key)
        assert shared_key is not None
        self.threadlink_group = int(group)

        self.key_schedule.update_hash(input_buf.data)
        self.key_schedule.extract(shared_key)

        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.HANDSHAKE, b"s hs traffic"
        )

        self._set_state(State.CLIENT_EXPECT_ENCRYPTED_EXTENSIONS)

    def _server_handle_hello(
        self,
        input_buf: Buffer,
        initial_buf: Buffer,
        handshake_buf: Buffer,
        onertt_buf: Buffer,
    ) -> None:
        peer_hello = pull_client_hello(input_buf)

        # negotiate parameters
        cipher_suite = negotiate(
            self._cipher_suites,
            peer_hello.cipher_suites,
            AlertHandshakeFailure("No supported cipher suite"),
        )
        compression_method = negotiate(
            self._legacy_compression_methods,
            peer_hello.legacy_compression_methods,
            AlertHandshakeFailure("No supported compression method"),
        )
        psk_key_exchange_mode = negotiate(
            self._psk_key_exchange_modes, peer_hello.psk_key_exchange_modes
        )
        signature_algorithm = negotiate(
            self._signature_algorithms_for_private_key(),
            peer_hello.signature_algorithms,
            AlertHandshakeFailure("No supported signature algorithm"),
        )
        supported_version = negotiate(
            self._supported_versions,
            peer_hello.supported_versions,
            AlertProtocolVersion("No supported protocol version"),
        )

        # negotiate ALPN
        if self._alpn_protocols is not None:
            self.alpn_negotiated = negotiate(
                self._alpn_protocols,
                peer_hello.alpn_protocols,
                AlertHandshakeFailure("No common ALPN protocols"),
            )

        self.client_random = peer_hello.random
        self.server_random = os.urandom(32)
        self.legacy_session_id = peer_hello.legacy_session_id
        self.received_extensions = peer_hello.other_extensions

        # notify application
        if self.alpn_cb:
            self.alpn_cb(self.alpn_negotiated)

        # select key schedule
        pre_shared_key = None
        if (
            self.get_session_ticket_cb is not None
            and psk_key_exchange_mode is not None
            and peer_hello.pre_shared_key is not None
            and len(peer_hello.pre_shared_key.identities) == 1
            and len(peer_hello.pre_shared_key.binders) == 1
        ):
            # ask application to find session ticket
            identity = peer_hello.pre_shared_key.identities[0]
            session_ticket = self.get_session_ticket_cb(identity[0])

            # validate session ticket
            if (
                session_ticket is not None
                and session_ticket.is_valid
                and session_ticket.cipher_suite == cipher_suite
            ):
                self.key_schedule = KeySchedule(cipher_suite)
                self.key_schedule.extract(session_ticket.resumption_secret)

                binder_key = self.key_schedule.derive_secret(b"res binder")
                binder_length = self.key_schedule.algorithm.digest_size

                hash_offset = input_buf.tell() - binder_length - 3
                binder = input_buf.data_slice(
                    hash_offset + 3, hash_offset + 3 + binder_length
                )

                self.key_schedule.update_hash(input_buf.data_slice(0, hash_offset))
                expected_binder = self.key_schedule.finished_verify_data(binder_key)

                if binder != expected_binder:
                    raise AlertHandshakeFailure("PSK validation failed")

                self.key_schedule.update_hash(
                    input_buf.data_slice(hash_offset, hash_offset + 3 + binder_length)
                )
                self._session_resumed = True

                # calculate early data key
                if peer_hello.early_data:
                    early_key = self.key_schedule.derive_secret(b"c e traffic")
                    self.early_data_accepted = True
                    self.update_traffic_key_cb(
                        Direction.DECRYPT,
                        Epoch.ZERO_RTT,
                        self.key_schedule.cipher_suite,
                        early_key,
                    )

                pre_shared_key = 0

        # if PSK is not used, initialize key schedule
        if pre_shared_key is None:
            self.key_schedule = KeySchedule(cipher_suite)
            self.key_schedule.extract(None)
            self.key_schedule.update_hash(input_buf.data)

        # perform key exchange
        public_key: Union[
            ec.EllipticCurvePublicKey, x25519.X25519PublicKey, x448.X448PublicKey
        ]
        shared_key: Optional[bytes] = None
        server_share: Optional[KeyShareEntry] = None
        for key_share in peer_hello.key_share:
            if key_share[0] == X25519MLKEM768:                    # ThreadLink PQ
                share, shared_key = _hybrid_server(key_share[1])
                server_share = (X25519MLKEM768, share)
                break
            if mode() == "require":
                continue
            peer_public_key = decode_public_key(key_share)
            if isinstance(peer_public_key, x25519.X25519PublicKey):
                self._x25519_private_key = x25519.X25519PrivateKey.generate()
                public_key = self._x25519_private_key.public_key()
                shared_key = self._x25519_private_key.exchange(peer_public_key)
                break
            elif isinstance(peer_public_key, x448.X448PublicKey):
                self._x448_private_key = x448.X448PrivateKey.generate()
                public_key = self._x448_private_key.public_key()
                shared_key = self._x448_private_key.exchange(peer_public_key)
                break
            elif isinstance(peer_public_key, ec.EllipticCurvePublicKey):
                ec_private_key = ec.generate_private_key(GROUP_TO_CURVE[key_share[0]]())
                self._ec_private_keys.append(ec_private_key)
                public_key = ec_private_key.public_key()
                shared_key = ec_private_key.exchange(ec.ECDH(), peer_public_key)
                break
        if shared_key is None and mode() == "require":
            raise AlertHandshakeFailure("THREADLINK_PQ=require: client offered no X25519MLKEM768 share")
        assert shared_key is not None
        if server_share is None:
            server_share = encode_public_key(public_key)
        self.threadlink_group = int(server_share[0])

        # send hello
        hello = ServerHello(
            random=self.server_random,
            legacy_session_id=self.legacy_session_id,
            cipher_suite=cipher_suite,
            compression_method=compression_method,
            key_share=server_share,
            pre_shared_key=pre_shared_key,
            supported_version=supported_version,
        )
        with push_message(self.key_schedule, initial_buf):
            push_server_hello(initial_buf, hello)
        self.key_schedule.extract(shared_key)

        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.HANDSHAKE, b"s hs traffic"
        )
        self._setup_traffic_protection(
            Direction.DECRYPT, Epoch.HANDSHAKE, b"c hs traffic"
        )

        # send encrypted extensions
        with push_message(self.key_schedule, handshake_buf):
            push_encrypted_extensions(
                handshake_buf,
                EncryptedExtensions(
                    alpn_protocol=self.alpn_negotiated,
                    early_data=self.early_data_accepted,
                    other_extensions=self.handshake_extensions,
                ),
            )

        if pre_shared_key is None:
            # send certificate request
            if self._request_client_certificate:
                with push_message(self.key_schedule, handshake_buf):
                    push_certificate_request(
                        handshake_buf,
                        CertificateRequest(
                            request_context=b"",
                            signature_algorithms=self._signature_algorithms,
                        ),
                    )

            # send certificate
            with push_message(self.key_schedule, handshake_buf):
                push_certificate(
                    handshake_buf,
                    Certificate(
                        request_context=b"",
                        certificates=[
                            (x.public_bytes(Encoding.DER), b"")
                            for x in [self.certificate] + self.certificate_chain
                        ],
                    ),
                )

            # send certificate verify
            signature = self.certificate_private_key.sign(
                self.key_schedule.certificate_verify_data(SERVER_CONTEXT_STRING),
                *signature_algorithm_params(signature_algorithm),
            )
            self.threadlink_sigalg = int(signature_algorithm)
            with push_message(self.key_schedule, handshake_buf):
                push_certificate_verify(
                    handshake_buf,
                    CertificateVerify(
                        algorithm=signature_algorithm, signature=signature
                    ),
                )

        # send finished
        with push_message(self.key_schedule, handshake_buf):
            push_finished(
                handshake_buf,
                Finished(
                    verify_data=self.key_schedule.finished_verify_data(self._enc_key)
                ),
            )

        # prepare traffic keys
        assert self.key_schedule.generation == 2
        self.key_schedule.extract(None)
        self._setup_traffic_protection(
            Direction.ENCRYPT, Epoch.ONE_RTT, b"s ap traffic"
        )
        self._next_dec_key = self.key_schedule.derive_secret(b"c ap traffic")

        self._psk_key_exchange_mode = psk_key_exchange_mode
        if self._request_client_certificate:
            self._set_state(State.SERVER_EXPECT_CERTIFICATE)
        else:
            self._server_expect_finished(onertt_buf)

    # The client signs its CertificateVerify inside aioquic's own
    # _client_handle_finished; record what it used without copying that method.
    orig_negotiate = T.negotiate

    T.Context.__init__ = __init__
    T.Context._client_send_hello = _client_send_hello
    T.Context._client_handle_hello = _client_handle_hello
    T.Context._server_handle_hello = _server_handle_hello
    T.Context._signature_algorithms_for_private_key = _signature_algorithms_for_private_key
    T.Context._check_certificate_verify_signature = _check_certificate_verify_signature
    T.signature_algorithm_params = signature_algorithm_params

    orig_client_finished = T.Context._client_handle_finished

    def _client_handle_finished(self, input_buf: Buffer, output_buf: Buffer) -> None:
        if self._certificate_request is not None and self.certificate_private_key is not None:
            alg = orig_negotiate(self._signature_algorithms_for_private_key(),
                                 self._certificate_request.signature_algorithms)
            self.threadlink_sigalg = None if alg is None else int(alg)
        orig_client_finished(self, input_buf, output_buf)

    T.Context._client_handle_finished = _client_handle_finished
