---
title: "ThreadLink: A QUIC-Based Agent-to-Agent Comlink"
abbrev: ThreadLink
docname: draft-greenblatt-threadlink-00
category: exp
ipr: trust200902
area: Applications
workgroup: Independent Submission
keyword: [QUIC, agent, A2A, comlink, TLS]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - ins: L. Greenblatt
    name: Larry Greenblatt
    organization: InterNetwork Defense
    email: hlgreenblatt@internetworkdefense.com
--- abstract

ThreadLink is a minimal agent-to-agent (A2A) comlink: a framed message
transport that runs over QUIC (RFC 9000) with mandatory TLS 1.3. It gives a
swarm of autonomous software agents a way to exchange messages directly, peer to
peer, without a central broker, and to keep a session alive across a change of
network path. ThreadLink defines only framing and connection lifecycle; the
application protocols that ride on it (route-table gossip, agent chat) are out of
scope and identified only by an opaque per-message type byte.

This document specifies the ThreadLink wire format, its use of QUIC and ALPN,
its connection lifecycle, and a type-byte registry. It is deliberately narrow.

**Applicability:** the protocol as specified here is intended for agents on a
trusted local network or the same host. Operation across untrusted wide-area
networks is NOT yet addressed and is identified as future work (Section 9). The
current authentication model provides confidentiality without peer authentication
by default (Section 8); do not deploy ThreadLink across an untrusted path without
the pinning upgrade described there.

--- middle

# Introduction

Autonomous software agents increasingly need to talk to one another: to
coordinate, to share what they have learned, or simply to ask a question and
receive an answer. Today this is commonly done by routing every message through
a central service, or by bolting a request/response API onto HTTP.

ThreadLink takes a different, deliberately small position: give agents a direct,
encrypted, peer-to-peer comlink built on QUIC, and let application protocols ride
on top of it. QUIC is chosen for four properties that matter to a swarm of
long-lived agents:

1. Mandatory, integral TLS 1.3 encryption — there is no cleartext mode.
2. Stream multiplexing without head-of-line blocking across streams.
3. A 1-RTT handshake (0-RTT on resumption).
4. Connection migration: a QUIC connection is identified by a Connection ID
   carried in the packets, not by the IP/port four-tuple, so it survives a
   change of network path.

The fourth property is the interesting one for agents that may move between
machines, networks, and compute providers.

ThreadLink itself is only the transport. It knows nothing about routing,
learning, or chat. Application protocols — for example ThreadHello (route-table
exchange) and ThreadChat (agent messaging) — ride on ThreadLink and are
identified by a one-byte message type that ThreadLink carries but does not
interpret.

## Relationship to prior and parallel work

ThreadLink is not the first attempt to give agents a network. Cisco's PACE and
similar link-layer efforts are aimed at agent/process communication in their own
domains; recent application-layer efforts such as Google's Agent-to-Agent (A2A)
protocol and the Model Context Protocol operate above HTTP. ThreadLink's distinct
angle is to be a QUIC-native, connection-migratable, framework-agnostic transport
that carries opaque application protocols through a thin adapter, rather than a
protocol tied to one agent framework or to HTTP semantics. No claim of
superiority is made; ThreadLink is early and narrow by design.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they
appear in all capitals, as shown here.

# Terminology

Agent:
: An autonomous software process that originates and consumes ThreadLink
  messages.

Comlink:
: A ThreadLink transport instance between two agents.

Frame:
: One complete ThreadLink message: a fixed header followed by a body.

Message type:
: A one-octet value identifying the riding protocol's message. Opaque to
  ThreadLink.

Riding protocol:
: An application protocol carried over ThreadLink (e.g. ThreadHello, ThreadChat),
  which defines the meaning of message types and bodies.

# Transport

ThreadLink runs over QUIC version 1 [RFC9000] with TLS 1.3 [RFC8446]. A
ThreadLink endpoint MUST NOT negotiate an unencrypted transport; QUIC provides
none.

## ALPN

An endpoint MUST offer the Application-Layer Protocol Negotiation (ALPN) [RFC7301]
identifier "threadlink/1" in the TLS handshake, and MUST NOT treat a connection
as ThreadLink unless "threadlink/1" was negotiated. The ALPN string carries the
protocol version; incrementing the trailing integer is the mechanism for a
future incompatible revision.

## Streams

Each request/response exchange SHOULD use its own QUIC bidirectional stream, so
that a large transfer on one stream cannot delay a small message on another.
A single frame is one message; a stream MAY carry more than one frame in
sequence. An endpoint MUST use one frame reader per stream and MUST NOT
interleave the byte streams of two QUIC streams into one reader.

## Default port

The default UDP port for ThreadLink is 4433. Use of a non-default port is
permitted and common; because the protocol is identified by ALPN, a receiver
need not rely on the port to recognize ThreadLink.

# Frame Format

Every ThreadLink message is a single frame: a fixed 10-octet header in network
byte order (big-endian), followed by a body of "length" octets.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic  = "TL01"                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Flags     |         Length (1/2)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Length (2/2)          |        Body (variable)  ...   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Magic (4 octets):
: The ASCII string "TL01". A receiver MUST verify the magic and MUST treat a
  mismatch as a fatal error for that stream. The magic catches a mis-wired or
  non-ThreadLink stream before the body is parsed.

Type (1 octet):
: The riding protocol's message type. ThreadLink carries this value but does not
  interpret it, except for the transport-owned control types in Section 6. An
  unknown type is NOT a wire error: a receiver that does not implement a type
  SHOULD respond with an ERROR frame (Section 6) rather than closing the stream.

Flags (1 octet):
: Reserved. A sender MUST set all bits to zero in this version. Bit 0 is reserved
  to indicate a compressed body in a future revision; a receiver MUST reject a
  frame whose flags contain a bit it does not understand.

Length (4 octets, unsigned):
: The length of the body in octets. A receiver MUST reject a frame whose declared
  length exceeds MAX_BODY (Section 5.1).

Body (variable):
: The message body. In this version the body is a UTF-8 encoded JSON object
  [RFC8259]. A receiver MUST reject a body that is not a valid JSON object.

## Body size limit

MAX_BODY is 4,194,304 octets (4 MiB). A sender MUST NOT emit a frame whose body
exceeds MAX_BODY, and a receiver MUST reject one, so that a hostile or buggy peer
cannot force an unbounded allocation. A riding protocol that needs to transfer
more than MAX_BODY MUST chunk it into multiple frames.

## Body encoding rationale

JSON is used because at the scale ThreadLink targets, message bodies are small
and human-readable framing is worth more than a denser encoding during
development and packet analysis. The Flags octet reserves the path to a compact
or compressed encoding without a header change.

# Control Messages

ThreadLink reserves a small set of message types for the transport itself. These
types MUST NOT be reassigned by a riding protocol.

| Type | Name  | Meaning                                            |
|-----:|-------|----------------------------------------------------|
| 0x05 | PING  | Liveness / latency probe. Peer SHOULD answer PONG. |
| 0x06 | PONG  | Response to PING.                                  |
| 0x07 | BYE   | Graceful close; peer MAY drop per-connection state.|
| 0x7F | ERROR | Handler failure, reported in lieu of a dead stream.|

An ERROR frame's body SHOULD contain a JSON object with an "error" member (a
short machine token) and MAY contain a "detail" member (human-readable text).

# Connection Lifecycle

An endpoint opens a ThreadLink comlink by completing a QUIC + TLS 1.3 handshake
with "threadlink/1" negotiated. It exchanges frames on one or more streams. It
closes gracefully by sending a BYE frame and closing the QUIC connection, or
ungracefully by QUIC connection close or idle timeout.

The RECOMMENDED idle timeout is 30 seconds.

## Connection migration

Because a QUIC connection is identified by its Connection ID and not by the
underlying address, a ThreadLink comlink survives a change of the local or remote
network path without re-handshaking. An implementation that supports migration
rotates the peer Connection ID; the TLS keys and all open streams are preserved.
Migration support is OPTIONAL but RECOMMENDED for agents that may move between
networks.

# Security Considerations

## What is protected

All ThreadLink traffic is encrypted: QUIC mandates TLS 1.3, and ThreadLink
provides no unencrypted mode. A passive observer on the path sees only encrypted
QUIC. This has been verified by capture: with the session keys, a ThreadLink
exchange decrypts to its frames; without them, the payload is opaque.

## What is NOT protected by default

The default deployment uses a self-signed certificate per agent. This provides
CONFIDENTIALITY but NOT peer AUTHENTICATION: an active on-path attacker who can
intercept the handshake can present its own self-signed certificate. ThreadLink
as specified here is therefore suitable for a TRUSTED local network or same-host
deployment, where an active on-path attacker is not part of the threat model.

## Authentication upgrade path

An endpoint's stable identity is the SHA-256 hash of its certificate's
SubjectPublicKeyInfo ("SPKI pin"). A swarm MAY move from trust-on-first-use to
pinned identity by advertising and verifying SPKI pins out of band or in a riding
protocol's handshake; an impostor presenting a different key is then rejected.
Wide-area deployment (Section 9) REQUIRES either SPKI pinning or a certificate
authority trust model; it MUST NOT rely on the self-signed default.

## Key logging

An implementation MAY support writing TLS traffic secrets to an SSLKEYLOGFILE for
diagnostics, as browsers and other tools do. This is a deliberate operator choice
for a specific capture and MUST default to off; when enabled it exposes the
session to anyone who obtains the log, so it MUST NOT be enabled in production.

# Future Work: Wide-Area Operation (the honest gap)

ThreadLink as specified is intended for local / trusted-network use. It is NOT
yet specified for operation across untrusted wide-area networks. Reaching that
requires, at minimum:

- An authentication model that does not depend on the self-signed default
  (Section 8.3): mandatory SPKI pinning, a CA trust model, or an equivalent.
- NAT traversal and peer reachability for agents behind NATs or firewalls.
- A discovery/directory mechanism suitable for the open internet (this document
  assumes an out-of-band address book).
- Abuse, rate-limiting, and denial-of-service considerations for an
  internet-facing listener.

These are stated here as open problems, not as solved. Until they are addressed,
an implementation SHOULD restrict ThreadLink to trusted networks.

# IANA Considerations

This document makes no request of IANA at this time. Were ThreadLink to advance,
the following would be registered:

- The ALPN protocol identifier "threadlink/1" in the TLS Application-Layer
  Protocol Negotiation (ALPN) Protocol IDs registry [RFC7301].
- A "ThreadLink Message Types" registry for the one-octet Type field, with the
  transport-owned assignments in Section 6 (0x05-0x07, 0x7F) marked reserved and
  the remainder available to riding protocols. At the time of writing the
  following ranges are in use by riding protocols and would be recorded for
  coordination: 0x01-0x04 (ThreadHello), 0x10-0x13 (ThreadChat).

# Implementation Status

This section is to be removed before eventual publication, per [RFC7942].

A reference implementation of ThreadLink exists in Python over aioquic, with a
test suite exercising the wire format, the handshake, control messages, and
connection migration on a live QUIC connection. Two riding protocols
(ThreadHello, ThreadChat) and a Wireshark dissector for all three have been
implemented and demonstrated interoperating across three distinct agent
frameworks on three hosts on a local network.

--- back

# Acknowledgments

ThreadLink was built for the BGI Commons HyperSprint. Thanks to the reviewers who
insisted the applicability and security sections say plainly where the protocol
does and does not yet work.
