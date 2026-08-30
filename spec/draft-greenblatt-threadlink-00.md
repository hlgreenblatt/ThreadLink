---
title: "ThreadLink: A QUIC-Based Transport for Agent-to-Agent Communication"
abbrev: ThreadLink
docname: draft-greenblatt-threadlink-00
category: exp
ipr: trust200902
area: Applications
workgroup: Independent Submission
keyword: [QUIC, agent, A2A, comlink, TLS, mutual authentication]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - ins: L. Greenblatt
    name: Larry Greenblatt
    organization: InterNetwork Defense
    email: hlgreenblatt@internetworkdefense.com
normative:
  RFC2119:
  RFC7301:
  RFC8174:
  RFC8446:
  RFC9000:
  RFC9001:
  RFC5280:
informative:
  RFC9221:
  RFC9308:
  PACE:
    title: "PACE: Protocol for Agent Communication Exchange"
    author:
      - ins: S. Nandakumar
      - ins: C. Jennings
    seriesinfo:
      Internet-Draft: draft-nandakumar-agentproto-moq-pace
    date: 2026
  A2A:
    title: "Agent-to-Agent (A2A) Protocol"
    date: 2025
  MCP:
    title: "Model Context Protocol"
    date: 2025
--- abstract

ThreadLink is a lightweight transport for secure, low-latency agent-to-agent
(A2A) communication over QUIC. It gives autonomous software agents a way to
exchange messages directly, peer to peer, without a central broker, and to keep
a session alive across a change of network path.

ThreadLink runs directly over QUIC with mandatory TLS 1.3, and requires mutual
certificate authentication: each endpoint demonstrates possession of its
cryptographic key during connection establishment. ThreadLink defines only a
frame format, connection lifecycle, and mutual-authentication requirement; the
application protocols that ride on it are out of scope and are identified by an
opaque per-message type byte.

ThreadLink does not define agent discovery, semantic identity, authorization,
task delegation, orchestration, or application message semantics. It also does
not define an identity authority: it proves which key is present and leaves the
binding of that key to an identity to the deployment. These functions are
supplied by deployments or protocols operating over ThreadLink.

--- middle

# Introduction

Autonomous software agents increasingly communicate not only with conventional
services but with one another: to coordinate, to share what they have learned, or
to ask a question and receive an answer. These patterns can differ from
traditional client/server models. An agent may maintain relationships with
several peers, exchange frequent small messages, stream intermediate results,
transfer larger artifacts, move between machines or networks, and form temporary
communication relationships as part of a larger distributed system. Transport
overhead can directly affect the responsiveness and scalability of such systems.

ThreadLink defines a lightweight transport for this environment. It runs directly
over QUIC {{RFC9000}} using the TLS 1.3 integration defined for QUIC {{RFC9001}},
and provides a secure substrate on which agent communication protocols operate
without defining or operating their own transport machinery.

ThreadLink favors direct peer-to-peer communication. The protocol requires no
centralized broker, relay, certificate authority, identity provider, or
application framework. This does not prohibit such components: relays,
directories, brokers, identity systems, and orchestration services may be used by
deployments or riding protocols where appropriate.

ThreadLink answers a deliberately narrow question: how can autonomous agents
communicate directly, securely, and efficiently? The interpretation of the
communication remains the responsibility of higher layers.

## Design Goals

1. Low latency: minimal additional cost beyond QUIC and TLS.
2. Peer-to-peer operation: two reachable endpoints communicate without a
   mandatory intermediary.
3. Secure transport: confidentiality, integrity, and mutual cryptographic peer
   authentication.
4. Connection reuse and multiplexing: independent exchanges share a QUIC
   connection without transport-level head-of-line blocking between streams.
5. Protocol independence: ThreadLink does not require a particular agent
   application protocol.
6. Minimal policy: semantic identity, authorization, and orchestration remain
   outside the transport unless required for transport operation.
7. Extensibility: new riding protocols deploy without redesigning ThreadLink.

## Non-Goals

ThreadLink does not define agent discovery; capability description; task
lifecycle; application message schemas; conversational state; authorization
scopes; delegation chains; orchestration policy; semantic agent identity; a
global identity authority; a centralized relay architecture; or a universal
multi-agent framework. A riding protocol or deployment may provide any of these.

## Requirements Language

{::boilerplate bcp14-tagged}

# Terminology

Agent:
: An autonomous software process that originates and consumes ThreadLink
  messages.

ThreadLink Endpoint:
: An implementation participating in a ThreadLink connection.

Peer:
: The remote ThreadLink endpoint associated with a connection.

Initiator:
: The endpoint that opens the underlying QUIC connection and therefore occupies
  the TLS client role.

Listener:
: The endpoint that accepts the underlying QUIC connection and therefore occupies
  the TLS server role. Initiator and Listener are connection-establishment roles
  only; they do not imply an application-level client/server relationship.

Frame:
: One complete ThreadLink message: a fixed header followed by a body.

Message Type:
: A one-octet value identifying the riding protocol's message. Opaque to
  ThreadLink except for the transport-owned control types.

Riding Protocol:
: An application protocol carried over ThreadLink (for example, route-table
  gossip or agent chat), which defines the meaning of message types and bodies.

Peer Key ID:
: A cryptographic identifier derived from the SubjectPublicKeyInfo of a peer
  certificate, as described in {{peer-key-id}}.

Semantic Identity:
: A deployment-level assertion associating a cryptographic peer with an agent,
  service, person, organization, device, or role.

# Transport

ThreadLink runs over QUIC version 1 {{RFC9000}} with TLS 1.3 {{RFC8446}} as
integrated by {{RFC9001}}. A ThreadLink endpoint MUST NOT negotiate an
unencrypted transport; QUIC provides none. ThreadLink does not define independent
congestion control, retransmission, stream ordering, transport encryption, or
connection migration; these are delegated to QUIC.

## ALPN

ThreadLink MUST identify itself during connection establishment using
Application-Layer Protocol Negotiation {{RFC7301}}. The ThreadLink ALPN
identifier is the string "threadlink/1". The version suffix permits a future
"threadlink/2" to be negotiated independently on the same UDP port. A peer that
cannot negotiate a mutually supported ThreadLink ALPN identifier MUST terminate
the connection with error code PROTOCOL_VERSION ({{errors}}).

## Streams

Each ThreadLink request/response exchange is carried on its own QUIC
bidirectional stream. Because QUIC streams do not impose head-of-line blocking on
one another, an exchange transferring a large body never delays an unrelated
exchange on the same connection. A malformed frame causes the affected stream to
be reset ({{errors}}); the connection and its other streams continue.

## Default Port

The default ThreadLink port is UDP 4433. Use of this port is not required; an
endpoint MAY listen on any UDP port, since ALPN distinguishes ThreadLink from
other QUIC-based protocols on the same port.

# Frame Format

A ThreadLink frame is a fixed 10-octet header followed by a body. All multi-octet
integer fields are big-endian.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Magic (0x54 4C 30 31 = "TL01")             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Flags     |         Length (high 16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Length (low 16)          |         Body (Length octets)  ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~

Magic (4 octets):
: The ASCII string "TL01". A stream whose first four octets are not this value is
  not a ThreadLink stream and MUST be treated as MALFORMED ({{errors}}).

Type (1 octet):
: The message type. Values 0x05, 0x06, 0x07, and 0x7F are reserved by the
  transport ({{control}}); all other values are opaque to ThreadLink and belong
  to the riding protocol.

Flags (1 octet):
: Reserved. A sender MUST set this to 0x00; a receiver MUST ignore it in this
  version.

Length (4 octets):
: The body length in octets, as an unsigned 32-bit integer.

Body (Length octets):
: The message body. See {{body}}.

## Body Size Limit {#body}

An implementation MUST reject a frame whose Length exceeds 4,194,304 octets (4
MiB) as MALFORMED, without allocating a buffer of the declared size. This bounds
the memory a single frame can commit before it is validated.

## Body Encoding

In this version the body is a UTF-8 JSON object. This is a property of the
transport's own control messages and of the riding protocols defined alongside
it; ThreadLink does not require a riding protocol to use JSON, and a future
version or riding-protocol binding MAY carry other serializations. JSON is chosen
here because bodies are small and human-inspectable at the scale ThreadLink
targets, which lowers the cost of debugging a live agent mesh.

# Control Messages {#control}

The transport owns four message types. All other type values are carried
uninterpreted for the riding protocol.

| Type | Name  | Meaning                                             |
|------|-------|-----------------------------------------------------|
| 0x05 | PING  | Liveness / latency probe.                            |
| 0x06 | PONG  | Reply to PING.                                       |
| 0x07 | BYE   | Graceful goodbye; the peer MAY release state.        |
| 0x7F | ERROR | A riding-protocol handler failure, reported as a frame rather than by tearing down the stream. |

An implementation MUST NOT interpret riding-protocol payload semantics except
where required to provide ThreadLink transport functions.

# Connection Lifecycle

## Establishment and Mutual Authentication {#mutual-auth}

ThreadLink requires certificate authentication in BOTH directions.

The Listener MUST request a client certificate during the TLS handshake. The
Initiator MUST present a certificate when requested, and the Listener MUST
present its certificate as required by TLS. Each peer MUST complete the TLS
proof-of-possession for its certificate before ThreadLink considers the peer
authenticated.

QUIC permits, but does not require, client authentication. ThreadLink raises this
to a requirement. Furthermore, because an endpoint that requests a client
certificate is not, by TLS alone, obligated to reject a client that presents
none, a ThreadLink Listener MUST verify that the Initiator actually presented a
certificate once the handshake completes, and MUST close the connection with
error code AUTH_REQUIRED ({{errors}}) if it did not.

An implementation MUST NOT use TLS post-handshake client authentication.

## Connection Readiness

A ThreadLink connection MUST NOT be exposed to riding protocols until:

1. the QUIC transport handshake has completed;
2. the TLS handshake has completed;
3. both peers have presented certificates and demonstrated possession of the
   corresponding private keys; and
4. the local peer-verification policy ({{trust}}) has accepted the remote peer.

## Connection Migration

An established ThreadLink connection is identified by its QUIC Connection ID, not
by the IP/port four-tuple, and therefore survives certain changes to an
endpoint's network path. Implementations SHOULD preserve established sessions
across QUIC connection migration where security policy permits. Riding protocols
MUST NOT assume that a peer's IP address is constant for the lifetime of a
connection.

## Idle Timeout and Liveness

ThreadLink relies on QUIC's idle-timeout mechanism to reclaim connections; the
reference implementation uses a 30-second idle timeout by default. An endpoint
MAY use PING/PONG ({{control}}) as an application-level liveness probe. A riding
protocol MAY define stronger liveness semantics.

# Riding Protocol Binding

ThreadLink is intended to carry more than one agent communication protocol. A
riding-protocol binding MUST define:

1. how the protocol is identified (its message type values in the 0x00-0xFF
   space, avoiding the transport-reserved values in {{control}});
2. how its exchanges map onto QUIC streams;
3. whether ordering within an exchange is required;
4. how protocol errors interact with ThreadLink streams;
5. any maximum body sizes the binding requires; and
6. whether additional authorization must occur before application messages are
   accepted.

ThreadLink does not require riding protocols to share a serialization.

# Cryptographic Peer Identification and Trust

Transport security is a property of ThreadLink, not its application purpose.

## Peer Key ID {#peer-key-id}

ThreadLink derives a Peer Key ID from the public key carried by the peer
certificate:

~~~
Peer Key ID = SHA-256( DER-encoded SubjectPublicKeyInfo )
~~~

A Peer Key ID identifies a cryptographic key. It does not by itself assert that
the key represents a particular agent, person, organization, device, or
authority. Because it is derived from the key, it is stable across certificate
renewal as long as the key is reused.

## Separation of Key Possession from Identity

Mutual authentication ({{mutual-auth}}) proves that each endpoint possesses the
private key corresponding to the public key it presented. The association of that
key with a semantic identity is external to ThreadLink:

~~~
        Semantic Agent Identity      (deployment / riding protocol)
                 |
          Authorization Policy       (deployment / riding protocol)
                 |
          Trust Association          (deployment policy, see below)
                 |
            Peer Key ID              (ThreadLink)
                 |
        TLS Proof of Possession      (TLS 1.3 / QUIC)
                 |
               QUIC
~~~

ThreadLink proves which key participates in the connection. A deployment or
riding protocol determines what that key represents and what the peer may do.

## Trust Policy {#trust}

ThreadLink authenticates an endpoint on its public key and does not define an
identity authority. It requires that mutual authentication occur, but leaves the
binding of a key to an identity to the deployment. A deployment MAY establish
that binding using:

- preconfigured Peer Key IDs;
- acceptance of a Peer Key ID on first contact, required thereafter
  (trust-on-first-use);
- validation of the presented certificate along a {{RFC5280}} certificate path
  to a trust anchor;
- an external identity service; or
- a decentralized public-key infrastructure, in which identity and its
  attestations are anchored to a tamper-evident distributed registry rather than
  to a single authority.

Mutual authentication is mandatory regardless of which trust policy is selected.
This separation lets a deployment choose its authentication infrastructure —
"bring your own authentication" — without altering the ThreadLink transport.
ThreadLink certificates are X.509, so each of these policies operates on standard
certificate material; only the deployment's verification policy differs.

A ThreadLink Listener MUST apply its trust policy before a connection is exposed
to riding protocols ({{mutual-auth}}). A policy that accepts any presented
certificate provides confidentiality and proof of key possession, but not a
binding to a known identity; see {{security}}.

## Key Rotation

A Peer Key ID identifies a key, not a permanent identity; generating a new key
creates a new Peer Key ID. A deployment that requires identity continuity across
key rotation SHOULD provide a mechanism external to ThreadLink for authorizing a
replacement key.

# Error Codes {#errors}

ThreadLink defines transport error codes carried in a QUIC CONNECTION_CLOSE
(application error) or RESET_STREAM. These are a SEPARATE namespace from the
message type byte ({{control}}): a message type says what kind of message a frame
is; an error code says why a connection or stream is ending.

| Code | Name             | Meaning                                             |
|------|------------------|-----------------------------------------------------|
| 0x00 | NO_ERROR         | Graceful close, no fault.                            |
| 0x01 | PROTOCOL_VERSION | No mutually supported ThreadLink or riding version.  |
| 0x02 | AUTH_REQUIRED    | Peer presented no certificate; mutual authentication is mandatory. |
| 0x03 | AUTH_FAILED      | Peer certificate present but rejected by the verification policy. |
| 0x04 | MALFORMED        | A frame violated the wire format (bad magic, length, or body). |
| 0x05 | RESOURCE         | A resource limit was exceeded (streams, body size, memory). |
| 0x06 | UNSUPPORTED      | The riding protocol or message type is not handled.  |
| 0x07 | INTERNAL         | An unexpected local failure left connection state unreliable. |

Where a failure affects only one exchange, an implementation SHOULD reset the
affected stream (for example, with MALFORMED for a bad frame) rather than
terminating the connection. A failure that makes the connection state unreliable
SHOULD terminate the connection.

# Security Considerations {#security}

ThreadLink relies on QUIC and TLS 1.3 for confidentiality, integrity, key
establishment, and cryptographic peer authentication. All ThreadLink traffic is
encrypted; there is no unencrypted mode. This has been confirmed by packet
capture: with the session keys a ThreadLink exchange decrypts to its frames;
without them the payload is opaque QUIC.

## Mutual Authentication Is Required; Trust Binding Is Not Defined

ThreadLink requires that both peers prove possession of a certificate's private
key ({{mutual-auth}}). It does NOT define how a key is bound to an identity; that
is a deployment trust policy ({{trust}}). A deployment that accepts any presented
certificate obtains confidentiality and proof of key possession, but an active
on-path attacker able to intercept the initial handshake could present its own
certificate. Such a deployment is therefore suitable for a trusted network, where
an active on-path attacker is not in the threat model. A deployment on an
untrusted path MUST bind keys to identities — by preconfigured Peer Key IDs, a
certificate-path trust anchor, or an equivalent mechanism — and MUST NOT rely on
accepting arbitrary certificates.

## Successful Authentication Is Not Authorization

Successful ThreadLink authentication MUST NOT be interpreted as authorization to
perform arbitrary riding-protocol operations. Authorization is the responsibility
of the deployment or riding protocol.

## Trust-on-First-Use

A deployment MAY record the Peer Key ID observed on an initial accepted
connection and require the same Peer Key ID thereafter. This does not protect the
first contact against an active attacker. A deployment requiring authenticated
first contact SHOULD obtain the expected Peer Key ID through an authenticated
external mechanism before the first connection.

## Key Compromise

Possession of a peer's private key lets an attacker authenticate as that peer
until the trust relationship is removed. Implementations SHOULD provide a means to
remove, replace, or distrust a stored Peer Key ID.

## Resource Exhaustion

Peer-to-peer agent systems can create many connections, streams, or concurrent
operations. Implementations SHOULD enforce limits on concurrent connections,
streams per connection, outstanding requests, inbound body size (a hard limit of
4 MiB applies per frame, see {{body}}), idle duration, and resources allocated
before a peer is verified. QUIC's own transport-level protections remain
applicable.

## 0-RTT

QUIC permits 0-RTT data on resumed connections, with replay properties different
from 1-RTT data. A ThreadLink implementation conforming to this document SHOULD
NOT process riding-protocol operations with externally visible side effects from
0-RTT data. A future specification MAY define safe 0-RTT use for operations known
to be replay-safe.

## Key Logging

An implementation MAY support writing TLS traffic secrets to a key-log file for
diagnostics, as web browsers and other tools do. This MUST default to off, and
when enabled it exposes the session to anyone who obtains the log; it MUST NOT be
enabled in production.

# Relationship to Other Agent Communication Work

Protocols such as A2A {{A2A}} and MCP {{MCP}} define application-level
interaction semantics and can potentially operate as ThreadLink riding protocols
through an appropriate binding.

PACE {{PACE}} defines an agent communication session layer over Media over QUIC
Transport, including session management, identity mechanisms, delegated
authorization, discovery, multimodal exchange, and relay-based communication.
ThreadLink instead operates directly over QUIC and provides a lightweight,
mutually authenticated peer transport, leaving session, discovery, authorization,
and relay semantics to higher layers. The two therefore address different
architectural boundaries; a session protocol of PACE's kind could in principle be
carried as a ThreadLink riding protocol. No claim of superiority is made.

# IANA Considerations

## ALPN Protocol Identifier

This document requests registration of the following identifier in the "TLS
Application-Layer Protocol Negotiation (ALPN) Protocol IDs" registry:

~~~
Protocol:                ThreadLink
Identification Sequence: 0x74 0x68 0x72 0x65 0x61 0x64 0x6C 0x69
                         0x6E 0x6B 0x2F 0x31 ("threadlink/1")
Reference:               This document
~~~

## ThreadLink Transport Error Codes

This document requests a new registry, "ThreadLink Transport Error Codes", with
the initial values in {{errors}} (0x00-0x07). The registration policy for further
values is Specification Required. Values are unsigned integers as carried in a
QUIC application CONNECTION_CLOSE or RESET_STREAM.

## ThreadLink Message Types

The transport reserves message type values 0x05, 0x06, 0x07, and 0x7F
({{control}}). This document does not request a global registry for the remaining
message type values: those belong to riding protocols and are meaningful only
within a riding-protocol binding, so no global namespace is required.

--- back

# Implementation Status

An open-source reference implementation exists (in Python, over aioquic) and
interoperates with two riding protocols: a route-table gossip protocol and an
agent-messaging protocol. The behavior specified here — the "threadlink/1" ALPN,
the "TL01" frame format, the 4 MiB body limit, the four control types, mandatory
mutual authentication with Listener-side enforcement of client-certificate
presence, the Peer Key ID, connection migration, and the transport error codes —
is exercised by the implementation's test suite, including a test that an
anonymous client is rejected with AUTH_REQUIRED. This section is to be removed
before publication as an RFC.

# Example Connection Establishment

~~~
Initiator                                      Listener
    |------------- QUIC Initial ---------------->|
    |              TLS ClientHello, ALPN         |
    |<------------ QUIC Handshake ---------------|
    |              Server Certificate            |
    |              CertificateRequest            |
    |------------- QUIC Handshake -------------->|
    |              Client Certificate            |
    |              CertificateVerify, Finished   |
    |<------------- Finished --------------------|
    |     Mutual key possession established      |
    |     Listener verifies client cert present  |
    |     Local trust policy evaluated           |
    |============ ThreadLink Ready ==============|
    |<======= Riding Protocol Streams ========>  |
~~~

The TLS roles are connection-establishment roles only. After establishment both
endpoints are ThreadLink peers.

# Acknowledgments

Thanks to the authors of PACE for framing the agent-communication session layer,
and to the QUIC and TLS working groups for the transport this work builds on.
