# ThreadLink specification

`draft-greenblatt-threadlink-00.md` — an Internet-Draft specifying the ThreadLink
wire format, its QUIC/ALPN binding, connection lifecycle, and message-type
registry.

## What this is (and is not)

This is an **Internet-Draft**, the standard on-ramp to the IETF process — not a
published RFC. Anyone may write and submit one; it timestamps the design, makes
the protocol citable and reviewable, and forces the spec to say plainly where it
works and where it does not. It advances only through review and rough consensus,
which this document has not yet undergone.

**Scope, stated honestly:** ThreadLink is specified here for **trusted local /
same-host** deployment. Wide-area operation across untrusted networks is named
future work (draft Section 9) with the open problems listed; the default
authentication model gives confidentiality without peer authentication (Section
8). Do not read this as a claim that ThreadLink is an internet-ready protocol
today — it is deliberately narrow and early.

## Building the submittable draft

The Markdown uses the kramdown-rfc2629 front matter. To produce the IETF
`.xml`/`.txt`:

```
pip install kramdown-rfc xml2rfc     # or: gem install kramdown-rfc2629
kramdown-rfc draft-greenblatt-threadlink-00.md > draft-greenblatt-threadlink-00.xml
xml2rfc draft-greenblatt-threadlink-00.xml       # -> .txt (and .html)
```

Submit the resulting `.xml` (or `.txt`) at <https://datatracker.ietf.org/submit/>.
The `-00` becomes the first published version; edits bump to `-01`, etc.

## Provenance

Every constant in the draft is taken from the reference implementation:
magic `TL01`, 10-octet header, MAX_BODY 4 MiB, ALPN `threadlink/1`, default UDP
4433, 30 s idle timeout — all verifiable in `../threadlink/wire.py` and
`../threadlink/link.py`.
