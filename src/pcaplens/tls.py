"""Read the SNI hostname from a TLS ClientHello. No decryption.

JA3/JA4 fingerprints are intentionally out of scope.

A TLS record on the wire looks like this (RFC 8446):

    type (1) | version (2) | length (2) | fragment

type 0x16 = handshake. The fragment then starts with:

    msg_type (1) | length (3) | message

msg_type 0x01 = ClientHello. After version/random/session/ciphers/compression
come optional extensions. SNI is extension type 0 (RFC 6066); the first
valid host_name entry is the hostname we want.

We only walk records from the start of a TCP stream. That is where a
ClientHello lives, and it avoids scanning huge transfers. Every length
field is checked before we slice, so a truncated or junk record returns
None instead of raising.
"""
from __future__ import annotations

_HANDSHAKE = 0x16
_CLIENT_HELLO = 0x01
_EXT_SNI = 0
_NAME_HOST = 0
# RFC 1035: a DNS name is at most 253 bytes on the wire.
_MAX_HOST = 253


def extract_sni(data: bytes) -> str | None:
    """Return the first usable SNI hostname, or None.

    Safe for empty, HTTP, truncated, and malformed bytes. The try/except
    is a backstop: the helpers below already check bounds before slicing.
    """
    try:
        return _extract_sni(data)
    except (IndexError, ValueError, TypeError):
        return None


def _u16(buf: bytes, off: int) -> int | None:
    if off + 2 > len(buf):
        return None
    return int.from_bytes(buf[off : off + 2], "big")


def _u24(buf: bytes, off: int) -> int | None:
    if off + 3 > len(buf):
        return None
    return int.from_bytes(buf[off : off + 3], "big")


def _extract_sni(data: bytes) -> str | None:
    off = 0
    while off + 5 <= len(data):
        rec_type = data[off]
        major, minor = data[off + 1], data[off + 2]
        rec_len = _u16(data, off + 3)
        if rec_len is None:
            return None
        # Leave the loop at the first record that is not a TLS handshake.
        # GREASE and other extensions live *inside* ClientHello, not here.
        if rec_type != _HANDSHAKE or major != 0x03 or minor > 4:
            break
        frag_start = off + 5
        frag_end = frag_start + rec_len
        if rec_len < 1 or frag_end > len(data):
            return None
        sni = _sni_from_handshake(data[frag_start:frag_end])
        if sni:
            return sni
        off = frag_end
    return None


def _sni_from_handshake(frag: bytes) -> str | None:
    if len(frag) < 4:
        return None
    msg_type = frag[0]
    msg_len = _u24(frag, 1)
    if msg_len is None or msg_type != _CLIENT_HELLO:
        return None
    if 4 + msg_len > len(frag):
        return None
    return _sni_from_client_hello(frag[4 : 4 + msg_len])


def _sni_from_client_hello(body: bytes) -> str | None:
    # Skip the fixed prefix: version (2) + random (32) + session_id_len (1).
    if len(body) < 35:
        return None
    off = 34
    sid_len = body[off]
    off += 1
    if off + sid_len + 2 > len(body):
        return None
    off += sid_len

    cs_len = _u16(body, off)
    if cs_len is None:
        return None
    off += 2
    if off + cs_len + 1 > len(body):
        return None
    off += cs_len

    comp_len = body[off]
    off += 1
    if off + comp_len > len(body):
        return None
    off += comp_len

    # SSLv3 ClientHellos may omit the extensions block entirely.
    if off == len(body):
        return None
    ext_len = _u16(body, off)
    if ext_len is None:
        return None
    off += 2
    if off + ext_len > len(body):
        return None
    return _sni_from_extensions(body[off : off + ext_len])


def _sni_from_extensions(exts: bytes) -> str | None:
    off = 0
    while off + 4 <= len(exts):
        etype = _u16(exts, off)
        elen = _u16(exts, off + 2)
        if etype is None or elen is None:
            return None
        off += 4
        if off + elen > len(exts):
            return None
        blob = exts[off : off + elen]
        off += elen
        # Skip GREASE (RFC 8701, e.g. 0x0A0A) and every other unknown type.
        if etype == _EXT_SNI:
            host = _hostname_from_sni(blob)
            if host:
                return host
    return None


def _hostname_from_sni(data: bytes) -> str | None:
    list_len = _u16(data, 0)
    if list_len is None or 2 + list_len > len(data):
        return None
    off = 2
    end = 2 + list_len
    while off + 3 <= end:
        name_type = data[off]
        name_len = _u16(data, off + 1)
        if name_len is None:
            return None
        off += 3
        if off + name_len > end:
            return None
        raw = data[off : off + name_len]
        off += name_len
        # RFC 6066: host_name = type 0. Skip empty / non-ASCII / other types
        # and keep looking so a later usable name still counts.
        if name_type == _NAME_HOST:
            host = _clean_hostname(raw)
            if host:
                return host
    return None


def _clean_hostname(raw: bytes) -> str | None:
    if not raw or len(raw) > _MAX_HOST or 0 in raw:
        return None
    try:
        host = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not host.isprintable() or any(c.isspace() for c in host):
        return None
    return host
