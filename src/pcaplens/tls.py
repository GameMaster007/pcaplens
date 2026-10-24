"""Parse TLS ClientHello metadata from the wire (no decryption).

Only the first handshake record of a TCP stream is inspected. JA3/JA4 are
intentionally out of scope.
"""
from __future__ import annotations

# TLS record content type 0x16 = handshake; 0x01 = ClientHello.
# SNI is extension type 0 (RFC 6066); name_type 0 = host_name.
_HANDSHAKE = 0x16
_CLIENT_HELLO = 0x01
_EXT_SNI = 0
_NAME_HOST = 0
_MAX_HOST = 253


def extract_sni(data: bytes) -> str | None:
    """Return the first SNI hostname from a TLS ClientHello, or None.

    Every length field is checked before slicing so a truncated or malformed
    record cannot raise. Non-TLS payloads (HTTP, empty, random) return None.
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
    # Walk consecutive TLS records from the start of the stream only.
    # Do not scan the whole payload — large transfers are common.
    off = 0
    while off + 5 <= len(data):
        rec_type = data[off]
        major, minor = data[off + 1], data[off + 2]
        rec_len = _u16(data, off + 3)
        if rec_len is None:
            return None
        # Stop at the first non-handshake / non-TLS-looking record.
        if rec_type != _HANDSHAKE or major != 0x03 or minor > 4:
            break
        frag_start = off + 5
        frag_end = frag_start + rec_len
        if rec_len < 1 or frag_end > len(data):
            return None  # advertised length past the captured bytes
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
    # version(2) + random(32) + session_id_len(1)
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

    # SSLv3 ClientHellos may omit extensions entirely.
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
        if etype == _EXT_SNI:
            host = _hostname_from_sni(blob)
            if host:
                return host
    return None


def _hostname_from_sni(data: bytes) -> str | None:
    list_len = _u16(data, 0)
    if list_len is None:
        return None
    if 2 + list_len > len(data):
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
        if name_type == _NAME_HOST:
            return _clean_hostname(raw)
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
