"""Bounded LZ4 block and Unity-flavoured LZMA decompression (standard library only).

Unity stores BlocksInfo and data blocks as raw LZ4 *block* streams (compression types
2 = LZ4 and 3 = LZ4HC share one decoder) or as LZMA streams with a 5-byte property
header and no size field.  Both decoders here are hardened against hostile input:
the output size is capped, every read is bounds-checked, back-reference offsets are
validated and every loop is bounded by the input length.  Nothing is executed or
decrypted.

Sources:
  * LZ4 block format: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
    (token = literal-length nibble | match-length nibble; 255-run length extension;
    2-byte little-endian offset, 0 is invalid; minimum match 4; the last sequence has
    literals only).  The "last 5 bytes are literals / last match starts 12 bytes before
    the end" rules bind encoders only and are deliberately not enforced when decoding.
  * Unity LZMA layout (props byte + u32 LE dictionary size + raw LZMA1 stream, sizes come
    from the container): AssetStudio BundleFile.cs / UnityPy CompressionHelper.py.
"""
from __future__ import annotations

import lzma
import struct
from typing import Optional

__all__ = [
    "CompressionError",
    "DEFAULT_MAX_OUTPUT",
    "MAX_LZMA_DICT_SIZE",
    "decompress_block",
    "decompress_lzma_unity",
]

#: Default hard cap on any single decompressed output (256 MiB).
DEFAULT_MAX_OUTPUT = 256 * 1024 * 1024

#: Refuse LZMA streams that ask for a dictionary larger than this (liblzma allocates it).
MAX_LZMA_DICT_SIZE = 256 * 1024 * 1024


class CompressionError(ValueError):
    """Raised for malformed or over-limit compressed data.

    ``kind`` is one of: ``truncated``, ``bad_offset``, ``output_too_large``,
    ``size_mismatch``, ``bad_header``, ``dict_too_large``, ``decode_error``.
    """

    def __init__(self, kind: str, message: str = "") -> None:
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind = kind
        self.message = message


def decompress_block(
    src: bytes,
    *,
    max_output: int = DEFAULT_MAX_OUTPUT,
    expected_size: Optional[int] = None,
) -> bytes:
    """Decompress one raw LZ4 block.

    ``expected_size`` (Unity always knows it) makes the decoder stop with
    ``output_too_large`` the moment the stream tries to exceed it and with
    ``size_mismatch`` if the stream ends short.  Without it ``max_output`` is the cap.
    """
    data = bytes(src)
    n = len(data)
    if max_output < 0:
        raise CompressionError("output_too_large", "negative max_output")
    if expected_size is not None:
        if expected_size < 0 or expected_size > max_output:
            raise CompressionError(
                "output_too_large", f"declared size {expected_size} exceeds limit {max_output}"
            )
        limit = expected_size
    else:
        limit = max_output

    out = bytearray()
    ip = 0
    while ip < n:
        token = data[ip]
        ip += 1

        lit = token >> 4
        if lit == 15:
            while True:
                if ip >= n:
                    raise CompressionError("truncated", "literal length runs past input")
                b = data[ip]
                ip += 1
                lit += b
                if b != 255:
                    break
        if lit:
            if ip + lit > n:
                raise CompressionError("truncated", "literals run past input")
            if len(out) + lit > limit:
                raise CompressionError("output_too_large", f"more than {limit} bytes")
            out += data[ip : ip + lit]
            ip += lit

        if ip >= n:
            break  # last sequence carries literals only

        if ip + 2 > n:
            raise CompressionError("truncated", "match offset runs past input")
        offset = data[ip] | (data[ip + 1] << 8)
        ip += 2
        if offset == 0 or offset > len(out):
            raise CompressionError("bad_offset", f"offset {offset} with {len(out)} bytes of history")

        mlen = token & 15
        if mlen == 15:
            while True:
                if ip >= n:
                    raise CompressionError("truncated", "match length runs past input")
                b = data[ip]
                ip += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        if len(out) + mlen > limit:
            raise CompressionError("output_too_large", f"more than {limit} bytes")

        start = len(out) - offset
        if offset >= mlen:
            out += out[start : start + mlen]
        else:  # overlapping copy: the last `offset` bytes repeat
            pattern = bytes(out[start:])
            reps, rem = divmod(mlen, offset)
            out += pattern * reps + pattern[:rem]

    if expected_size is not None and len(out) != expected_size:
        raise CompressionError("size_mismatch", f"decoded {len(out)} bytes, expected {expected_size}")
    return bytes(out)


def _lzma_filters(props_header: bytes) -> list:
    if len(props_header) < 5:
        raise CompressionError("bad_header", "LZMA property header needs 5 bytes")
    props = props_header[0]
    (dict_size,) = struct.unpack_from("<I", props_header, 1)
    if props >= 9 * 5 * 5:
        raise CompressionError("bad_header", f"invalid lc/lp/pb byte 0x{props:02x}")
    lc = props % 9
    rest = props // 9
    lp = rest % 5
    pb = rest // 5
    if dict_size > MAX_LZMA_DICT_SIZE:
        raise CompressionError("dict_too_large", f"dictionary {dict_size} bytes exceeds {MAX_LZMA_DICT_SIZE}")
    return [{"id": lzma.FILTER_LZMA1, "dict_size": max(dict_size, 4096), "lc": lc, "lp": lp, "pb": pb}]


def decompress_lzma_unity(
    data: bytes,
    props_header: Optional[bytes] = None,
    *,
    expected_size: Optional[int] = None,
    max_output: int = DEFAULT_MAX_OUTPUT,
) -> bytes:
    """Decompress a Unity LZMA stream (raw LZMA1 with out-of-band properties).

    If ``props_header`` is None the first 5 bytes of ``data`` are the header
    (props byte + u32 LE dictionary size) and the rest is the raw stream; otherwise
    ``data`` is the raw stream.  Unity streams normally have no end marker, so the
    uncompressed size must come from the container (``expected_size``).  Output is
    capped at ``min(expected_size, max_output)``.
    """
    raw = bytes(data)
    if props_header is None:
        if len(raw) < 5:
            raise CompressionError("truncated", "LZMA stream shorter than its 5-byte header")
        props_header, raw = raw[:5], raw[5:]
    filters = _lzma_filters(bytes(props_header))

    if expected_size is not None:
        if expected_size < 0 or expected_size > max_output:
            raise CompressionError(
                "output_too_large", f"declared size {expected_size} exceeds limit {max_output}"
            )
        want = expected_size
    else:
        want = max_output

    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    try:
        out = dec.decompress(raw, max_length=want + 1)
    except (lzma.LZMAError, EOFError, ValueError) as exc:
        raise CompressionError("decode_error", str(exc)) from exc
    if len(out) > want:
        raise CompressionError("output_too_large", f"more than {want} bytes")
    if expected_size is not None and len(out) != expected_size:
        raise CompressionError("size_mismatch", f"decoded {len(out)} bytes, expected {expected_size}")
    return out
