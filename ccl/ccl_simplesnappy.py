"""
Copyright 2020, CCL Forensics

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from struct import unpack
from io import BytesIO
from typing import BinaryIO, Optional, Tuple
from enum import IntEnum

__version__ = "0.4"
__description__ = "Pure Python reimplementation of Google's Snappy decompression"
__contact__ = "Alex Caithness"


DEBUG = False
FRAME_MAGIC = bytes.fromhex("73 4E 61 50 70 59")


def make_crc_table(poly):
    table = []
    for i in range(256):
        crc = 0
        for _ in range(8):
            if (i ^ crc) & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            i >>= 1
        table.append(crc)
    return table


CRC_POLY = 0x82F63B78
CRC_QUICK_TABLE = tuple(make_crc_table(CRC_POLY))


def crc32c(data, xor_value=0xffffffff):
    value = 0xffffffff
    for b in data:
        value = CRC_QUICK_TABLE[(b ^ value) & 0xff] ^ (value >> 8)

    value ^= xor_value
    return value


# def log(msg):
#     if DEBUG:
#         print(msg)


class NoMoreData(Exception):
    ...


class ElementType(IntEnum):
    """Run type in the compressed snappy data (literal data or offset to backreferenced data_"""
    Literal = 0
    CopyOneByte = 1
    CopyTwoByte = 2
    CopyFourByte = 3


def _read_le_varint(stream: BinaryIO) -> Optional[Tuple[int, bytes]]:
    """Read varint from a stream.
    If the read is successful: returns a tuple of the (unsigned) value and the raw bytes making up that varint,
    otherwise returns None"""
    # this only outputs unsigned
    i = 0
    result = 0
    underlying_bytes = []
    while i < 10:  # 64 bit max possible?
        raw = stream.read(1)
        if len(raw) < 1:
            return None
        tmp, = raw
        underlying_bytes.append(tmp)
        result |= ((tmp & 0x7f) << (i * 7))
        if (tmp & 0x80) == 0:
            break
        i += 1
    return result, bytes(underlying_bytes)


def read_le_varint(stream: BinaryIO) -> Optional[int]:
    """Convenience version of _read_le_varint that only returns the value or None"""
    x = _read_le_varint(stream)
    if x is None:
        return None
    else:
        return x[0]


def read_uint16(stream: BinaryIO) -> int:
    """Reads an Uint16 from stream"""
    return unpack("<H", stream.read(2))[0]


def read_uint24(stream: BinaryIO) -> int:
    """Reads an Uint24 from stream"""
    return unpack("<I", stream.read(3) + b"\x00")[0]


def read_uint32(stream: BinaryIO) -> int:
    """Reads an Uint32 from stream"""
    return unpack("<I", stream.read(4))[0]


def read_byte(stream: BinaryIO) -> Optional[int]:
    """Reads a single byte from stream (or returns None if EOD is met)"""
    x = stream.read(1)
    if x:
        return x[0]

    return None


def decompress(data: BinaryIO) -> bytes:
    """Decompresses the snappy compressed data stream"""
    uncompressed_length = read_le_varint(data)
    # log(f"Uncompressed length: {uncompressed_length}")

    out = BytesIO()

    while True:
        start_offset = data.tell()
        # log(f"Reading tag at offset {start_offset}")
        type_byte = read_byte(data)
        if type_byte is None:
            break

        # log(f"Type Byte is {type_byte:02x}")

        tag = type_byte & 0x03

        # log(f"Element Type is: {ElementType(tag)}")

        if tag == ElementType.Literal:
            if ((type_byte & 0xFC) >> 2) < 60:  # embedded in tag
                length = 1 + ((type_byte & 0xFC) >> 2)
                # log(f"Literal length is embedded in type byte and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 60:  # 8 bit
                length = 1 + read_byte(data)
                # log(f"Literal length is 8bit and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 61:  # 16 bit
                length = 1 + read_uint16(data)
                # log(f"Literal length is 16bit and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 62:  # 16 bit
                length = 1 + read_uint24(data)
                # log(f"Literal length is 24bit and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 63:  # 16 bit
                length = 1 + read_uint32(data)
                # log(f"Literal length is 32bit and is {length}")
            else:
                raise ValueError()  # cannot ever happen

            literal_data = data.read(length)
            if len(literal_data) < length:
                raise ValueError("Couldn't read enough literal data")

            out.write(literal_data)

        else:
            if tag == ElementType.CopyOneByte:
                length = ((type_byte & 0x1C) >> 2) + 4
                offset = ((type_byte & 0xE0) << 3) | read_byte(data)
            elif tag == ElementType.CopyTwoByte:
                length = 1 + ((type_byte & 0xFC) >> 2)
                offset = read_uint16(data)
            elif tag == ElementType.CopyFourByte:
                length = 1 + ((type_byte & 0xFC) >> 2)
                offset = read_uint32(data)
            else:
                raise ValueError()  # cannot ever happen

            if offset == 0:
                raise ValueError("Offset cannot be 0")

            actual_offset = out.tell() - offset
            # log(f"Current Outstream Length: {out.tell()}")
            # log(f"Backreference length: {length}")
            # log(f"Backreference relative offset: {offset}")
            # log(f"Backreference absolute offset: {actual_offset}")

            # have to read incrementally because you might have to read data that you've just written
            # for i in range(length):
            #     out.write(out.getbuffer()[actual_offset + i: actual_offset + i + 1].tobytes())
            buffer = out.getbuffer()[actual_offset: actual_offset + length].tobytes()
            if offset - length <= 0:
                # better safe than sorry, this way we're sure to extend it
                # as much as needed without doing some extra calculations
                buffer = (buffer * length)[:length]
            out.write(buffer)

    result = out.getvalue()
    if uncompressed_length != len(result):
        raise ValueError("Wrong data length in uncompressed data")
        # TODO: allow a partial / potentially bad result via a flag in the function call?

    return result


def check_masked_crc(crc, data, xor_value=0xffffffff):
    check = crc32c(data, xor_value=xor_value)

    check = ((check >> 15) | (check << 17)) & 0xffffffff  # rotate
    check += 0xa282ead8  # add constant
    check %= 0x100000000  # wraparound as an uint32

    return crc == check


def read_frame(frame_stream: BinaryIO):
    frame_header = frame_stream.read(4)
    if not frame_header:
        raise NoMoreData()
    if len(frame_header) < 4:
        raise ValueError("Could not read entire frame header")

    frame_id = frame_header[0]
    frame_length, = unpack("<I", frame_header[1:] + b"\x00")

    data = frame_stream.read(frame_length)
    if len(data) != frame_length:
        raise ValueError(f"Could not read all data; wanted: {frame_length}; got: {len(data)}")

    return frame_id, data

