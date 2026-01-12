\
from __future__ import annotations

import struct
from dataclasses import dataclass

# SOME/IP-like header:
# service_id (2), method_id (2), length (4), client_id (2), session_id (2),
# protocol_version (1), interface_version (1), message_type (1), reserved (1)
_HDR = struct.Struct(">HHIHHBBBB")


@dataclass(frozen=True)
class SomeIpHeader:
    service_id: int
    method_id: int
    length: int  # = 8 + payload_len
    client_id: int
    session_id: int
    protocol_version: int
    interface_version: int
    message_type: int
    reserved: int

    @property
    def payload_len(self) -> int:
        # SOME/IP length includes the 8 bytes after the length field; so payload = length - 8
        return self.length - 8


def pack_header(
    *,
    service_id: int,
    method_id: int,
    payload_len: int,
    client_id: int,
    session_id: int,
    protocol_version: int,
    interface_version: int,
    message_type: int,
    reserved: int,
) -> bytes:
    length = 8 + payload_len
    return _HDR.pack(
        service_id & 0xFFFF,
        method_id & 0xFFFF,
        length & 0xFFFFFFFF,
        client_id & 0xFFFF,
        session_id & 0xFFFF,
        protocol_version & 0xFF,
        interface_version & 0xFF,
        message_type & 0xFF,
        reserved & 0xFF,
    )


def unpack_header(data: bytes) -> SomeIpHeader:
    if len(data) != _HDR.size:
        raise ValueError(f"header size must be {_HDR.size} bytes")
    vals = _HDR.unpack(data)
    return SomeIpHeader(
        service_id=vals[0],
        method_id=vals[1],
        length=vals[2],
        client_id=vals[3],
        session_id=vals[4],
        protocol_version=vals[5],
        interface_version=vals[6],
        message_type=vals[7],
        reserved=vals[8],
    )
