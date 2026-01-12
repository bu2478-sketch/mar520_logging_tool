\
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .field_types import FieldSpec
from .someip import unpack_header, SomeIpHeader


def _build_struct(fields: List[FieldSpec]) -> struct.Struct:
    fmt = ">" + "".join(f.fmt for f in fields)
    return struct.Struct(fmt)


@dataclass
class ParsedPacket:
    header: SomeIpHeader
    message_name: str
    payload: bytes


class PacketParser:
    def __init__(self, spec):
        self.spec = spec
        # map (service_id, method_id) -> name
        self._id_map = {(m.service_id, m.method_id): name for name, m in spec.messages.items()}

        self._gen_struct = _build_struct(spec.general_fields)
        self._rd_hdr_struct = _build_struct(spec.rd_header_fields)
        self._det_struct = _build_struct(spec.det_fields)

        self._rd_hdr_len = self._rd_hdr_struct.size
        self._det_len = self._det_struct.size

    def identify(self, hdr: SomeIpHeader) -> str:
        return self._id_map.get((hdr.service_id, hdr.method_id), "UNKNOWN")

    def validate_header(self, hdr: SomeIpHeader) -> None:
        # Check protocol/interface/message type/reserved
        if hdr.protocol_version != self.spec.protocol_version:
            raise ValueError(f"Protocol version mismatch: {hdr.protocol_version:#x}")
        if hdr.interface_version != self.spec.interface_version:
            raise ValueError(f"Interface version mismatch: {hdr.interface_version:#x}")
        if hdr.message_type != self.spec.message_type:
            raise ValueError(f"Message type mismatch: {hdr.message_type:#x}")
        if hdr.reserved != self.spec.reserved:
            raise ValueError(f"Reserved mismatch: {hdr.reserved:#x}")

    def validate_payload_len(self, name: str, payload_len: int) -> None:
        exp = self.spec.messages[name].payload_len
        if payload_len != exp:
            raise ValueError(f"{name} payload len mismatch: got={payload_len} expected={exp}")

    def parse_general(self, payload: bytes) -> Tuple:
        if len(payload) != self._gen_struct.size:
            raise ValueError("General payload size mismatch")
        return self._gen_struct.unpack(payload)

    def parse_radar_detection_header(self, payload: bytes) -> Tuple:
        if len(payload) < self._rd_hdr_len:
            raise ValueError("Radar payload too short for header")
        return self._rd_hdr_struct.unpack(payload[: self._rd_hdr_len])

    def parse_first_detection(self, payload: bytes) -> Tuple:
        base = self._rd_hdr_len
        if len(payload) < base + self._det_len:
            raise ValueError("Radar payload too short for first detection")
        return self._det_struct.unpack(payload[base : base + self._det_len])

    def deep_parse_all_detections(self, payload: bytes) -> List[Tuple]:
        base = self._rd_hdr_len
        out = []
        for i in range(self.spec.det_count):
            off = base + i * self._det_len
            out.append(self._det_struct.unpack(payload[off : off + self._det_len]))
        return out

    @property
    def header_size(self) -> int:
        return 16

    def decode_from_stream(self, buf: bytearray) -> Optional[ParsedPacket]:
        """
        Consumes from buf if a full packet is available.
        Returns ParsedPacket or None if incomplete.
        """
        if len(buf) < self.header_size:
            return None
        hdr = unpack_header(bytes(buf[: self.header_size]))
        total_len = self.header_size + hdr.payload_len
        if len(buf) < total_len:
            return None
        payload = bytes(buf[self.header_size : total_len])
        del buf[:total_len]
        name = self.identify(hdr)
        return ParsedPacket(header=hdr, message_name=name, payload=payload)
