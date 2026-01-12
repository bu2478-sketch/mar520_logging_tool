\
from __future__ import annotations

import os
import struct
import time
from typing import Dict, List, Tuple

from .field_types import FieldSpec
from .someip import pack_header
from .spec import InterfaceSpec
from ..radar.generator import DetectionGenConfig, build_detection_records


def _build_struct(fields: List[FieldSpec]) -> struct.Struct:
    fmt = ">" + "".join(f.fmt for f in fields)
    return struct.Struct(fmt)


class PacketSerializer:
    def __init__(self, spec: InterfaceSpec):
        self.spec = spec

        self._gen_struct = _build_struct(spec.general_fields)
        self._rd_hdr_struct = _build_struct(spec.rd_header_fields)
        self._det_struct = _build_struct(spec.det_fields)

        self._cfg = DetectionGenConfig(det_count=spec.det_count)

        # Pre-allocate buffers for performance
        self._general_payload = bytearray(spec.messages["TCP_GeneralMessage"].payload_len)
        self._rd_payload = bytearray(spec.messages["TCP_RadarDetection"].payload_len)

        # offsets in RD payload
        self._rd_hdr_len = self._rd_hdr_struct.size
        self._det_len = self._det_struct.size

        assert self._rd_hdr_len + self._det_len * spec.det_count == len(self._rd_payload)

        self._cycle_counter = 0
        self._t0 = time.time()

    @staticmethod
    def _rand_in_field_range(f: FieldSpec) -> object:
        """Return a random value compatible with struct packing for this field."""
        import random
        if f.fmt.endswith("s"):
            return bytes(random.getrandbits(8) for _ in range(f.nbytes))

        lo = f.lower_raw if f.lower_raw is not None else 0
        hi = f.upper_raw if f.upper_raw is not None else (2 ** (8 * f.nbytes) - 1)

        # Clamp for unsigned formats
        if f.fmt in ("B", "H", "I", "Q"):
            lo = max(lo, 0)
            maxv = {"B": 0xFF, "H": 0xFFFF, "I": 0xFFFFFFFF, "Q": 0xFFFFFFFFFFFFFFFF}[f.fmt]
            hi = min(hi, maxv)

        return random.randint(lo, hi)

    def _gen_values_for_fields(self, fields: List[FieldSpec]) -> Tuple:
        vals = []
        for f in fields:
            vals.append(self._rand_in_field_range(f))
        return tuple(vals)

    def build_general_packet(self) -> bytes:
        # Fill payload
        vals = self._gen_values_for_fields(self.spec.general_fields)
        self._gen_struct.pack_into(self._general_payload, 0, *vals)

        md = self.spec.messages["TCP_GeneralMessage"]
        hdr = pack_header(
            service_id=md.service_id,
            method_id=md.method_id,
            payload_len=len(self._general_payload),
            client_id=self.spec.client_id,
            session_id=self.spec.session_id,
            protocol_version=self.spec.protocol_version,
            interface_version=self.spec.interface_version,
            message_type=self.spec.message_type,
            reserved=self.spec.reserved,
        )
        return hdr + self._general_payload

    def build_radar_detection_packet(self) -> bytes:
        import random

        # Build RD header values (reasonable constants + counters)
        # We'll populate key signals by name where it makes sense; others random within range.
        hdr_vals = []
        now_ms = int((time.time() - self._t0) * 1000) & 0xFFFFFFFF
        for f in self.spec.rd_header_fields:
            name = f.name.strip()
            if name.startswith("Interface version ID"):
                hdr_vals.append(bytes([1, 1, 1]))
            elif name == "Interface ID":
                hdr_vals.append(1)
            elif name == "Number of valid serving sensors":
                hdr_vals.append(1)
            elif name == "Sensor ID":
                hdr_vals.append(1)
            elif name == "Time stamp - measurement":
                hdr_vals.append(now_ms)
            elif name == "Cycle counter":
                hdr_vals.append(self._cycle_counter & 0xFFFFFFFF)
            elif name == "Recognised detections - capability":
                hdr_vals.append(self.spec.det_count)
            elif name == "Number of valid detections":
                hdr_vals.append(self.spec.det_count)
            else:
                hdr_vals.append(self._rand_in_field_range(f))

        # Pack RD header
        self._rd_hdr_struct.pack_into(self._rd_payload, 0, *hdr_vals)

        # Build detection records with uniform-ish az/el coverage
        det_records = build_detection_records(self.spec.det_fields, self._cfg, self._cycle_counter)

        # Pack detections
        off = self._rd_hdr_len
        for rec in det_records:
            self._det_struct.pack_into(self._rd_payload, off, *rec)
            off += self._det_len

        self._cycle_counter += 1

        md = self.spec.messages["TCP_RadarDetection"]
        hdr = pack_header(
            service_id=md.service_id,
            method_id=md.method_id,
            payload_len=len(self._rd_payload),
            client_id=self.spec.client_id,
            session_id=self.spec.session_id,
            protocol_version=self.spec.protocol_version,
            interface_version=self.spec.interface_version,
            message_type=self.spec.message_type,
            reserved=self.spec.reserved,
        )
        return hdr + self._rd_payload