\
from __future__ import annotations

import csv
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

from .field_types import FieldSpec, parse_float_maybe, parse_int_maybe

_RE_HEX = re.compile(r"0x[0-9A-Fa-f]+")


@dataclass(frozen=True)
class MessageDef:
    name: str
    service_id: int
    method_id: int
    payload_len: int


@dataclass(frozen=True)
class InterfaceSpec:
    # SOME/IP-like header (16B total)
    protocol_version: int
    interface_version: int
    message_type: int
    reserved: int
    client_id: int
    session_id: int

    messages: Dict[str, MessageDef]

    general_fields: List[FieldSpec]
    rd_header_fields: List[FieldSpec]
    det_fields: List[FieldSpec]
    det_count: int = 2048

    @property
    def someip_header_size(self) -> int:
        return 16

    def expected_payload_len(self, name: str) -> int:
        return self.messages[name].payload_len

    def expected_total_packet_len(self, name: str) -> int:
        # total bytes on the wire = 16 + payload_len
        return self.someip_header_size + self.expected_payload_len(name)


def _read_rows(path: str, encoding: str = "utf-8") -> List[List[str]]:
    with open(path, newline="", encoding=encoding) as f:
        return list(csv.reader(f))


def _guess_rows(path: str) -> List[List[str]]:
    # these CSVs are either ASCII or ISO-8859-1
    for enc in ("utf-8-sig", "utf-8", "ascii", "ISO-8859-1", "cp949", "euc-kr"):
        try:
            return _read_rows(path, enc)
        except Exception:
            continue
    raise ValueError(f"Cannot read CSV: {path}")


def _parse_table_fields(rows: List[List[str]]) -> List[FieldSpec]:
    # Expected columns: Category, signal, Description, bit size, byte size, type,
    # lower value, upper value, resolution, offset, MinPhys, MaxPhys, unit, Default, remark
    fields: List[FieldSpec] = []
    current_cat = ""
    for r in rows[2:]:
        if len(r) < 6:
            continue
        cat = (r[0] or "").strip()
        sig = (r[1] or "").strip()
        if cat:
            current_cat = cat
        if not sig:
            continue

        nbytes = parse_int_maybe(r[4])  # byte size
        if nbytes is None:
            continue

        c_type = (r[5] or "").strip()
        lower_raw = parse_int_maybe(r[6])
        upper_raw = parse_int_maybe(r[7])

        resolution = parse_float_maybe(r[8])
        offset = parse_float_maybe(r[9])
        min_phys = parse_float_maybe(r[10])
        max_phys = parse_float_maybe(r[11])

        fields.append(
            FieldSpec(
                name=sig,
                nbytes=nbytes,
                c_type=c_type,
                lower_raw=lower_raw,
                upper_raw=upper_raw,
                resolution=resolution,
                offset=offset,
                min_phys=min_phys,
                max_phys=max_phys,
            )
        )
    return fields


def _parse_interface_overview(rows: List[List[str]]) -> Tuple[int, int, int, int, Dict[str, MessageDef]]:
    # Locate the table row that begins with "TCP_GeneralMessage"
    msg_defs: Dict[str, MessageDef] = {}

    proto_ver = 0x01
    if_ver = 0x01
    msg_type = 0x02
    reserved = 0x00

    for r in rows:
        if len(r) >= 13 and (r[1] or "").strip() in ("TCP_GeneralMessage", "TCP_RadarDetection"):
            name = (r[1] or "").strip()
            payload_len = int(r[3])  # "Message size [bytes]" column
            service_id = int(r[4], 16) if (r[4] or "").startswith("0x") else int(r[4])
            method_id = int(r[5], 16) if (r[5] or "").startswith("0x") else int(r[5])
            # r[6] is length field value (8 + payload_len); we can ignore and compute ourselves.
            # protocol/interface/msg_type/reserved are in r[9:12]
            try:
                proto_ver = int(r[9], 16)
                if_ver = int(r[10], 16)
                msg_type = int(r[11], 16)
                reserved = int(r[12], 16)
            except Exception:
                pass

            msg_defs[name] = MessageDef(name=name, service_id=service_id, method_id=method_id, payload_len=payload_len)

    if not msg_defs:
        raise ValueError("Could not find message definitions in interface_overview.csv")

    return proto_ver, if_ver, msg_type, reserved, msg_defs


def load_spec(repo_root: str, session_id: int = 0x0001) -> InterfaceSpec:
    proto_dir = os.path.join(repo_root, "protocol")
    rows_overview = _guess_rows(os.path.join(proto_dir, "interface_overview.csv"))
    proto_ver, if_ver, msg_type, reserved, msg_defs = _parse_interface_overview(rows_overview)

    rows_gen = _guess_rows(os.path.join(proto_dir, "tcp_general_message.csv"))
    rows_rd_hdr = _guess_rows(os.path.join(proto_dir, "tcr_rd_message_header.csv"))
    rows_det = _guess_rows(os.path.join(proto_dir, "TCP_RD_Message_entity.csv"))

    general_fields = _parse_table_fields(rows_gen)
    rd_header_fields = _parse_table_fields(rows_rd_hdr)
    det_fields = _parse_table_fields(rows_det)

    # Sanity: payload sizes should match
    if sum(f.nbytes for f in general_fields) != msg_defs["TCP_GeneralMessage"].payload_len:
        raise ValueError("GeneralMessage payload length mismatch vs interface_overview.csv")
    expected_rd = sum(f.nbytes for f in rd_header_fields) + 2048 * sum(f.nbytes for f in det_fields)
    if expected_rd != msg_defs["TCP_RadarDetection"].payload_len:
        raise ValueError("RadarDetection payload length mismatch vs interface_overview.csv")

    return InterfaceSpec(
        protocol_version=proto_ver,
        interface_version=if_ver,
        message_type=msg_type,
        reserved=reserved,
        client_id=0x0001,
        session_id=session_id,
        messages=msg_defs,
        general_fields=general_fields,
        rd_header_fields=rd_header_fields,
        det_fields=det_fields,
    )
