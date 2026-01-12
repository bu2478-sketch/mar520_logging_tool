\
from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Any, Callable, Optional

# Map C-like scalar types to struct format chars (without endianness prefix)
_SCALARS = {
    "uint8_t": "B",
    "int8_t": "b",
    "uint16_t": "H",
    "int16_t": "h",
    "uint32_t": "I",
    "int32_t": "i",
    "uint64_t": "Q",
    "int64_t": "q",
    "float": "f",
    "float32": "f",
    "double": "d",
    "float64": "d",
}

_array_pat = re.compile(r"^(?P<base>[A-Za-z_]\w*)\[(?P<n>\d+)\]$")


@dataclass(frozen=True)
class FieldSpec:
    name: str
    nbytes: int
    c_type: str
    lower_raw: Optional[int] = None
    upper_raw: Optional[int] = None
    resolution: Optional[float] = None
    offset: Optional[float] = None
    min_phys: Optional[float] = None
    max_phys: Optional[float] = None

    fmt: str = ""  # computed struct format (no endianness)

    def __post_init__(self):
        # dataclass is frozen; use object.__setattr__
        fmt = infer_struct_fmt(self.c_type, self.nbytes)
        object.__setattr__(self, "fmt", fmt)


def infer_struct_fmt(c_type: str, nbytes: int) -> str:
    c_type = (c_type or "").strip()
    if not c_type:
        return f"{nbytes}s"

    # Enumeration -> treat as unsigned int of nbytes
    if c_type.lower() == "enumeration":
        return {1: "B", 2: "H", 4: "I", 8: "Q"}.get(nbytes, f"{nbytes}s")

    m = _array_pat.match(c_type)
    if m:
        base = m.group("base")
        n = int(m.group("n"))
        # Common case: uint8_t[n] => pack as bytes string
        if base == "uint8_t" and n == nbytes:
            return f"{nbytes}s"
        # Otherwise fall back to raw bytes
        return f"{nbytes}s"

    if c_type in _SCALARS:
        # verify size matches
        size = struct.calcsize(_SCALARS[c_type])
        if size != nbytes:
            return f"{nbytes}s"
        return _SCALARS[c_type]

    # char[8] etc may be exported already as "char[8]"
    if c_type.startswith("char[") and c_type.endswith("]"):
        return f"{nbytes}s"

    # Unknown -> raw bytes
    return f"{nbytes}s"


def parse_int_maybe(x: str) -> Optional[int]:
    x = (x or "").strip()
    if not x:
        return None
    try:
        if x.lower().startswith("0x"):
            return int(x, 16)
        return int(float(x))
    except Exception:
        return None


def parse_float_maybe(x: str) -> Optional[float]:
    x = (x or "").strip()
    if not x:
        return None
    try:
        return float(x)
    except Exception:
        return None
