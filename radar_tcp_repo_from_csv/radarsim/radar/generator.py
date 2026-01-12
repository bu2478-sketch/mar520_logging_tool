\
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..protocol.field_types import FieldSpec

@dataclass
class DetectionGenConfig:
    det_count: int = 2048
    # stratification grid (must multiply to det_count)
    az_bins: int = 64
    el_bins: int = 32
    range_m_min: float = 2.0
    range_m_max: float = 120.0
    vel_mps_min: float = -30.0
    vel_mps_max: float = 30.0


def _phys_to_raw(fs: FieldSpec, phys: float) -> int:
    if fs.resolution is None or fs.offset is None:
        raise ValueError(f"Field {fs.name} missing resolution/offset")
    raw = int(round((phys - fs.offset) / fs.resolution))
    if fs.lower_raw is not None:
        raw = max(raw, fs.lower_raw)
    if fs.upper_raw is not None:
        raw = min(raw, fs.upper_raw)
    return raw


def build_detection_records(
    det_fields: List[FieldSpec],
    cfg: DetectionGenConfig,
    cycle_counter: int,
) -> List[Tuple]:
    """
    Returns list of tuples matching per-detection struct fields order.
    Generates azimuth/elevation with stratified sampling over full MinPhys..MaxPhys range.
    """
    if cfg.az_bins * cfg.el_bins != cfg.det_count:
        raise ValueError("az_bins * el_bins must equal det_count")

    # Find key field specs
    fs_range = next(f for f in det_fields if f.name.strip() == "Position {radial distance}")
    fs_az = next(f for f in det_fields if f.name.strip() == "Position {azimuth}")
    fs_el = next(f for f in det_fields if f.name.strip() in ("Positon {elevation}", "Position {elevation}"))

    fs_vel = next(f for f in det_fields if f.name.strip().startswith("Relative velocity {radial distance}"))

    az_min = fs_az.min_phys if fs_az.min_phys is not None else -1.0
    az_max = fs_az.max_phys if fs_az.max_phys is not None else 1.0
    el_min = fs_el.min_phys if fs_el.min_phys is not None else -0.3
    el_max = fs_el.max_phys if fs_el.max_phys is not None else 0.3

    dets: List[Tuple] = []
    det_id = 0

    # Rotate the grid each cycle a bit to avoid repeating exact pattern
    az_shift = (cycle_counter * 7) % cfg.az_bins
    el_shift = (cycle_counter * 3) % cfg.el_bins

    for el_i in range(cfg.el_bins):
        for az_i in range(cfg.az_bins):
            # stratified cell bounds
            a0 = az_min + ((az_i + az_shift) / cfg.az_bins) * (az_max - az_min)
            a1 = az_min + ((az_i + az_shift + 1) / cfg.az_bins) * (az_max - az_min)
            e0 = el_min + ((el_i + el_shift) / cfg.el_bins) * (el_max - el_min)
            e1 = el_min + ((el_i + el_shift + 1) / cfg.el_bins) * (el_max - el_min)

            az = random.uniform(a0, a1)
            el = random.uniform(e0, e1)

            rng = random.uniform(cfg.range_m_min, cfg.range_m_max)
            vel = random.uniform(cfg.vel_mps_min, cfg.vel_mps_max)

            raw_rng = _phys_to_raw(fs_range, rng)
            raw_az = _phys_to_raw(fs_az, az)
            raw_el = _phys_to_raw(fs_el, el)
            raw_vel = _phys_to_raw(fs_vel, vel)

            # Create raw values for all fields
            values = []
            for f in det_fields:
                name = f.name.strip()
                if name == "Detection ID":
                    values.append(det_id & 0xFFFF if f.nbytes == 2 else det_id & 0xFF)
                elif name == "Existence probability - detection level":
                    # confidence 70..100%
                    values.append(random.randint(70, 100) & 0xFF)
                elif name == "Position {radial distance}":
                    values.append(raw_rng)
                elif name == "Position {azimuth}":
                    values.append(raw_az)
                elif name in ("Positon {elevation}", "Position {elevation}"):
                    values.append(raw_el)
                elif name == "Relative velocity {radial distance}":
                    values.append(raw_vel)
                elif name == "Relative velocity {radial distance} - quality":
                    values.append(random.randint(0, 100) & 0xFF)
                else:
                    # generic in-range random
                    if f.fmt.endswith("s"):
                        values.append(bytes(random.getrandbits(8) for _ in range(f.nbytes)))
                    else:
                        lo = f.lower_raw if f.lower_raw is not None else 0
                        hi = f.upper_raw if f.upper_raw is not None else (2 ** (8 * f.nbytes) - 1)
                        if f.fmt in ("B", "H", "I", "Q"):
                            lo = max(lo, 0)
                            maxv = {"B": 0xFF, "H": 0xFFFF, "I": 0xFFFFFFFF, "Q": 0xFFFFFFFFFFFFFFFF}[f.fmt]
                            hi = min(hi, maxv)
                        values.append(random.randint(lo, hi))
            dets.append(tuple(values))
            det_id += 1

    return dets
