import socket
import struct
import threading
import time
import math

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

HOST = "127.0.0.1"
PORT = 4545
ENDIAN = ">"

# ===== TCP Header (16 bytes) =====
FMT_HEADER = ENDIAN + "HHIHHBBBB"
HEADER = struct.Struct(FMT_HEADER)
HEADER_SIZE = HEADER.size

SERVICE_ID_EXPECT = 0x6000
METHOD_GENERAL = 0x8001
METHOD_RADAR   = 0x8002
LEN_FIELD_MINUS = 8  # length = payload + 8

PAYLOAD_GENERAL_LEN = 3368
PAYLOAD_RADAR_LEN   = 112680

# ===== General offsets (필요 필드만) =====
OFF_VEHICLE_TYPE   = 0
OFF_GEAR_POSITION  = 1
OFF_STEER_ANGLE    = 2
OFF_WHEEL_SPEEDS   = 16
OFF_ECU_ID         = 64
OFF_HW_VERSION     = 114
OFF_SW_VERSION     = 118
OFF_FRAME_NUM      = 150

U8   = struct.Struct(ENDIAN + "B")
I16  = struct.Struct(ENDIAN + "h")
U16x4= struct.Struct(ENDIAN + "4H")
U32  = struct.Struct(ENDIAN + "I")

# ===== Radar layout =====
RADAR_INTERNAL_HDR_SIZE = 40
DETECTION_SIZE = 55
NUM_DET = 2048

DET_OFF_POS_R = 26
DET_POS_STRUCT = struct.Struct(ENDIAN + "HHH")  # pos_r, pos_az, pos_el

OFF_RD_TIMESTAMP    = 6
OFF_RD_CYCLECOUNTER = 10

AZ_DEN = 65535.0
EL_DEN = 65535.0

R_SCALE = 0.05          # raw -> 표시 스케일
GUI_UPDATE_SEC = 0.5
LOG_EVERY_N = 1         # 로그 너무 많으면 5~10 추천

# 3D 보기용: 최대거리 제한(너무 멀면 화면이 비어보일 수 있음)
R_MAX_VIEW = 4000.0

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed by peer")
        buf.extend(chunk)
    return bytes(buf)

def parse_c_string(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", errors="ignore")

def parse_general(payload: bytes):
    vehicle_type = U8.unpack_from(payload, OFF_VEHICLE_TYPE)[0]
    gear_pos     = U8.unpack_from(payload, OFF_GEAR_POSITION)[0]
    steer_angle  = I16.unpack_from(payload, OFF_STEER_ANGLE)[0]
    wheel_speeds = U16x4.unpack_from(payload, OFF_WHEEL_SPEEDS)
    frame_num    = U32.unpack_from(payload, OFF_FRAME_NUM)[0]
    ecu_id = parse_c_string(payload[OFF_ECU_ID:OFF_ECU_ID+50])
    hw_ver = parse_c_string(payload[OFF_HW_VERSION:OFF_HW_VERSION+4])
    sw_ver = parse_c_string(payload[OFF_SW_VERSION:OFF_SW_VERSION+32])
    return vehicle_type, gear_pos, steer_angle, wheel_speeds, frame_num, ecu_id, hw_ver, sw_ver

# === raw angle mapping ===
def raw_to_rad_full(raw: np.ndarray, den: float) -> np.ndarray:
    """raw(0..65535) -> rad(-pi..pi) (현재 서버 시뮬과 동일 가정)"""
    return (raw / den) * (2.0 * math.pi) - math.pi

# 만약 스펙이 -60..+60 deg 같은 제한범위면 이걸로 바꿔서 쓰면 됨:
# def raw_to_rad_fov(raw: np.ndarray, fov_deg: float) -> np.ndarray:
#     fov = math.radians(fov_deg)
#     # raw 0..65535 -> -fov..+fov
#     return (raw / 65535.0) * (2.0 * fov) - fov

class SharedRadarFrame:
    def __init__(self):
        self.lock = threading.Lock()
        self.xyz = None          # (N,3)
        self.ts = 0
        self.cycle = 0
        self.updated_at = 0.0

shared = SharedRadarFrame()

def radar_payload_to_xyz(payload: bytes):
    ts = struct.unpack_from(ENDIAN + "I", payload, OFF_RD_TIMESTAMP)[0]
    cycle = struct.unpack_from(ENDIAN + "I", payload, OFF_RD_CYCLECOUNTER)[0]

    det_area = memoryview(payload)[RADAR_INTERNAL_HDR_SIZE:]

    r_raw  = np.empty(NUM_DET, dtype=np.float32)
    az_raw = np.empty(NUM_DET, dtype=np.float32)
    el_raw = np.empty(NUM_DET, dtype=np.float32)

    for i in range(NUM_DET):
        base = i * DETECTION_SIZE + DET_OFF_POS_R
        pr, paz, pel = DET_POS_STRUCT.unpack_from(det_area, base)
        r_raw[i]  = pr
        az_raw[i] = paz
        el_raw[i] = pel

    r = r_raw * R_SCALE
    az = raw_to_rad_full(az_raw, AZ_DEN)
    el = raw_to_rad_full(el_raw, EL_DEN)

    # 3D 변환 (spherical-ish)
    # r: radial distance
    # az: yaw around z
    # el: pitch up/down
    ce = np.cos(el)
    x = r * ce * np.cos(az)
    y = r * ce * np.sin(az)
    z = r * np.sin(el)

    xyz = np.column_stack((x, y, z))

    # 보기 좋게 너무 먼 점 제거(원하면 끄기)
    mask = r <= R_MAX_VIEW
    xyz = xyz[mask]
    az2 = az[mask]
    el2 = el[mask]
    r2  = r[mask]

    return xyz, ts, cycle, az2, el2, r2

def receiver_thread():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("Receiver connected.")

        last_time_general = None
        last_time_radar = None
        gen_count = 0
        rad_count = 0

        while True:
            header_bytes = recv_exact(sock, HEADER_SIZE)
            (service_id, method_id, length_field, client_id, session_id,
             proto_ver, if_ver, msg_type, reserved) = HEADER.unpack(header_bytes)

            payload_len = length_field - LEN_FIELD_MINUS
            payload = recv_exact(sock, payload_len)
            now = time.time()

            if service_id != SERVICE_ID_EXPECT:
                print(f"[WARN] service_id mismatch: 0x{service_id:04X}")

            if method_id == METHOD_GENERAL:
                if payload_len != PAYLOAD_GENERAL_LEN:
                    print(f"[WARN] General len mismatch: {payload_len}")
                    continue

                gen_count += 1
                dt_ms = None if last_time_general is None else (now - last_time_general) * 1000.0
                last_time_general = now

                vt, gear, steer, wheels, frame, ecu, hw, sw = parse_general(payload)

                if gen_count % LOG_EVERY_N == 0:
                    print(
                        f"[General] dt={('N/A' if dt_ms is None else f'{dt_ms:.1f}ms')} "
                        f"frame={frame} gear={gear} steer={steer} wheel={wheels} "
                        f"ecu='{ecu}' hw='{hw}' sw='{sw}'"
                    )

            elif method_id == METHOD_RADAR:
                if payload_len != PAYLOAD_RADAR_LEN:
                    print(f"[WARN] Radar len mismatch: {payload_len}")
                    continue

                rad_count += 1
                dt_ms = None if last_time_radar is None else (now - last_time_radar) * 1000.0
                last_time_radar = now

                xyz, ts, cycle, az, el, rr = radar_payload_to_xyz(payload)

                with shared.lock:
                    shared.xyz = xyz
                    shared.ts = ts
                    shared.cycle = cycle
                    shared.updated_at = now

                if rad_count % LOG_EVERY_N == 0:
                    # 3개 포인트(필터 후)
                    n = min(3, xyz.shape[0])
                    if n == 0:
                        pts = "(no pts)"
                    else:
                        pts_list = []
                        for k in range(n):
                            pts_list.append(
                                f"(az={math.degrees(float(az[k])):+.1f}deg "
                                f"el={math.degrees(float(el[k])):+.1f}deg "
                                f"r={float(rr[k]):.1f})"
                            )
                        pts = " ".join(pts_list)

                    print(
                        f"[Radar ] dt={('N/A' if dt_ms is None else f'{dt_ms:.1f}ms')} "
                        f"ts={ts} cycle={cycle} N={xyz.shape[0]} pts3={pts}"
                    )

            else:
                pass

def main_gui_3d():
    th = threading.Thread(target=receiver_thread, daemon=True)
    th.start()

    fig = plt.figure()
    ax = fig.add_subplot(111, projection="3d")
    ax.set_title("Radar Detections 3D (x,y,z)")

    scat = ax.scatter([], [], [], s=4)

    # 고정 축 범위(깜빡임 줄임). 필요하면 자동으로 바꿔도 됨.
    lim = R_MAX_VIEW
    ax.set_xlim(-lim, lim)
    ax.set_ylim(-lim, lim)
    ax.set_zlim(-lim * 0.3, lim * 0.3)

    # 보기 각도(원하는 대로)
    ax.view_init(elev=18, azim=-60)

    last_draw_t = 0.0

    def update(_):
        nonlocal last_draw_t
        now = time.time()
        if now - last_draw_t < GUI_UPDATE_SEC:
            return scat,

        with shared.lock:
            xyz = None if shared.xyz is None else shared.xyz.copy()
            ts = shared.ts
            cycle = shared.cycle
            updated_at = shared.updated_at

        if xyz is None or xyz.size == 0:
            return scat,

        # matplotlib 3d scatter 업데이트
        scat._offsets3d = (xyz[:, 0], xyz[:, 1], xyz[:, 2])

        ax.set_xlabel(f"ts={ts} cycle={cycle} updated_at={updated_at:.2f}")
        last_draw_t = now
        return scat,

    ani = FuncAnimation(fig, update, interval=50, blit=False)
    plt.show()

if __name__ == "__main__":
    try:
        main_gui_3d()
    except KeyboardInterrupt:
        print("\nClient terminated.")
    except Exception as e:
        print(f"\nClient error: {e}")
