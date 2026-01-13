import socket
import struct
import threading
import time
import math

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# =========================
# Config
# =========================
HOST = "127.0.0.1"
PORT = 4545
ENDIAN = ">"

# TCP Header (16B)
FMT_HEADER = ENDIAN + "HHIHHBBBB"
HEADER = struct.Struct(FMT_HEADER)
HEADER_SIZE = HEADER.size

SERVICE_ID_EXPECT = 0x6000
METHOD_GENERAL = 0x8001
METHOD_RADAR   = 0x8002
LEN_FIELD_MINUS = 8

PAYLOAD_GENERAL_LEN = 3368
PAYLOAD_RADAR_LEN   = 112680

# General offsets (필요 필드만)
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

# Radar layout
RADAR_INTERNAL_HDR_SIZE = 40
DETECTION_SIZE = 55
NUM_DET = 2048

DET_OFF_POS_R = 26
DET_POS_STRUCT = struct.Struct(ENDIAN + "HHH")  # pos_r, pos_az, pos_el

OFF_RD_TIMESTAMP    = 6
OFF_RD_CYCLECOUNTER = 10

# ===== 네가 말한 변환 스펙 =====
RANGE_SCALE_M = 0.01           # range_m = raw * 0.01
ANGLE_SCALE   = 0.0001         # rad
ANGLE_OFFSET  = -1.5708        # -pi/2 근처

# 로그/GUI 속도
LOG_EVERY_N = 1
GUI_UPDATE_SEC = 0.2

# FOV Cone
CONE_HALF_ANGLE_DEG = 60.0
CONE_HALF_ANGLE_RAD = math.radians(CONE_HALF_ANGLE_DEG)

# 표시 최대거리 (range_m 최대가 655.35m)
R_MAX_VIEW = 750.0

# =========================
# Utils
# =========================
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

# =========================
# Shared data (thread-safe)
# =========================
class SharedRadarFrame:
    def __init__(self):
        self.lock = threading.Lock()
        self.xyz = None
        self.ts = 0
        self.cycle = 0
        self.updated_at = 0.0
        self.last_rmax = 10.0

shared = SharedRadarFrame()

# =========================
# Radar parse
# =========================
def radar_payload_to_xyz(payload: bytes):
    ts = struct.unpack_from(ENDIAN + "I", payload, OFF_RD_TIMESTAMP)[0]
    cycle = struct.unpack_from(ENDIAN + "I", payload, OFF_RD_CYCLECOUNTER)[0]

    det_area = memoryview(payload)[RADAR_INTERNAL_HDR_SIZE:]

    r_raw  = np.empty(NUM_DET, dtype=np.float32)
    az_raw = np.empty(NUM_DET, dtype=np.float32)
    el_raw = np.empty(NUM_DET, dtype=np.float32)

    # 2048개만 루프(충분히 빠름)
    for i in range(NUM_DET):
        base = i * DETECTION_SIZE + DET_OFF_POS_R
        pr, paz, pel = DET_POS_STRUCT.unpack_from(det_area, base)
        r_raw[i]  = pr
        az_raw[i] = paz
        el_raw[i] = pel

    # ✅ 네 스펙 변환
    r  = r_raw * RANGE_SCALE_M
    az = az_raw * ANGLE_SCALE + ANGLE_OFFSET
    el = el_raw * ANGLE_SCALE + ANGLE_OFFSET

    # 3D 변환 (az=yaw about z, el=elevation)
    ce = np.cos(el)
    x = r * ce * np.cos(az)
    y = r * ce * np.sin(az)
    z = r * np.sin(el)

    xyz = np.column_stack((x, y, z))

    # 보기 좋게 너무 먼 점 제거(원하면 제거해도 됨)
    mask = r <= R_MAX_VIEW
    xyz = xyz[mask]
    az2 = az[mask]
    el2 = el[mask]
    r2  = r[mask]

    return xyz, ts, cycle, az2, el2, r2

# =========================
# Cone(FOV) drawing
# (3D에서 linestyle '--'가 잘 안 보이는 경우가 많아서 "실선"으로 강제)
# =========================
def draw_cone_fov(ax, half_angle_rad: float, r_max: float):
    # surface
    phi = np.linspace(0, 2.0 * math.pi, 180)
    rr  = np.linspace(0, r_max, 60)
    Phi, R = np.meshgrid(phi, rr)

    X = R * math.cos(half_angle_rad)              # +X axis
    Y = R * math.sin(half_angle_rad) * np.cos(Phi)
    Z = R * math.sin(half_angle_rad) * np.sin(Phi)

    ax.plot_surface(
        X, Y, Z,
        color="red",
        alpha=0.10,
        linewidth=0,
        shade=False
    )

    # axis line (+X)
    ax.plot([0, r_max], [0, 0], [0, 0], color="red", linewidth=2.2, alpha=0.95)

    # end ring
    phi2 = np.linspace(0, 2.0 * math.pi, 240)
    x_ring = np.full_like(phi2, r_max * math.cos(half_angle_rad))
    rad_ring = r_max * math.sin(half_angle_rad)
    y_ring = rad_ring * np.cos(phi2)
    z_ring = rad_ring * np.sin(phi2)
    ax.plot(x_ring, y_ring, z_ring, color="red", linewidth=2.2, alpha=0.95)

    # generatrix lines
    lines = 12
    for k in range(lines):
        a = 2.0 * math.pi * k / lines
        x1 = r_max * math.cos(half_angle_rad)
        y1 = rad_ring * math.cos(a)
        z1 = rad_ring * math.sin(a)
        ax.plot([0, x1], [0, y1], [0, z1], color="red", linewidth=1.6, alpha=0.85)

# =========================
# Receiver thread: General+Radar dt 로깅
# =========================
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
            now = now = time.perf_counter()


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
                    shared.last_rmax = float(rr.max()) if rr.size else shared.last_rmax

                if rad_count % LOG_EVERY_N == 0:
                    n = min(3, xyz.shape[0])
                    if n == 0:
                        pts = "(no pts)"
                    else:
                        pts_list = []
                        for k in range(n):
                            pts_list.append(
                                f"(az={math.degrees(float(az[k])):+.1f}deg "
                                f"el={math.degrees(float(el[k])):+.1f}deg "
                                f"r={float(rr[k]):.2f}m)"
                            )
                        pts = " ".join(pts_list)

                    print(
                        f"[Radar ] dt={('N/A' if dt_ms is None else f'{dt_ms:.1f}ms')} "
                        f"ts={ts} cycle={cycle} N={xyz.shape[0]} rmax={shared.last_rmax:.2f}m pts3={pts}"
                    )

            else:
                pass

# =========================
# 3D GUI
# =========================
def main_gui_3d():
    th = threading.Thread(target=receiver_thread, daemon=True)
    th.start()

    fig = plt.figure()
    ax = fig.add_subplot(111, projection="3d")
    ax.set_title(f"Radar 3D + FOV Cone (±{CONE_HALF_ANGLE_DEG:.0f}°)")

    scat = ax.scatter([], [], [], s=4)

    ax.set_box_aspect((1, 1, 1))
    ax.grid(True)
    ax.view_init(elev=18, azim=-60)

    # cone 먼저 그림
    draw_cone_fov(ax, CONE_HALF_ANGLE_RAD, min(R_MAX_VIEW, 700.0))

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
            rmax = shared.last_rmax

        if xyz is None or xyz.size == 0:
            return scat,

        scat._offsets3d = (xyz[:, 0], xyz[:, 1], xyz[:, 2])

        # ✅ range가 실제로 변하는지 눈으로 확인되게, 축을 rmax 기반으로 갱신
        lim = max(10.0, min(R_MAX_VIEW, rmax))
        ax.set_xlim(0, lim)
        ax.set_ylim(-lim, lim)
        ax.set_zlim(-lim, lim)

        ax.set_xlabel(f"ts={ts} cycle={cycle} updated_at={updated_at:.2f} rmax={lim:.2f}m")
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
