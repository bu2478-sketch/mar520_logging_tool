import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 4545

ENDIAN = ">"  # 서버와 동일 (big-endian). little이면 "<"

# ===== TCP Header (16 bytes) =====
FMT_HEADER = ENDIAN + "HHIHHBBBB"
HEADER_STRUCT = struct.Struct(FMT_HEADER)
HEADER_SIZE = HEADER_STRUCT.size  # 16

SERVICE_ID_EXPECT = 0x6000
METHOD_GENERAL = 0x8001
METHOD_RADAR   = 0x8002

# 스펙: Length = payload_len + 8
LEN_FIELD_MINUS = 8

# ===== Payload 길이(스펙) =====
PAYLOAD_GENERAL_LEN = 3368
PAYLOAD_RADAR_LEN   = 112680

# ===== General Payload offsets =====
OFF_VEHICLE_TYPE   = 0
OFF_GEAR_POSITION  = 1
OFF_STEER_ANGLE    = 2
OFF_WHEEL_SPEEDS   = 16
OFF_ECU_ID         = 64
OFF_HW_VERSION     = 114
OFF_SW_VERSION     = 118
OFF_FRAME_NUM      = 150

# ===== Radar Payload internal layout =====
# RadarPayload = RadarInternalHeader(40B) + DetectionEntry(55B)*2048
RADAR_INTERNAL_HDR_SIZE = 40
DETECTION_SIZE = 55
NUM_DET = 2048

# Radar internal header Struct (40B) - 서버와 동일해야 함
# 3s BBB II HH B 8H H B H
FMT_RD_HEADER = ENDIAN + "3sBBBIIHHB8HHBH"
RD_HDR = struct.Struct(FMT_RD_HEADER)
assert RD_HDR.size == RADAR_INTERNAL_HDR_SIZE

# DetectionEntry Struct (55B) - 서버와 동일해야 함
FMT_DET = ENDIAN + "BHBHHhBBBHBBB4s4sHHHHHHHHHBB3sBBBBH"
DET = struct.Struct(FMT_DET)
assert DET.size == DETECTION_SIZE


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

def parse_general(payload: bytes, dt_ms: float | None):
    vehicle_type  = struct.unpack_from(ENDIAN + "B", payload, OFF_VEHICLE_TYPE)[0]
    gear_pos      = struct.unpack_from(ENDIAN + "B", payload, OFF_GEAR_POSITION)[0]
    steer_angle   = struct.unpack_from(ENDIAN + "h", payload, OFF_STEER_ANGLE)[0]
    wheel_speeds  = struct.unpack_from(ENDIAN + "4H", payload, OFF_WHEEL_SPEEDS)
    frame_num     = struct.unpack_from(ENDIAN + "I", payload, OFF_FRAME_NUM)[0]

    ecu_id = parse_c_string(payload[OFF_ECU_ID:OFF_ECU_ID+50])
    hw_ver = parse_c_string(payload[OFF_HW_VERSION:OFF_HW_VERSION+4])
    sw_ver = parse_c_string(payload[OFF_SW_VERSION:OFF_SW_VERSION+32])

    dt_str = "N/A" if dt_ms is None else f"{dt_ms:.1f}ms"

    print(
        f"[General] dt={dt_str} frame={frame_num} "
        f"gear={gear_pos} steer={steer_angle} wheel={wheel_speeds} "
        f"ecu='{ecu_id}' hw='{hw_ver}' sw='{sw_ver}'"
    )

def parse_radar(payload: bytes, dt_ms: float | None):
    dt_str = "N/A" if dt_ms is None else f"{dt_ms:.1f}ms"

    # 1) Radar internal header (40B) 파싱
    hdr_bytes = payload[:RADAR_INTERNAL_HDR_SIZE]
    (if_ver3, interface_id, num_sensors, sensor_id,
     timestamp, cycle_counter, cycle_time, variation, data_qualifier,
     rv_b, rv_e, range_b, range_e, az_b, az_e, el_b, el_e,
     recog_cap, recog_status, num_valid) = RD_HDR.unpack(hdr_bytes)

    if_ver3_hex = if_ver3.hex()
    print(
        f"[RadarHdr] dt={dt_str} ifVer={if_ver3_hex} ifID={interface_id} sensors={num_sensors} sensorID={sensor_id} "
        f"ts={timestamp} cycle={cycle_counter} cycT={cycle_time} var={variation} dq={data_qualifier} "
        f"numValid={num_valid}"
    )

    # 2) DetectionEntry 샘플 몇 개만 파싱
    det_area = payload[RADAR_INTERNAL_HDR_SIZE:]
    expected_det_bytes = DETECTION_SIZE * NUM_DET
    if len(det_area) != expected_det_bytes:
        print(f"[WARN] Radar detection bytes mismatch. expected={expected_det_bytes}, got={len(det_area)}")
        return

    def read_det(i: int):
        off = i * DETECTION_SIZE
        d = DET.unpack_from(det_area, off)

        existence_prob = d[0]
        det_id         = d[1]
        obj_ref        = d[2]
        ts_diff        = d[3]
        rcs            = d[4]
        rcs_err        = d[5]
        snr            = d[6]
        snr_err        = d[7]

        # position: d[15], d[16], d[17]
        pos_r  = d[15]
        pos_az = d[16]
        pos_el = d[17]
        rel_v  = d[21]
        power  = d[23]

        return (existence_prob, det_id, obj_ref, ts_diff, rcs, rcs_err, snr, snr_err, pos_r, pos_az, pos_el, rel_v, power)

    sample_idxs = [0, 1, 2, 2047]
    for idx in sample_idxs:
        (exist, det_id, obj_ref, ts_diff, rcs, rcs_err, snr, snr_err,
         pos_r, pos_az, pos_el, rel_v, power) = read_det(idx)
        print(
            f"  [Det {idx:4d}] exist={exist} id={det_id} objRef={obj_ref} tsDiff={ts_diff} "
            f"rcs={rcs} rcsErr={rcs_err} snr={snr}/{snr_err} "
            f"pos(r,az,el)=({pos_r},{pos_az},{pos_el}) v={rel_v} pwr={power}"
        )

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"Connecting to {HOST}:{PORT} ...")
        sock.connect((HOST, PORT))
        print("Connected.")

        # ✅ method별 dt 측정용
        last_time_general = None
        last_time_radar = None

        while True:
            # 1) TCP Header 수신
            header_bytes = recv_exact(sock, HEADER_SIZE)
            (service_id, method_id, length_field, client_id, session_id,
             proto_ver, if_ver, msg_type, reserved) = HEADER_STRUCT.unpack(header_bytes)

            # 2) Payload 길이 계산
            payload_len = length_field - LEN_FIELD_MINUS
            if payload_len < 0:
                print(f"[WARN] invalid length_field={length_field}")
                break

            # 3) Payload 수신
            payload = recv_exact(sock, payload_len)

            # ✅ 수신시각
            now = time.time()

            # 4) 헤더 검증
            if service_id != SERVICE_ID_EXPECT:
                print(f"[WARN] service_id mismatch: 0x{service_id:04X}")

            # 5) 메시지 타입별 처리 + dt 계산
            if method_id == METHOD_GENERAL:
                if payload_len != PAYLOAD_GENERAL_LEN:
                    print(f"[WARN] General payload len mismatch. expected={PAYLOAD_GENERAL_LEN}, got={payload_len}")
                    continue

                dt_ms = None if last_time_general is None else (now - last_time_general) * 1000.0
                last_time_general = now
                parse_general(payload, dt_ms)

            elif method_id == METHOD_RADAR:
                if payload_len != PAYLOAD_RADAR_LEN:
                    print(f"[WARN] Radar payload len mismatch. expected={PAYLOAD_RADAR_LEN}, got={payload_len}")
                    continue

                dt_ms = None if last_time_radar is None else (now - last_time_radar) * 1000.0
                last_time_radar = now
                parse_radar(payload, dt_ms)

            else:
                print(f"[Unknown] method=0x{method_id:04X} payload_len={payload_len} (skipped)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nClient terminated.")
    except Exception as e:
        print(f"\nClient error: {e}")
