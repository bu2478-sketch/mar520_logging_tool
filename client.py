import socket
import struct

HOST = "127.0.0.1"
PORT = 4545

ENDIAN = ">"  # 서버와 동일하게 (big-endian). little이면 "<"

# ===== Header (16 bytes) =====
FMT_HEADER = ENDIAN + "HHIHHBBBB"
HEADER_STRUCT = struct.Struct(FMT_HEADER)
HEADER_SIZE = HEADER_STRUCT.size  # 16

SERVICE_ID_EXPECT = 0x6000
METHOD_GENERAL = 0x8001
METHOD_RADAR   = 0x8002

# 스펙: Length = payload_len + 8
LEN_FIELD_MINUS = 8

# ===== General Payload byte offsets (스펙 기반 고정) =====
# payload 총 길이 = 3368 (General)
PAYLOAD_GENERAL_LEN = 3368

OFF_VEHICLE_TYPE   = 0   # uint8
OFF_GEAR_POSITION  = 1   # uint8
OFF_STEER_ANGLE    = 2   # int16
OFF_WHEEL_SPEEDS   = 16  # uint16[4] (fl, fr, rl, rr)
OFF_ECU_ID         = 64  # char[50]
OFF_HW_VERSION     = 114 # char[4]
OFF_SW_VERSION     = 118 # char[32]
OFF_FRAME_NUM      = 150 # uint32

# (필요하면 더 추가해서 읽으면 됨)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """TCP에서 n바이트를 정확히 받을 때까지 recv"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed by peer")
        buf.extend(chunk)
    return bytes(buf)

def parse_c_string(b: bytes) -> str:
    """NULL 패딩된 char[N]을 문자열로"""
    return b.split(b"\x00", 1)[0].decode("ascii", errors="ignore")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"Connecting to {HOST}:{PORT} ...")
        sock.connect((HOST, PORT))
        print("Connected.")

        while True:
            # 1) Header 수신
            header_bytes = recv_exact(sock, HEADER_SIZE)
            (service_id, method_id, length_field, client_id, session_id,
             proto_ver, if_ver, msg_type, reserved) = HEADER_STRUCT.unpack(header_bytes)

            # 2) Payload 길이 계산 (스펙: length = payload + 8)
            payload_len = length_field - LEN_FIELD_MINUS
            if payload_len < 0:
                print(f"[WARN] invalid length_field={length_field}")
                break

            # 3) Payload 수신
            payload = recv_exact(sock, payload_len)

            # ---- 헤더 검증/출력 (원하면) ----
            if service_id != SERVICE_ID_EXPECT:
                print(f"[WARN] service_id mismatch: 0x{service_id:04X}")

            # 4) 메시지 타입별 처리
            if method_id == METHOD_GENERAL:
                if payload_len != PAYLOAD_GENERAL_LEN:
                    print(f"[WARN] General payload len mismatch. expected={PAYLOAD_GENERAL_LEN}, got={payload_len}")
                    continue

                # 필요한 필드만 “오프셋 기반”으로 뽑기 (Complex 등은 안 품)
                vehicle_type  = struct.unpack_from(ENDIAN + "B", payload, OFF_VEHICLE_TYPE)[0]
                gear_pos      = struct.unpack_from(ENDIAN + "B", payload, OFF_GEAR_POSITION)[0]
                steer_angle   = struct.unpack_from(ENDIAN + "h", payload, OFF_STEER_ANGLE)[0]
                wheel_speeds  = struct.unpack_from(ENDIAN + "4H", payload, OFF_WHEEL_SPEEDS)  # tuple(4)
                frame_num     = struct.unpack_from(ENDIAN + "I", payload, OFF_FRAME_NUM)[0]

                ecu_id        = parse_c_string(payload[OFF_ECU_ID:OFF_ECU_ID+50])
                hw_ver        = parse_c_string(payload[OFF_HW_VERSION:OFF_HW_VERSION+4])
                sw_ver        = parse_c_string(payload[OFF_SW_VERSION:OFF_SW_VERSION+32])

                print(
                    f"[General] frame={frame_num} "
                    f"gear={gear_pos} steer={steer_angle} "
                    f"wheel={wheel_speeds} ecu='{ecu_id}' hw='{hw_ver}' sw='{sw_ver}'"
                )

            elif method_id == METHOD_RADAR:
                # Radar payload 포맷이 아직 없으면 일단 읽고 스킵
                print(f"[Radar] sess=0x{session_id:04X} payload_len={payload_len} (skipped)")

            else:
                print(f"[Unknown] method=0x{method_id:04X} payload_len={payload_len} (skipped)")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nClient terminated.")
    except Exception as e:
        print(f"\nClient error: {e}")
