import socket
import time
import struct
from dataclasses import dataclass

# ---- 설정값 ----
HOST = "0.0.0.0"
PORT = 4545

# ---- Header 상수 ----
SERVICE_ID = 0x6000
METHOD_GENERAL = 0x8001
CLIENT_ID  = 0x0001
PROTO_VER  = 0x01
IF_VER     = 0x01
MSG_TYPE   = 0x02
RESERVED   = 0x00

ENDIAN = ">"   # Big-endian

# SOME/IP Header Format:
# ServiceID(H), MethodID(H), Length(I), ClientID(H), SessionID(H), 
# Proto(B), IF(B), Type(B), Res(B)
FMT_HEADER = ENDIAN + "HHIHHBBBB"

# ---- Payload Format ----
COMPLEX_FMT = "hh"  # int16 I, int16 Q

FMT_PAYLOAD = (
    ENDIAN +
    "B"  # VehicleType
    "B"  # GearPosition
    "h"  # SteeringAngle
    "B"  # YawSignalStatus
    "H"  # YawRate_dps
    "B"  # EngineRunningStatus
    "B"  # EngineStatus
    "H"  # AcceleratorPedalValue
    "B"  # AppliedAcceleratorPedalStatus
    "H"  # ActualAccelerationPedalValue
    "B"  # GearSelectDisplay
    "B"  # EngineTargetGear
    "4H" # WheelSpeed_kmph[4]
    "8s" # Reserved1
    "B"  # SensorPosition
    "B"  # MountingDirection
    "h"  # XOffset_m
    "h"  # YOffset_m
    "h"  # ZOffset_m
    "h"  # AzimuthEOLOffset_deg
    "h"  # ElvevationEOLOffset_deg
    "20s" # Reserved2
    "50s" # ECU_Id
    "4s"  # HW_Version
    "32s" # SW_Version
    "I"   # FrameNum
    "H"   # CenterFrequency
    "H"   # PRI_us
    "H"   # TotalTargetNum
    "H"   # ProcessingTime
    "66s" # Reserved3
    + (COMPLEX_FMT * 256)  # SampleCalibrationData: 512 shorts
    + (COMPLEX_FMT * 128)  # Reserved4 (Complex): 256 shorts
    + "H"  # SacqElemNullingRatePct
    + "H"  # Reserved5
    + "H"  # CurrentNoiseLevel_mag
    + "H"  # PrevNoiseLevel_mag
    + "4s"  # Reserved6
    + "8s"  # Reserved7
    + "8s"  # Reserved8
    + "8s"  # Reserved9
    + "32s" # Reserved10
)

@dataclass
class GeneralMessage:
    # 값 변경이 필요한 필드들만 기본값 설정
    FrameNum: int = 0
    SteeringAngle: int = 100
    
    def to_bytes(self) -> bytes:
        # 1. 고정/더미 데이터 생성
        wheel_speed = [100, 100, 100, 100] # FL, FR, RL, RR
        
        # Complex Data 생성 (I=0, Q=0)
        # fmt에 'h'가 512개(256*2) 나오므로 인자도 512개가 필요함
        complex_data_256 = [0] * (256 * 2) 
        complex_data_128 = [0] * (128 * 2)

        # 문자열 안전 변환 (bytes로 인코딩 후 길이 맞춤)
        ecu_id = b"ECU-TEST-001".ljust(50, b'\x00')
        hw_ver = b"v1.0".ljust(4, b'\x00')
        sw_ver = b"SW-2024.01".ljust(32, b'\x00')

        return struct.pack(
            FMT_PAYLOAD,
            0, 5, self.SteeringAngle, 0, 0, 0, 0, 0, 0, 0, 0, 0, # 기본 필드
            *wheel_speed,          # 리스트 언패킹 (4H)
            b'\x00'*8,             # Reserved1
            1, 1, 0, 0, 0, 0, 0,   # Offsets
            b'\x00'*20,            # Reserved2
            ecu_id, hw_ver, sw_ver,
            self.FrameNum, 77000, 50, 10, 200, # Radar info
            b'\x00'*66,            # Reserved3
            *complex_data_256,     # 리스트 언패킹 (512개 인자)
            *complex_data_128,     # 리스트 언패킹 (256개 인자)
            80, 0, 150, 140,       # Noise info
            b'\x00'*4, b'\x00'*8, b'\x00'*8, b'\x00'*8, b'\x00'*32 # Reserved 6~10
        )

def create_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}")
    return server_sock

if __name__ == "__main__":
    server_sock = create_server()
    conn, addr = server_sock.accept()
    print(f"Connected by {addr}")
    
    session_id = 0
    frame_count = 0

    try:
        while True:
            # 1. Payload 생성
            # 시뮬레이션을 위해 FrameNum 등을 증가시킴
            msg = GeneralMessage(FrameNum=frame_count, SteeringAngle=100 + (frame_count % 10))
            payload = msg.to_bytes()

            # 2. Header 생성
            # Length = Payload 길이 + 8 bytes (ClientID ~ Reserved)
            payload_len = len(payload)
            header_len_field = payload_len + 8 

            header = struct.pack(
                FMT_HEADER,
                SERVICE_ID,
                METHOD_GENERAL,
                header_len_field,
                CLIENT_ID,
                session_id,
                PROTO_VER,
                IF_VER,
                MSG_TYPE,
                RESERVED
            )

            # 3. 전송 (Header + Payload)
            conn.sendall(header + payload)
            
            # 로그 출력 (선택)
            if frame_count % 20 == 0: # 너무 빠르니 가끔 출력
                print(f"Sent Frame: {frame_count}, SessionID: {session_id}, Size: {len(header) + len(payload)}")

            # 4. 상태 업데이트
            session_id = (session_id + 1) & 0xFFFF # 0~65535 순환
            frame_count += 1
            
            # 5. 주기 유지 (50ms)
            time.sleep(0.05)

    except KeyboardInterrupt:
        print("\nServer shutting down.")
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        if 'conn' in locals(): conn.close()
        server_sock.close()