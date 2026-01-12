import socket
import struct
import time

# 전송 설정
HOST = '0.0.0.0'
PORT = 4545  # 명세서 2-1항 참조

def pack_general_message():
    # 1. General Message (명세서 순서대로 패킹)
    # 포맷 설명: ! (Network Order), B (uint8), h (int16), H (uint16), I (uint32)
    # 아래는 명세서 초반부 필드 구성 예시입니다.
    fmt = "!BBhB H B B H B H B B" # VehicleType, Gear, Steer, YawStat, YawRate, EngRun...
    gen_header = struct.pack(fmt,
        0,      # VehicleType (uint8)
        5,      # GearPosition (uint8, 5:Drive)
        100,    # SteeringAngle (int16, 0.1 res -> 10.0 deg)
        0,      # YawSignalStatus (uint8)
        32768,  # YawRate (uint16, offset 적용 전 raw)
        1,      # EngineRunStatus (uint8)
        3,      # EngineStatus (uint8)
        0,      # AccelPedalVal (uint16)
        0,      # AccelPedalStatus (uint8)
        0,      # ActlAccelPedalVal (uint16)
        5,      # GearSelectDisplay (uint8)
        1       # TargetGear (uint8)
    )
    
    # 나머지 112,680바이트까지의 패딩 (실제 데이터 전송 시에는 이 부분을 실제 값으로 채움)
    total_size = 112680
    return gen_header.ljust(total_size, b'\x00')

def pack_radar_detection():
    # 2. Radar Detection Message (Header + Payload)
    # Header - Interface (3+1+1+1+4+4+2+2+1 = 19 bytes)
    header = struct.pack('!BBBBBBIIHHB',
        1, 1, 1,    # Interface Version
        1,          # Interface ID
        1,          # Number of sensors
        1,          # Sensor ID
        int(time.time()), # Timestamp
        100,        # Cycle Counter
        50,         # Cycle Time (50ms)
        0,          # Variation
        0           # Data Qualifier
    )
    # Header - Ambiguity & Info (나머지 필드 생략분 패딩)
    header_padding = b'\x00' * (116008 - 112680 - (2048 * 16)) # 전체에서 General과 Payload 뺀 나머지
    
    # Payload (2048 Entities) - 개당 16바이트 가정
    # Existence(1), ID(2), ObjID(1), TimeDiff(2), RCS(2), RCS_Err(2), SNR(1), SNR_Err(1), MultiProb(1), AmbID(2)...
    entity_fmt = "!BHBHHhBBB H" # 명세서 타입에 맞춘 16바이트 조합
    single_entity = struct.pack(entity_fmt, 100, 1, 0, 0, 500, 0, 50, 0, 0, 0)
    payload = single_entity * 2048
    
    return header + header_padding + payload

# 서버 구동
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind((HOST, PORT))
server_sock.listen(1)

print(f"Radar Server Listening on {PORT}...")

try:
    conn, addr = server_sock.accept()
    print(f"Connected by {addr}")
    while True:
        # 1. General Message 전송
        gen_msg = pack_general_message()
        conn.sendall(struct.pack('!I', len(gen_msg)) + gen_msg)
        
        # 2. Radar Detection Message 전송
        radar_msg = pack_radar_detection()
        conn.sendall(struct.pack('!I', len(radar_msg)) + radar_msg)
        
        print("Sent one frame (General + Radar)")
        time.sleep(0.05) # 50ms 주기
except Exception as e:
    print(f"Server Error: {e}")
finally:
    server_sock.close()