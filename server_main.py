import socket
import time
import struct
from dataclasses import dataclass
import math

HOST = "0.0.0.0"
PORT = 4545

# =========================
# 공통: TCP Header (16B)
# =========================
ENDIAN = ">"  # 사양서 little이면 "<"
FMT_HEADER = ENDIAN + "HHIHHBBBB"
HEADER_SIZE = struct.calcsize(FMT_HEADER)
assert HEADER_SIZE == 16

SERVICE_ID = 0x6000
CLIENT_ID  = 0x0001
SESSION_ID = 0xFFFF  # 고정(원하면 증가시키면 됨)
PROTO_VER  = 0x01
IF_VER     = 0x01
MSG_TYPE   = 0x02
RESERVED   = 0x00

METHOD_GENERAL = 0x8001
METHOD_RADAR   = 0x8002

# Length = payload_len + 8 (표 기준)
LENGTH_GENERAL = 0x0D30   # 3376
LENGTH_RADAR   = 0x1B830  # 112688

HEADER_GENERAL_BYTES = struct.pack(
    FMT_HEADER, SERVICE_ID, METHOD_GENERAL, LENGTH_GENERAL,
    CLIENT_ID, SESSION_ID, PROTO_VER, IF_VER, MSG_TYPE, RESERVED
)
HEADER_RADAR_BYTES = struct.pack(
    FMT_HEADER, SERVICE_ID, METHOD_RADAR, LENGTH_RADAR,
    CLIENT_ID, SESSION_ID, PROTO_VER, IF_VER, MSG_TYPE, RESERVED
)

# =========================
# 유틸
# =========================
def fixed_bytes(b: bytes, n: int) -> bytes:
    if len(b) >= n:
        return b[:n]
    return b + (b"\x00" * (n - len(b)))

def u8(x: int) -> int:
    return x & 0xFF

def u16(x: int) -> int:
    return x & 0xFFFF

def u32(x: int) -> int:
    return x & 0xFFFFFFFF

def i16(x: int) -> int:
    # struct 'h'는 -32768..32767
    x = int(x)
    if x < -32768:
        return -32768
    if x > 32767:
        return 32767
    return x

def create_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}")
    return server_sock

def send_message(conn, message: bytes):
    conn.sendall(message)

# =========================
# GeneralMessage (payload 3368B)
# =========================
FMT_GENERAL_PAYLOAD = (
    ENDIAN +
    "B" "B" "h" "B" "H" "B" "B" "H" "B" "H" "B" "B"
    "4H"
    "8s"
    "B" "B"
    "h" "h" "h" "h" "h"
    "20s" "50s" "4s" "32s"
    "I" "H" "H" "H" "H"
    "66s"
    "2048s"
    "1024s"
    "H" "H" "H" "H"
    "4s" "8s" "8s" "8s" "32s"
)
PAYLOAD_LEN_GENERAL = 3368
assert struct.calcsize(FMT_GENERAL_PAYLOAD) == PAYLOAD_LEN_GENERAL

@dataclass
class GeneralMessage:
    VehicleType: int
    GearPosition: int
    SteeringAngle_deg: int
    YawSignalStatus: int
    YawRate_dps: int
    EngineRunningStatus: int
    EngineStatus: int
    AcceleratorPedalValue: int
    AppliedAcceleratorPedalStatus: int
    ActualAccelerationPedalValue: int
    GearSelectDisplay: int
    EngineTargetGear: int

    WheelSpeed_kmph_fl: int
    WheelSpeed_kmph_fr: int
    WheelSpeed_kmph_rl: int
    WheelSpeed_kmph_rr: int

    Reserved1: bytes
    SensorPosition: int
    MountingDirection: int
    XOffset_m: int
    YOffset_m: int
    ZOffset_m: int
    AzimuthEOLOffset_deg: int
    ElvevationEOLOffset_deg: int

    Reserved2: bytes
    ECU_Id: bytes
    HW_Version: bytes
    SW_Version: bytes

    FrameNum: int
    CenterFrequency: int
    PRI_us: int
    TotalTargetNum: int
    ProcessingTime: int

    Reserved3: bytes
    SampleCalibrationData: bytes
    Reserved4: bytes

    SacqElemNullingRatePct: int
    Reserved5: int
    CurrentNoiseLevel_mag: int
    PrevNoiseLevel_mag: int

    Reserved6: bytes
    Reserved7: bytes
    Reserved8: bytes
    Reserved9: bytes
    Reserved10: bytes

    def to_bytes(self) -> bytes:
        return struct.pack(
            FMT_GENERAL_PAYLOAD,
            u8(self.VehicleType),
            u8(self.GearPosition),
            i16(self.SteeringAngle_deg),
            u8(self.YawSignalStatus),
            u16(self.YawRate_dps),
            u8(self.EngineRunningStatus),
            u8(self.EngineStatus),
            u16(self.AcceleratorPedalValue),
            u8(self.AppliedAcceleratorPedalStatus),
            u16(self.ActualAccelerationPedalValue),
            u8(self.GearSelectDisplay),
            u8(self.EngineTargetGear),

            u16(self.WheelSpeed_kmph_fl),
            u16(self.WheelSpeed_kmph_fr),
            u16(self.WheelSpeed_kmph_rl),
            u16(self.WheelSpeed_kmph_rr),

            fixed_bytes(self.Reserved1, 8),
            u8(self.SensorPosition),
            u8(self.MountingDirection),
            i16(self.XOffset_m),
            i16(self.YOffset_m),
            i16(self.ZOffset_m),
            i16(self.AzimuthEOLOffset_deg),
            i16(self.ElvevationEOLOffset_deg),

            fixed_bytes(self.Reserved2, 20),
            fixed_bytes(self.ECU_Id, 50),
            fixed_bytes(self.HW_Version, 4),
            fixed_bytes(self.SW_Version, 32),

            u32(self.FrameNum),
            u16(self.CenterFrequency),
            u16(self.PRI_us),
            u16(self.TotalTargetNum),
            u16(self.ProcessingTime),

            fixed_bytes(self.Reserved3, 66),
            fixed_bytes(self.SampleCalibrationData, 2048),
            fixed_bytes(self.Reserved4, 1024),

            u16(self.SacqElemNullingRatePct),
            u16(self.Reserved5),
            u16(self.CurrentNoiseLevel_mag),
            u16(self.PrevNoiseLevel_mag),

            fixed_bytes(self.Reserved6, 4),
            fixed_bytes(self.Reserved7, 8),
            fixed_bytes(self.Reserved8, 8),
            fixed_bytes(self.Reserved9, 8),
            fixed_bytes(self.Reserved10, 32),
        )

# =========================
# RadarDetection (payload 112680B)
# RadarPayload = RadarInternalHeader(40B) + DetectionEntry(55B)*2048
# =========================
# 40B: 3s BBB II HH B 8H H B H
FMT_RD_HEADER = ENDIAN + "3sBBBIIHHB8HHBH"
RD_HEADER = struct.Struct(FMT_RD_HEADER)
assert RD_HEADER.size == 40

# 55B DetectionEntry (네 타입 순서 기반)
FMT_DET = ENDIAN + "BHBHHhBBBHBBB4s4sHHHHHHHHHBB3sBBBBH"
DET = struct.Struct(FMT_DET)
assert DET.size == 55

NUM_DET = 2048
PAYLOAD_LEN_RADAR = 112680
assert RD_HEADER.size + DET.size * NUM_DET == PAYLOAD_LEN_RADAR

# ===== 분포 설정(원하는 느낌으로 조절) =====
FOV_DEG = 90.0
FOV_RAD = math.radians(FOV_DEG)

R_MIN_RAW = 1000
R_MAX_RAW = 60000

ROT_STEP_RAW = 120        # 프레임마다 azimuth raw 회전량(값 키우면 더 빨리 회전)
R_JITTER_RAW = 200        # 거리 흔들림(값 키우면 더 출렁)

def clamp_u16(x: int) -> int:
    if x < 0: return 0
    if x > 65535: return 65535
    return x

def xorshift32(x: int) -> int:
    x &= 0xFFFFFFFF
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17) & 0xFFFFFFFF
    x ^= (x << 5)  & 0xFFFFFFFF
    return x & 0xFFFFFFFF

def theta_to_raw(theta_rad: float) -> int:
    # client에서 theta = (raw/65535)*2pi - pi 로 복원한다는 가정
    raw = int(((theta_rad + math.pi) / (2.0 * math.pi)) * 65535.0)
    return clamp_u16(raw)

def build_base_points(num: int):
    """
    2048개를 부채꼴(FOV) 내부에 '골고루' 퍼뜨리는 베이스 생성.
    - theta: 균등
    - r: 면적 균등을 위해 sqrt(u) 사용 (시각적으로 더 고르게 보임)
    """
    base_az = [0] * num
    base_r  = [0] * num
    for i in range(num):
        s = (i + 1) * 0xA341316C  # seed
        s = xorshift32(s)
        u_theta = (s & 0xFFFF) / 65535.0
        theta = -FOV_RAD + (2.0 * FOV_RAD) * u_theta
        base_az[i] = theta_to_raw(theta)

        s = xorshift32(s)
        u_r = (s & 0xFFFF) / 65535.0
        r = R_MIN_RAW + int((R_MAX_RAW - R_MIN_RAW) * math.sqrt(u_r))
        base_r[i] = clamp_u16(r)
    return base_az, base_r

BASE_AZ_RAW, BASE_R_RAW = build_base_points(NUM_DET)

def raw_to_theta(raw: int) -> float:
    return (raw / 65535.0) * (2.0 * math.pi) - math.pi

def theta_to_raw(theta: float) -> int:
    raw = int(((theta + math.pi) / (2.0 * math.pi)) * 65535.0)
    return clamp_u16(raw)



@dataclass
class RadarDetectionMessage:
    # RadarDetection Internal Header fields
    InterfaceVersion: bytes   # uint8[3]
    InterfaceID: int          # uint8
    NumberOfSensors: int      # uint8
    SensorID: int             # uint8
    Timestamp: int            # uint32
    CycleCounter: int         # uint32
    CycleTime: int            # uint16
    Variation: int            # uint16
    DataQualifier: int        # uint8

    # ambiguity domains: uint16[2] x4
    RV_Amb_Begin: int
    RV_Amb_End: int
    Range_Amb_Begin: int
    Range_Amb_End: int
    Az_Amb_Begin: int
    Az_Amb_End: int
    El_Amb_Begin: int
    El_Amb_End: int

    RecognisedCapability: int # uint16
    RecognisedStatus: int     # uint8
    NumberValidDetections: int# uint16 (이 값이 2048이 아니어도 됨)

    def to_bytes(self, frame_idx: int, t_sec: float) -> bytes:
        """
        요구사항:
        - DetectionEntry 2048개를 '전부' 매 프레임 채움 (0 padding 금지)
        - NumberValidDetections는 헤더값 그대로 사용 가능
        """
        buf = bytearray(PAYLOAD_LEN_RADAR)

        # 1) Internal Header pack (40B)
        RD_HEADER.pack_into(
            buf, 0,
            fixed_bytes(self.InterfaceVersion, 3),
            u8(self.InterfaceID),
            u8(self.NumberOfSensors),
            u8(self.SensorID),
            u32(self.Timestamp),
            u32(self.CycleCounter),
            u16(self.CycleTime),
            u16(self.Variation),
            u8(self.DataQualifier),

            u16(self.RV_Amb_Begin), u16(self.RV_Amb_End),
            u16(self.Range_Amb_Begin), u16(self.Range_Amb_End),
            u16(self.Az_Amb_Begin), u16(self.Az_Amb_End),
            u16(self.El_Amb_Begin), u16(self.El_Amb_End),

            u16(self.RecognisedCapability),
            u8(self.RecognisedStatus),
            u16(self.NumberValidDetections),
        )

        # 2) DetectionEntry 2048개 전부 채우기
        base = RD_HEADER.size

        # 각도 분포: 0..65535 전체를 고르게 + 프레임에 따라 회전
        rot = (frame_idx * 200) & 0xFFFF

        for i in range(NUM_DET):
            # ---- "변화하는" 시뮬 값들 (전부 0 아닌 값으로 구성) ----
            existence_prob = 150 + int(100 * (0.5 + 0.5 * math.sin(t_sec * 1.3 + i * 0.01)))  # 150~250
            detection_id = i
            object_id_ref = i & 0xFF
            timestamp_diff = (frame_idx & 0xFFFF)

            rcs = 500 + ((i * 7 + frame_idx * 3) % 3000)  # 500~3499
            rcs_err = i16(int(20 * math.sin(t_sec * 2.0 + i * 0.02)))  # -20..20

            snr = 10 + ((i * 3 + frame_idx) % 70)  # 10~79
            snr_err = (i + frame_idx) % 6          # 0~5

            multi_target_prob = (i + frame_idx) & 0xFF
            ambiguity_group_id = (i // 2) & 0xFFFF
            detection_ambiguity_prob = (i * 5 + frame_idx) & 0xFF
            free_space_prob = (255 - (i + frame_idx) % 200) & 0xFF

            num_valid_det_class = 1
            class_id = i % 4
            det_class_type = bytes([class_id, 0, 0, 0])  # enumeration[4]
            det_class_conf = bytes([min(100, 30 + (i % 70)), 0, 0, 0])  # uint8[4]

            # position (raw uint16)
            #pos_r  = 1000 + ((i * 31 + frame_idx * 9) % 60000)  # 1000~60999
            #pos_az = u16((i * 65535 // (NUM_DET - 1)) + rot)     # 0..65535 분포 + 회전
            #pos_el = 200 + ((i * 11 + frame_idx * 4) % 5000)     # 200~5199

            # --- 골고루 산개되는 az/r (베이스 + 회전 + 작은 jitter) ---
            #rot = u16(frame_idx * ROT_STEP_RAW)

            #pos_az = u16(BASE_AZ_RAW[i] + rot)

            # --- FOV 안에서만 스윙하는 오프셋(라디안) ---
            theta_off = 0.6 * FOV_RAD * math.sin(t_sec * 0.6)  # 0.6은 스윙 크기

            base_theta = raw_to_theta(BASE_AZ_RAW[i])
            theta = base_theta + theta_off

            # FOV 밖으로 나가지 않게 clamp
            if theta < -FOV_RAD: theta = -FOV_RAD
            if theta >  FOV_RAD: theta =  FOV_RAD

            pos_az = theta_to_raw(theta)

            # r은 베이스에 작은 흔들림만 (프레임/인덱스에 따라 부드럽게 변화)
            jr = int(R_JITTER_RAW * math.sin(t_sec * 1.2 + i * 0.013))
            pos_r = clamp_u16(BASE_R_RAW[i] + jr)

            # elevation은 필요하면 비슷하게 흔들거나 고정
            pos_el = 200 + ((i * 11 + frame_idx * 4) % 5000)

            # position errors
            pos_r_err  = 5 + (i % 20)
            pos_az_err = 5 + ((i + 3) % 20)
            pos_el_err = 5 + ((i + 7) % 20)

            # velocity (raw uint16)
            rel_v_r = u16(30000 + int(2000 * math.sin(t_sec * 1.7 + i * 0.015)))
            rel_v_r_err = 1 + (i % 10)

            power = 200 + ((i * 13 + frame_idx * 5) % 2000)  # 200~2199

            az_method = 1
            el_method = 1

            pos_quality = bytes([
                1 + (i % 3),          # 1~3
                1 + ((i // 3) % 3),   # 1~3
                1 + ((i // 7) % 3),   # 1~3
            ])

            amb_model_az  = (i + frame_idx) & 0xFF
            amb_model_el  = (i * 2 + frame_idx) & 0xFF
            rel_v_quality = (i * 3 + frame_idx) & 0xFF
            amb_model_vel = (i * 4 + frame_idx) & 0xFF
            amb_index_vel = (i + frame_idx * 17) & 0xFFFF

            DET.pack_into(
                buf, base + i * DET.size,
                u8(existence_prob),
                u16(detection_id),
                u8(object_id_ref),
                u16(timestamp_diff),
                u16(rcs),
                i16(rcs_err),
                u8(snr),
                u8(snr_err),
                u8(multi_target_prob),
                u16(ambiguity_group_id),
                u8(detection_ambiguity_prob),
                u8(free_space_prob),
                u8(num_valid_det_class),
                fixed_bytes(det_class_type, 4),
                fixed_bytes(det_class_conf, 4),
                u16(pos_r),
                u16(pos_az),
                u16(pos_el),
                u16(pos_r_err),
                u16(pos_az_err),
                u16(pos_el_err),
                u16(rel_v_r),
                u16(rel_v_r_err),
                u16(power),
                u8(az_method),
                u8(el_method),
                fixed_bytes(pos_quality, 3),
                u8(amb_model_az),
                u8(amb_model_el),
                u8(rel_v_quality),
                u8(amb_model_vel),
                u16(amb_index_vel),
            )

        return bytes(buf)

# =========================
# Server main: 50ms마다 General -> Radar 순서 송신
# =========================
if __name__ == "__main__":
    server_sock = create_server()
    conn, addr = server_sock.accept()
    print(f"Connected by {addr}")

    # ---- General 초기화 ----
    gm = GeneralMessage(
        VehicleType=0,
        GearPosition=5,
        SteeringAngle_deg=0,
        YawSignalStatus=0,
        YawRate_dps=0,
        EngineRunningStatus=1,
        EngineStatus=2,
        AcceleratorPedalValue=0,
        AppliedAcceleratorPedalStatus=0,
        ActualAccelerationPedalValue=0,
        GearSelectDisplay=0,
        EngineTargetGear=0,

        WheelSpeed_kmph_fl=0,
        WheelSpeed_kmph_fr=0,
        WheelSpeed_kmph_rl=0,
        WheelSpeed_kmph_rr=0,

        Reserved1=b"\x00"*8,
        SensorPosition=0,
        MountingDirection=0,
        XOffset_m=0,
        YOffset_m=0,
        ZOffset_m=0,
        AzimuthEOLOffset_deg=0,
        ElvevationEOLOffset_deg=0,

        Reserved2=b"\x00"*20,
        ECU_Id=b"ECU123",
        HW_Version=b"HW01",
        SW_Version=b"SW01",

        FrameNum=0,
        CenterFrequency=0,
        PRI_us=0,
        TotalTargetNum=0,
        ProcessingTime=0,

        Reserved3=b"\x00"*66,
        SampleCalibrationData=b"\x11"*2048,  # 0 말고 임의 채움(원하면 변화시켜도 됨)
        Reserved4=b"\x22"*1024,              # 0 말고 임의 채움

        SacqElemNullingRatePct=0,
        Reserved5=0,
        CurrentNoiseLevel_mag=0,
        PrevNoiseLevel_mag=0,

        Reserved6=b"\x00"*4,
        Reserved7=b"\x00"*8,
        Reserved8=b"\x00"*8,
        Reserved9=b"\x00"*8,
        Reserved10=b"\x00"*32,
    )

    # ---- Radar 초기화 ----
    rd = RadarDetectionMessage(
        InterfaceVersion=bytes([1, 0, 0]),
        InterfaceID=1,
        NumberOfSensors=1,
        SensorID=0,
        Timestamp=0,
        CycleCounter=0,
        CycleTime=50,
        Variation=0,
        DataQualifier=0,

        RV_Amb_Begin=0, RV_Amb_End=0,
        Range_Amb_Begin=0, Range_Amb_End=0,
        Az_Amb_Begin=0, Az_Amb_End=0,
        El_Amb_Begin=0, El_Amb_End=0,

        RecognisedCapability=0,
        RecognisedStatus=0,
        NumberValidDetections=100,  # 예: 헤더는 100만 유효라고 표시해도 됨(요구사항대로 2048이 아닐 수 있음)
    )

    period = 0.05
    t0 = time.time()
    next_t = time.time()
    radar_frame = 0

    try:
        while True:
            now = time.time()
            t = now - t0

            # ---- General update ----
            gm.SteeringAngle_deg = int(300 * math.sin(t))  # int16 raw
            base = int(100 + 20 * math.sin(t * 0.5))
            gm.WheelSpeed_kmph_fl = base
            gm.WheelSpeed_kmph_fr = base
            gm.WheelSpeed_kmph_rl = base
            gm.WheelSpeed_kmph_rr = base
            gm.FrameNum = (gm.FrameNum + 1) & 0xFFFFFFFF

            general_payload = gm.to_bytes()
            assert len(general_payload) == PAYLOAD_LEN_GENERAL
            send_message(conn, HEADER_GENERAL_BYTES + general_payload)

            # ---- Radar update ----
            rd.Timestamp = u32(int((now - t0) * 1000))  # ms 예시
            rd.CycleCounter = u32(rd.CycleCounter + 1)
            radar_payload = rd.to_bytes(radar_frame, t)
            radar_frame += 1

            assert len(radar_payload) == PAYLOAD_LEN_RADAR
            send_message(conn, HEADER_RADAR_BYTES + radar_payload)

            # ---- 50ms 주기 ----
            next_t += period
            sleep_s = next_t - time.time()
            if sleep_s > 0:
                time.sleep(sleep_s)
            else:
                next_t = time.time()

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        conn.close()
        server_sock.close()
