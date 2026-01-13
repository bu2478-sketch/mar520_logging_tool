import socket
import time
import struct
from dataclasses import dataclass
import math

HOST = "0.0.0.0"
PORT = 4545

# =========================
# Header 고정값(표 기준)
# =========================
ENDIAN = ">"  # 사양서가 little이면 "<"
FMT_HEADER = ENDIAN + "HHIHHBBBB"  # 16 bytes

SERVICE_ID = 0x6000
METHOD_GENERAL = 0x8001
LENGTH_GENERAL = 0x0D30  # 3376 (표 기준)
CLIENT_ID = 0x0001
SESSION_ID = 0xFFFF      # 지금은 고정
PROTO_VER = 0x01
IF_VER = 0x01
MSG_TYPE = 0x02
RESERVED = 0x00

HEADER_GENERAL_BYTES = struct.pack(
    FMT_HEADER,
    SERVICE_ID,
    METHOD_GENERAL,
    LENGTH_GENERAL,
    CLIENT_ID,
    SESSION_ID,
    PROTO_VER,
    IF_VER,
    MSG_TYPE,
    RESERVED,
)

# =========================
# General Payload 포맷
# - Complex_t[256], Complex_t[128]은 bytes 블록으로 처리
#   (각각 2048, 1024 bytes)  -> payload total 3368 맞춤
# =========================
FMT_PAYLOAD = (
    ENDIAN +
    "B"  # uint8_t
    "B"  # uint8_t
    "h"  # int16_t
    "B"  # uint8_t
    "H"  # uint16_t
    "B"  # uint8_t
    "B"  # uint8_t
    "H"  # uint16_t
    "B"  # uint8_t
    "H"  # uint16_t
    "B"  # uint8_t
    "B"  # uint8_t
    "4H" # uint16_t[4]
    "8s" # char[8]
    "B"  # uint8_t
    "B"  # uint8_t
    "h"  # int16_t
    "h"  # int16_t
    "h"  # int16_t
    "h"  # int16_t
    "h"  # int16_t
    "20s" # char[20]
    "50s" # char[50]
    "4s"  # char[4]
    "32s" # char[32]
    "I"   # uint32_t
    "H"   # uint16_t
    "H"   # uint16_t
    "H"   # uint16_t
    "H"   # uint16_t
    "66s"  # char[66]
    "2048s" # Complex_t[256] 블록 (2048 bytes)
    "1024s" # Complex_t[128] 블록 (1024 bytes)
    "H"   # uint16_t  (SacqElemNullingRatePct)
    "H"   # uint16_t  (Reserved5)
    "H"   # uint16_t  (CurrentNoiseLevel_mag)
    "H"   # uint16_t  (PrevNoiseLevel_mag)
    "4s"  # char[4]
    "8s"  # char[8]
    "8s"  # char[8]
    "8s"  # char[8]
    "32s" # char[32]
)

PAYLOAD_LEN_GENERAL = 3368
assert struct.calcsize(FMT_HEADER) == 16
assert struct.calcsize(FMT_PAYLOAD) == PAYLOAD_LEN_GENERAL

def fixed_bytes(b: bytes, n: int) -> bytes:
    """char[N] 필드는 N바이트 정확히 맞춰야 해서 패딩/잘라내기"""
    if len(b) >= n:
        return b[:n]
    return b + (b"\x00" * (n - len(b)))

@dataclass
class GeneralMessage:
    VehicleType: int
    GearPosition: int
    SteeringAngle_deg: int      # int16 raw
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

    Reserved1: bytes            # 8
    SensorPosition: int
    MountingDirection: int
    XOffset_m: int              # int16
    YOffset_m: int              # int16
    ZOffset_m: int              # int16
    AzimuthEOLOffset_deg: int   # int16
    ElvevationEOLOffset_deg: int# int16

    Reserved2: bytes            # 20
    ECU_Id: bytes               # 50
    HW_Version: bytes           # 4
    SW_Version: bytes           # 32

    FrameNum: int               # uint32
    CenterFrequency: int        # uint16
    PRI_us: int                 # uint16
    TotalTargetNum: int         # uint16
    ProcessingTime: int         # uint16

    Reserved3: bytes            # 66
    SampleCalibrationData: bytes# 2048
    Reserved4: bytes            # 1024

    SacqElemNullingRatePct: int # uint16
    Reserved5: int              # ✅ uint16 (bytes 아님)
    CurrentNoiseLevel_mag: int  # uint16
    PrevNoiseLevel_mag: int     # uint16

    Reserved6: bytes            # 4
    Reserved7: bytes            # 8
    Reserved8: bytes            # 8
    Reserved9: bytes            # 8
    Reserved10: bytes           # 32

    def to_bytes(self) -> bytes:
        return struct.pack(
            FMT_PAYLOAD,
            self.VehicleType,
            self.GearPosition,
            self.SteeringAngle_deg,
            self.YawSignalStatus,
            self.YawRate_dps,
            self.EngineRunningStatus,
            self.EngineStatus,
            self.AcceleratorPedalValue,
            self.AppliedAcceleratorPedalStatus,
            self.ActualAccelerationPedalValue,
            self.GearSelectDisplay,
            self.EngineTargetGear,

            self.WheelSpeed_kmph_fl,
            self.WheelSpeed_kmph_fr,
            self.WheelSpeed_kmph_rl,
            self.WheelSpeed_kmph_rr,

            fixed_bytes(self.Reserved1, 8),
            self.SensorPosition,
            self.MountingDirection,
            self.XOffset_m,
            self.YOffset_m,
            self.ZOffset_m,
            self.AzimuthEOLOffset_deg,
            self.ElvevationEOLOffset_deg,

            fixed_bytes(self.Reserved2, 20),
            fixed_bytes(self.ECU_Id, 50),
            fixed_bytes(self.HW_Version, 4),
            fixed_bytes(self.SW_Version, 32),

            self.FrameNum,
            self.CenterFrequency,
            self.PRI_us,
            self.TotalTargetNum,
            self.ProcessingTime,

            fixed_bytes(self.Reserved3, 66),
            fixed_bytes(self.SampleCalibrationData, 2048),
            fixed_bytes(self.Reserved4, 1024),

            self.SacqElemNullingRatePct,
            self.Reserved5,
            self.CurrentNoiseLevel_mag,
            self.PrevNoiseLevel_mag,

            fixed_bytes(self.Reserved6, 4),
            fixed_bytes(self.Reserved7, 8),
            fixed_bytes(self.Reserved8, 8),
            fixed_bytes(self.Reserved9, 8),
            fixed_bytes(self.Reserved10, 32),
        )
    
@dataclass
class RadarDetectionMessage:
    #Radar Detection Header
    InterfaceVersion: bytes #3bytes uinit8_t[3]
    InterfaceID: int #1byte enumeatuion
    NumberOfSensors: int #1byte uint8_t
    SensorID: int #1byte uint8_t
    Timestamp: int #4bytes uint32_t
    CycleCounter: int #4bytes uint32_t
    CycleTime: int #2bytes uint16_t
    Variation: int #2bytes uint16_t
    DataQualifier: int #1byte enumeatuion

    RadialVelocityAmbiguityDomain_Begin_end: int #4bytes uint16_t[2]
    RangeAmbiguityDomain_Begin_end: int #4bytes uint16_t[2]
    AngleAzumuthAmbiguityDomain_Begin_end: int #4bytes uint16_t[2]
    AngleElevationAmbiguityDomain_Begin_end: int #4bytes uint16_t[2]

    Recognised_detections_capability: int #2bytes uint16_t
    Recognised_detections_status: int #1byte enumeatuion
    NumberValidDetections: int #2bytes uint16_t

    #Radar Detection Payload (Entity Data)
    #Detection[2048]
    #inner information

def create_server():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(1)
    print(f"Server listening on {HOST}:{PORT}")
    return server_sock

def send_message(conn, message: bytes):
    # TCP는 sendall 쓰는게 제일 안전/간단
    conn.sendall(message)

if __name__ == "__main__":
    server_sock = create_server()
    conn, addr = server_sock.accept()
    print(f"Connected by {addr}")

    # 초기 payload (대부분 0으로)
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
        SampleCalibrationData=b"\x00"*2048,
        Reserved4=b"\x00"*1024,

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

    period = 0.05
    t0 = time.time()

    try:
        while True:
            t = time.time() - t0

            # 예시 시뮬레이션: steering / wheel speed / frame 증가
            gm.SteeringAngle_deg = int(300 * math.sin(t))  # int16 raw
            base = int(100 + 20 * math.sin(t * 0.5))
            gm.WheelSpeed_kmph_fl = base
            gm.WheelSpeed_kmph_fr = base
            gm.WheelSpeed_kmph_rl = base
            gm.WheelSpeed_kmph_rr = base

            gm.FrameNum = (gm.FrameNum + 1) & 0xFFFFFFFF

            payload_bytes = gm.to_bytes()
            assert len(payload_bytes) == PAYLOAD_LEN_GENERAL

            packet = HEADER_GENERAL_BYTES + payload_bytes
            send_message(conn, packet)

            time.sleep(period)

    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        conn.close()
        server_sock.close()
