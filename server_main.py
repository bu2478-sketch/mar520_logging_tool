import socket
import struct
import time
import math
from dataclasses import dataclass

HOST = "0.0.0.0"
PORT = 4545

# =========================
# Common TCP Header (16B)
# =========================
ENDIAN = ">"
FMT_HEADER = ENDIAN + "HHIHHBBBB"
HDR = struct.Struct(FMT_HEADER)
assert HDR.size == 16

SERVICE_ID = 0x6000
CLIENT_ID  = 0x0001
SESSION_ID = 0xFFFF
PROTO_VER  = 0x01
IF_VER     = 0x01
MSG_TYPE   = 0x02
RESERVED   = 0x00

METHOD_GENERAL = 0x8001
METHOD_RADAR   = 0x8002

LEN_MINUS = 8  # length = payload_len + 8

# =========================
# Utils
# =========================
def fixed_bytes(b: bytes, n: int) -> bytes:
    if len(b) >= n:
        return b[:n]
    return b + (b"\x00" * (n - len(b)))

def u8(x: int) -> int:   return x & 0xFF
def u16(x: int) -> int:  return x & 0xFFFF
def u32(x: int) -> int:  return x & 0xFFFFFFFF

def i16(x: int) -> int:
    x = int(x)
    if x < -32768: return -32768
    if x >  32767: return  32767
    return x

def clamp(x: int, lo: int, hi: int) -> int:
    return lo if x < lo else hi if x > hi else x

def make_header(method_id: int, payload_len: int) -> bytes:
    length_field = payload_len + LEN_MINUS
    return HDR.pack(
        SERVICE_ID, method_id, length_field,
        CLIENT_ID, SESSION_ID,
        PROTO_VER, IF_VER, MSG_TYPE, RESERVED
    )

def create_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"Server listening on {HOST}:{PORT}")
    return s

def send_message(conn, b: bytes):
    conn.sendall(b)

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
GEN = struct.Struct(FMT_GENERAL_PAYLOAD)
PAYLOAD_LEN_GENERAL = 3368
assert GEN.size == PAYLOAD_LEN_GENERAL

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
        return GEN.pack(
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
FMT_RD_HEADER = ENDIAN + "3sBBBIIHHB8HHBH"
RD_HEADER = struct.Struct(FMT_RD_HEADER)
assert RD_HEADER.size == 40

FMT_DET = ENDIAN + "BHBHHhBBBHBBB4s4sHHHHHHHHHBB3sBBBBH"
DET = struct.Struct(FMT_DET)
assert DET.size == 55

NUM_DET = 2048
PAYLOAD_LEN_RADAR = 40 + 55 * NUM_DET
assert PAYLOAD_LEN_RADAR == 112680

# ===== angle raw domain =====
ANG_RAW_MAX = 31416
ANG_CENTER  = ANG_RAW_MAX // 2  # 15708

# ✅ 고정 "원뿔 크기" (FOV 반각) : 30deg 기준이면 이렇게
# rad(30)/0.0001 ≈ 5236.62
MAX_DELTA_RAW = int(round(math.radians(30.0) / 0.0001))

# ✅ 회전만: 한 바퀴를 몇 프레임에 돌릴지
ROT_FRAMES = 240  # 12초 @50ms

# ✅ range raw LUT: 0..65535 등간격 (항상 동일)
R_RAW_MAX = 65535
R_RAW_LUT = [int(round(i * R_RAW_MAX / (NUM_DET - 1))) for i in range(NUM_DET)]

def frame_to_az_el(frame_idx: int) -> tuple[int, int]:
    """
    고정 크기 원뿔(반지름 MAX_DELTA_RAW)에서
    중심축(ANG_CENTER) 기준으로 원형으로만 회전.
    """
    phi = 2.0 * math.pi * ((frame_idx % ROT_FRAMES) / ROT_FRAMES)

    d_az = int(round(MAX_DELTA_RAW * math.cos(phi)))
    d_el = int(round(MAX_DELTA_RAW * math.sin(phi)))

    pos_az = clamp(ANG_CENTER + d_az, 0, ANG_RAW_MAX)
    pos_el = clamp(ANG_CENTER + d_el, 0, ANG_RAW_MAX)
    return pos_az, pos_el

@dataclass
class RadarDetectionMessage:
    InterfaceVersion: bytes   # 3s
    InterfaceID: int
    NumberOfSensors: int
    SensorID: int
    Timestamp: int            # uint32
    CycleCounter: int         # uint32
    CycleTime: int            # uint16
    Variation: int            # uint16
    DataQualifier: int        # uint8

    RV_Amb_Begin: int
    RV_Amb_End: int
    Range_Amb_Begin: int
    Range_Amb_End: int
    Az_Amb_Begin: int
    Az_Amb_End: int
    El_Amb_Begin: int
    El_Amb_End: int

    RecognisedCapability: int
    RecognisedStatus: int
    NumberValidDetections: int

    def to_bytes(self, frame_idx: int) -> bytes:
        buf = bytearray(PAYLOAD_LEN_RADAR)

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

        base = RD_HEADER.size

        # ✅ 한 프레임에서 2048개는 모두 같은 방향(az/el)
        pos_az, pos_el = frame_to_az_el(frame_idx)

        for i in range(NUM_DET):
            # ✅ range는 항상 0..65535 등간격
            pos_r = R_RAW_LUT[i]

            # 나머지는 0만 피해서 적당히
            existence_prob = 200
            detection_id = i
            object_id_ref = i & 0xFF
            timestamp_diff = frame_idx & 0xFFFF

            rcs = 1000 + (i % 2000)
            rcs_err = 0

            snr = 40
            snr_err = 1

            multi_target_prob = 0
            ambiguity_group_id = 0
            detection_ambiguity_prob = 0
            free_space_prob = 200

            num_valid_det_class = 1
            class_id = i % 4
            det_class_type = bytes([class_id, 0, 0, 0])
            det_class_conf = bytes([80, 0, 0, 0])

            pos_r_err  = 5
            pos_az_err = 5
            pos_el_err = 5

            rel_v_r = 30000
            rel_v_r_err = 1
            power = 500

            az_method = 1
            el_method = 1
            pos_quality = bytes([2, 2, 2])

            amb_model_az  = 0
            amb_model_el  = 0
            rel_v_quality = 0
            amb_model_vel = 0
            amb_index_vel = 0

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
# Main: 50ms마다 General -> Radar 송신
# =========================
def main():
    server_sock = create_server()
    conn, addr = server_sock.accept()
    print(f"Connected by {addr}")

    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1<<20)  # 1MB
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

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
        SampleCalibrationData=b"\x11"*2048,
        Reserved4=b"\x22"*1024,

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
        NumberValidDetections=NUM_DET,
    )

    period = 0.05
    t0 = time.time()
    next_t = time.perf_counter()
    frame_idx = 0

    hdr_general = make_header(METHOD_GENERAL, PAYLOAD_LEN_GENERAL)
    hdr_radar   = make_header(METHOD_RADAR, PAYLOAD_LEN_RADAR)

    try:
        while True:
            now = time.time()
            t = now - t0

            # ---- General update ----
            gm.SteeringAngle_deg = int(300 * math.sin(t))
            base = int(100 + 20 * math.sin(t * 0.5))
            gm.WheelSpeed_kmph_fl = base
            gm.WheelSpeed_kmph_fr = base
            gm.WheelSpeed_kmph_rl = base
            gm.WheelSpeed_kmph_rr = base
            gm.FrameNum = (gm.FrameNum + 1) & 0xFFFFFFFF

            send_message(conn, hdr_general + gm.to_bytes())

            # ---- Radar update ----
            rd.Timestamp = u32(int((now - t0) * 1000))
            rd.CycleCounter = u32(rd.CycleCounter + 1)
            send_message(conn, hdr_radar + rd.to_bytes(frame_idx))

            frame_idx += 1

            # ---- 50ms period ----
            next_t += period
            sleep_s = next_t - time.perf_counter()
            if sleep_s > 0:
                time.sleep(sleep_s)
            else:
                next_t = time.perf_counter()

    except (BrokenPipeError, ConnectionResetError):
        print("Client disconnected.")
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        conn.close()
        server_sock.close()

if __name__ == "__main__":
    main()
