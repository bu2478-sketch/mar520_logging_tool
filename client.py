import socket
import struct

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet: return None
        data += packet
    return data

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 4545))

try:
    while True:
        # 1. 길이 헤더(4바이트) 수신
        len_data = recv_all(sock, 4)
        if not len_data: break
        msg_len = struct.unpack('!I', len_data)[0]
        
        # 2. 본문 수신
        payload = recv_all(sock, msg_len)
        if not payload: break

        if msg_len == 112680:
            # General Message 파싱
            # !BBhBH (7바이트)
            res = struct.unpack('!BBhBH', payload[:7])
            print(f"[GEN] Gear: {res[1]}, Steer: {res[2]*0.1}")
        else:
            # Radar Detection 파싱
            # 헤더(56B) 건너뛰고 첫 번째 엔티티(16B) 파싱
            header_size = 56
            entity_size = 16
            
            # 버퍼 크기 안전 점검
            if len(payload) >= header_size + entity_size:
                # 첫 번째 엔티티 슬라이싱 (56바이트부터 16바이트만큼)
                entity_data = payload[header_size : header_size + entity_size]
                # 서버에서 보낸 16바이트 형식에 맞춰 해제
                # (주의: 서버에서 15바이트+1바이트패딩으로 보냈으므로 동일하게 슬라이싱)
                det = struct.unpack('!BHBHHhBBBH', entity_data[:15])
                print(f"[RADAR] First Det ID: {det[1]}, RCS: {det[4]*0.005 - 100}")
            else:
                print(f"[RADAR] Data too short: {len(payload)} bytes")

except Exception as e:
    print(f"Client Error: {e}")
finally:
    sock.close()