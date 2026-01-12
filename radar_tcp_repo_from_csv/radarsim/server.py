from __future__ import annotations

import argparse
import os
import socket
import time
from typing import Optional

from .protocol.spec import load_spec
from .protocol.serialize import PacketSerializer


def run_server(host: str, port: int, session_id: int) -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    spec = load_spec(repo_root=repo_root, session_id=session_id)
    ser = PacketSerializer(spec)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    print(f"[server] listening on {host}:{port}")

    conn, addr = srv.accept()
    print(f"[server] client connected: {addr[0]}:{addr[1]}")
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    period = 0.050  # 50ms
    next_t = time.perf_counter()

    try:
        while True:
            # Send General then RadarDetection
            conn.sendall(ser.build_general_packet())
            conn.sendall(ser.build_radar_detection_packet())

            next_t += period
            dt = next_t - time.perf_counter()
            if dt > 0:
                time.sleep(dt)
            else:
                # behind schedule; resync but don't sleep negative
                next_t = time.perf_counter()
    except (BrokenPipeError, ConnectionResetError):
        print("[server] client disconnected")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        srv.close()


def _parse_int_auto(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=4545)
    ap.add_argument("--session-id", type=_parse_int_auto, default=0x0001)
    args = ap.parse_args()
    run_server(args.host, args.port, args.session_id)


if __name__ == "__main__":
    main()
