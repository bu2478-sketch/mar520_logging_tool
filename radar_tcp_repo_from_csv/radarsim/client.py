\
from __future__ import annotations

import argparse
import os
import socket
import time

from .protocol.spec import load_spec
from .protocol.parse import PacketParser


def run_client(host: str, port: int, strict: bool, deep: bool, session_id: int) -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    spec = load_spec(repo_root=repo_root, session_id=session_id)
    parser = PacketParser(spec)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"[client] connected to {host}:{port}")

    buf = bytearray()
    n_ok = 0
    t0 = time.time()

    while True:
        chunk = s.recv(65536)
        if not chunk:
            print("[client] connection closed")
            break
        buf.extend(chunk)

        while True:
            pkt = parser.decode_from_stream(buf)
            if pkt is None:
                break

            name = pkt.message_name
            if name == "UNKNOWN":
                raise SystemExit(f"[FAIL] Unknown message IDs: svc={pkt.header.service_id:#x} method={pkt.header.method_id:#x}")

            if strict:
                parser.validate_header(pkt.header)
                parser.validate_payload_len(name, len(pkt.payload))

                # fixed client/session checks (session ID is allowed to be fixed constant)
                if pkt.header.client_id != spec.client_id:
                    raise SystemExit(f"[FAIL] client_id mismatch: {pkt.header.client_id:#x}")
                if pkt.header.session_id != spec.session_id:
                    raise SystemExit(f"[FAIL] session_id mismatch: {pkt.header.session_id:#x}")

            # light parsing (cheap)
            if name == "TCP_GeneralMessage":
                _ = parser.parse_general(pkt.payload) if deep else None
            else:
                _ = parser.parse_radar_detection_header(pkt.payload)
                _ = parser.parse_first_detection(pkt.payload)
                if deep:
                    _ = parser.deep_parse_all_detections(pkt.payload)

            n_ok += 1
            if n_ok % 40 == 0:
                dt = time.time() - t0
                print(f"[client] ok packets={n_ok} rate={n_ok/dt:.1f} pkt/s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4545)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--session-id", type=_parse_int_auto, default=0x0001)
    args = ap.parse_args()
    run_client(args.host, args.port, args.strict, args.deep, args.session_id)


if __name__ == "__main__":
    main()
