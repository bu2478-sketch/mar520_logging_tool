# Radar TCP Interface (CSV-based)

This repo implements a TCP sender + client validator for the MAR520 radar interface.

It is generated **directly from the provided CSV specs**:

- `protocol/interface_overview.csv` (MOST IMPORTANT: SOME/IP-like header + message IDs + payload sizes)
- `protocol/tcp_general_message.csv` (GeneralMessage payload fields)
- `protocol/tcr_rd_message_header.csv` (RadarDetection payload header fields)
- `protocol/TCP_RD_Message_entity.csv` (RadarDetection detection entity fields, repeated 2048 times)

## What it does

- Sends, every 50 ms:
  1) `TCP_GeneralMessage`
  2) `TCP_RadarDetection`

- Serializer guarantees:
  - field order / sizes
  - big-endian packing (network order)
  - SOME/IP-like Length = 8 + payload_len

- RadarDetection test data:
  - 2048 detections per packet
  - azimuth/elevation are **stratified** over the full range to avoid angle bias (uniform-ish coverage)

## Run

### 1) Sender (TCP server)
```bash
python -m radarsim.server --host 0.0.0.0 --port 4545
```

### 2) Client (validator)
```bash
python -m radarsim.client --host 127.0.0.1 --port 4545 --strict
```

Options:
- `--deep` : fully parse and validate all payload fields (heavier CPU)
- `--session-id 0x1234` : override fixed session id (default 0x0001)

## Notes

- Endianness: **big-endian** (`>`), consistent with network/SOME/IP conventions.
- SessionID: fixed constant is OK (per your request).
