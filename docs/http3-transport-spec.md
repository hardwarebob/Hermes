# Native HTTP/3 (QUIC) Transport & Client Proxy Specification

## 1. Overview & Motivation

To serve as a drop-in replacement for **Amazon DCV** across cloud VMs, NATs, and restrictive firewalls, Hermes needs a **single-UDP-port, multiplexed, zero-head-of-line-blocking** transport that carries both reliable control/API streams and unreliable real-time media datagrams.

This specification defines:
1. A host-side **HTTP/3 (QUIC + RFC 9221 DATAGRAM)** server embedded in Hermes (`transport_modes` includes `http3`, or `h3_server_enabled = true`).
2. A native client-side proxy (**`hermes --h3-proxy <host[:port]>`**) that terminates the HTTP/3 connection and exposes local loopback TCP/UDP endpoints for unmodified Moonlight, Artemis, Hestia, and browser clients.

---

## 2. Wire Protocol (RFC 9114 + RFC 9221)

- **Transport:** UDP on `h3_server_port` (default `48443`).
- **ALPN:** `h3`.
- **TLS 1.3:** Uses Hermes's configured certificate (`nvhttp.cert` / `nvhttp.pkey`).
- **QUIC Settings:**
  - `max_datagram_frame_size = 1500` (RFC 9221 unreliable datagrams enabled).
  - Concurrent bidirectional streams for HTTP/3 requests and TCP tunnel streams.

### 2.1 Reliable Streams (`POST /_hermes/tcp/<port>`)
- Each client TCP connection to a Hermes port (`47984` HTTPS, `47989` HTTP, `47990` Web UI/Hestia API, `48010` RTSP) maps to one bidirectional HTTP/3 stream:
  - Request headers: `:method = POST`, `:path = /_hermes/tcp/<port>`, optional `authorization: Bearer <token>`.
  - Response headers: `:status = 200` once connected to `127.0.0.1:<port>`.
  - Stream body carries raw bidirectional TCP payload bytes (end-of-stream maps to `SHUT_WR`).
- Only Hermes's own configured service ports (`PORT_HTTP`, `PORT_HTTPS`, `confighttp::PORT_HTTPS`, `RTSP_SETUP_PORT`) are permitted.

### 2.2 Unreliable Media & Control (`QUIC DATAGRAM`)
- Each UDP packet for Video (`47998`), Control (`47999`), Audio (`48000`), or Mic (`48002`) is sent as a single **QUIC DATAGRAM** frame:
  - `[2 bytes big-endian target_port] [raw UDP payload]`
- Because QUIC DATAGRAM frames are **unreliable and unordered**, lost video/audio packets never stall subsequent frames or control streams (zero HoL blocking).
- The server maintains a per-connection UDP relay socket for each allowed media port and forwards return packets back to the client as `[2 bytes big-endian source_port] [raw UDP payload]` QUIC DATAGRAMs.

---

## 3. Native Client Proxy (`hermes --h3-proxy`)

Usage:
```bash
hermes --h3-proxy <host[:port]> [--insecure] [--token <bearer_token>] [--bind 127.0.0.1]
```

1. Establishes a single QUIC/HTTP/3 connection to `<host>:<port>` (default port `48443`).
2. Binds local loopback listeners (`127.0.0.1`) on Hermes's standard TCP (`47984`, `47989`, `47990`, `48010`) and UDP (`47998`, `47999`, `48000`, `48002`) ports.
3. Bridges all local client traffic over the single HTTP/3 connection, allowing unmodified Moonlight/Artemis/Hestia clients to connect to `127.0.0.1` over a single remote UDP port.

---

## 4. Configuration Keys

| Key | Default | Description |
| :--- | :--- | :--- |
| `h3_server_enabled` | `false` | Enable the native HTTP/3 (QUIC) server |
| `h3_server_port` | `48443` | UDP listen port for HTTP/3 |
| `transport_modes` | `udp` | May include `http3` to enable the HTTP/3 server |
