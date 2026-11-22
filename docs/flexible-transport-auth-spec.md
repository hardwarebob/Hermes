# Flexible Transport & Authentication Specification

## 1. Overview & Motivation

Hermes currently inherits GameStream's fixed assumptions:
- **Authentication:** Web UI uses a single local username/password (`sunshine_state.json`), and streaming clients authenticate via a 4-digit PIN pairing flow that installs a TLS client certificate (`named_certs`).
- **Transport:** Control, video, audio, and microphone streams require raw UDP ports (`47998`–`48002`) alongside TCP (`47984`, `47989`, `47990`, `48010`).

To serve as a general-purpose remote desktop and virtual desktop host—across LAN, WAN, bastions, headless servers, and SSH-only environments—Hermes needs **selectable, optional** authentication providers and transport modes while remaining 100% backwards-compatible with existing Moonlight, Artemis, and Hestia clients.

---

## 2. Flexible Authentication (`auth`)

All authentication methods are **opt-in / selectable** via `hermes.conf` and may be combined.

### 2.1 Configuration Keys
| Key | Default | Description |
| :--- | :--- | :--- |
| `auth_providers` | `local` | Comma-separated list of enabled providers: `local`, `pam`, `ssh_key`, `token` |
| `pam_service` | `hermes` | PAM service name (`pam_start`); falls back to `login` if `/etc/pam.d/hermes` is absent |
| `pam_allowed_users` | `""` | Comma-separated OS usernames allowed via PAM (empty = process owner user only) |
| `ssh_authorized_keys` | `~/.ssh/authorized_keys` | Path to OpenSSH `authorized_keys` file for SSH key auth |
| `token_ttl_seconds` | `86400` | Default lifetime for issued Bearer API tokens (0 = non-expiring until revoked) |

### 2.2 Provider 1: Local Credentials & mTLS (Existing)
- Retains existing `sunshine_state.json` Web UI login and 4-digit PIN + TLS client certificate pairing (`named_certs`).

### 2.3 Provider 2: Linux PAM (`libpam`)
Uses `pam_start()`, `pam_authenticate()`, and `pam_acct_mgmt()` with a non-interactive conversation callback.

1. **Web UI Login (`POST /api/login`):**
   - Accepts optional `"auth_method": "pam"` (or automatic fallback when `pam` is in `auth_providers`).
   - Validates `username` against `pam_allowed_users` (if empty, restricts to the OS user running Hermes) before invoking PAM.
   - On success, issues the standard `auth` session cookie.
2. **Headless Client Pairing (`POST /api/auth/pam/pair`):**
   - Replaces the interactive 4-digit PIN for headless/remote-desktop onboarding.
   - Request JSON: `{ "username": "...", "password": "...", "uniqueid": "...", "devicename": "...", "client_cert": "<PEM>" }`.
   - On PAM success, registers `client_cert` in `named_certs` (or issues a Bearer token if `client_cert` is omitted).

### 2.4 Provider 3: SSH Public-Key Challenge-Response
Authenticates clients using keys in `ssh_authorized_keys` (`~/.ssh/authorized_keys`) via `libssh` (`ssh_pki_*`) or `ssh-keygen -Y verify`.

1. **Request Challenge (`GET /api/auth/ssh/challenge?uniqueid=<id>`):**
   - Returns `{ "challenge_id": "<hex>", "nonce": "<base64-32-bytes>", "namespace": "hermes-auth", "expires_in": 60 }`.
2. **Verify Signature (`POST /api/auth/ssh/verify`):**
   - Request JSON: `{ "challenge_id": "...", "public_key": "<openssh-pubkey>", "signature": "<SSHSIG-or-raw-sig>", "uniqueid": "...", "devicename": "...", "client_cert": "<optional PEM>" }`.
   - Host checks that `public_key` matches an entry in `ssh_authorized_keys` (ignoring options/comments or honoring `from=` if present) and verifies `signature` over `nonce`.
   - On success, either registers `client_cert` into `named_certs` or returns a scoped Bearer token (`{ "token": "...", "expires_at": ... }`).

### 2.5 Provider 4: Scoped Bearer / API Tokens
- `Authorization: Bearer <token>` is accepted by both `confighttp` (`authenticate()`) and `nvhttp` endpoints (`/launch`, `/resume`, `/applist`, `/cancel`, `/actions/clipboard`) when `token` is enabled.
- Tokens are 256-bit random values stored as SHA-256 hashes in memory/state with `crypto::PERM` permissions, optional `uniqueid` binding, and expiration.
- Management endpoints: `GET /api/tokens`, `POST /api/tokens`, `DELETE /api/tokens/<id>`.

---

## 3. Flexible Transport (`transport`)

All transport modes are **selectable/optional** and interoperate with the existing session/stream pipeline.

### 3.1 Configuration Keys
| Key | Default | Description |
| :--- | :--- | :--- |
| `transport_modes` | `udp` | Comma-separated enabled modes: `udp`, `tcp_interleaved`, `unix_socket`, `ssh` |
| `unix_socket_path` | `$XDG_RUNTIME_DIR/hermes/hermes.sock` | Local Unix domain socket path for multiplexed proxy access |
| `ssh_server_enabled` | `false` | Enable embedded `libssh` server |
| `ssh_server_port` | `48022` | Listen port for embedded `libssh` server |
| `ssh_host_key` | `<config_dir>/ssh_host_ed25519_key` | Host private key for embedded `libssh` server |

### 3.2 Mode 1: Standard UDP + RTSP/TCP (Default)
- Existing behavior: RTSP over TCP (`48010`), video/audio/mic over UDP (`47998`, `48000`, `48002`), control over ENet/UDP (`47999`).

### 3.3 Mode 2: RTSP-Interleaved TCP Transport (`ssh -L` Friendly)
Allows full streaming over a **single TCP port** (`48010`, e.g., `ssh -L 48010:localhost:48010`) with **zero UDP ports**.

1. **Capability Advertisement (`DESCRIBE`):**
   - `a=x-ss-transport.modes:udp,rtsp-interleaved`
   - `a=x-ss-transport.tcpInterleaved:1`
2. **Negotiation (`SETUP`):**
   - Client sends `Transport: RTP/AVP/TCP;unicast;interleaved=<ch_data>-<ch_ctrl>` (e.g. `0-1` for `video0`, `2-3` for `audio`, `4-5` for `control`, `6-7` for `mic`, `8-9` for `video1`, etc.).
   - Host responds `200 OK` with `Transport: RTP/AVP/TCP;unicast;interleaved=<ch_data>-<ch_ctrl>` and keeps the RTSP TCP connection open after `PLAY` to carry interleaved frames.
3. **Wire Framing (RFC 2326 §10.12):**
   - Each packet is prefixed with 4 bytes: `0x24` (`'$'`), `uint8_t channel`, `uint16_t length` (big-endian), followed by `length` bytes of payload.
   - Control packets on the interleaved control channel carry the same plaintext/AES-GCM-encrypted control payloads without ENet UDP overhead.
   - In TCP-interleaved mode, FEC shard generation is skipped (`fec_percentage = 0`) to avoid redundant bandwidth overhead over reliable TCP.

### 3.4 Mode 3: Unix Domain Socket + `hermes --proxy` (`stdio` Bridge)
Enables zero-port-forwarding streaming over standard OpenSSH (`ssh -T user@host hermes --proxy`).

1. **Daemon Unix Socket:**
   - When `unix_socket` is enabled, Hermes listens on `unix_socket_path` (mode `0600`, owned by the running user).
   - Accepts length-prefixed or HTTP/RTSP-upgraded streams and routes them internally to the `nvhttp` / `rtsp` handlers.
2. **CLI `stdio` Proxy (`hermes --proxy [--socket <path>]`):**
   - Connects to `unix_socket_path` and bidirectionally pumps `stdin`/`stdout` with non-blocking I/O.
   - Allows clients (or `ProxyCommand`) to tunnel all HTTP, RTSP, and interleaved media traffic through an existing `sshd` session with OS-level SSH authentication already satisfied.

### 3.5 Mode 4: Embedded `libssh` Server & `"hermes"` Subsystem (Optional)
For hosts without `sshd` exposed or where Hermes runs standalone:
- Embedded `libssh` listener on `ssh_server_port` (`48022` default).
- Authenticates incoming clients via `ssh_authorized_keys` (publickey) and/or PAM (`password` / `keyboard-interactive`).
- Supports:
  - `direct-tcpip` forwarding to Hermes's local HTTP/HTTPS/RTSP ports, and
  - `"hermes"` SSH subsystem channel bridged directly to the internal Unix socket / RTSP-interleaved mux.

---

## 4. Implementation Plan

1. **Phase 1 — Authentication (`src/auth.h`, `src/auth.cpp`, `CMakeLists.txt`, `config.*`, `confighttp.cpp`, `nvhttp.cpp`):**
   - Detect `pam` and `libssh` in CMake (with clean compile-time guards `SUNSHINE_BUILD_PAM`, `SUNSHINE_BUILD_LIBSSH`).
   - Implement `auth::pam_authenticate()`, `auth::ssh_verify_challenge()`, and `auth::token_manager_t`.
   - Wire into `confighttp.cpp` (`/api/login`, `/api/auth/pam/pair`, `/api/auth/ssh/challenge`, `/api/auth/ssh/verify`, `/api/tokens`, Bearer check in `authenticate()`) and `nvhttp.cpp` (Bearer token support on protected endpoints).
2. **Phase 2 — RTSP-Interleaved TCP Transport (`src/rtsp.cpp`, `src/stream.cpp`):**
   - Parse `RTP/AVP/TCP;interleaved=...` in `cmd_setup()`.
   - Route video, audio, and control packets over `$` interleaved framing on the RTSP TCP socket when negotiated.
3. **Phase 3 — Unix Socket & `hermes --proxy` (`src/transport_unix.h/.cpp`, `src/main.cpp`):**
   - Add Unix domain socket listener and `--proxy` CLI subcommand.
4. **Phase 4 — Embedded `libssh` Subsystem (`src/transport_ssh.h/.cpp`):**
   - Add optional `libssh` server with publickey + PAM auth and `"hermes"` subsystem channel.
