# Multi-Track Video over RTSP Specification (Multi-Monitor Streaming)

## 1. Background & Ecosystem Survey

Standard GameStream / Moonlight / Sunshine sessions carry **one** video track per RTSP session (`VIDEO_STREAM_PORT = 9`, `CONTROL_PORT = 10`, `AUDIO_STREAM_PORT = 11`, `MIC_STREAM_PORT = 12` in [stream.h](../src/stream.h)).

A survey of existing forks and workarounds shows:
- **Upstream Sunshine / Moonlight:** Single `m=video` track only. Multiple physical monitors are either selected individually (`output_name`) or captured as a single combined ultra-wide canvas.
- **Apollo (`ClassicOldSong/Apollo`) & Vibepollo (`Nonary/Vibepollo`):** Provide per-client dynamic virtual displays (multi-client, one video track per client) or single combined-canvas workarounds.
- **Multi-instance Sunshine:** Running N separate Sunshine/Hermes processes on N port ranges with N client connections.

No upstream Sunshine/Apollo/Moonlight implementation currently carries **two or more independent video signals inside a single RTSP session** for a multi-monitor client. Extending RTSP with indexed video tracks (`video0`, `video1`, ...) is the cleanest, backwards-compatible way to support true multi-monitor streaming with independent resolutions, refresh rates, scaling, and HDR per display.

---

## 2. Design Goals

1. **Full backwards compatibility:** Unmodified Moonlight/Artemis clients continue to negotiate `streamid=video` (track `0` on `VIDEO_STREAM_PORT`) with zero behavior change.
2. **Independent per-monitor video pipelines:** Each track has its own `hermes-kms` virtual output (`Virtual-1`, `Virtual-2`, ...), capture descriptor, hardware encoder, packetizer/FEC queue, and UDP socket.
3. **Single shared control, audio, and mic session:** One ENet control channel, one audio stream, and one mic stream per client session.
4. **Session-wide privacy:** All virtual outputs belonging to the session share the active `local_session_controller_t` privacy policy (`kwin_per_output_lock`, `mutter_per_output_lock`, `wlroots_per_output_lock`, or `disable_outputs`).

---

## 3. HTTP Negotiation (`/launch` and `/resume`)

### 3.1 Client Request Parameters ([nvhttp.cpp](../src/nvhttp.cpp))
Add an optional `monitors` parameter (JSON array or comma-separated `WxHxFPS[:hdr]` list) to `/launch` and `/resume`:

```text
monitors=[{"w":2560,"h":1440,"fps":120,"hdr":1},{"w":1920,"h":1200,"fps":60,"hdr":0}]
```

- When `monitors` is omitted, Hermes behaves identically to today (single track `0` from `mode` + `fps` + `hdr`).
- When `monitors` has `N >= 1` entries, `launch_session_t` stores a `std::vector<monitor_request_t> monitors` and allocates `N` `hermes-kms` virtual outputs (`Virtual-1` .. `Virtual-N`) arranged side-by-side (or according to client-supplied `x, y` offsets).

---

## 4. RTSP Signaling Extensions ([rtsp.cpp](../src/rtsp.cpp))

### 4.1 `DESCRIBE`
`cmd_describe()` advertises multi-track capability and per-track metadata while keeping existing SDP lines intact for track `0`:

```sdp
a=x-ss-general.featureFlags:<flags>
a=x-ss-video.maxTracks:<N>
a=x-ss-video[0].refPicInvalidation:1
a=x-ss-video[0].output:Virtual-1
a=x-ss-video[0].geometry:0,0,2560x1440
m=video <port_1> RTP/AVP 98
a=x-ss-video[1].track:1
a=x-ss-video[1].output:Virtual-2
a=x-ss-video[1].geometry:2560,0,1920x1200
```

### 4.2 `SETUP`
`cmd_setup()` currently maps `streamid=<type>/...` for `audio`, `video`, `control`, and `mic`:
- `streamid=video` and `streamid=video0`: treated identically as track `0`, bound to `net::map_port(stream::VIDEO_STREAM_PORT)`.
- `streamid=video<i>` (`i >= 1`): allocates/maps a dedicated UDP port (e.g. `VIDEO_TRACK_BASE_PORT + i`, or dynamically bound ephemeral port) and returns:
  - `Transport: server_port=<port_i>`
  - `X-SS-Ping-Payload: <track_i_ping_payload>` (unique 16-byte ping token per track so UDP NAT hole-punching unambiguously binds each client socket to track `i`).

### 4.3 `ANNOUNCE`
`cmd_announce()` parses optional per-track attributes `a=x-nv-video[<i>].*` (codec, bitrate, FPS, dynamicRange, chroma, slicesPerFrame), falling back to `a=x-nv-video[0].*` for any omitted per-track field.

---

## 5. Media & Control Plane ([stream.cpp](../src/stream.cpp), `video.cpp`)

### 5.1 `session_t` Video Track Array
Replace the single `videoThread` / `video_sock` on `session_t` with:

```cpp
struct video_track_t {
  uint32_t track_id;
  std::string display_name;   // e.g. HERMES-1 / HERMES-2
  std::string output_name;    // e.g. Virtual-1 / Virtual-2
  video::config_t config;
  udp::socket sock;
  udp::endpoint peer;
  std::string ping_payload;
  std::thread thread;
};
```

- `session_t::video_tracks` holds `1..N` `video_track_t` instances.
- Each `video_track_t` runs its own capture (`hermes-kms` zero-copy DMABUF), encoder (VAAPI/NVENC), RTP/FEC packetizer, and `SS_ENC_VIDEO` encryption state.
- `TEARDOWN` / session stop joins all `video_tracks[i].thread` and closes all sockets cleanly.

### 5.2 Control Channel (`ENet`)
Extend video-specific control messages with an optional `track_id` (default `0` when packet length matches legacy v1 format):
- `IDR_FRAME` / `REFERENCE_FRAME_INVALIDATION`: targets `track_id` instead of resetting all encoders.
- `LOSS_STATS` / adaptive bitrate feedback: adjusts bitrate/FEC independently per `track_id`.

---

## 6. Input Routing & Compositor Privacy

### 6.1 Privacy Controller ([local_session_controller.h](../src/platform/linux/local_session_controller.h))
- Update `prepare_output_privacy_for_capture()` and `on_stream_starting()` to accept `std::vector<std::string> output_names` (keeping a single-string overload or passing all session virtual outputs) so **every** `Virtual-1..N` output receives `Unlocked` (unless `session_privacy_lock_virtual_display` is set) and `AlwaysOn`.

### 6.2 Input Coordinate Mapping
- **Relative mouse, keyboard, gamepad:** Shared across the desktop as today.
- **Absolute pointer, touch, pen:** Include `track_id` in the input packet (or map client surface coordinates against `video_tracks[track_id].geometry`) so pointer/touch/pen events land accurately on `Virtual-1` vs `Virtual-2`.

---

## 7. Client Requirements (Artemis / Moonlight) & Rollout

1. **Phase 1 (Host — Hermes):**
   - Multi-output `launch_session_t` allocation via `hermes-kms`.
   - `rtsp.cpp` `video<i>` `DESCRIBE` / `SETUP` / `ANNOUNCE` + per-track `video_track_t` in `stream.cpp`.
   - Multi-output `local_session_controller_t` policy application.
2. **Phase 2 (Client — Artemis / Moonlight):**
   - Parse `a=x-ss-video.maxTracks` and `a=x-ss-video[<i>].*` in `DESCRIBE`.
   - Send `SETUP` for `video0`, `video1`, ... and open one decoder + swapchain/window per track.
   - Route per-window absolute pointer/touch events with `track_id`.
