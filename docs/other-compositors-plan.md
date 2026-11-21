# Modular Lock Screen, Per-Output DPMS & Remote Session Plan for GNOME (Mutter) and wlroots/Hyprland

Hermes's `local_session_controller_t` ([local_session_controller.h](../src/platform/linux/local_session_controller.h)) and `session_privacy_mode` are compositor-agnostic. This document outlines how to bring the same **Mode A (shared desktop, per-output lock + DPMS)** and **Mode B (independent compositor session)** capabilities to **GNOME (Mutter + GNOME Shell)** and **wlroots / Sway / Hyprland**.

---

## 1. Shared Contract (Across All Compositors)

To integrate cleanly with Hermes's `local_session_controller_t`:
1. **Per-output lock & DPMS policy:** Physical outputs (`HDMI-*`, `DP-*`) can show the lock screen and enter DPMS sleep (`power-save-mode` / `OFF`) while a designated virtual output stays unlocked and awake.
2. **Input routing split:** Physical `libinput` devices stay confined to the lock screen and wake physical DPMS; virtual/remote input (`libei`/EIS, `uinput`, or compositor virtual pointer/keyboard) drives the unlocked virtual output without waking physical monitors.
3. **Remote session D-Bus/IPC registry:** Exposes `activeSessions`, `registerSession`, `unregisterSession`, `requestDisconnect`, and `setOutputPolicies` (or a compositor-neutral `org.freedesktop.RemoteSessions` / per-compositor interface) so the lock screen displays the active remote session and offers **Disconnect on unlock** after local authentication.

---

## 2. GNOME (Mutter + GNOME Shell)

In GNOME, display/KMS/input lives in **Mutter** (`libmutter`), while the lock screen (`ScreenShield` / `UnlockDialog`) lives in **GNOME Shell** (`js/ui/screenShield.js`, `js/ui/unlockDialog.js`).

### Mode A: Single-Session Per-Output Lock & DPMS
1. **Mutter (`MetaMonitorManager` / `MetaBackendNative` / `MetaRenderer`):**
   - Add per-monitor `lock_policy` (`FOLLOW_SESSION` vs `UNLOCKED`) and `dpms_policy` (`FOLLOW_SESSION` vs `ALWAYS_ON`) to `MetaLogicalMonitor` / `MetaOutput`, exposed via `org.gnome.Mutter.DisplayConfig` (or a companion `org.gnome.Mutter.RemoteSessions` D-Bus interface).
   - Update `MetaBackend` / `MetaPowerSave` so `power-save-mode` (`META_POWER_SAVE_OFF`) can be applied per-CRTC/output rather than blanking every `MetaOnscreenNative` globally.
   - Update `MetaSeatImpl` / `ClutterInputDevice` routing so `ClutterSeat` virtual devices (`libei` / `MetaVirtualInputDeviceNative`) are not blocked by `ScreenShield` grabs and do not reset idle/DPMS timers on physical monitors.
2. **GNOME Shell (`ScreenShield` & `UnlockDialog`):**
   - Currently `ScreenShield` (`js/ui/screenShield.js`) creates a `lockDialogGroup` / `St.Widget` curtain covering every `Main.layoutManager.monitors` entry and grabs all modal input (`Main.pushModal`).
   - Skip creating the shield/curtain on monitors whose `lock_policy == UNLOCKED`, and allow virtual input targeting those monitors to bypass the shield's modal grab.
   - In `UnlockDialog`, read `activeSessions` from the D-Bus registry, display *"Active remote session: Hermes (<client>)"*, and add a **"Disconnect on unlock"** toggle that emits `requestDisconnect(sessionId)` only after `Shell.UserVerifier` authentication succeeds.

### Mode B: Independent / Isolated Mutter Session
- Mutter already supports `--headless` / `--virtual-monitor` (and `org.gnome.Mutter.ScreenCast` + `org.gnome.Mutter.RemoteDesktop` / `libei`).
- To run a second **KMS-backed** Mutter instance exclusively on `hermes-kms` (`/dev/dri/card2`) while `seat0` stays locked:
  - Allow `MetaBackendNative` to run without claiming `seat0` VT ownership when `MUTTER_DRM_DEVICES=/dev/dri/card2` (or `--drm-standalone`) is set, pairing `card2` with a render node (`/dev/dri/renderD128`) and `--no-libinput` (virtual input via `libei` only).

---

## 3. wlroots / Sway / Hyprland

wlroots-based compositors (Sway, labwc, Hyprland) use **`ext-session-lock-v1`** for screen locking (`swaylock`, `hyprlock`) and **`wlr-output-power-management-v1`** for per-output DPMS.

### Key Advantage
- `wlr-output-power-management-v1` is **already per-output**, so physical outputs can enter DPMS off while a headless/virtual output (`HEADLESS-1` / `Virtual-1`) stays on.

### Required Changes
1. **Per-output `ext-session-lock-v1` exclusion (compositor + lock client):**
   - By protocol, `ext_session_lock_v1` requires the compositor to hide all normal surfaces and only show `ext_session_lock_surface_v1` on every output.
   - Add an output policy (`unlocked_while_locked`) in the compositor (`wlr_session_lock_v1` / Sway / Hyprland) so lock surfaces are only mapped on physical outputs while normal windows on the `unlocked_while_locked` virtual output remain visible and interactive.
2. **Input routing split:**
   - Tag `wlr_virtual_pointer_v1` / `wlr_virtual_keyboard_v1` / `libei` devices as `unlocked_outputs_only` so they pass through the session-lock input filter to the virtual output without resetting `ext_idle_notifier_v1` or waking physical DPMS.
3. **Lock screen UI (`swaylock` / `hyprlock`):**
   - Query the compositor IPC / `org.freedesktop.RemoteSessions` D-Bus service to show the active remote session banner and add an authenticated **"Disconnect on unlock"** option.
4. **Mode B (Independent wlroots session):**
   - wlroots already supports `WLR_DRM_DEVICES=/dev/dri/card2` and `WLR_BACKENDS=drm,libinput` (or headless), needing only a seatless/no-VT option when `card2` is kept off `seat0`.

---

## 4. Hermes Integration (`local_session_controller_t`)

Once a compositor exposes the D-Bus/IPC contract:
1. Add `mutter_per_output_lock` / `wlroots_per_output_lock` implementations in `src/platform/linux/local_session_controller.cpp`.
2. Update `create_local_session_controller("auto")` to probe the running `sessionCompositor()` (`kwin`, `mutter`, `wlroots`, `hyprland`) and select the matching controller automatically.
