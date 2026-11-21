# Setting Up Modular KWin Lock Screen & Privacy Modes with Hermes

This guide explains how to build and configure the custom **KWin**, **KScreenLocker**, **Hermes-KMS**, and **Hermes** stack so physical monitors can show the KDE lock screen (and enter DPMS sleep) while the virtual streaming display remains unlocked and active.

---

## Repositories & Branches

| Component | Repository | Branch |
| :--- | :--- | :--- |
| **KWin** | `https://github.com/hardwarebob/kwin.git` | `hermes-modular-lock` |
| **KScreenLocker** | `https://github.com/hardwarebob/kscreenlocker.git` | `hermes-remote-sessions` |
| **Hermes** | `https://github.com/hardwarebob/Hermes.git` | `modular-session-privacy` |
| **Hermes-KMS** | `https://github.com/MrOz59/Hermes-KMS.git` | `main` (v0.4.1 / UAPI 14+) |

---

## 1. Install `hermes-kms` (DKMS, UAPI >= 11)

Hermes requires `hermes-kms` UAPI >= 11 (e.g. `0.4.1`, UAPI `14`).

```bash
git clone --depth=1 https://github.com/MrOz59/Hermes-KMS.git /tmp/hermes-kms
sudo cp -a /tmp/hermes-kms /usr/src/hermes-kms-0.4.1
sudo dkms install hermes-kms/0.4.1 -k "$(uname -r)"
sudo modprobe hermes_kms
```

If an older `hermes_kms` module was already loaded, stop your display manager (e.g. `sudo systemctl stop sddm`), run `sudo modprobe -r hermes_kms && sudo modprobe hermes_kms`, and start it again.

---

## 2. Build & Install KWin (`hermes-modular-lock`)

```bash
git clone --filter=blob:none -b hermes-modular-lock https://github.com/hardwarebob/kwin.git ~/code/kwin
cmake -B ~/code/kwin/build -S ~/code/kwin -G Ninja -DCMAKE_INSTALL_PREFIX=/usr
cmake --build ~/code/kwin/build -j"$(nproc)"
sudo cmake --install ~/code/kwin/build
```

Reload KWin in an active Plasma Wayland session (or log out and back in):

```bash
qdbus6 org.kde.KWin /KWin replace
```

Verify the new D-Bus interface is active:

```bash
qdbus6 org.kde.KWin /RemoteSessions
```

---

## 3. Build & Install KScreenLocker (`hermes-remote-sessions`)

```bash
git clone --filter=blob:none -b hermes-remote-sessions https://github.com/hardwarebob/kscreenlocker.git ~/code/kscreenlocker
cmake -B ~/code/kscreenlocker/build -S ~/code/kscreenlocker -G Ninja -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_TESTING=OFF
cmake --build ~/code/kscreenlocker/build -j"$(nproc)"
sudo cmake --install ~/code/kscreenlocker/build
```

### Plasma Desktop Lock Screen UI (`LockScreenUi.qml`)
`kscreenlocker_greet` exposes `remoteSessions` (`hasActiveSessions`, `activeSessions`, `disconnectOnUnlock`) to QML. `kscreenlocker`'s fallback theme already renders it; for the standard Plasma desktop lock screen, add the status card inside the `mainBlock` `ColumnLayout` in `/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen/LockScreenUi.qml` (below the `MediaControls.qml` `Loader`):

```qml
Rectangle {
    visible: typeof remoteSessions !== "undefined" && remoteSessions.hasActiveSessions
    Layout.topMargin: Kirigami.Units.smallSpacing
    Layout.alignment: Qt.AlignHCenter
    radius: Kirigami.Units.cornerRadius
    color: Qt.rgba(0, 0, 0, 0.45)
    border.color: Qt.rgba(1, 1, 1, 0.2)
    border.width: 1
    implicitWidth: remoteBannerCol.implicitWidth + Kirigami.Units.largeSpacing * 2
    implicitHeight: remoteBannerCol.implicitHeight + Kirigami.Units.largeSpacing * 1.5

    ColumnLayout {
        id: remoteBannerCol
        anchors.centerIn: parent
        spacing: Kirigami.Units.smallSpacing

        PlasmaComponents3.Label {
            Layout.alignment: Qt.AlignHCenter
            color: "white"
            font.bold: true
            text: {
                if (typeof remoteSessions === "undefined" || !remoteSessions.hasActiveSessions) {
                    return "";
                }
                const s = remoteSessions.activeSessions[0];
                return "Active remote session: " + (s.provider || "Remote") + " (" + (s.clientName || "Client") + ")";
            }
        }

        PlasmaComponents3.CheckBox {
            Layout.alignment: Qt.AlignHCenter
            checked: typeof remoteSessions !== "undefined" && remoteSessions.disconnectOnUnlock
            text: "Disconnect on unlock"
            onToggled: {
                if (typeof remoteSessions !== "undefined") {
                    remoteSessions.disconnectOnUnlock = checked;
                }
            }
        }
    }
}
```

---

## 4. Build & Install Hermes (`modular-session-privacy`)

```bash
git clone --recursive -b modular-session-privacy https://github.com/hardwarebob/Hermes.git ~/code/Hermes
cmake -B ~/code/Hermes/build -S ~/code/Hermes -G Ninja \
  -DBUILD_DOCS=OFF \
  -DBUILD_TESTS=OFF \
  -DSUNSHINE_ENABLE_CUDA=OFF \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DSUNSHINE_ASSETS_DIR=share/hermes
cmake --build ~/code/Hermes/build -j"$(nproc)"
sudo cmake --install ~/code/Hermes/build
sudo install -m 755 ~/code/Hermes/build/sunshine /usr/bin/hermes
sudo setcap cap_sys_admin=p /usr/bin/hermes
```

---

## 5. Configure Hermes (`~/.config/sunshine/sunshine.conf`)

Set `session_privacy_mode` in `~/.config/sunshine/sunshine.conf`:

```ini
virtual_display_backend = hermes_kms
session_privacy_mode = kwin_per_output_lock
isolated_virtual_display_option = disabled
inhibit_screen_lock = false
```

Available `session_privacy_mode` values:
- `auto` — selects `kwin_per_output_lock` if `org.kde.KWin.RemoteSessions` is available, otherwise falls back to `none`.
- `kwin_per_output_lock` — keeps physical monitors enabled, locks `seat0` via `org.freedesktop.ScreenSaver.Lock`, marks `Virtual-1` as `Unlocked` + `AlwaysOn` DPMS, and registers the session on `/RemoteSessions`.
- `kwin_standalone_session` — registers the session on `/RemoteSessions` for an independent `kwin_wayland --drm-standalone --no-libinput` session.
- `disable_outputs` / `none` — uses legacy output-disabling behavior or no-op.

Restart Hermes:

```bash
systemctl --user restart hermes
```

---

## Behavior Summary
- When a client connects, physical monitors lock and show **`Active remote session: Hermes (Client)`** with a **"Disconnect on unlock"** checkbox, and can enter DPMS sleep while `Virtual-1` keeps streaming.
- Unlocking with **"Disconnect on unlock"** unchecked returns to the shared desktop with the stream still running.
- Unlocking with **"Disconnect on unlock"** checked terminates the active stream and tears down `Virtual-1`.
