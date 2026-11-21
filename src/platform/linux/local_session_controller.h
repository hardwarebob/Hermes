/**
 * @file src/platform/linux/local_session_controller.h
 * @brief Generic selectable local-session / display-privacy controller interface.
 */
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace platf {

  /**
   * @brief Pluggable controller for coordinating local desktop lock/DPMS/privacy
   * while a remote streaming session is active.
   */
  class local_session_controller_t {
  public:
    virtual ~local_session_controller_t() = default;

    virtual std::string_view name() const = 0;
    virtual bool is_available() const = 0;

    virtual bool on_stream_starting(
      const std::string &client_name,
      const std::string &output_name,
      std::function<void()> on_disconnect
    ) = 0;

    virtual void on_stream_stopping() = 0;
  };

  /**
   * @brief Selects a local session controller matching `mode`:
   *   - "auto": chooses the best available backend (currently kwin_per_output_lock if present, else none/disable_outputs)
   *   - "none" / "disable_outputs": no-op controller (relies on standard virtual-display output handling)
   *   - "kwin_per_output_lock": Mode A via org.kde.KWin.RemoteSessions
   *   - "kwin_standalone_session": Mode B via standalone kwin_wayland + org.kde.KWin.RemoteSessions
   */
  std::unique_ptr<local_session_controller_t> create_local_session_controller(const std::string &mode);

}  // namespace platf
