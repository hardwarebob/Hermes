/**
 * @file src/platform/linux/local_session_controller.cpp
 * @brief Generic local-session / display-privacy controller implementations.
 */
#include "local_session_controller.h"

#include "src/logging.h"

#include <atomic>
#include <mutex>
#include <thread>
#include <utility>

#ifdef SUNSHINE_BUILD_SDBUS
#include <systemd/sd-bus.h>
#endif

namespace platf {
  namespace {

    class noop_session_controller_t final : public local_session_controller_t {
    public:
      explicit noop_session_controller_t(std::string mode_name) :
          m_name(std::move(mode_name)) {}

      std::string_view name() const override {
        return m_name;
      }

      bool is_available() const override {
        return true;
      }

      bool on_stream_starting(const std::string &, const std::string &, std::function<void()>) override {
        return true;
      }

      void on_stream_stopping() override {}

    private:
      std::string m_name;
    };

#ifdef SUNSHINE_BUILD_SDBUS
    constexpr auto kwin_service = "org.kde.KWin";
    constexpr auto kwin_remote_path = "/RemoteSessions";
    constexpr auto kwin_remote_iface = "org.kde.KWin.RemoteSessions";

    class kwin_remote_session_controller_t : public local_session_controller_t {
    public:
      kwin_remote_session_controller_t(std::string mode_name, bool configure_output_policies) :
          m_name(std::move(mode_name)),
          m_configure_output_policies(configure_output_policies) {}

      ~kwin_remote_session_controller_t() override {
        on_stream_stopping();
      }

      std::string_view name() const override {
        return m_name;
      }

      bool is_available() const override {
        sd_bus *bus = nullptr;
        if (sd_bus_open_user(&bus) < 0 || !bus) {
          return false;
        }
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = nullptr;
        const int rc = sd_bus_call_method(
          bus,
          kwin_service,
          kwin_remote_path,
          "org.freedesktop.DBus.Introspectable",
          "Introspect",
          &err,
          &reply,
          ""
        );
        sd_bus_message_unref(reply);
        sd_bus_error_free(&err);
        sd_bus_unref(bus);
        return rc >= 0;
      }

      bool on_stream_starting(
        const std::string &client_name,
        const std::string &output_name,
        std::function<void()> on_disconnect
      ) override {
        on_stream_stopping();

        std::lock_guard lg(m_mutex);
        if (sd_bus_open_user(&m_bus) < 0 || !m_bus) {
          BOOST_LOG(warning) << m_name << ": failed to open user D-Bus";
          return false;
        }

        m_output_name = output_name;
        m_on_disconnect = std::move(on_disconnect);

        if (m_configure_output_policies && !m_output_name.empty()) {
          set_output_policies(m_bus, m_output_name, true, true);
        }

        if (m_configure_output_policies) {
          sd_bus_error lock_err = SD_BUS_ERROR_NULL;
          sd_bus_call_method(
            m_bus,
            "org.freedesktop.ScreenSaver",
            "/ScreenSaver",
            "org.freedesktop.ScreenSaver",
            "Lock",
            &lock_err,
            nullptr,
            ""
          );
          sd_bus_error_free(&lock_err);
        }

        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = nullptr;
        const int rc = sd_bus_call_method(
          m_bus,
          kwin_service,
          kwin_remote_path,
          kwin_remote_iface,
          "registerSession",
          &err,
          &reply,
          "sss",
          "Hermes",
          client_name.empty() ? "Client" : client_name.c_str(),
          m_output_name.c_str()
        );
        if (rc < 0) {
          BOOST_LOG(warning) << m_name << ": registerSession failed: " << (err.message ? err.message : strerror(-rc));
          sd_bus_error_free(&err);
          sd_bus_message_unref(reply);
          sd_bus_unref(m_bus);
          m_bus = nullptr;
          return false;
        }

        const char *sid = nullptr;
        if (sd_bus_message_read(reply, "s", &sid) >= 0 && sid) {
          m_session_id = sid;
        }
        sd_bus_message_unref(reply);
        sd_bus_error_free(&err);

        sd_bus_match_signal(
          m_bus,
          &m_signal_slot,
          kwin_service,
          kwin_remote_path,
          kwin_remote_iface,
          "disconnectRequested",
          &kwin_remote_session_controller_t::on_disconnect_signal,
          this
        );

        m_running.store(true, std::memory_order_release);
        m_worker = std::thread([this] {
          while (m_running.load(std::memory_order_acquire)) {
            int r = sd_bus_process(m_bus, nullptr);
            if (r > 0) {
              continue;
            }
            if (r < 0) {
              break;
            }
            sd_bus_wait(m_bus, 200000);
          }
        });

        BOOST_LOG(info) << m_name << ": registered remote session " << m_session_id
                        << " for output '" << m_output_name << "'";
        return true;
      }

      void on_stream_stopping() override {
        m_running.store(false, std::memory_order_release);
        if (m_worker.joinable()) {
          m_worker.join();
        }

        std::lock_guard lg(m_mutex);
        if (!m_bus) {
          return;
        }

        if (!m_session_id.empty()) {
          sd_bus_error err = SD_BUS_ERROR_NULL;
          sd_bus_call_method(
            m_bus,
            kwin_service,
            kwin_remote_path,
            kwin_remote_iface,
            "unregisterSession",
            &err,
            nullptr,
            "s",
            m_session_id.c_str()
          );
          sd_bus_error_free(&err);
          m_session_id.clear();
        }

        if (m_configure_output_policies && !m_output_name.empty()) {
          set_output_policies(m_bus, m_output_name, false, false);
        }

        if (m_signal_slot) {
          sd_bus_slot_unref(m_signal_slot);
          m_signal_slot = nullptr;
        }
        sd_bus_unref(m_bus);
        m_bus = nullptr;
      }

    private:
      static int on_disconnect_signal(sd_bus_message *m, void *userdata, sd_bus_error *) {
        auto *self = static_cast<kwin_remote_session_controller_t *>(userdata);
        const char *sid = nullptr;
        if (sd_bus_message_read(m, "s", &sid) >= 0 && sid && self->m_session_id == sid) {
          BOOST_LOG(info) << self->m_name << ": disconnectRequested received for session " << sid;
          if (self->m_on_disconnect) {
            self->m_on_disconnect();
          }
        }
        return 0;
      }

      static void set_output_policies(sd_bus *bus, const std::string &output_name, bool unlocked, bool always_on) {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_call_method(
          bus,
          kwin_service,
          kwin_remote_path,
          kwin_remote_iface,
          "setOutputPolicies",
          &err,
          nullptr,
          "sbb",
          output_name.c_str(),
          unlocked ? 1 : 0,
          always_on ? 1 : 0
        );
        sd_bus_error_free(&err);
      }

      std::string m_name;
      bool m_configure_output_policies;
      std::mutex m_mutex;
      sd_bus *m_bus {nullptr};
      sd_bus_slot *m_signal_slot {nullptr};
      std::string m_session_id;
      std::string m_output_name;
      std::function<void()> m_on_disconnect;
      std::atomic<bool> m_running {false};
      std::thread m_worker;
    };
#endif  // SUNSHINE_BUILD_SDBUS

  }  // namespace

  std::unique_ptr<local_session_controller_t> create_local_session_controller(const std::string &mode) {
#ifdef SUNSHINE_BUILD_SDBUS
    if (mode == "kwin_per_output_lock") {
      return std::make_unique<kwin_remote_session_controller_t>("kwin_per_output_lock", true);
    }
    if (mode == "kwin_standalone_session") {
      return std::make_unique<kwin_remote_session_controller_t>("kwin_standalone_session", false);
    }
    if (mode == "auto") {
      auto kwin = std::make_unique<kwin_remote_session_controller_t>("kwin_per_output_lock", true);
      if (kwin->is_available()) {
        return kwin;
      }
    }
#endif
    return std::make_unique<noop_session_controller_t>(mode.empty() ? "none" : mode);
  }

}  // namespace platf
