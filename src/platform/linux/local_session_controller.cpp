/**
 * @file src/platform/linux/local_session_controller.cpp
 * @brief Generic local-session / display-privacy controller implementations.
 */
#include "local_session_controller.h"

#include "misc.h"
#include "src/logging.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
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

      bool on_stream_starting(const std::string &, const std::string &, std::function<void()>, bool) override {
        return true;
      }

      void on_stream_stopping() override {}

    private:
      std::string m_name;
    };

#ifdef SUNSHINE_BUILD_SDBUS
    struct dbus_compositor_spec_t {
      const char *service;
      const char *path;
      const char *iface;
      const char *register_method;
      const char *unregister_method;
      const char *set_policies_method;
      const char *disconnect_signal;
      const char *screensaver_service;
      const char *screensaver_path;
      const char *screensaver_iface;
    };

    constexpr dbus_compositor_spec_t kwin_spec {
      "org.kde.KWin",
      "/RemoteSessions",
      "org.kde.KWin.RemoteSessions",
      "registerSession",
      "unregisterSession",
      "setOutputPolicies",
      "disconnectRequested",
      "org.freedesktop.ScreenSaver",
      "/ScreenSaver",
      "org.freedesktop.ScreenSaver",
    };

    constexpr dbus_compositor_spec_t mutter_spec {
      "org.gnome.Mutter.RemoteSessions",
      "/RemoteSessions",
      "org.gnome.Mutter.RemoteSessions",
      "RegisterSession",
      "UnregisterSession",
      "SetOutputPolicies",
      "DisconnectRequested",
      "org.gnome.ScreenSaver",
      "/org/gnome/ScreenSaver",
      "org.gnome.ScreenSaver",
    };

    class dbus_remote_session_controller_t final : public local_session_controller_t {
    public:
      dbus_remote_session_controller_t(
        std::string mode_name,
        const dbus_compositor_spec_t &spec,
        bool configure_output_policies
      ) :
          m_name(std::move(mode_name)),
          m_spec(spec),
          m_configure_output_policies(configure_output_policies) {}

      ~dbus_remote_session_controller_t() override {
        on_stream_stopping();
      }

      std::string_view name() const override {
        return m_name;
      }

      bool is_available() const override {
        sd_bus *bus = nullptr;
        if (platf::open_user_bus(&bus) < 0 || !bus) {
          return false;
        }
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = nullptr;
        const int rc = sd_bus_call_method(
          bus,
          m_spec.service,
          m_spec.path,
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
        std::function<void()> on_disconnect,
        bool lock_virtual_display
      ) override {
        on_stream_stopping();

        std::lock_guard lg(m_mutex);
        if (platf::open_user_bus(&m_bus) < 0 || !m_bus) {
          BOOST_LOG(warning) << m_name << ": failed to open user D-Bus";
          return false;
        }

        m_output_name = output_name;
        m_on_disconnect = std::move(on_disconnect);

        if (m_configure_output_policies && !m_output_name.empty()) {
          set_output_policies(m_bus, m_output_name, !lock_virtual_display, true);
        }

        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_message *reply = nullptr;
        const int rc = sd_bus_call_method(
          m_bus,
          m_spec.service,
          m_spec.path,
          m_spec.iface,
          m_spec.register_method,
          &err,
          &reply,
          "sss",
          "Hermes",
          client_name.empty() ? "Client" : client_name.c_str(),
          m_output_name.c_str()
        );
        if (rc < 0) {
          BOOST_LOG(warning) << m_name << ": " << m_spec.register_method
                             << " failed: " << (err.message ? err.message : strerror(-rc));
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

        if (m_configure_output_policies) {
          sd_bus_error lock_err = SD_BUS_ERROR_NULL;
          sd_bus_call_method(
            m_bus,
            m_spec.screensaver_service,
            m_spec.screensaver_path,
            m_spec.screensaver_iface,
            "Lock",
            &lock_err,
            nullptr,
            ""
          );
          sd_bus_error_free(&lock_err);
        }

        sd_bus_match_signal(
          m_bus,
          &m_signal_slot,
          m_spec.service,
          m_spec.path,
          m_spec.iface,
          m_spec.disconnect_signal,
          &dbus_remote_session_controller_t::on_disconnect_signal,
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
            m_spec.service,
            m_spec.path,
            m_spec.iface,
            m_spec.unregister_method,
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
        auto *self = static_cast<dbus_remote_session_controller_t *>(userdata);
        const char *sid = nullptr;
        if (sd_bus_message_read(m, "s", &sid) >= 0 && sid && self->m_session_id == sid) {
          BOOST_LOG(info) << self->m_name << ": disconnectRequested received for session " << sid;
          if (self->m_on_disconnect) {
            self->m_on_disconnect();
          }
        }
        return 0;
      }

      void set_output_policies(sd_bus *bus, const std::string &output_name, bool unlocked, bool always_on) const {
        sd_bus_error err = SD_BUS_ERROR_NULL;
        sd_bus_call_method(
          bus,
          m_spec.service,
          m_spec.path,
          m_spec.iface,
          m_spec.set_policies_method,
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
      dbus_compositor_spec_t m_spec;
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

    class wlroots_session_controller_t final : public local_session_controller_t {
    public:
      ~wlroots_session_controller_t() override {
        on_stream_stopping();
      }

      std::string_view name() const override {
        return "wlroots_per_output_lock";
      }

      bool is_available() const override {
        const char *swaysock = std::getenv("SWAYSOCK");
        return swaysock && *swaysock;
      }

      bool on_stream_starting(
        const std::string &client_name,
        const std::string &output_name,
        std::function<void()> on_disconnect,
        bool lock_virtual_display
      ) override {
        on_stream_stopping();

        std::lock_guard lg(m_mutex);
        m_output_name = output_name;
        m_client_name = client_name.empty() ? "Client" : client_name;
        m_session_id = "hermes-wlroots-1";
        m_on_disconnect = std::move(on_disconnect);

        if (!m_output_name.empty() && !lock_virtual_display) {
          std::string cmd = "swaymsg output '" + m_output_name + "' unlocked_while_locked on >/dev/null 2>&1";
          std::system(cmd.c_str());
        }

        if (platf::open_user_bus(&m_bus) >= 0 && m_bus) {
          static const sd_bus_vtable vtable[] = {
            SD_BUS_VTABLE_START(0),
            SD_BUS_PROPERTY("ActiveSessions", "aa{sv}", &wlroots_session_controller_t::prop_active_sessions, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
            SD_BUS_METHOD("RequestDisconnect", "s", "", &wlroots_session_controller_t::method_request_disconnect, SD_BUS_VTABLE_UNPRIVILEGED),
            SD_BUS_SIGNAL("DisconnectRequested", "s", 0),
            SD_BUS_VTABLE_END,
          };
          if (sd_bus_add_object_vtable(m_bus, &m_vtable_slot, "/RemoteSessions", "org.freedesktop.RemoteSessions", vtable, this) >= 0) {
            sd_bus_request_name(m_bus, "org.freedesktop.RemoteSessions", 0);
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
          }
        }

        std::system("loginctl lock-session >/dev/null 2>&1 || swaylock -f >/dev/null 2>&1 &");
        BOOST_LOG(info) << "wlroots_per_output_lock: active for output '" << m_output_name << "'";
        return true;
      }

      void on_stream_stopping() override {
        m_running.store(false, std::memory_order_release);
        if (m_worker.joinable()) {
          m_worker.join();
        }

        std::lock_guard lg(m_mutex);
        if (!m_output_name.empty()) {
          std::string cmd = "swaymsg output '" + m_output_name + "' unlocked_while_locked off >/dev/null 2>&1";
          std::system(cmd.c_str());
          m_output_name.clear();
        }
        if (m_vtable_slot) {
          sd_bus_slot_unref(m_vtable_slot);
          m_vtable_slot = nullptr;
        }
        if (m_bus) {
          sd_bus_release_name(m_bus, "org.freedesktop.RemoteSessions");
          sd_bus_unref(m_bus);
          m_bus = nullptr;
        }
        m_session_id.clear();
      }

    private:
      static int prop_active_sessions(sd_bus *, const char *, const char *, const char *, sd_bus_message *reply, void *userdata, sd_bus_error *) {
        auto *self = static_cast<wlroots_session_controller_t *>(userdata);
        int r = sd_bus_message_open_container(reply, 'a', "a{sv}");
        if (r < 0) {
          return r;
        }
        if (!self->m_session_id.empty()) {
          r = sd_bus_message_open_container(reply, 'a', "{sv}");
          if (r >= 0) {
            sd_bus_message_append(reply, "{sv}", "id", "s", self->m_session_id.c_str());
            sd_bus_message_append(reply, "{sv}", "provider", "s", "Hermes");
            sd_bus_message_append(reply, "{sv}", "clientName", "s", self->m_client_name.c_str());
            sd_bus_message_append(reply, "{sv}", "outputName", "s", self->m_output_name.c_str());
            sd_bus_message_close_container(reply);
          }
        }
        return sd_bus_message_close_container(reply);
      }

      static int method_request_disconnect(sd_bus_message *m, void *userdata, sd_bus_error *) {
        auto *self = static_cast<wlroots_session_controller_t *>(userdata);
        const char *sid = nullptr;
        if (sd_bus_message_read(m, "s", &sid) >= 0 && sid && self->m_session_id == sid) {
          if (self->m_on_disconnect) {
            self->m_on_disconnect();
          }
        }
        return sd_bus_reply_method_return(m, "");
      }

      std::mutex m_mutex;
      sd_bus *m_bus {nullptr};
      sd_bus_slot *m_vtable_slot {nullptr};
      std::string m_session_id;
      std::string m_client_name;
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
      return std::make_unique<dbus_remote_session_controller_t>("kwin_per_output_lock", kwin_spec, true);
    }
    if (mode == "kwin_standalone_session") {
      return std::make_unique<dbus_remote_session_controller_t>("kwin_standalone_session", kwin_spec, false);
    }
    if (mode == "mutter_per_output_lock") {
      return std::make_unique<dbus_remote_session_controller_t>("mutter_per_output_lock", mutter_spec, true);
    }
    if (mode == "mutter_standalone_session") {
      return std::make_unique<dbus_remote_session_controller_t>("mutter_standalone_session", mutter_spec, false);
    }
    if (mode == "wlroots_per_output_lock") {
      return std::make_unique<wlroots_session_controller_t>();
    }
    if (mode == "auto") {
      auto kwin = std::make_unique<dbus_remote_session_controller_t>("kwin_per_output_lock", kwin_spec, true);
      if (kwin->is_available()) {
        return kwin;
      }
      auto mutter = std::make_unique<dbus_remote_session_controller_t>("mutter_per_output_lock", mutter_spec, true);
      if (mutter->is_available()) {
        return mutter;
      }
      auto wlroots = std::make_unique<wlroots_session_controller_t>();
      if (wlroots->is_available()) {
        return wlroots;
      }
    }
#endif
    return std::make_unique<noop_session_controller_t>(mode.empty() ? "none" : mode);
  }

  bool prepare_output_privacy_for_capture(
    const std::string &mode,
    const std::string &output_name,
    bool lock_virtual_display
  ) {
    if (output_name.empty()) {
      return false;
    }
#ifdef SUNSHINE_BUILD_SDBUS
    auto apply_spec = [&](const dbus_compositor_spec_t &spec) -> bool {
      sd_bus *bus = nullptr;
      if (platf::open_user_bus(&bus) < 0 || !bus) {
        return false;
      }
      sd_bus_error err = SD_BUS_ERROR_NULL;
      const int rc = sd_bus_call_method(
        bus,
        spec.service,
        spec.path,
        spec.iface,
        spec.set_policies_method,
        &err,
        nullptr,
        "sbb",
        output_name.c_str(),
        lock_virtual_display ? 0 : 1,
        1
      );
      sd_bus_error_free(&err);
      sd_bus_unref(bus);
      return rc >= 0;
    };

    if (mode == "kwin_per_output_lock") {
      return apply_spec(kwin_spec);
    }
    if (mode == "mutter_per_output_lock") {
      return apply_spec(mutter_spec);
    }
    if (mode == "wlroots_per_output_lock") {
      std::string cmd = "swaymsg output '" + output_name + "' dpms on" +
                        (lock_virtual_display ? "" : " unlocked_while_locked on") + " >/dev/null 2>&1";
      return std::system(cmd.c_str()) == 0;
    }
    if (mode == "auto") {
      if (apply_spec(kwin_spec) || apply_spec(mutter_spec)) {
        return true;
      }
      if (const char *swaysock = std::getenv("SWAYSOCK"); swaysock && *swaysock) {
        std::string cmd = "swaymsg output '" + output_name + "' dpms on" +
                          (lock_virtual_display ? "" : " unlocked_while_locked on") + " >/dev/null 2>&1";
        return std::system(cmd.c_str()) == 0;
      }
    }
#endif
    return false;
  }

}  // namespace platf
