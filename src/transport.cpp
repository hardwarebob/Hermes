/**
 * @file src/transport.cpp
 * @brief Flexible transport servers (Unix domain socket mux, stdio proxy, embedded libssh server).
 */
#include "transport.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

#ifdef __linux__
  #include <poll.h>
  #include <sys/socket.h>
  #include <sys/stat.h>
  #include <sys/un.h>
  #include <unistd.h>
#endif

#ifdef SUNSHINE_BUILD_LIBSSH
  #include <libssh/callbacks.h>
  #include <libssh/libssh.h>
  #include <libssh/server.h>
#endif

#include "auth.h"
#include "config.h"
#include "globals.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "platform/common.h"
#include "rtsp.h"
#include "transport_h3.h"
#include "utility.h"

namespace transport {

  namespace {
    uint16_t pick_local_target_port(const uint8_t *buf, size_t len) {
      // Explicit HERM<port_be16> mux header?
      if (len >= 6 && buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'R' && buf[3] == 'M') {
        const uint16_t requested = static_cast<uint16_t>((buf[4] << 8) | buf[5]);
        const uint16_t http_p = net::map_port(nvhttp::PORT_HTTP);
        const uint16_t https_p = net::map_port(nvhttp::PORT_HTTPS);
        const uint16_t rtsp_p = net::map_port(rtsp_stream::RTSP_SETUP_PORT);
        if (requested == http_p || requested == https_p || requested == rtsp_p) {
          return requested;
        }
      }
      // TLS ClientHello (0x16 0x03) -> HTTPS
      if (len >= 2 && buf[0] == 0x16 && buf[1] == 0x03) {
        return net::map_port(nvhttp::PORT_HTTPS);
      }
      // RTSP request -> RTSP port
      const std::string_view head(reinterpret_cast<const char *>(buf), std::min<size_t>(len, 16));
      if (head.starts_with("OPTIONS ") || head.starts_with("DESCRIBE ") ||
          head.starts_with("SETUP ") || head.starts_with("ANNOUNCE ") ||
          head.starts_with("PLAY ") || head.starts_with("TEARDOWN ")) {
        return net::map_port(rtsp_stream::RTSP_SETUP_PORT);
      }
      // Default to HTTP
      return net::map_port(nvhttp::PORT_HTTP);
    }

    bool is_allowed_forward_port(uint16_t port) {
      return port == net::map_port(nvhttp::PORT_HTTP) ||
             port == net::map_port(nvhttp::PORT_HTTPS) ||
             port == net::map_port(rtsp_stream::RTSP_SETUP_PORT);
    }

#ifdef __linux__
    void pump_bidirectional_fds(int fd_a, int fd_b) {
      std::array<char, 16384> buf;
      struct pollfd fds[2];
      fds[0].fd = fd_a;
      fds[0].events = POLLIN;
      fds[1].fd = fd_b;
      fds[1].events = POLLIN;

      while (true) {
        const int rc = ::poll(fds, 2, 1000);
        if (rc < 0) {
          if (errno == EINTR) {
            continue;
          }
          break;
        }
        if (rc == 0) {
          continue;
        }
        for (int i = 0; i < 2; ++i) {
          if (fds[i].fd < 0) {
            continue;
          }
          const int dst = (i == 0) ? fd_b : fd_a;
          if (fds[i].revents & POLLIN) {
            const ssize_t n = ::read(fds[i].fd, buf.data(), buf.size());
            if (n <= 0) {
              ::shutdown(dst, SHUT_WR);
              fds[i].fd = -1;
              if (fds[0].fd < 0 && fds[1].fd < 0) {
                return;
              }
              continue;
            }
            ssize_t off = 0;
            while (off < n) {
              const ssize_t w = ::write(dst, buf.data() + off, static_cast<size_t>(n - off));
              if (w <= 0) {
                return;
              }
              off += w;
            }
          } else if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            ::shutdown(dst, SHUT_WR);
            fds[i].fd = -1;
            if (fds[0].fd < 0 && fds[1].fd < 0) {
              return;
            }
          }
        }
      }
    }

    int connect_local_tcp(uint16_t port) {
      boost::asio::io_context ioc;
      boost::asio::ip::tcp::socket sock(ioc);
      boost::system::error_code ec;
      sock.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), port), ec);
      if (ec) {
        return -1;
      }
      return ::dup(sock.native_handle());
    }

    void handle_unix_client(int client_fd) {
      auto close_client = util::fail_guard([client_fd]() { ::close(client_fd); });
      std::array<uint8_t, 32> peek_buf {};
      const ssize_t peeked = ::recv(client_fd, peek_buf.data(), peek_buf.size(), MSG_PEEK);
      if (peeked <= 0) {
        return;
      }
      const uint16_t target_port = pick_local_target_port(peek_buf.data(), static_cast<size_t>(peeked));
      if (peeked >= 6 && peek_buf[0] == 'H' && peek_buf[1] == 'E' && peek_buf[2] == 'R' && peek_buf[3] == 'M') {
        // Consume the 6-byte HERM mux header
        std::array<uint8_t, 6> hdr {};
        if (::recv(client_fd, hdr.data(), hdr.size(), MSG_WAITALL) != 6) {
          return;
        }
      }
      const int target_fd = connect_local_tcp(target_port);
      if (target_fd < 0) {
        return;
      }
      auto close_target = util::fail_guard([target_fd]() { ::close(target_fd); });
      pump_bidirectional_fds(client_fd, target_fd);
    }

    void run_unix_socket_server(safe::mail_raw_t::event_t<bool> shutdown_event) {
      const std::string sock_path = default_unix_socket_path();
      std::error_code ec;
      std::filesystem::create_directories(std::filesystem::path(sock_path).parent_path(), ec);
      std::filesystem::remove(sock_path, ec);

      const int listen_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (listen_fd < 0) {
        BOOST_LOG(error) << "Unix transport: failed to create socket: " << std::strerror(errno);
        return;
      }
      auto close_listen = util::fail_guard([&]() {
        ::close(listen_fd);
        std::error_code rm_ec;
        std::filesystem::remove(sock_path, rm_ec);
      });

      struct sockaddr_un addr {};
      addr.sun_family = AF_UNIX;
      if (sock_path.size() >= sizeof(addr.sun_path)) {
        BOOST_LOG(error) << "Unix transport: socket path too long: " << sock_path;
        return;
      }
      std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path.c_str());

      if (::bind(listen_fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
        BOOST_LOG(error) << "Unix transport: bind(" << sock_path << ") failed: " << std::strerror(errno);
        return;
      }
      ::chmod(sock_path.c_str(), 0600);
      if (::listen(listen_fd, 64) != 0) {
        BOOST_LOG(error) << "Unix transport: listen failed: " << std::strerror(errno);
        return;
      }

      BOOST_LOG(info) << "Unix domain socket transport listening on [" << sock_path << ']';

      while (!shutdown_event->peek()) {
        struct pollfd pfd {listen_fd, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, 250);
        if (rc <= 0) {
          continue;
        }
        const int client_fd = ::accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
        if (client_fd >= 0) {
          std::thread(handle_unix_client, client_fd).detach();
        }
      }
    }
#endif

#if defined(__linux__) && defined(SUNSHINE_BUILD_LIBSSH)
    std::string ensure_ssh_host_key() {
      std::string key_path = config::sunshine.ssh_host_key;
      if (key_path.empty()) {
        key_path = (platf::appdata() / "ssh_host_ed25519_key").string();
      }
      std::error_code ec;
      if (!std::filesystem::exists(key_path, ec)) {
        std::filesystem::create_directories(std::filesystem::path(key_path).parent_path(), ec);
        ssh_key host_key = nullptr;
        if (ssh_pki_generate(SSH_KEYTYPE_ED25519, 0, &host_key) == SSH_OK && host_key) {
          if (ssh_pki_export_privkey_file(host_key, nullptr, nullptr, nullptr, key_path.c_str()) == SSH_OK) {
            ::chmod(key_path.c_str(), 0600);
            BOOST_LOG(info) << "SSH transport: generated Ed25519 host key at [" << key_path << ']';
          }
          ssh_key_free(host_key);
        }
      }
      return key_path;
    }

    void handle_ssh_session(ssh_session session) {
      auto free_sess = util::fail_guard([session]() {
        ssh_disconnect(session);
        ssh_free(session);
      });

      if (ssh_handle_key_exchange(session) != SSH_OK) {
        BOOST_LOG(debug) << "SSH transport: key exchange failed: " << ssh_get_error(session);
        return;
      }

      ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY | SSH_AUTH_METHOD_PASSWORD);

      bool authenticated = false;
      ssh_channel channel = nullptr;
      bool hermes_subsystem = false;
      int forward_fd = -1;

      auto close_forward = util::fail_guard([&]() {
        if (forward_fd >= 0) {
          ::close(forward_fd);
          forward_fd = -1;
        }
        if (channel) {
          ssh_channel_close(channel);
          ssh_channel_free(channel);
          channel = nullptr;
        }
      });

      while (!authenticated || !channel) {
        ssh_message msg = ssh_message_get(session);
        if (!msg) {
          return;
        }
        auto free_msg = util::fail_guard([msg]() { ssh_message_free(msg); });

        const int type = ssh_message_type(msg);
        const int subtype = ssh_message_subtype(msg);

        if (type == SSH_REQUEST_AUTH) {
          if (subtype == SSH_AUTH_METHOD_PUBLICKEY && auth::provider_enabled("ssh_key")) {
            ssh_key pub = ssh_message_auth_pubkey(msg);
            char *b64 = nullptr;
            if (pub && ssh_pki_export_pubkey_base64(pub, &b64) == SSH_OK && b64) {
              const std::string line = std::string(ssh_key_type_to_char(ssh_key_type(pub))) + " " + b64;
              ssh_string_free_char(b64);
              if (auth::is_ssh_pubkey_authorized(line)) {
                if (ssh_message_auth_publickey_state(msg) == SSH_PUBLICKEY_STATE_VALID) {
                  authenticated = true;
                  ssh_message_auth_reply_success(msg, 0);
                  continue;
                }
                ssh_message_auth_reply_pk_ok_simple(msg);
                continue;
              }
            }
          } else if (subtype == SSH_AUTH_METHOD_PASSWORD && auth::provider_enabled("pam")) {
            const char *user = ssh_message_auth_user(msg);
            const char *pass = ssh_message_auth_password(msg);
            if (user && pass && auth::authenticate_pam(user, pass).ok) {
              authenticated = true;
              ssh_message_auth_reply_success(msg, 0);
              continue;
            }
          }
          ssh_message_reply_default(msg);
          continue;
        }

        if (!authenticated) {
          ssh_message_reply_default(msg);
          continue;
        }

        if (type == SSH_REQUEST_CHANNEL_OPEN && subtype == SSH_CHANNEL_SESSION && !channel) {
          channel = ssh_message_channel_request_open_reply_accept(msg);
          continue;
        }

        if (type == SSH_REQUEST_CHANNEL_OPEN && subtype == SSH_CHANNEL_DIRECT_TCPIP && !channel) {
          const uint16_t dest_port = static_cast<uint16_t>(ssh_message_channel_request_open_destination_port(msg));
          if (is_allowed_forward_port(dest_port)) {
            forward_fd = connect_local_tcp(dest_port);
            if (forward_fd >= 0) {
              channel = ssh_message_channel_request_open_reply_accept(msg);
              break;
            }
          }
          ssh_message_reply_default(msg);
          continue;
        }

        if (type == SSH_REQUEST_CHANNEL && subtype == SSH_CHANNEL_REQUEST_SUBSYSTEM && channel) {
          const char *sub = ssh_message_channel_request_subsystem(msg);
          if (sub && std::string_view(sub) == "hermes") {
            hermes_subsystem = true;
            ssh_message_channel_request_reply_success(msg);
            break;
          }
          ssh_message_reply_default(msg);
          continue;
        }

        ssh_message_reply_default(msg);
      }

      if (hermes_subsystem && forward_fd < 0) {
        // Connect SSH subsystem directly to local Unix socket mux
        const std::string sock_path = default_unix_socket_path();
        forward_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (forward_fd >= 0) {
          struct sockaddr_un addr {};
          addr.sun_family = AF_UNIX;
          std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path.c_str());
          if (::connect(forward_fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
            ::close(forward_fd);
            forward_fd = -1;
          }
        }
      }

      if (!channel || forward_fd < 0) {
        return;
      }

      std::array<char, 16384> buf {};
      while (!ssh_channel_is_eof(channel) && !ssh_channel_is_closed(channel)) {
        const int r = ssh_channel_read_nonblocking(channel, buf.data(), buf.size(), 0);
        if (r > 0) {
          ssize_t off = 0;
          while (off < r) {
            const ssize_t w = ::write(forward_fd, buf.data() + off, static_cast<size_t>(r - off));
            if (w <= 0) {
              return;
            }
            off += w;
          }
        } else if (r == SSH_ERROR) {
          return;
        }

        struct pollfd pfd {forward_fd, POLLIN, 0};
        if (::poll(&pfd, 1, 10) > 0 && (pfd.revents & POLLIN)) {
          const ssize_t n = ::read(forward_fd, buf.data(), buf.size());
          if (n <= 0) {
            return;
          }
          if (ssh_channel_write(channel, buf.data(), static_cast<uint32_t>(n)) == SSH_ERROR) {
            return;
          }
        }
      }
    }

    void run_ssh_server(safe::mail_raw_t::event_t<bool> shutdown_event) {
      const std::string host_key = ensure_ssh_host_key();
      ssh_bind sshbind = ssh_bind_new();
      if (!sshbind) {
        BOOST_LOG(error) << "SSH transport: ssh_bind_new failed";
        return;
      }
      auto free_bind = util::fail_guard([sshbind]() { ssh_bind_free(sshbind); });

      const unsigned int port = config::sunshine.ssh_server_port;
      ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
      ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, host_key.c_str());

      if (ssh_bind_listen(sshbind) < 0) {
        BOOST_LOG(error) << "SSH transport: listen on port " << port << " failed: " << ssh_get_error(sshbind);
        return;
      }
      ssh_bind_set_blocking(sshbind, 0);
      BOOST_LOG(info) << "Embedded SSH transport listening on port [" << port << ']';

      while (!shutdown_event->peek()) {
        ssh_session session = ssh_new();
        if (!session) {
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
          continue;
        }
        const int rc = ssh_bind_accept(sshbind, session);
        if (rc == SSH_OK) {
          std::thread(handle_ssh_session, session).detach();
        } else {
          ssh_free(session);
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
      }
    }
#endif
  }  // namespace

  std::string default_unix_socket_path() {
    if (!config::sunshine.unix_socket_path.empty()) {
      return config::sunshine.unix_socket_path;
    }
    if (const char *runtime_dir = std::getenv("XDG_RUNTIME_DIR"); runtime_dir && *runtime_dir) {
      return std::string(runtime_dir) + "/hermes/hermes.sock";
    }
#ifdef __linux__
    return "/tmp/hermes-" + std::to_string(static_cast<unsigned long>(::geteuid())) + ".sock";
#else
    return {};
#endif
  }

  void start() {
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);
    std::vector<std::thread> threads;

#ifdef __linux__
    if (auth::transport_enabled("unix_socket") || config::sunshine.ssh_server_enabled || auth::transport_enabled("ssh")) {
      threads.emplace_back(run_unix_socket_server, shutdown_event);
    }
#endif

#if defined(__linux__) && defined(SUNSHINE_BUILD_LIBSSH)
    if (config::sunshine.ssh_server_enabled || auth::transport_enabled("ssh")) {
      threads.emplace_back(run_ssh_server, shutdown_event);
    }
#endif

#if defined(__linux__) && defined(SUNSHINE_BUILD_HTTP3)
    if (config::sunshine.h3_server_enabled || auth::transport_enabled("http3")) {
      threads.emplace_back(transport_h3::start);
    }
#endif

    for (auto &t : threads) {
      if (t.joinable()) {
        t.join();
      }
    }
  }

  int run_stdio_proxy(const std::string &socket_path) {
#ifdef __linux__
    const std::string path = socket_path.empty() ? default_unix_socket_path() : socket_path;
    const int sock_fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) {
      return 1;
    }
    auto close_sock = util::fail_guard([sock_fd]() { ::close(sock_fd); });

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
      return 1;
    }
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());

    if (::connect(sock_fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
      return 2;
    }

    std::array<char, 16384> buf {};
    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd = sock_fd;
    fds[1].events = POLLIN;

    while (true) {
      const int rc = ::poll(fds, 2, -1);
      if (rc < 0) {
        if (errno == EINTR) {
          continue;
        }
        break;
      }
      if (fds[0].revents & POLLIN) {
        const ssize_t n = ::read(STDIN_FILENO, buf.data(), buf.size());
        if (n <= 0) {
          ::shutdown(sock_fd, SHUT_WR);
          fds[0].fd = -1;
        } else {
          ssize_t off = 0;
          while (off < n) {
            const ssize_t w = ::write(sock_fd, buf.data() + off, static_cast<size_t>(n - off));
            if (w <= 0) {
              return 0;
            }
            off += w;
          }
        }
      }
      if (fds[1].revents & POLLIN) {
        const ssize_t n = ::read(sock_fd, buf.data(), buf.size());
        if (n <= 0) {
          return 0;
        }
        ssize_t off = 0;
        while (off < n) {
          const ssize_t w = ::write(STDOUT_FILENO, buf.data() + off, static_cast<size_t>(n - off));
          if (w <= 0) {
            return 0;
          }
          off += w;
        }
      }
      if ((fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) && fds[0].fd != -1) {
        ::shutdown(sock_fd, SHUT_WR);
        fds[0].fd = -1;
      }
      if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
        return 0;
      }
    }
    return 0;
#else
    (void) socket_path;
    return 1;
#endif
  }

}  // namespace transport
