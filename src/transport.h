/**
 * @file src/transport.h
 * @brief Flexible transport servers (Unix domain socket mux, stdio proxy, embedded libssh server).
 */
#pragma once

#include <string>

namespace transport {

  /**
   * @brief Resolve the Unix domain socket path from config or XDG_RUNTIME_DIR.
   */
  std::string default_unix_socket_path();

  /**
   * @brief Start enabled flexible transport listeners (Unix socket, embedded libssh) until shutdown.
   */
  void start();

  /**
   * @brief Run stdin/stdout <-> Unix domain socket bridge (`hermes --proxy`).
   */
  int run_stdio_proxy(const std::string &socket_path = {});

}  // namespace transport
