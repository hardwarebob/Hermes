/**
 * @file src/transport_h3.h
 * @brief Native HTTP/3 (QUIC + RFC 9221 Datagram) server and client proxy.
 */
#pragma once

#include <string>

namespace transport_h3 {

  /**
   * @brief Start the host HTTP/3 (QUIC) transport server until shutdown.
   */
  void start();

  /**
   * @brief Run the native HTTP/3 client proxy (`hermes --h3-proxy <host[:port]>`).
   */
  int run_h3_proxy(
    const std::string &remote,
    bool insecure = false,
    const std::string &bearer_token = {},
    const std::string &bind_addr = "127.0.0.1"
  );

}  // namespace transport_h3
