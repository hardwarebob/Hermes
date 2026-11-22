/**
 * @file src/transport_h3.cpp
 * @brief Native HTTP/3 (QUIC + RFC 9221 Datagram) server and client proxy.
 */
#include "transport_h3.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef __linux__
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#ifdef SUNSHINE_BUILD_HTTP3
  #include <nghttp3/nghttp3.h>
  #include <ngtcp2/ngtcp2.h>
  #include <ngtcp2/ngtcp2_crypto.h>
  #include <ngtcp2/ngtcp2_crypto_ossl.h>
  #include <openssl/rand.h>
  #include <openssl/ssl.h>
#endif

#include "auth.h"
#include "config.h"
#include "confighttp.h"
#include "globals.h"
#include "logging.h"
#include "network.h"
#include "nvhttp.h"
#include "rtsp.h"
#include "stream.h"
#include "utility.h"

namespace transport_h3 {

#if defined(__linux__) && defined(SUNSHINE_BUILD_HTTP3)
  namespace {
    ngtcp2_tstamp now_ns() {
      return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::steady_clock::now().time_since_epoch()
        ).count()
      );
    }

    int set_nonblocking(int fd) {
      int flags = ::fcntl(fd, F_GETFL, 0);
      if (flags < 0) {
        return -1;
      }
      return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    bool is_allowed_tcp_port(uint16_t port) {
      return port == net::map_port(nvhttp::PORT_HTTP) ||
             port == net::map_port(nvhttp::PORT_HTTPS) ||
             port == net::map_port(confighttp::PORT_HTTPS) ||
             port == net::map_port(rtsp_stream::RTSP_SETUP_PORT);
    }

    bool is_allowed_udp_port(uint16_t port) {
      return port == net::map_port(stream::VIDEO_STREAM_PORT) ||
             port == net::map_port(stream::CONTROL_PORT) ||
             port == net::map_port(stream::AUDIO_STREAM_PORT) ||
             port == net::map_port(stream::MIC_STREAM_PORT);
    }

    int connect_loopback_tcp_nb(uint16_t port) {
      int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (fd < 0) {
        return -1;
      }
      struct sockaddr_in addr {};
      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);
      addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      const int rc = ::connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr));
      if (rc < 0 && errno != EINPROGRESS) {
        ::close(fd);
        return -1;
      }
      return fd;
    }

    void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *) {
      RAND_bytes(dest, static_cast<int>(destlen));
    }

    int get_new_cid_cb(ngtcp2_conn *, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *) {
      if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      cid->datalen = cidlen;
      if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      return 0;
    }

    struct tunnel_stream_t {
      int64_t stream_id {-1};
      int tcp_fd {-1};
      uint16_t target_port {0};
      std::string path;
      std::string auth_header;
      std::deque<std::vector<uint8_t>> to_quic;
      bool tcp_eof {false};
      bool quic_eof {false};
      bool response_sent {false};
      bool rejected {false};
    };

    struct udp_relay_t {
      int fd {-1};
      uint16_t port {0};
    };

    struct h3_peer_conn_t {
      ngtcp2_conn *qconn {nullptr};
      nghttp3_conn *h3conn {nullptr};
      ngtcp2_crypto_ossl_ctx *ossl_ctx {nullptr};
      SSL *ssl {nullptr};
      ngtcp2_crypto_conn_ref conn_ref {};
      int udp_fd {-1};
      struct sockaddr_storage remote_addr {};
      socklen_t remote_len {0};
      struct sockaddr_storage local_addr {};
      socklen_t local_len {0};
      bool is_server {true};
      bool h3_bound {false};
      std::unordered_map<int64_t, std::unique_ptr<tunnel_stream_t>> streams;
      std::unordered_map<uint16_t, udp_relay_t> udp_relays;
      std::deque<std::vector<uint8_t>> outbound_dgrams;

      ~h3_peer_conn_t() {
        for (auto &[_, r] : udp_relays) {
          if (r.fd >= 0) {
            ::close(r.fd);
          }
        }
        for (auto &[_, s] : streams) {
          if (s && s->tcp_fd >= 0) {
            ::close(s->tcp_fd);
          }
        }
        if (h3conn) {
          nghttp3_conn_del(h3conn);
        }
        if (ssl) {
          SSL_set_app_data(ssl, nullptr);
          SSL_free(ssl);
        }
        if (ossl_ctx) {
          ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
        }
        if (qconn) {
          ngtcp2_conn_del(qconn);
        }
      }
    };

    ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref) {
      auto *p = static_cast<h3_peer_conn_t *>(ref->user_data);
      return p ? p->qconn : nullptr;
    }

    nghttp3_ssize read_stream_data_cb(
      nghttp3_conn *,
      int64_t stream_id,
      nghttp3_vec *vec,
      size_t veccnt,
      uint32_t *pflags,
      void *conn_user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      auto it = peer->streams.find(stream_id);
      if (it == peer->streams.end() || !it->second) {
        return NGHTTP3_ERR_WOULDBLOCK;
      }
      auto &st = *it->second;
      if (st.to_quic.empty()) {
        if (st.tcp_eof) {
          *pflags |= NGHTTP3_DATA_FLAG_EOF;
          return 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
      }
      size_t count = 0;
      for (const auto &chunk : st.to_quic) {
        if (count >= veccnt) {
          break;
        }
        vec[count].base = const_cast<uint8_t *>(chunk.data());
        vec[count].len = chunk.size();
        ++count;
      }
      if (st.tcp_eof && count == st.to_quic.size()) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
      }
      return static_cast<nghttp3_ssize>(count);
    }

    int h3_recv_data_cb(
      nghttp3_conn *,
      int64_t stream_id,
      const uint8_t *data,
      size_t datalen,
      void *conn_user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      auto it = peer->streams.find(stream_id);
      if (it == peer->streams.end() || !it->second || it->second->tcp_fd < 0) {
        return 0;
      }
      const int fd = it->second->tcp_fd;
      size_t off = 0;
      while (off < datalen) {
        const ssize_t w = ::send(fd, data + off, datalen - off, MSG_NOSIGNAL);
        if (w < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
          }
          break;
        }
        off += static_cast<size_t>(w);
      }
      return 0;
    }

    int h3_acked_stream_data_cb(
      nghttp3_conn *,
      int64_t stream_id,
      uint64_t datalen,
      void *conn_user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      auto it = peer->streams.find(stream_id);
      if (it == peer->streams.end() || !it->second) {
        return 0;
      }
      auto &q = it->second->to_quic;
      uint64_t rem = datalen;
      while (rem > 0 && !q.empty()) {
        auto &front = q.front();
        if (front.size() <= rem) {
          rem -= front.size();
          q.pop_front();
        } else {
          front.erase(front.begin(), front.begin() + static_cast<std::ptrdiff_t>(rem));
          rem = 0;
        }
      }
      return 0;
    }

    int h3_recv_header_cb(
      nghttp3_conn *,
      int64_t stream_id,
      int32_t,
      nghttp3_rcbuf *name,
      nghttp3_rcbuf *value,
      uint8_t,
      void *conn_user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      auto it = peer->streams.find(stream_id);
      if (it == peer->streams.end()) {
        auto st = std::make_unique<tunnel_stream_t>();
        st->stream_id = stream_id;
        it = peer->streams.emplace(stream_id, std::move(st)).first;
      }
      auto nv = nghttp3_rcbuf_get_buf(name);
      auto vv = nghttp3_rcbuf_get_buf(value);
      std::string_view k(reinterpret_cast<const char *>(nv.base), nv.len);
      std::string_view v(reinterpret_cast<const char *>(vv.base), vv.len);
      if (k == ":path") {
        it->second->path = std::string(v);
      } else if (k == "authorization") {
        it->second->auth_header = std::string(v);
      }
      return 0;
    }

    int h3_end_headers_cb(nghttp3_conn *h3, int64_t stream_id, int, void *conn_user_data, void *) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      if (!peer->is_server) {
        return 0;
      }
      auto it = peer->streams.find(stream_id);
      if (it == peer->streams.end() || !it->second || it->second->response_sent) {
        return 0;
      }
      auto &st = *it->second;
      st.response_sent = true;

      uint16_t port = 0;
      constexpr std::string_view prefix = "/_hermes/tcp/";
      if (st.path.rfind(prefix, 0) == 0) {
        port = static_cast<uint16_t>(std::atoi(st.path.substr(prefix.size()).c_str()));
      }

      if (auth::provider_enabled("token") && !st.auth_header.empty()) {
        if (!auth::verify_bearer_token(st.auth_header)) {
          st.rejected = true;
        }
      }

      const char *status_str = "200";
      if (st.rejected) {
        status_str = "401";
      } else if (!is_allowed_tcp_port(port)) {
        status_str = "403";
        st.rejected = true;
      } else {
        st.target_port = port;
        st.tcp_fd = connect_loopback_tcp_nb(port);
        if (st.tcp_fd < 0) {
          status_str = "502";
          st.rejected = true;
        }
      }

      const nghttp3_nv resp_nva[] = {
        {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":status")),
         const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(status_str)),
         7,
         std::strlen(status_str),
         NGHTTP3_NV_FLAG_NONE}
      };
      nghttp3_data_reader dr {read_stream_data_cb};
      nghttp3_conn_submit_response(h3, stream_id, resp_nva, 1, st.rejected ? nullptr : &dr);
      if (st.rejected) {
        st.tcp_eof = true;
      }
      return 0;
    }

    int h3_end_stream_cb(nghttp3_conn *, int64_t stream_id, void *conn_user_data, void *) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      auto it = peer->streams.find(stream_id);
      if (it != peer->streams.end() && it->second) {
        it->second->quic_eof = true;
        if (it->second->tcp_fd >= 0) {
          ::shutdown(it->second->tcp_fd, SHUT_WR);
        }
      }
      return 0;
    }

    int h3_stream_close_cb(nghttp3_conn *, int64_t stream_id, uint64_t, void *conn_user_data, void *) {
      auto *peer = static_cast<h3_peer_conn_t *>(conn_user_data);
      peer->streams.erase(stream_id);
      return 0;
    }

    int bind_h3_control_streams(h3_peer_conn_t *peer) {
      if (peer->h3_bound || !peer->h3conn) {
        return 0;
      }
      int64_t ctrl_id = -1;
      int64_t qpack_enc_id = -1;
      int64_t qpack_dec_id = -1;
      if (ngtcp2_conn_open_uni_stream(peer->qconn, &ctrl_id, nullptr) != 0 ||
          ngtcp2_conn_open_uni_stream(peer->qconn, &qpack_enc_id, nullptr) != 0 ||
          ngtcp2_conn_open_uni_stream(peer->qconn, &qpack_dec_id, nullptr) != 0) {
        return -1;
      }
      if (nghttp3_conn_bind_control_stream(peer->h3conn, ctrl_id) != 0 ||
          nghttp3_conn_bind_qpack_streams(peer->h3conn, qpack_enc_id, qpack_dec_id) != 0) {
        return -1;
      }
      peer->h3_bound = true;
      return 0;
    }

    int quic_handshake_completed_cb(ngtcp2_conn *, void *user_data) {
      auto *peer = static_cast<h3_peer_conn_t *>(user_data);
      return bind_h3_control_streams(peer) == 0 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
    }

    int quic_recv_stream_data_cb(
      ngtcp2_conn *qconn,
      uint32_t flags,
      int64_t stream_id,
      uint64_t,
      const uint8_t *data,
      size_t datalen,
      void *user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(user_data);
      if (!peer->h3conn) {
        return 0;
      }
      const int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
      const nghttp3_ssize consumed = nghttp3_conn_read_stream(peer->h3conn, stream_id, data, datalen, fin);
      if (consumed < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
      }
      ngtcp2_conn_extend_max_stream_offset(qconn, stream_id, static_cast<uint64_t>(consumed));
      ngtcp2_conn_extend_max_offset(qconn, static_cast<uint64_t>(consumed));
      return 0;
    }

    int quic_acked_stream_data_cb(
      ngtcp2_conn *,
      int64_t stream_id,
      uint64_t,
      uint64_t datalen,
      void *user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(user_data);
      if (peer->h3conn) {
        nghttp3_conn_add_ack_offset(peer->h3conn, stream_id, datalen);
      }
      return 0;
    }

    int quic_stream_close_cb(
      ngtcp2_conn *,
      uint32_t,
      int64_t stream_id,
      uint64_t app_error_code,
      void *user_data,
      void *
    ) {
      auto *peer = static_cast<h3_peer_conn_t *>(user_data);
      if (peer->h3conn) {
        nghttp3_conn_close_stream(peer->h3conn, stream_id, app_error_code);
      }
      return 0;
    }

    int quic_recv_datagram_cb(ngtcp2_conn *, uint32_t, const uint8_t *data, size_t datalen, void *user_data) {
      auto *peer = static_cast<h3_peer_conn_t *>(user_data);
      if (!peer->is_server || datalen < 3) {
        return 0;
      }
      const uint16_t port = static_cast<uint16_t>((data[0] << 8) | data[1]);
      if (!is_allowed_udp_port(port)) {
        return 0;
      }
      auto it = peer->udp_relays.find(port);
      if (it == peer->udp_relays.end()) {
        int rfd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (rfd < 0) {
          return 0;
        }
        it = peer->udp_relays.emplace(port, udp_relay_t {rfd, port}).first;
      }
      struct sockaddr_in dst {};
      dst.sin_family = AF_INET;
      dst.sin_port = htons(port);
      dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      ::sendto(it->second.fd, data + 2, datalen - 2, 0, reinterpret_cast<struct sockaddr *>(&dst), sizeof(dst));
      return 0;
    }

    int flush_quic_packets(h3_peer_conn_t *peer) {
      std::array<uint8_t, 1452> pkt {};
      ngtcp2_path_storage ps;
      ngtcp2_path_storage_zero(&ps);
      ngtcp2_pkt_info pi {};
      const ngtcp2_tstamp ts = now_ns();

      // Send pending QUIC datagrams first
      while (!peer->outbound_dgrams.empty()) {
        const auto &dg = peer->outbound_dgrams.front();
        int accepted = 0;
        const ngtcp2_ssize n = ngtcp2_conn_write_datagram(
          peer->qconn,
          &ps.path,
          &pi,
          pkt.data(),
          pkt.size(),
          &accepted,
          0,
          0,
          dg.data(),
          dg.size(),
          ts
        );
        if (n < 0) {
          if (n == NGTCP2_ERR_WRITE_MORE) {
            peer->outbound_dgrams.pop_front();
            continue;
          }
          break;
        }
        if (n > 0) {
          ::sendto(peer->udp_fd, pkt.data(), static_cast<size_t>(n), 0, reinterpret_cast<const struct sockaddr *>(&peer->remote_addr), peer->remote_len);
        }
        if (accepted) {
          peer->outbound_dgrams.pop_front();
        } else {
          break;
        }
      }

      // Send pending HTTP/3 stream frames + ACKs
      for (int iter = 0; iter < 64; ++iter) {
        int64_t stream_id = -1;
        int fin = 0;
        std::array<nghttp3_vec, 8> vec {};
        nghttp3_ssize sveccnt = 0;
        if (peer->h3conn && peer->h3_bound) {
          sveccnt = nghttp3_conn_writev_stream(peer->h3conn, &stream_id, &fin, vec.data(), vec.size());
          if (sveccnt < 0) {
            return -1;
          }
        }
        ngtcp2_ssize datalen = 0;
        const uint32_t wflags = (sveccnt > 0 && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
        const ngtcp2_ssize n = ngtcp2_conn_writev_stream(
          peer->qconn,
          &ps.path,
          &pi,
          pkt.data(),
          pkt.size(),
          &datalen,
          wflags,
          stream_id,
          reinterpret_cast<const ngtcp2_vec *>(vec.data()),
          static_cast<size_t>(sveccnt),
          ts
        );
        if (n < 0) {
          if (n == NGTCP2_ERR_WRITE_MORE) {
            if (peer->h3conn && stream_id >= 0 && datalen >= 0) {
              nghttp3_conn_add_write_offset(peer->h3conn, stream_id, static_cast<size_t>(datalen));
            }
            continue;
          }
          return -1;
        }
        if (peer->h3conn && stream_id >= 0 && datalen >= 0) {
          nghttp3_conn_add_write_offset(peer->h3conn, stream_id, static_cast<size_t>(datalen));
        }
        if (n == 0) {
          break;
        }
        ::sendto(peer->udp_fd, pkt.data(), static_cast<size_t>(n), 0, reinterpret_cast<const struct sockaddr *>(&peer->remote_addr), peer->remote_len);
      }
      return 0;
    }

    int select_h3_alpn_cb(SSL *, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *) {
      static constexpr unsigned char h3_proto[] = {2, 'h', '3'};
      unsigned char *sel = nullptr;
      unsigned char sellen = 0;
      if (SSL_select_next_proto(&sel, &sellen, h3_proto, sizeof(h3_proto), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        *out = sel;
        *outlen = sellen;
        return SSL_TLSEXT_ERR_OK;
      }
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    void pump_peer_local_io(h3_peer_conn_t *peer) {
      std::array<uint8_t, 16384> buf {};
      for (auto &[sid, st] : peer->streams) {
        if (!st || st->tcp_fd < 0 || st->tcp_eof) {
          continue;
        }
        const ssize_t n = ::recv(st->tcp_fd, buf.data(), buf.size(), 0);
        if (n > 0) {
          st->to_quic.emplace_back(buf.begin(), buf.begin() + n);
          if (peer->h3conn) {
            nghttp3_conn_resume_stream(peer->h3conn, sid);
          }
        } else if (n == 0) {
          st->tcp_eof = true;
          if (peer->h3conn) {
            nghttp3_conn_resume_stream(peer->h3conn, sid);
          }
        }
      }
      for (auto &[port, relay] : peer->udp_relays) {
        if (relay.fd < 0) {
          continue;
        }
        const ssize_t n = ::recv(relay.fd, buf.data() + 2, buf.size() - 2, 0);
        if (n > 0) {
          buf[0] = static_cast<uint8_t>((port >> 8) & 0xFF);
          buf[1] = static_cast<uint8_t>(port & 0xFF);
          peer->outbound_dgrams.emplace_back(buf.begin(), buf.begin() + 2 + n);
        }
      }
    }
  }  // namespace

  void start() {
    if (ngtcp2_crypto_ossl_init() != 0) {
      BOOST_LOG(error) << "HTTP/3 transport: ngtcp2_crypto_ossl_init failed";
      return;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
      BOOST_LOG(error) << "HTTP/3 transport: SSL_CTX_new failed";
      return;
    }
    auto free_ctx = util::fail_guard([ssl_ctx]() { SSL_CTX_free(ssl_ctx); });

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, config::nvhttp.cert.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, config::nvhttp.pkey.c_str(), SSL_FILETYPE_PEM) != 1) {
      BOOST_LOG(error) << "HTTP/3 transport: failed to load server cert/key";
      return;
    }
    SSL_CTX_set_alpn_select_cb(ssl_ctx, select_h3_alpn_cb, nullptr);

    const uint16_t listen_port = config::sunshine.h3_server_port;
    const int udp_fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (udp_fd < 0) {
      BOOST_LOG(error) << "HTTP/3 transport: socket failed: " << std::strerror(errno);
      return;
    }
    auto close_udp = util::fail_guard([udp_fd]() { ::close(udp_fd); });

    int v6only = 0;
    ::setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    int reuse = 1;
    ::setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in6 bind_addr {};
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_port = htons(listen_port);
    bind_addr.sin6_addr = in6addr_any;
    if (::bind(udp_fd, reinterpret_cast<struct sockaddr *>(&bind_addr), sizeof(bind_addr)) != 0) {
      BOOST_LOG(error) << "HTTP/3 transport: bind UDP port " << listen_port << " failed: " << std::strerror(errno);
      return;
    }

    BOOST_LOG(info) << "HTTP/3 (QUIC) transport listening on UDP port [" << listen_port << ']';

    auto shutdown_event = mail::man->event<bool>(mail::shutdown);
    std::unordered_map<std::string, std::unique_ptr<h3_peer_conn_t>> peers;
    std::array<uint8_t, 2048> pkt {};

    while (!shutdown_event->peek()) {
      struct pollfd pfd {udp_fd, POLLIN, 0};
      ::poll(&pfd, 1, 5);

      if (pfd.revents & POLLIN) {
        while (true) {
          struct sockaddr_storage src_addr {};
          socklen_t src_len = sizeof(src_addr);
          const ssize_t n = ::recvfrom(udp_fd, pkt.data(), pkt.size(), 0, reinterpret_cast<struct sockaddr *>(&src_addr), &src_len);
          if (n <= 0) {
            break;
          }

          ngtcp2_version_cid vc {};
          if (ngtcp2_pkt_decode_version_cid(&vc, pkt.data(), static_cast<size_t>(n), NGTCP2_MAX_CIDLEN) != 0) {
            continue;
          }
          const std::string dcid_key(reinterpret_cast<const char *>(vc.dcid), vc.dcidlen);
          auto it = peers.find(dcid_key);
          if (it == peers.end()) {
            ngtcp2_pkt_hd hd {};
            if (ngtcp2_accept(&hd, pkt.data(), static_cast<size_t>(n)) != 0) {
              continue;
            }
            auto peer = std::make_unique<h3_peer_conn_t>();
            peer->is_server = true;
            peer->udp_fd = udp_fd;
            peer->remote_addr = src_addr;
            peer->remote_len = src_len;
            peer->local_len = sizeof(peer->local_addr);
            ::getsockname(udp_fd, reinterpret_cast<struct sockaddr *>(&peer->local_addr), &peer->local_len);

            peer->ssl = SSL_new(ssl_ctx);
            if (!peer->ssl || ngtcp2_crypto_ossl_ctx_new(&peer->ossl_ctx, peer->ssl) != 0) {
              continue;
            }
            ngtcp2_crypto_ossl_configure_server_session(peer->ssl);
            peer->conn_ref.get_conn = get_conn_cb;
            peer->conn_ref.user_data = peer.get();
            SSL_set_app_data(peer->ssl, &peer->conn_ref);
            SSL_set_accept_state(peer->ssl);

            ngtcp2_cid scid {};
            scid.datalen = 16;
            RAND_bytes(scid.data, static_cast<int>(scid.datalen));

            ngtcp2_callbacks cbs {};
            cbs.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
            cbs.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
            cbs.encrypt = ngtcp2_crypto_encrypt_cb;
            cbs.decrypt = ngtcp2_crypto_decrypt_cb;
            cbs.hp_mask = ngtcp2_crypto_hp_mask_cb;
            cbs.recv_stream_data = quic_recv_stream_data_cb;
            cbs.acked_stream_data_offset = quic_acked_stream_data_cb;
            cbs.stream_close = quic_stream_close_cb;
            cbs.handshake_completed = quic_handshake_completed_cb;
            cbs.rand = rand_cb;
            cbs.get_new_connection_id = get_new_cid_cb;
            cbs.update_key = ngtcp2_crypto_update_key_cb;
            cbs.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
            cbs.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
            cbs.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
            cbs.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
            cbs.recv_datagram = quic_recv_datagram_cb;

            ngtcp2_settings settings {};
            ngtcp2_settings_default(&settings);
            settings.initial_ts = now_ns();
            settings.max_tx_udp_payload_size = 1452;

            ngtcp2_transport_params params {};
            ngtcp2_transport_params_default(&params);
            params.initial_max_streams_bidi = 256;
            params.initial_max_streams_uni = 16;
            params.initial_max_data = 16 * 1024 * 1024;
            params.initial_max_stream_data_bidi_local = 4 * 1024 * 1024;
            params.initial_max_stream_data_bidi_remote = 4 * 1024 * 1024;
            params.initial_max_stream_data_uni = 256 * 1024;
            params.max_datagram_frame_size = 1500;
            params.original_dcid = hd.dcid;
            params.original_dcid_present = 1;

            ngtcp2_path path {
              {reinterpret_cast<struct sockaddr *>(&peer->local_addr), peer->local_len},
              {reinterpret_cast<struct sockaddr *>(&peer->remote_addr), peer->remote_len},
              nullptr
            };

            if (ngtcp2_conn_server_new(&peer->qconn, &hd.scid, &scid, &path, hd.version, &cbs, &settings, &params, nullptr, peer.get()) != 0) {
              continue;
            }
            ngtcp2_conn_set_tls_native_handle(peer->qconn, peer->ossl_ctx);

            nghttp3_callbacks h3cbs {};
            h3cbs.acked_stream_data = h3_acked_stream_data_cb;
            h3cbs.stream_close = h3_stream_close_cb;
            h3cbs.recv_data = h3_recv_data_cb;
            h3cbs.recv_header = h3_recv_header_cb;
            h3cbs.end_headers = h3_end_headers_cb;
            h3cbs.end_stream = h3_end_stream_cb;
            nghttp3_settings h3settings {};
            nghttp3_settings_default(&h3settings);
            if (nghttp3_conn_server_new(&peer->h3conn, &h3cbs, &h3settings, nullptr, peer.get()) != 0) {
              continue;
            }

            const std::string scid_key(reinterpret_cast<const char *>(scid.data), scid.datalen);
            it = peers.emplace(scid_key, std::move(peer)).first;
          }

          auto *peer = it->second.get();
          ngtcp2_path path {
            {reinterpret_cast<struct sockaddr *>(&peer->local_addr), peer->local_len},
            {reinterpret_cast<struct sockaddr *>(&src_addr), src_len},
            nullptr
          };
          ngtcp2_pkt_info pi {};
          ngtcp2_conn_read_pkt(peer->qconn, &path, &pi, pkt.data(), static_cast<size_t>(n), now_ns());
        }
      }

      const ngtcp2_tstamp ts = now_ns();
      for (auto it = peers.begin(); it != peers.end();) {
        auto *peer = it->second.get();
        if (ngtcp2_conn_handle_expiry(peer->qconn, ts) != 0) {
          it = peers.erase(it);
          continue;
        }
        pump_peer_local_io(peer);
        if (flush_quic_packets(peer) != 0) {
          it = peers.erase(it);
          continue;
        }
        ++it;
      }
    }
  }

  int run_h3_proxy(
    const std::string &remote,
    bool insecure,
    const std::string &bearer_token,
    const std::string &bind_addr
  ) {
    std::string host = remote;
    uint16_t port = config::sunshine.h3_server_port;
    if (auto colon = remote.rfind(':'); colon != std::string::npos) {
      host = remote.substr(0, colon);
      port = static_cast<uint16_t>(std::atoi(remote.substr(colon + 1).c_str()));
    }
    if (host.empty()) {
      std::cerr << "Usage: hermes --h3-proxy <host[:port]> [--insecure] [--token <token>] [--bind 127.0.0.1]\n";
      return 1;
    }

    if (ngtcp2_crypto_ossl_init() != 0) {
      return 1;
    }

    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = nullptr;
    const std::string port_str = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
      std::cerr << "Failed to resolve " << host << ':' << port << '\n';
      return 1;
    }
    auto free_res = util::fail_guard([res]() { ::freeaddrinfo(res); });

    const int udp_fd = ::socket(res->ai_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (udp_fd < 0) {
      return 1;
    }
    auto close_udp = util::fail_guard([udp_fd]() { ::close(udp_fd); });

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
      return 1;
    }
    auto free_ctx = util::fail_guard([ssl_ctx]() { SSL_CTX_free(ssl_ctx); });
    if (insecure) {
      SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
    } else {
      SSL_CTX_set_default_verify_paths(ssl_ctx);
    }
    static constexpr unsigned char alpn[] = {2, 'h', '3'};
    SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn));

    auto peer = std::make_unique<h3_peer_conn_t>();
    peer->is_server = false;
    peer->udp_fd = udp_fd;
    std::memcpy(&peer->remote_addr, res->ai_addr, res->ai_addrlen);
    peer->remote_len = res->ai_addrlen;
    peer->local_len = res->ai_addrlen;
    if (res->ai_family == AF_INET) {
      auto *sin = reinterpret_cast<struct sockaddr_in *>(&peer->local_addr);
      sin->sin_family = AF_INET;
      sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
      auto *sin6 = reinterpret_cast<struct sockaddr_in6 *>(&peer->local_addr);
      sin6->sin6_family = AF_INET6;
      sin6->sin6_addr = in6addr_loopback;
    }

    peer->ssl = SSL_new(ssl_ctx);
    if (!peer->ssl || ngtcp2_crypto_ossl_ctx_new(&peer->ossl_ctx, peer->ssl) != 0) {
      return 1;
    }
    ngtcp2_crypto_ossl_configure_client_session(peer->ssl);
    peer->conn_ref.get_conn = get_conn_cb;
    peer->conn_ref.user_data = peer.get();
    SSL_set_app_data(peer->ssl, &peer->conn_ref);
    SSL_set_connect_state(peer->ssl);
    SSL_set_tlsext_host_name(peer->ssl, host.c_str());

    ngtcp2_cid dcid {}, scid {};
    dcid.datalen = 16;
    scid.datalen = 16;
    RAND_bytes(dcid.data, 16);
    RAND_bytes(scid.data, 16);

    ngtcp2_callbacks cbs {};
    cbs.client_initial = ngtcp2_crypto_client_initial_cb;
    cbs.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    cbs.encrypt = ngtcp2_crypto_encrypt_cb;
    cbs.decrypt = ngtcp2_crypto_decrypt_cb;
    cbs.hp_mask = ngtcp2_crypto_hp_mask_cb;
    cbs.recv_retry = ngtcp2_crypto_recv_retry_cb;
    cbs.recv_stream_data = quic_recv_stream_data_cb;
    cbs.acked_stream_data_offset = quic_acked_stream_data_cb;
    cbs.stream_close = quic_stream_close_cb;
    cbs.handshake_completed = quic_handshake_completed_cb;
    cbs.rand = rand_cb;
    cbs.get_new_connection_id = get_new_cid_cb;
    cbs.update_key = ngtcp2_crypto_update_key_cb;
    cbs.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cbs.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cbs.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    cbs.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    cbs.recv_datagram = [](ngtcp2_conn *, uint32_t, const uint8_t *data, size_t datalen, void *ud) -> int {
      auto *p = static_cast<h3_peer_conn_t *>(ud);
      if (datalen < 3) {
        return 0;
      }
      const uint16_t src_port = static_cast<uint16_t>((data[0] << 8) | data[1]);
      auto it = p->udp_relays.find(src_port);
      if (it != p->udp_relays.end() && it->second.fd >= 0) {
        // Relay back to local client's last seen UDP peer stored in local_addr? Wait: local UDP uses connected or last peer.
        ::send(it->second.fd, data + 2, datalen - 2, 0);
      }
      return 0;
    };

    ngtcp2_settings settings {};
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.max_tx_udp_payload_size = 1452;

    ngtcp2_transport_params params {};
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 256;
    params.initial_max_streams_uni = 16;
    params.initial_max_data = 16 * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 4 * 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 4 * 1024 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.max_datagram_frame_size = 1500;

    ngtcp2_path path {
      {reinterpret_cast<struct sockaddr *>(&peer->local_addr), peer->local_len},
      {reinterpret_cast<struct sockaddr *>(&peer->remote_addr), peer->remote_len},
      nullptr
    };

    if (ngtcp2_conn_client_new(&peer->qconn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cbs, &settings, &params, nullptr, peer.get()) != 0) {
      return 1;
    }
    ngtcp2_conn_set_tls_native_handle(peer->qconn, peer->ossl_ctx);

    nghttp3_callbacks h3cbs {};
    h3cbs.acked_stream_data = h3_acked_stream_data_cb;
    h3cbs.stream_close = h3_stream_close_cb;
    h3cbs.recv_data = h3_recv_data_cb;
    h3cbs.recv_header = h3_recv_header_cb;
    h3cbs.end_headers = h3_end_headers_cb;
    h3cbs.end_stream = h3_end_stream_cb;
    nghttp3_settings h3settings {};
    nghttp3_settings_default(&h3settings);
    if (nghttp3_conn_client_new(&peer->h3conn, &h3cbs, &h3settings, nullptr, peer.get()) != 0) {
      return 1;
    }

    // Bind local loopback TCP & UDP listeners for Hermes ports
    const std::array<uint16_t, 4> tcp_ports {
      net::map_port(nvhttp::PORT_HTTP),
      net::map_port(nvhttp::PORT_HTTPS),
      net::map_port(confighttp::PORT_HTTPS),
      net::map_port(rtsp_stream::RTSP_SETUP_PORT)
    };
    const std::array<uint16_t, 4> udp_ports {
      net::map_port(stream::VIDEO_STREAM_PORT),
      net::map_port(stream::CONTROL_PORT),
      net::map_port(stream::AUDIO_STREAM_PORT),
      net::map_port(stream::MIC_STREAM_PORT)
    };

    struct tcp_listener_t {
      int fd {-1};
      uint16_t port {0};
    };
    std::vector<tcp_listener_t> tcp_listeners;
    for (uint16_t p : tcp_ports) {
      int lfd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (lfd < 0) {
        continue;
      }
      int reuse = 1;
      ::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
      struct sockaddr_in laddr {};
      laddr.sin_family = AF_INET;
      laddr.sin_port = htons(p);
      ::inet_pton(AF_INET, bind_addr.c_str(), &laddr.sin_addr);
      if (::bind(lfd, reinterpret_cast<struct sockaddr *>(&laddr), sizeof(laddr)) == 0 && ::listen(lfd, 32) == 0) {
        tcp_listeners.push_back({lfd, p});
      } else {
        ::close(lfd);
      }
    }
    auto close_listeners = util::fail_guard([&]() {
      for (auto &l : tcp_listeners) {
        ::close(l.fd);
      }
    });

    for (uint16_t p : udp_ports) {
      int ufd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (ufd < 0) {
        continue;
      }
      struct sockaddr_in laddr {};
      laddr.sin_family = AF_INET;
      laddr.sin_port = htons(p);
      ::inet_pton(AF_INET, bind_addr.c_str(), &laddr.sin_addr);
      if (::bind(ufd, reinterpret_cast<struct sockaddr *>(&laddr), sizeof(laddr)) == 0) {
        peer->udp_relays.emplace(p, udp_relay_t {ufd, p});
      } else {
        ::close(ufd);
      }
    }

    std::cout << "Hermes HTTP/3 proxy -> " << host << ':' << port << " (local bind " << bind_addr << ")\n";

    std::array<uint8_t, 2048> pkt {};
    while (true) {
      if (flush_quic_packets(peer.get()) != 0) {
        return 1;
      }

      struct pollfd pfd {udp_fd, POLLIN, 0};
      ::poll(&pfd, 1, 5);
      if (pfd.revents & POLLIN) {
        while (true) {
          const ssize_t n = ::recv(udp_fd, pkt.data(), pkt.size(), 0);
          if (n <= 0) {
            break;
          }
          ngtcp2_pkt_info pi {};
          if (ngtcp2_conn_read_pkt(peer->qconn, &path, &pi, pkt.data(), static_cast<size_t>(n), now_ns()) != 0) {
            return 1;
          }
        }
      }

      if (peer->h3_bound) {
        // Accept new local TCP connections and open HTTP/3 tunnel streams
        for (const auto &l : tcp_listeners) {
          const int cfd = ::accept4(l.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (cfd < 0) {
            continue;
          }
          int64_t sid = -1;
          if (ngtcp2_conn_open_bidi_stream(peer->qconn, &sid, nullptr) != 0) {
            ::close(cfd);
            continue;
          }
          auto st = std::make_unique<tunnel_stream_t>();
          st->stream_id = sid;
          st->tcp_fd = cfd;
          st->target_port = l.port;
          st->path = "/_hermes/tcp/" + std::to_string(l.port);

          std::vector<nghttp3_nv> nva = {
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":method")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("POST")), 7, 4, NGHTTP3_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":scheme")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("https")), 7, 5, NGHTTP3_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":authority")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(host.c_str())), 10, host.size(), NGHTTP3_NV_FLAG_NONE},
            {const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(":path")),
             const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(st->path.c_str())), 5, st->path.size(), NGHTTP3_NV_FLAG_NONE},
          };
          std::string auth_val;
          if (!bearer_token.empty()) {
            auth_val = "Bearer " + bearer_token;
            nva.push_back({
              const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>("authorization")),
              const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(auth_val.c_str())),
              13,
              auth_val.size(),
              NGHTTP3_NV_FLAG_NONE
            });
          }
          peer->streams.emplace(sid, std::move(st));
          nghttp3_data_reader dr {read_stream_data_cb};
          nghttp3_conn_submit_request(peer->h3conn, sid, nva.data(), nva.size(), &dr, nullptr);
        }

        // Read local UDP sockets -> queue QUIC DATAGRAMs
        std::array<uint8_t, 1500> ubuf {};
        for (auto &[p, relay] : peer->udp_relays) {
          struct sockaddr_storage client_addr {};
          socklen_t client_len = sizeof(client_addr);
          const ssize_t n = ::recvfrom(relay.fd, ubuf.data() + 2, ubuf.size() - 2, 0, reinterpret_cast<struct sockaddr *>(&client_addr), &client_len);
          if (n > 0) {
            ::connect(relay.fd, reinterpret_cast<struct sockaddr *>(&client_addr), client_len);
            ubuf[0] = static_cast<uint8_t>((p >> 8) & 0xFF);
            ubuf[1] = static_cast<uint8_t>(p & 0xFF);
            peer->outbound_dgrams.emplace_back(ubuf.begin(), ubuf.begin() + 2 + n);
          }
        }
        pump_peer_local_io(peer.get());
      }

      if (ngtcp2_conn_handle_expiry(peer->qconn, now_ns()) != 0) {
        return 1;
      }
    }
  }
#else
  void start() {}

  int run_h3_proxy(const std::string &, bool, const std::string &, const std::string &) {
    std::cerr << "Hermes was built without HTTP/3 (libngtcp2/libnghttp3) support.\n";
    return 1;
  }
#endif

}  // namespace transport_h3
