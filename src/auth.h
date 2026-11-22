/**
 * @file src/auth.h
 * @brief Flexible authentication providers (PAM, SSH public-key, Bearer tokens).
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "crypto.h"

namespace auth {

  bool provider_enabled(std::string_view name);
  bool transport_enabled(std::string_view name);

  struct pam_result_t {
    bool ok {false};
    std::string error;
  };

  /**
   * @brief Authenticate a local OS user via Linux PAM.
   */
  pam_result_t authenticate_pam(const std::string &username, const std::string &password);

  struct ssh_challenge_t {
    std::string challenge_id;
    std::string nonce_b64;
    int expires_in_sec {60};
  };

  struct ssh_verify_result_t {
    bool ok {false};
    std::string error;
    std::string key_comment;
  };

  /**
   * @brief Create a short-lived random challenge for SSH key authentication.
   */
  ssh_challenge_t create_ssh_challenge(const std::string &unique_id);

  /**
   * @brief Verify an OpenSSH SSHSIG signature against authorized_keys.
   */
  ssh_verify_result_t verify_ssh_challenge(
    const std::string &challenge_id,
    const std::string &public_key_line,
    const std::string &signature_pem,
    const std::string &unique_id
  );

  /**
   * @brief Check if an already-parsed SSH public key matches authorized_keys.
   */
  bool is_ssh_pubkey_authorized(const std::string &public_key_line, std::string *comment_out = nullptr);

  struct token_info_t {
    std::string id;
    std::string label;
    std::string unique_id;
    crypto::PERM perm {crypto::PERM::_all};
    std::int64_t created_at {0};
    std::int64_t expires_at {0};  // 0 = non-expiring
  };

  /**
   * @brief Issue a new random Bearer API token (returns {raw_token, metadata}).
   */
  std::pair<std::string, token_info_t> issue_token(
    const std::string &label,
    const std::string &unique_id,
    crypto::PERM perm = crypto::PERM::_all,
    int ttl_seconds = -1
  );

  /**
   * @brief Verify an HTTP `Authorization: Bearer <token>` header value.
   */
  std::optional<token_info_t> verify_bearer_token(std::string_view auth_header);

  std::vector<token_info_t> list_tokens();
  bool revoke_token(const std::string &id);

}  // namespace auth
