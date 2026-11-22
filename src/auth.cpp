/**
 * @file src/auth.cpp
 * @brief Flexible authentication providers (PAM, SSH public-key, Bearer tokens).
 */
#include "auth.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef __linux__
  #include <pwd.h>
  #include <unistd.h>
  #include <sys/wait.h>
#endif

#ifdef SUNSHINE_BUILD_PAM
  #include <security/pam_appl.h>
#endif

#ifdef SUNSHINE_BUILD_LIBSSH
  #include <libssh/libssh.h>
#endif

#include "config.h"
#include "logging.h"
#include "utility.h"

using namespace std::literals;

namespace auth {

  namespace {
    bool csv_contains(std::string_view csv, std::string_view needle) {
      size_t start = 0;
      while (start <= csv.size()) {
        auto comma = csv.find(',', start);
        if (comma == std::string_view::npos) {
          comma = csv.size();
        }
        auto item = csv.substr(start, comma - start);
        while (!item.empty() && (item.front() == ' ' || item.front() == '\t')) {
          item.remove_prefix(1);
        }
        while (!item.empty() && (item.back() == ' ' || item.back() == '\t')) {
          item.remove_suffix(1);
        }
        if (item == needle) {
          return true;
        }
        if (comma == csv.size()) {
          break;
        }
        start = comma + 1;
      }
      return false;
    }

    std::string b64_encode(const unsigned char *data, size_t len) {
      std::string out(4 * ((len + 2) / 3), '\0');
      const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), data, static_cast<int>(len));
      if (written > 0) {
        out.resize(static_cast<size_t>(written));
      } else {
        out.clear();
      }
      return out;
    }

    std::string sha256_hex(std::string_view input) {
      auto digest = crypto::hash(std::string(input));
      return util::hex(digest).to_string();
    }

    std::int64_t unix_now_sec() {
      return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
      ).count();
    }

    std::string expand_authorized_keys_path() {
      std::string path = config::sunshine.ssh_authorized_keys;
      if (path.empty()) {
        path = "~/.ssh/authorized_keys";
      }
      if (path.rfind("~/", 0) == 0) {
        const char *home = std::getenv("HOME");
#ifdef __linux__
        if (!home || !*home) {
          if (auto *pw = getpwuid(geteuid())) {
            home = pw->pw_dir;
          }
        }
#endif
        if (home && *home) {
          return std::string(home) + path.substr(1);
        }
      }
      return path;
    }

    struct pending_challenge_t {
      std::string nonce_raw;
      std::string unique_id;
      std::chrono::steady_clock::time_point expires_at;
    };

    std::mutex challenges_mutex;
    std::unordered_map<std::string, pending_challenge_t> pending_challenges;

    struct stored_token_t {
      std::string hash_hex;
      token_info_t info;
    };

    std::mutex tokens_mutex;
    std::vector<stored_token_t> stored_tokens;
  }  // namespace

  bool provider_enabled(std::string_view name) {
    return csv_contains(config::sunshine.auth_providers, name);
  }

  bool transport_enabled(std::string_view name) {
    return csv_contains(config::sunshine.transport_modes, name);
  }

  pam_result_t authenticate_pam(const std::string &username, const std::string &password) {
    if (!provider_enabled("pam")) {
      return {false, "PAM authentication provider is disabled"};
    }
    if (username.empty() || password.empty()) {
      return {false, "Username and password are required"};
    }
#ifndef SUNSHINE_BUILD_PAM
    return {false, "Hermes was built without libpam support"};
#else
    if (!config::sunshine.pam_allowed_users.empty()) {
      if (!csv_contains(config::sunshine.pam_allowed_users, username)) {
        return {false, "User is not in pam_allowed_users"};
      }
    } else {
      const char *current_user = nullptr;
      if (auto *pw = getpwuid(geteuid())) {
        current_user = pw->pw_name;
      }
      if (!current_user || username != current_user) {
        return {false, "PAM login restricted to current host user"};
      }
    }

    struct conv_state_t {
      const std::string *password;
    } state {&password};

    auto conv_fn = [](int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) -> int {
      if (num_msg <= 0 || !msg || !resp || !appdata_ptr) {
        return PAM_CONV_ERR;
      }
      auto *st = static_cast<conv_state_t *>(appdata_ptr);
      auto *responses = static_cast<struct pam_response *>(std::calloc(static_cast<size_t>(num_msg), sizeof(struct pam_response)));
      if (!responses) {
        return PAM_BUF_ERR;
      }
      for (int i = 0; i < num_msg; ++i) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF || msg[i]->msg_style == PAM_PROMPT_ECHO_ON) {
          responses[i].resp = ::strdup(st->password->c_str());
          if (!responses[i].resp) {
            for (int j = 0; j < i; ++j) {
              std::free(responses[j].resp);
            }
            std::free(responses);
            return PAM_BUF_ERR;
          }
        }
      }
      *resp = responses;
      return PAM_SUCCESS;
    };

    const struct pam_conv conv {conv_fn, &state};

    auto try_service = [&](const std::string &service) -> std::pair<int, std::string> {
      pam_handle_t *pamh = nullptr;
      int rc = pam_start(service.c_str(), username.c_str(), &conv, &pamh);
      if (rc != PAM_SUCCESS || !pamh) {
        return {rc, pam_strerror(nullptr, rc)};
      }
      rc = pam_authenticate(pamh, PAM_SILENT);
      if (rc == PAM_SUCCESS) {
        rc = pam_acct_mgmt(pamh, PAM_SILENT);
      }
      std::string err = rc == PAM_SUCCESS ? "" : pam_strerror(pamh, rc);
      pam_end(pamh, rc);
      return {rc, std::move(err)};
    };

    std::string service = config::sunshine.pam_service.empty() ? "hermes" : config::sunshine.pam_service;
    if (!std::filesystem::exists("/etc/pam.d/" + service) && service == "hermes") {
      service = "login";
    }

    auto [rc, err] = try_service(service);
    if (rc != PAM_SUCCESS) {
      BOOST_LOG(warning) << "PAM authentication failed for user [" << username << "] via service [" << service << "]: " << err;
      return {false, err.empty() ? "PAM authentication failed" : err};
    }

    BOOST_LOG(info) << "PAM authentication succeeded for user [" << username << "] via service [" << service << "]";
    return {true, {}};
#endif
  }

  ssh_challenge_t create_ssh_challenge(const std::string &unique_id) {
    unsigned char raw_id[16];
    unsigned char raw_nonce[32];
    RAND_bytes(raw_id, sizeof(raw_id));
    RAND_bytes(raw_nonce, sizeof(raw_nonce));

    std::string challenge_id = util::hex_vec(raw_id);
    std::string nonce_raw(reinterpret_cast<const char *>(raw_nonce), sizeof(raw_nonce));
    std::string nonce_b64 = b64_encode(raw_nonce, sizeof(raw_nonce));

    const auto now = std::chrono::steady_clock::now();
    {
      std::lock_guard<std::mutex> lock(challenges_mutex);
      for (auto it = pending_challenges.begin(); it != pending_challenges.end();) {
        if (it->second.expires_at <= now) {
          it = pending_challenges.erase(it);
        } else {
          ++it;
        }
      }
      pending_challenges[challenge_id] = pending_challenge_t {
        std::move(nonce_raw),
        unique_id,
        now + std::chrono::seconds(60)
      };
    }

    return {std::move(challenge_id), std::move(nonce_b64), 60};
  }

  bool is_ssh_pubkey_authorized(const std::string &public_key_line, std::string *comment_out) {
    const auto auth_path = expand_authorized_keys_path();
    std::ifstream file(auth_path);
    if (!file.is_open()) {
      return false;
    }

    auto extract_type_and_b64 = [](const std::string &line, std::string &type, std::string &b64, std::string &comment) -> bool {
      std::istringstream iss(line);
      std::string tok1, tok2;
      if (!(iss >> tok1 >> tok2)) {
        return false;
      }
      if (tok1.rfind("ssh-", 0) == 0 || tok1.rfind("ecdsa-", 0) == 0 || tok1.rfind("sk-", 0) == 0) {
        type = tok1;
        b64 = tok2;
        std::getline(iss >> std::ws, comment);
        return true;
      }
      // Line might start with authorized_keys options before the key type
      std::string tok3;
      if (iss >> tok3) {
        if (tok2.rfind("ssh-", 0) == 0 || tok2.rfind("ecdsa-", 0) == 0 || tok2.rfind("sk-", 0) == 0) {
          type = tok2;
          b64 = tok3;
          std::getline(iss >> std::ws, comment);
          return true;
        }
      }
      return false;
    };

    std::string cand_type, cand_b64, cand_comment;
    if (!extract_type_and_b64(public_key_line, cand_type, cand_b64, cand_comment)) {
      return false;
    }

#ifdef SUNSHINE_BUILD_LIBSSH
    ssh_key cand_key = nullptr;
    if (ssh_pki_import_pubkey_base64(cand_b64.c_str(), ssh_key_type_from_name(cand_type.c_str()), &cand_key) != SSH_OK || !cand_key) {
      return false;
    }
    auto cand_guard = util::fail_guard([&]() { ssh_key_free(cand_key); });
#endif

    std::string line;
    while (std::getline(file, line)) {
      if (line.empty() || line[0] == '#') {
        continue;
      }
      std::string auth_type, auth_b64, auth_comment;
      if (!extract_type_and_b64(line, auth_type, auth_b64, auth_comment)) {
        continue;
      }
#ifdef SUNSHINE_BUILD_LIBSSH
      ssh_key auth_key = nullptr;
      if (ssh_pki_import_pubkey_base64(auth_b64.c_str(), ssh_key_type_from_name(auth_type.c_str()), &auth_key) == SSH_OK && auth_key) {
        const bool match = (ssh_key_cmp(cand_key, auth_key, SSH_KEY_CMP_PUBLIC) == 0);
        ssh_key_free(auth_key);
        if (match) {
          if (comment_out) {
            *comment_out = auth_comment;
          }
          return true;
        }
      }
#else
      if (auth_type == cand_type && auth_b64 == cand_b64) {
        if (comment_out) {
          *comment_out = auth_comment;
        }
        return true;
      }
#endif
    }
    return false;
  }

  ssh_verify_result_t verify_ssh_challenge(
    const std::string &challenge_id,
    const std::string &public_key_line,
    const std::string &signature_pem,
    const std::string &unique_id
  ) {
    if (!provider_enabled("ssh_key")) {
      return {false, "SSH key authentication provider is disabled", {}};
    }

    pending_challenge_t challenge;
    {
      std::lock_guard<std::mutex> lock(challenges_mutex);
      auto it = pending_challenges.find(challenge_id);
      if (it == pending_challenges.end()) {
        return {false, "Invalid or expired challenge_id", {}};
      }
      challenge = std::move(it->second);
      pending_challenges.erase(it);
    }

    if (std::chrono::steady_clock::now() > challenge.expires_at) {
      return {false, "Challenge expired", {}};
    }
    if (!challenge.unique_id.empty() && !unique_id.empty() && challenge.unique_id != unique_id) {
      return {false, "Challenge unique_id mismatch", {}};
    }

    std::string comment;
    if (!is_ssh_pubkey_authorized(public_key_line, &comment)) {
      return {false, "Public key is not present in authorized_keys", {}};
    }

#ifdef __linux__
    // Verify OpenSSH SSHSIG signature using ssh-keygen -Y verify
    std::error_code ec;
    const auto tmp_dir = std::filesystem::temp_directory_path(ec) / ("hermes-ssh-" + challenge_id);
    std::filesystem::create_directories(tmp_dir, ec);
    auto cleanup = util::fail_guard([&]() {
      std::error_code rm_ec;
      std::filesystem::remove_all(tmp_dir, rm_ec);
    });

    const auto allowed_path = tmp_dir / "allowed_signers";
    const auto sig_path = tmp_dir / "sig";
    const std::string principal = unique_id.empty() ? "hermes-client" : unique_id;

    {
      std::ofstream f(allowed_path);
      f << principal << ' ' << public_key_line << '\n';
    }
    {
      std::ofstream f(sig_path);
      f << signature_pem;
    }

    int pipe_fd[2];
    if (::pipe(pipe_fd) != 0) {
      return {false, "Failed to create verification pipe", {}};
    }

    pid_t pid = ::fork();
    if (pid == 0) {
      ::close(pipe_fd[1]);
      ::dup2(pipe_fd[0], STDIN_FILENO);
      ::close(pipe_fd[0]);
      ::execlp(
        "ssh-keygen",
        "ssh-keygen",
        "-Y", "verify",
        "-f", allowed_path.c_str(),
        "-I", principal.c_str(),
        "-n", "hermes-auth",
        "-s", sig_path.c_str(),
        nullptr
      );
      _exit(127);
    }
    ::close(pipe_fd[0]);
    const auto &msg = challenge.nonce_raw;
    ssize_t off = 0;
    while (off < static_cast<ssize_t>(msg.size())) {
      ssize_t w = ::write(pipe_fd[1], msg.data() + off, msg.size() - static_cast<size_t>(off));
      if (w <= 0) {
        break;
      }
      off += w;
    }
    ::close(pipe_fd[1]);

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      return {false, "SSH signature verification failed", {}};
    }

    return {true, {}, std::move(comment)};
#else
    return {false, "SSH signature verification is only implemented on Linux", {}};
#endif
  }

  std::pair<std::string, token_info_t> issue_token(
    const std::string &label,
    const std::string &unique_id,
    crypto::PERM perm,
    int ttl_seconds
  ) {
    unsigned char raw_id[8];
    unsigned char raw_tok[32];
    RAND_bytes(raw_id, sizeof(raw_id));
    RAND_bytes(raw_tok, sizeof(raw_tok));

    const std::string raw_token = "hermes_" + util::hex_vec(raw_tok);
    const std::int64_t now = unix_now_sec();
    const int effective_ttl = ttl_seconds >= 0 ? ttl_seconds : config::sunshine.token_ttl_seconds;
    const std::int64_t expires = effective_ttl > 0 ? (now + effective_ttl) : 0;

    token_info_t info;
    info.id = util::hex_vec(raw_id);
    info.label = label;
    info.unique_id = unique_id;
    info.perm = perm;
    info.created_at = now;
    info.expires_at = expires;

    {
      std::lock_guard<std::mutex> lock(tokens_mutex);
      stored_tokens.push_back(stored_token_t {sha256_hex(raw_token), info});
    }

    return {raw_token, info};
  }

  std::optional<token_info_t> verify_bearer_token(std::string_view auth_header) {
    if (!provider_enabled("token")) {
      return std::nullopt;
    }
    constexpr std::string_view prefix = "Bearer ";
    if (auth_header.size() <= prefix.size() || auth_header.substr(0, prefix.size()) != prefix) {
      return std::nullopt;
    }
    auto token = auth_header.substr(prefix.size());
    while (!token.empty() && token.back() == ' ') {
      token.remove_suffix(1);
    }
    const std::string hash = sha256_hex(token);
    const std::int64_t now = unix_now_sec();

    std::lock_guard<std::mutex> lock(tokens_mutex);
    for (auto it = stored_tokens.begin(); it != stored_tokens.end();) {
      if (it->info.expires_at > 0 && it->info.expires_at <= now) {
        it = stored_tokens.erase(it);
        continue;
      }
      if (it->hash_hex == hash) {
        return it->info;
      }
      ++it;
    }
    return std::nullopt;
  }

  std::vector<token_info_t> list_tokens() {
    const std::int64_t now = unix_now_sec();
    std::vector<token_info_t> out;
    std::lock_guard<std::mutex> lock(tokens_mutex);
    for (auto it = stored_tokens.begin(); it != stored_tokens.end();) {
      if (it->info.expires_at > 0 && it->info.expires_at <= now) {
        it = stored_tokens.erase(it);
        continue;
      }
      out.push_back(it->info);
      ++it;
    }
    return out;
  }

  bool revoke_token(const std::string &id) {
    std::lock_guard<std::mutex> lock(tokens_mutex);
    for (auto it = stored_tokens.begin(); it != stored_tokens.end(); ++it) {
      if (it->info.id == id) {
        stored_tokens.erase(it);
        return true;
      }
    }
    return false;
  }

}  // namespace auth
