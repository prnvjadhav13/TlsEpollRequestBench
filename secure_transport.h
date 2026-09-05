// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <cstddef>
#include <cstdint>
#include <atomic>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

namespace secure_transport {

class PrivateKeyPassphrase {
public:
    ~PrivateKeyPassphrase() noexcept;
    PrivateKeyPassphrase(const PrivateKeyPassphrase&) = delete;
    PrivateKeyPassphrase& operator=(const PrivateKeyPassphrase&) = delete;
    [[nodiscard]] int copy_to(char* buffer, int buffer_size) const noexcept;

private:
    explicit PrivateKeyPassphrase(std::vector<char> value);
    friend std::shared_ptr<const PrivateKeyPassphrase>
        load_private_key_passphrase_file(const std::string& path);
    friend class TlsContext;
    std::vector<char> value_;
};

// Loads a non-empty passphrase from an owner-only regular file without following
// symlinks. A final LF or CRLF is removed. Intended for a protected runtime
// credential filesystem rather than a source-controlled persistent file.
[[nodiscard]] std::shared_ptr<const PrivateKeyPassphrase>
load_private_key_passphrase_file(const std::string& path);

enum class Mode : std::uint8_t { Tcp, Tls };

enum class TlsVersionPolicy : std::uint8_t {
    Tls13Only,
    Tls12Only,
    Tls12And13
};

[[nodiscard]] Mode parse_mode(std::string_view value);
[[nodiscard]] std::string_view mode_name(Mode mode) noexcept;
[[nodiscard]] TlsVersionPolicy parse_tls_version_policy(std::string_view value);
[[nodiscard]] std::string_view tls_version_policy_name(TlsVersionPolicy policy) noexcept;
[[nodiscard]] std::string runtime_version();

struct ServerTlsConfig {
    std::string certificate_chain_file;
    std::string private_key_file;
    std::string client_ca_file;
    std::string client_crl_file;
    std::vector<std::string> allowed_client_sans;
    std::shared_ptr<const PrivateKeyPassphrase> private_key_passphrase;
    TlsVersionPolicy version_policy = TlsVersionPolicy::Tls13Only;
};

struct ClientTlsConfig {
    std::string certificate_chain_file;
    std::string private_key_file;
    std::string server_ca_file;
    std::string expected_server_name;
    std::string server_crl_file;
    std::shared_ptr<const PrivateKeyPassphrase> private_key_passphrase;
    TlsVersionPolicy version_policy = TlsVersionPolicy::Tls13Only;
};

class TlsContext {
public:
    ~TlsContext() noexcept;
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    TlsContext(TlsContext&&) noexcept;
    TlsContext& operator=(TlsContext&&) noexcept;

    [[nodiscard]] static std::shared_ptr<TlsContext> make_server(
        const ServerTlsConfig& config);
    [[nodiscard]] static std::shared_ptr<TlsContext> make_client(
        const ClientTlsConfig& config);

private:
    TlsContext(SSL_CTX* context, std::vector<std::string> allowed_peer_sans) noexcept;
    friend class TlsSession;
    SSL_CTX* context_ = nullptr;
    std::vector<std::string> allowed_peer_sans_;
};

class TlsContextStore {
public:
    explicit TlsContextStore(std::shared_ptr<TlsContext> initial) noexcept;
    [[nodiscard]] std::shared_ptr<TlsContext> load() const noexcept;
    void store(std::shared_ptr<TlsContext> replacement) noexcept;

private:
    std::atomic<std::shared_ptr<TlsContext>> current_;
};

enum class IoStatus : std::uint8_t {
    Complete,
    WantRead,
    WantWrite,
    PeerClosed,
    Fatal
};

struct IoResult {
    IoStatus status = IoStatus::Fatal;
    std::size_t bytes = 0;
};

class TlsSession {
public:
    TlsSession(std::shared_ptr<TlsContext> context,
               int fd,
               bool server,
               std::string_view expected_server_name = {});
    ~TlsSession() noexcept;
    TlsSession(const TlsSession&) = delete;
    TlsSession& operator=(const TlsSession&) = delete;
    TlsSession(TlsSession&&) noexcept;
    TlsSession& operator=(TlsSession&&) noexcept;

    [[nodiscard]] IoStatus handshake() noexcept;
    [[nodiscard]] IoResult read(std::span<std::byte> destination) noexcept;
    [[nodiscard]] IoResult write(std::span<const std::byte> source) noexcept;
    [[nodiscard]] IoStatus shutdown() noexcept;
    [[nodiscard]] bool has_buffered_plaintext() const noexcept;
    [[nodiscard]] bool peer_verified() const noexcept;
    [[nodiscard]] bool peer_authorized() const;
    [[nodiscard]] std::string negotiated_version() const;
    [[nodiscard]] std::string negotiated_cipher() const;
    [[nodiscard]] bool session_reused() const noexcept;
    [[nodiscard]] std::vector<std::string> peer_san_identities() const;
    [[nodiscard]] const std::string& last_error() const noexcept;

private:
    [[nodiscard]] IoStatus classify(int result, std::size_t bytes) noexcept;
    void capture_errors(std::string_view operation) noexcept;

    std::shared_ptr<TlsContext> context_;
    SSL* ssl_ = nullptr;
    std::string last_error_;
};

} // namespace secure_transport
