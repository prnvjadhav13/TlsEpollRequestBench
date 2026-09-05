// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.

#include "secure_transport.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

namespace secure_transport {
namespace {

constexpr const char* kTls12CipherList =
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256";

constexpr const char* kTls13CipherSuites =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256";

[[nodiscard]] std::string drain_error_queue(std::string_view operation) {
    std::string message(operation);
    bool found = false;
    for (unsigned long code = ERR_get_error(); code != 0; code = ERR_get_error()) {
        std::array<char, 256> text{};
        ERR_error_string_n(code, text.data(), text.size());
        message += found ? "; " : ": ";
        message += text.data();
        found = true;
    }
    if (!found) {
        message += ": TLS peer closed or socket I/O failed";
    }
    return message;
}

void require(bool condition, std::string_view operation) {
    if (!condition) {
        throw std::runtime_error(drain_error_queue(operation));
    }
}

void configure_common(SSL_CTX* context, TlsVersionPolicy policy) {
    const int minimum = policy == TlsVersionPolicy::Tls13Only
        ? TLS1_3_VERSION : TLS1_2_VERSION;
    const int maximum = policy == TlsVersionPolicy::Tls12Only
        ? TLS1_2_VERSION : TLS1_3_VERSION;
    require(SSL_CTX_set_min_proto_version(context, minimum) == 1,
            "set minimum TLS version");
    require(SSL_CTX_set_max_proto_version(context, maximum) == 1,
            "set maximum TLS version");
    SSL_CTX_set_security_level(context, 2);
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_options(context, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_clear_options(context,
                          SSL_OP_ALLOW_NO_DHE_KEX | SSL_OP_PREFER_NO_DHE_KEX);
    SSL_CTX_set_options(context, SSL_OP_NO_TICKET);
    require(SSL_CTX_set_num_tickets(context, 0) == 1,
            "disable TLS 1.3 session tickets");
    SSL_CTX_set_max_early_data(context, 0); // Explicitly reject replayable TLS 1.3 0-RTT.
    require(SSL_CTX_set_cipher_list(context, kTls12CipherList) == 1,
            "configure TLS 1.2 cipher suites");
    require(SSL_CTX_set_ciphersuites(context, kTls13CipherSuites) == 1,
            "configure TLS 1.3 cipher suites");
    require(SSL_CTX_set1_groups_list(context, "X25519:P-256:P-384") == 1,
            "configure TLS key-exchange groups");
    SSL_CTX_set_verify_depth(context, 4);
    SSL_CTX_set_mode(context, SSL_MODE_RELEASE_BUFFERS);
}

void load_crl(SSL_CTX* context, const std::string& crl_file) {
    if (crl_file.empty()) {
        return;
    }
    X509_STORE* store = SSL_CTX_get_cert_store(context);
    require(store != nullptr, "get certificate store for CRL");
    require(X509_STORE_load_file(store, crl_file.c_str()) == 1, "load certificate CRL");
    require(X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL) == 1,
            "enable certificate revocation checking");
}

struct PrivateKeyPrompt {
    std::string text;
    const PrivateKeyPassphrase* passphrase = nullptr;
    bool allow_interactive = true;
};

int private_key_password_callback(char* buffer,
                                  int buffer_size,
                                  int /*read_or_write*/,
                                  void* user_data) noexcept {
    if (buffer == nullptr || buffer_size <= 0 || user_data == nullptr) {
        return -1;
    }
    const auto* prompt = static_cast<const PrivateKeyPrompt*>(user_data);
    if (prompt->passphrase != nullptr) {
        return prompt->passphrase->copy_to(buffer, buffer_size);
    }
    if (!prompt->allow_interactive) {
        return -1;
    }
    if (EVP_read_pw_string(buffer, buffer_size, prompt->text.c_str(), 0) != 0) {
        return -1;
    }
    return static_cast<int>(std::strlen(buffer));
}

void load_identity(SSL_CTX* context,
                   const std::string& certificate_chain_file,
                   const std::string& private_key_file,
                   std::string_view identity_role,
                   const std::shared_ptr<const PrivateKeyPassphrase>& passphrase,
                   bool allow_interactive_prompt) {
    require(!certificate_chain_file.empty(), "certificate-chain path is empty");
    require(!private_key_file.empty(), "private-key path is empty");
    require(SSL_CTX_use_certificate_chain_file(context,
                                                certificate_chain_file.c_str()) == 1,
            "load certificate chain");
    PrivateKeyPrompt prompt{
        "Enter " + std::string(identity_role) + " private-key passphrase for " +
        private_key_file + ":",
        passphrase.get(),
        allow_interactive_prompt};
    SSL_CTX_set_default_passwd_cb(context, private_key_password_callback);
    SSL_CTX_set_default_passwd_cb_userdata(context, &prompt);
    const int key_load_result = SSL_CTX_use_PrivateKey_file(context,
                                                             private_key_file.c_str(),
                                                             SSL_FILETYPE_PEM);
    // The prompt is stack-owned and is needed only while loading this key.
    SSL_CTX_set_default_passwd_cb(context, nullptr);
    SSL_CTX_set_default_passwd_cb_userdata(context, nullptr);
    if (key_load_result != 1 && passphrase == nullptr && !allow_interactive_prompt) {
        throw std::runtime_error(
            drain_error_queue("load " + std::string(identity_role) +
                " private key noninteractively; encrypted keys require "
                "--tls-key-passphrase-file for reload"));
    }
    require(key_load_result == 1, "load " + std::string(identity_role) + " private key");
    require(SSL_CTX_check_private_key(context) == 1,
            "verify certificate/private-key match");
}

} // namespace

PrivateKeyPassphrase::PrivateKeyPassphrase(std::vector<char> value)
    : value_(std::move(value)) {}

struct PrivateKeyPassphrase::SharedEnabler final : PrivateKeyPassphrase {
    explicit SharedEnabler(std::vector<char> value)
        : PrivateKeyPassphrase(std::move(value)) {}
};

std::shared_ptr<const PrivateKeyPassphrase> PrivateKeyPassphrase::create(
    std::vector<char> value) {
    return std::make_shared<SharedEnabler>(std::move(value));
}

PrivateKeyPassphrase::~PrivateKeyPassphrase() noexcept {
    if (!value_.empty()) {
        OPENSSL_cleanse(value_.data(), value_.size());
    }
}

int PrivateKeyPassphrase::copy_to(char* buffer, int buffer_size) const noexcept {
    if (buffer == nullptr || buffer_size <= 0 ||
        value_.size() >= static_cast<std::size_t>(buffer_size)) {
        return -1;
    }
    std::memcpy(buffer, value_.data(), value_.size());
    buffer[value_.size()] = '\0';
    return static_cast<int>(value_.size());
}

std::shared_ptr<const PrivateKeyPassphrase>
load_private_key_passphrase_file(const std::string& path) {
    constexpr std::size_t kMaximumPassphraseBytes = 4096;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        throw std::runtime_error("open private-key passphrase file failed: " +
                                 std::string(std::strerror(errno)));
    }
    struct FdGuard {
        int fd;
        ~FdGuard() { if (fd >= 0) (void)::close(fd); }
    } guard{fd};

    struct stat status {};
    if (::fstat(fd, &status) < 0) {
        throw std::runtime_error("inspect private-key passphrase file failed: " +
                                 std::string(std::strerror(errno)));
    }
    if (!S_ISREG(status.st_mode) || status.st_uid != ::geteuid() ||
        (status.st_mode & 0077) != 0) {
        throw std::runtime_error(
            "private-key passphrase file must be a regular, owner-only file owned by this user");
    }

    std::vector<char> value;
    struct ValueCleanser {
        std::vector<char>& value;
        bool active = true;
        ~ValueCleanser() {
            if (active && !value.empty()) {
                OPENSSL_cleanse(value.data(), value.size());
            }
        }
    } value_cleanser{value};
    value.reserve(128);
    std::array<char, 256> chunk{};
    struct ChunkCleanser {
        std::array<char, 256>& chunk;
        ~ChunkCleanser() { OPENSSL_cleanse(chunk.data(), chunk.size()); }
    } chunk_cleanser{chunk};
    for (;;) {
        const ssize_t count = ::read(fd, chunk.data(), chunk.size());
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error("read private-key passphrase file failed: " +
                                     std::string(std::strerror(errno)));
        }
        if (count == 0) {
            break;
        }
        const std::size_t bytes = static_cast<std::size_t>(count);
        if (value.size() + bytes > kMaximumPassphraseBytes) {
            throw std::runtime_error("private-key passphrase exceeds 4096 bytes");
        }
        value.insert(value.end(), chunk.data(), chunk.data() + bytes);
    }
    if (!value.empty() && value.back() == '\n') {
        value.pop_back();
        if (!value.empty() && value.back() == '\r') {
            value.pop_back();
        }
    }
    if (value.empty() || std::find(value.begin(), value.end(), '\0') != value.end()) {
        throw std::runtime_error("private-key passphrase file is empty or contains a NUL byte");
    }
    // Keep cleansing the source until ownership has transferred successfully.
    // If allocation throws, value_cleanser still erases the passphrase.
    auto result = PrivateKeyPassphrase::create(std::move(value));
    value_cleanser.active = false;
    return result;
}

Mode parse_mode(std::string_view value) {
    if (value == "tcp") {
        return Mode::Tcp;
    }
    if (value == "tls") {
        return Mode::Tls;
    }
    throw std::invalid_argument("--transport must be tcp or tls");
}

TlsVersionPolicy parse_tls_version_policy(std::string_view value) {
    if (value == "tls13") {
        return TlsVersionPolicy::Tls13Only;
    }
    if (value == "tls12") {
        return TlsVersionPolicy::Tls12Only;
    }
    if (value == "tls12-or-tls13") {
        return TlsVersionPolicy::Tls12And13;
    }
    throw std::invalid_argument(
        "--tls-version must be tls13, tls12, or tls12-or-tls13");
}

std::string_view tls_version_policy_name(TlsVersionPolicy policy) noexcept {
    switch (policy) {
    case TlsVersionPolicy::Tls13Only:
        return "TLS1.3-only";
    case TlsVersionPolicy::Tls12Only:
        return "TLS1.2-only";
    case TlsVersionPolicy::Tls12And13:
        return "TLS1.2+TLS1.3";
    }
    return "unknown";
}

std::string_view mode_name(Mode mode) noexcept {
    return mode == Mode::Tls ? "tls" : "tcp";
}

std::string runtime_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

void TlsContext::ContextDeleter::operator()(SSL_CTX* context) const noexcept {
    SSL_CTX_free(context);
}

struct TlsContext::SharedEnabler final : TlsContext {
    SharedEnabler(ContextPtr context, std::vector<std::string> allowed_peer_sans)
        : TlsContext(std::move(context), std::move(allowed_peer_sans)) {}
};

TlsContext::TlsContext(ContextPtr context,
                       std::vector<std::string> allowed_peer_sans) noexcept
    : context_(std::move(context)),
      allowed_peer_sans_(std::move(allowed_peer_sans)) {}

TlsContext::~TlsContext() noexcept = default;

TlsContext::TlsContext(TlsContext&& other) noexcept = default;

TlsContext& TlsContext::operator=(TlsContext&& other) noexcept = default;

TlsContextStore::TlsContextStore(std::shared_ptr<TlsContext> initial) noexcept
    : current_(std::move(initial)) {}

std::shared_ptr<TlsContext> TlsContextStore::load() const noexcept {
    return current_.load(std::memory_order_acquire);
}

void TlsContextStore::store(std::shared_ptr<TlsContext> replacement) noexcept {
    current_.store(std::move(replacement), std::memory_order_release);
}

std::shared_ptr<TlsContext> TlsContext::make_server(const ServerTlsConfig& config) {
    if (OPENSSL_version_major() < 3) {
        throw std::runtime_error("OpenSSL 3.x or newer is required");
    }
    ERR_clear_error();
    SSL_CTX* raw = SSL_CTX_new(TLS_server_method());
    require(raw != nullptr, "create server TLS context");
    ContextPtr guard(raw);
    configure_common(raw, config.version_policy);
    load_identity(raw, config.certificate_chain_file, config.private_key_file, "SERVER",
                  config.private_key_passphrase,
                  config.allow_interactive_private_key_prompt);
    require(!config.client_ca_file.empty(), "client-CA path is empty");
    require(SSL_CTX_load_verify_locations(raw, config.client_ca_file.c_str(), nullptr) == 1,
            "load trusted client CA");
    STACK_OF(X509_NAME)* names = SSL_load_client_CA_file(config.client_ca_file.c_str());
    require(names != nullptr, "load advertised client CA names");
    SSL_CTX_set_client_CA_list(raw, names); // ownership transferred
    SSL_CTX_set_verify(raw, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    load_crl(raw, config.client_crl_file);
    SSL_CTX_set_session_cache_mode(raw, SSL_SESS_CACHE_OFF);
    require(!config.allowed_client_sans.empty(), "client SAN allowlist is empty");
    auto allowed = config.allowed_client_sans;
    std::sort(allowed.begin(), allowed.end());
    allowed.erase(std::unique(allowed.begin(), allowed.end()), allowed.end());
    return std::make_shared<SharedEnabler>(std::move(guard), std::move(allowed));
}

std::shared_ptr<TlsContext> TlsContext::make_client(const ClientTlsConfig& config) {
    if (OPENSSL_version_major() < 3) {
        throw std::runtime_error("OpenSSL 3.x or newer is required");
    }
    ERR_clear_error();
    SSL_CTX* raw = SSL_CTX_new(TLS_client_method());
    require(raw != nullptr, "create client TLS context");
    ContextPtr guard(raw);
    configure_common(raw, config.version_policy);
    load_identity(raw, config.certificate_chain_file, config.private_key_file, "CLIENT",
                  config.private_key_passphrase,
                  config.allow_interactive_private_key_prompt);
    require(!config.server_ca_file.empty(), "server-CA path is empty");
    require(SSL_CTX_load_verify_locations(raw, config.server_ca_file.c_str(), nullptr) == 1,
            "load trusted server CA");
    SSL_CTX_set_verify(raw, SSL_VERIFY_PEER, nullptr);
    load_crl(raw, config.server_crl_file);
    SSL_CTX_set_session_cache_mode(raw, SSL_SESS_CACHE_OFF);
    return std::make_shared<SharedEnabler>(std::move(guard), std::vector<std::string>{});
}

void TlsSession::SessionDeleter::operator()(SSL* session) const noexcept {
    SSL_free(session);
}

TlsSession::TlsSession(std::shared_ptr<TlsContext> context,
                       int fd,
                       bool server,
                       std::string_view expected_server_name)
    : context_(std::move(context)) {
    if (!context_ || fd < 0) {
        throw std::invalid_argument("TLS session requires a context and valid socket");
    }
    ERR_clear_error();
    SSL* raw_ssl = SSL_new(context_->context_.get());
    require(raw_ssl != nullptr, "create TLS session");
    SessionPtr guard(raw_ssl);
    require(SSL_set_fd(raw_ssl, fd) == 1, "attach TLS session to socket");
    if (server) {
        SSL_set_accept_state(raw_ssl);
    } else {
        if (expected_server_name.empty()) {
            throw std::invalid_argument("TLS client requires an expected server name or IP");
        }
        const std::string identity(expected_server_name);
        X509_VERIFY_PARAM* parameters = SSL_get0_param(raw_ssl);
        const bool is_ip = X509_VERIFY_PARAM_set1_ip_asc(parameters, identity.c_str()) == 1;
        if (!is_ip) {
            ERR_clear_error(); // set1_ip_asc reports ordinary non-IP input as failure.
            require(SSL_set_tlsext_host_name(raw_ssl, identity.c_str()) == 1,
                    "configure TLS SNI");
            require(SSL_set1_host(raw_ssl, identity.c_str()) == 1,
                    "configure TLS hostname verification");
            SSL_set_hostflags(raw_ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        }
        SSL_set_connect_state(raw_ssl);
    }
    ssl_ = std::move(guard);
}

TlsSession::~TlsSession() noexcept = default;

TlsSession::TlsSession(TlsSession&& other) noexcept = default;

TlsSession& TlsSession::operator=(TlsSession&& other) noexcept = default;

void TlsSession::capture_errors(std::string_view operation) noexcept {
    try {
        last_error_ = drain_error_queue(operation);
    } catch (...) {
        last_error_ = "TLS operation failed (diagnostic allocation failed)";
    }
}

IoStatus TlsSession::classify(int result, std::size_t) noexcept {
    const int error = SSL_get_error(ssl_.get(), result);
    switch (error) {
    case SSL_ERROR_WANT_READ:
        return IoStatus::WantRead;
    case SSL_ERROR_WANT_WRITE:
        return IoStatus::WantWrite;
    case SSL_ERROR_ZERO_RETURN:
        return IoStatus::PeerClosed;
    default:
        capture_errors("TLS I/O");
        return IoStatus::Fatal;
    }
}

IoStatus TlsSession::handshake() noexcept {
    ERR_clear_error();
    const int result = SSL_do_handshake(ssl_.get());
    return result == 1 ? IoStatus::Complete : classify(result, 0);
}

IoResult TlsSession::read(std::span<std::byte> destination) noexcept {
    ERR_clear_error();
    std::size_t bytes = 0;
    const int result = SSL_read_ex(ssl_.get(), destination.data(), destination.size(), &bytes);
    return result == 1 ? IoResult{IoStatus::Complete, bytes}
                       : IoResult{classify(result, bytes), 0};
}

IoResult TlsSession::write(std::span<const std::byte> source) noexcept {
    ERR_clear_error();
    std::size_t bytes = 0;
    const int result = SSL_write_ex(ssl_.get(), source.data(), source.size(), &bytes);
    return result == 1 ? IoResult{IoStatus::Complete, bytes}
                       : IoResult{classify(result, bytes), 0};
}

IoStatus TlsSession::shutdown() noexcept {
    ERR_clear_error();
    const int result = SSL_shutdown(ssl_.get());
    if (result == 1) {
        return IoStatus::Complete;
    }
    if (result == 0) {
        return IoStatus::WantRead;
    }
    return classify(result, 0);
}

bool TlsSession::has_buffered_plaintext() const noexcept {
    return SSL_pending(ssl_.get()) > 0;
}

bool TlsSession::peer_verified() const noexcept {
    return SSL_get_verify_result(ssl_.get()) == X509_V_OK &&
           SSL_get0_peer_certificate(ssl_.get()) != nullptr;
}

bool TlsSession::peer_authorized() const {
    if (!peer_verified() || context_->allowed_peer_sans_.empty()) {
        return false;
    }
    for (const std::string& identity : peer_san_identities()) {
        if (std::binary_search(context_->allowed_peer_sans_.begin(),
                               context_->allowed_peer_sans_.end(), identity)) {
            return true;
        }
    }
    return false;
}

std::string TlsSession::negotiated_version() const {
    return SSL_get_version(ssl_.get());
}

std::string TlsSession::negotiated_cipher() const {
    const char* cipher = SSL_get_cipher_name(ssl_.get());
    return cipher == nullptr ? "unknown" : cipher;
}

bool TlsSession::session_reused() const noexcept {
    return SSL_session_reused(ssl_.get()) == 1;
}

std::vector<std::string> TlsSession::peer_san_identities() const {
    std::vector<std::string> identities;
    X509* certificate = SSL_get0_peer_certificate(ssl_.get());
    if (certificate == nullptr) {
        return identities;
    }
    GENERAL_NAMES* raw_names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr));
    if (raw_names == nullptr) {
        return identities;
    }
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)>
        names(raw_names, &GENERAL_NAMES_free);
    const int count = sk_GENERAL_NAME_num(names.get());
    for (int i = 0; i < count; ++i) {
        const GENERAL_NAME* name = sk_GENERAL_NAME_value(names.get(), i);
        const ASN1_STRING* value = nullptr;
        std::string_view prefix;
        if (name->type == GEN_URI) {
            value = name->d.uniformResourceIdentifier;
            prefix = "URI:";
        } else if (name->type == GEN_DNS) {
            value = name->d.dNSName;
            prefix = "DNS:";
        } else {
            continue;
        }
        const unsigned char* bytes = ASN1_STRING_get0_data(value);
        const int length = ASN1_STRING_length(value);
        if (bytes == nullptr || length <= 0 ||
            std::memchr(bytes, 0, static_cast<std::size_t>(length)) != nullptr) {
            continue; // Reject embedded-NUL identities.
        }
        identities.emplace_back(prefix);
        identities.back().append(reinterpret_cast<const char*>(bytes),
                                 static_cast<std::size_t>(length));
    }
    return identities;
}

const std::string& TlsSession::last_error() const noexcept {
    return last_error_;
}

} // namespace secure_transport
