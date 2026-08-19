#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <sstream>
#include <fstream>
#include <random>
#include <algorithm>
#include <chrono>
#include <limits>
#include <atomic>
#include <mutex>
#include <filesystem>

#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include "tcp_common_config.h"

namespace {

constexpr auto kClientIoTimeout = std::chrono::seconds(5);
constexpr std::size_t kDefaultMaxConcurrency = 128;
constexpr std::size_t kMaxPrintedErrorsPerRound = 10;

int parse_int_arg(const char* text, const char* arg_name) {
    try {
        std::size_t pos = 0;
        const std::string value(text);
        const int parsed = std::stoi(value, &pos, 10);
        if (pos != value.size()) {
            throw std::invalid_argument("trailing characters");
        }
        return parsed;
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string(arg_name) + " must be a valid integer");
    }
}

class ConnectError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Socket {
public:
    Socket() = default;

    explicit Socket(int fd) : fd_(fd) {}

    ~Socket() {
        reset();
    }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    Socket(Socket&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    int get() const noexcept {
        return fd_;
    }

    bool valid() const noexcept {
        return fd_ >= 0;
    }

    void reset() noexcept {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_ = -1;
};

class TcpClient {
public:
    TcpClient(std::string server_ip, std::uint16_t server_port)
        : server_ip_(std::move(server_ip)), server_port_(server_port) {}

    void connect_to_server() {
        const int fd = ::socket(AF_INET,
                                SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                                IPPROTO_TCP);
        if (fd < 0) {
            throw std::runtime_error(std::string("socket failed: ") + std::strerror(errno));
        }

        socket_ = Socket(fd);

        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port_);
        if (::inet_pton(AF_INET, server_ip_.c_str(), &server_addr.sin_addr) != 1) {
            throw std::invalid_argument("invalid IPv4 address: " + server_ip_);
        }

        if (::connect(socket_.get(),
                      reinterpret_cast<sockaddr*>(&server_addr),
                      sizeof(server_addr)) < 0) {
            const int connect_errno = errno;
            if (connect_errno != EINPROGRESS && connect_errno != EWOULDBLOCK) {
                throw_connect_error(connect_errno);
            }
            wait_for_connection();
        }

        const int current_flags = ::fcntl(socket_.get(), F_GETFL, 0);
        if (current_flags < 0 ||
            ::fcntl(socket_.get(), F_SETFL, current_flags & ~O_NONBLOCK) < 0) {
            throw std::runtime_error(std::string("failed to restore blocking socket mode: ") +
                                     std::strerror(errno));
        }
        set_socket_io_timeout(socket_.get(), kClientIoTimeout);
    }

    void send_request(std::string_view request) {
        std::string framed_request(request);
        if (framed_request.empty() || framed_request.back() != '\n') {
            framed_request.push_back('\n');
        }

        send_all(reinterpret_cast<const std::uint8_t*>(framed_request.data()),
                 framed_request.size());
    }

    void shutdown_write() {
        if (socket_.valid() && ::shutdown(socket_.get(), SHUT_WR) < 0) {
            throw std::runtime_error(std::string("shutdown(SHUT_WR) failed: ") + std::strerror(errno));
        }
    }

    std::vector<std::uint8_t> receive_response() {
        std::vector<std::uint8_t> response;
        std::vector<std::uint8_t> buffer(1024);

        while (true) {
            ssize_t n = ::recv(socket_.get(), buffer.data(), buffer.size(), 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("recv failed: ") + std::strerror(errno));
            }
            if (n == 0) {
                break;
            }

            response.insert(response.end(), buffer.begin(), buffer.begin() + n);
        }

        return response;
    }

private:
    [[nodiscard]] std::string endpoint() const {
        return server_ip_ + ":" + std::to_string(server_port_);
    }

    [[noreturn]] void throw_connect_error(int error_code) {
        socket_.reset();
        std::string reason;
        switch (error_code) {
        case ECONNREFUSED:
            reason = "connection refused; the host responded but no server is listening "
                     "on this port";
            break;
        case ETIMEDOUT:
            reason = "connection timed out; verify the server IP, port, routing, and firewall";
            break;
        case ENETUNREACH:
            reason = "network unreachable; verify the server IP and network route";
            break;
        case EHOSTUNREACH:
            reason = "host unreachable; verify the server IP, routing, and firewall";
            break;
        case EACCES:
            reason = "connection blocked by local permissions or firewall policy";
            break;
        default:
            reason = std::strerror(error_code);
            break;
        }
        throw ConnectError("cannot connect to TCP server " + endpoint() + ": " + reason);
    }

    void wait_for_connection() {
        const auto deadline = std::chrono::steady_clock::now() + kClientIoTimeout;
        pollfd descriptor{socket_.get(), POLLOUT, 0};

        for (;;) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                throw_connect_error(ETIMEDOUT);
            }
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            const int timeout_ms = static_cast<int>(
                std::max<std::int64_t>(1, remaining.count()));
            descriptor.revents = 0;
            const int ready = ::poll(&descriptor, 1, timeout_ms);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw_connect_error(errno);
            }
            if (ready == 0) {
                throw_connect_error(ETIMEDOUT);
            }
            if ((descriptor.revents & POLLNVAL) != 0) {
                throw_connect_error(EBADF);
            }

            int socket_error = 0;
            socklen_t error_length = sizeof(socket_error);
            if (::getsockopt(socket_.get(), SOL_SOCKET, SO_ERROR,
                             &socket_error, &error_length) < 0) {
                throw_connect_error(errno);
            }
            if (socket_error != 0) {
                throw_connect_error(socket_error);
            }
            return;
        }
    }

    void set_socket_io_timeout(int fd, std::chrono::seconds timeout) {
        timeval socket_timeout{};
        socket_timeout.tv_sec = static_cast<decltype(socket_timeout.tv_sec)>(timeout.count());
        socket_timeout.tv_usec = 0;

        if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout, sizeof(socket_timeout)) < 0) {
            throw std::runtime_error(std::string("setsockopt(SO_RCVTIMEO) failed: ") + std::strerror(errno));
        }

        if (::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &socket_timeout, sizeof(socket_timeout)) < 0) {
            throw std::runtime_error(std::string("setsockopt(SO_SNDTIMEO) failed: ") + std::strerror(errno));
        }
    }

    void send_all(const std::uint8_t* data, std::size_t size) {
        std::size_t sent = 0;
        while (sent < size) {
            ssize_t n = ::send(socket_.get(), data + sent, size - sent, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("send failed: ") + std::strerror(errno));
            }
            if (n == 0) {
                throw std::runtime_error("send returned 0");
            }
            sent += static_cast<std::size_t>(n);
        }
    }

    std::string server_ip_;
    std::uint16_t server_port_;
    Socket socket_;
};

std::string render_hex_dump(const std::vector<std::uint8_t>& data) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) {
            out << std::setw(4) << i << ": ";
        }

        out << std::setw(2) << static_cast<unsigned>(data[i]) << ' ';

        if (i % 16 == 15 || i + 1 == data.size()) {
            out << '\n';
        }
    }
    return out.str();
}

constexpr std::size_t kDefaultRequestCount = 8;

std::string payload_range_string() {
    return "[" + std::to_string(tcp_common::kMinPayloadSize) + ", " +
           std::to_string(tcp_common::kMaxPayloadSize) + "]";
}

std::vector<std::string> load_request_keys(const std::string& keys_file) {
    std::error_code file_size_error;
    const std::uintmax_t file_size = std::filesystem::file_size(keys_file, file_size_error);
    if (file_size_error) {
        throw std::runtime_error("failed to inspect request-keys file: " + keys_file +
                                 ": " + file_size_error.message());
    }
    if (file_size == 0 || file_size > tcp_common::kMaxRequestKeysFileSizeBytes) {
        throw std::runtime_error("request-keys file size is outside the supported range: " +
                                 keys_file);
    }

    std::ifstream in(keys_file, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open request-keys file: " + keys_file);
    }

    std::vector<std::string> requests;
    std::string req;
    while (std::getline(in, req)) {
        if (!req.empty() && req.back() == '\r') {
            req.pop_back();
        }
        if (req.empty() || req.size() > tcp_common::kMaxRequestKeySize) {
            throw std::runtime_error("request-key length out of range [1, " +
                                     std::to_string(tcp_common::kMaxRequestKeySize) + "]");
        }
        if (req.find('\0') != std::string::npos) {
            throw std::runtime_error("request key contains an embedded NUL byte");
        }
        if (requests.size() >= tcp_common::kMaxMappingEntries) {
            throw std::runtime_error("request-keys file contains too many keys");
        }
        requests.push_back(std::move(req));
    }

    if (!in.eof()) {
        throw std::runtime_error("failed while reading request-keys file: " + keys_file);
    }

    if (requests.empty()) {
        throw std::runtime_error("request-keys file has zero request keys");
    }

    return requests;
}

std::vector<std::string> pick_random_requests(const std::vector<std::string>& all_requests,
                                              std::size_t request_count) {
    if (all_requests.empty()) {
        throw std::runtime_error("no requests available for random selection");
    }

    std::vector<std::string> selected;
    selected.reserve(request_count);

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<std::size_t> idx_dist(0, all_requests.size() - 1);

    for (std::size_t i = 0; i < request_count; ++i) {
        selected.push_back(all_requests[idx_dist(rng)]);
    }

    return selected;
}

} // namespace

struct RequestResult {
    std::string request;
    std::string output;
    bool connect_failed = false;
    bool success = false;
    std::size_t response_bytes = 0;
};

int main(int argc, char* argv[]) {
    try {
        if (argc < 3) {
            throw std::invalid_argument(
                "Usage: ./tcp_client <server_ip> <server_port> [--keys-file <path>] [--request-count <N>] [--forever] [--verbose] [--max-concurrency <N>]");
        }

        const std::string server_ip = argv[1];
        const int parsed_port = parse_int_arg(argv[2], "<server_port>");
        if (parsed_port <= 0 || parsed_port > 65535) {
            throw std::invalid_argument("<server_port> must be in range 1..65535");
        }
        const std::uint16_t server_port = static_cast<std::uint16_t>(parsed_port);

        std::string keys_file = tcp_common::kDefaultClientKeysFile;
        std::size_t request_count = kDefaultRequestCount;
        bool run_forever = false;
        bool verbose_output = false;
        std::size_t max_concurrency = kDefaultMaxConcurrency;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--keys-file") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--keys-file requires a file path");
                }
                keys_file = argv[i + 1];
                ++i;
            } else if (arg == "--request-count") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--request-count requires a numeric value");
                }
                const int parsed = parse_int_arg(argv[i + 1], "--request-count");
                if (parsed <= 0) {
                    throw std::invalid_argument("--request-count must be positive");
                }
                request_count = static_cast<std::size_t>(parsed);
                ++i;
            } else if (arg == "--forever") {
                run_forever = true;
            } else if (arg == "--verbose") {
                verbose_output = true;
            } else if (arg == "--max-concurrency") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--max-concurrency requires a numeric value");
                }
                const int parsed = parse_int_arg(argv[i + 1], "--max-concurrency");
                if (parsed <= 0) {
                    throw std::invalid_argument("--max-concurrency must be positive");
                }
                max_concurrency = static_cast<std::size_t>(parsed);
                ++i;
            } else {
                throw std::invalid_argument("Unknown argument: " + std::string(arg));
            }
        }

        const std::vector<std::string> all_requests = load_request_keys(keys_file);
        std::cout << "Loaded " << all_requests.size() << " request key(s) from " << keys_file
                  << ". Sending " << request_count << " request(s) per round"
                  << (run_forever ? " forever" : "")
                  << " with max concurrency " << max_concurrency
                  << (verbose_output ? " (verbose mode)." : " (summary mode).")
                  << std::endl;

        std::size_t round = 0;
        bool any_request_failed = false;
        do {
            ++round;
            const std::vector<std::string> requests = pick_random_requests(all_requests, request_count);
            std::vector<RequestResult> results;
            if (verbose_output) {
                results.resize(requests.size());
            }

            const std::size_t worker_count = std::min<std::size_t>(
                requests.size(),
                std::max<std::size_t>(1, max_concurrency));

            std::atomic<std::size_t> next_index{0};
            std::atomic<std::size_t> success_count{0};
            std::atomic<std::size_t> connect_failed_count{0};
            std::atomic<std::size_t> failed_count{0};
            std::atomic<std::size_t> bytes_received_total{0};
            std::vector<std::string> sample_errors;
            sample_errors.reserve(kMaxPrintedErrorsPerRound);
            std::mutex sample_errors_mtx;

            auto maybe_record_error = [&](std::string msg) {
                std::lock_guard<std::mutex> lk(sample_errors_mtx);
                if (sample_errors.size() < kMaxPrintedErrorsPerRound) {
                    sample_errors.push_back(std::move(msg));
                }
            };

            std::vector<std::thread> workers;
            workers.reserve(worker_count);
            const auto round_started = std::chrono::steady_clock::now();

            try {
                for (std::size_t worker_i = 0; worker_i < worker_count; ++worker_i) {
                    workers.emplace_back([&] {
                        while (true) {
                            const std::size_t i = next_index.fetch_add(1, std::memory_order_relaxed);
                            if (i >= requests.size()) {
                                return;
                            }

                            if (verbose_output) {
                                results[i].request = requests[i];
                            }

                            try {
                                TcpClient client(server_ip, server_port);
                                client.connect_to_server();
                                client.send_request(requests[i]);
                                client.shutdown_write();

                                std::vector<std::uint8_t> response = client.receive_response();
                                if (response.size() < tcp_common::kMinPayloadSize ||
                                    response.size() > tcp_common::kMaxPayloadSize) {
                                    throw std::runtime_error(
                                        "response size " + std::to_string(response.size()) +
                                        " is outside expected range " + payload_range_string());
                                }
                                bytes_received_total.fetch_add(response.size(), std::memory_order_relaxed);
                                success_count.fetch_add(1, std::memory_order_relaxed);

                                if (verbose_output) {
                                    std::ostringstream out;
                                    out << "Request: " << requests[i] << '\n';
                                    out << "Received " << response.size() << " byte(s) from server\n";
                                    out << render_hex_dump(response);
                                    results[i].output = out.str();
                                    results[i].connect_failed = false;
                                    results[i].success = true;
                                    results[i].response_bytes = response.size();
                                }
                            } catch (const ConnectError& ex) {
                                connect_failed_count.fetch_add(1, std::memory_order_relaxed);
                                failed_count.fetch_add(1, std::memory_order_relaxed);
                                const std::string error_line = std::string("Request: ") + requests[i] +
                                                               "\nError: " + ex.what() + '\n';
                                maybe_record_error(error_line);
                                if (verbose_output) {
                                    results[i].output = error_line;
                                    results[i].connect_failed = true;
                                    results[i].success = false;
                                }
                            } catch (const std::exception& ex) {
                                failed_count.fetch_add(1, std::memory_order_relaxed);
                                const std::string error_line = std::string("Request: ") + requests[i] +
                                                               "\nError: " + ex.what() + '\n';
                                maybe_record_error(error_line);
                                if (verbose_output) {
                                    results[i].output = error_line;
                                    results[i].connect_failed = false;
                                    results[i].success = false;
                                }
                            }
                        }
                    });
                }
            } catch (...) {
                for (auto& worker : workers) {
                    if (worker.joinable()) {
                        worker.join();
                    }
                }
                throw;
            }

            for (auto& worker : workers) {
                if (worker.joinable()) {
                    worker.join();
                }
            }

            const auto round_finished = std::chrono::steady_clock::now();
            const double elapsed_seconds =
                std::chrono::duration<double>(round_finished - round_started).count();

            const std::size_t success = success_count.load(std::memory_order_relaxed);
            const std::size_t connect_failed = connect_failed_count.load(std::memory_order_relaxed);
            const std::size_t failed = failed_count.load(std::memory_order_relaxed);
            const std::size_t total_bytes = bytes_received_total.load(std::memory_order_relaxed);
            any_request_failed = any_request_failed || failed != 0;
            const double requests_per_second =
                elapsed_seconds > 0.0
                    ? static_cast<double>(requests.size()) / elapsed_seconds
                    : 0.0;
            const double successful_mib_per_second =
                elapsed_seconds > 0.0
                    ? static_cast<double>(total_bytes) / (1024.0 * 1024.0) / elapsed_seconds
                    : 0.0;

            std::cout << "========== Round " << round << " ==========" << std::endl;
            std::cout << "success=" << success
                      << " failed=" << failed
                      << " connect_failed=" << connect_failed
                      << " bytes_received=" << total_bytes
                      << " elapsed_ms=" << std::fixed << std::setprecision(3)
                      << (elapsed_seconds * 1000.0)
                      << " requests_per_second=" << std::setprecision(2)
                      << requests_per_second
                      << " successful_MiB_per_second=" << successful_mib_per_second
                      << std::endl;
            if (verbose_output) {
                for (const auto& result : results) {
                    std::cout << "----------------------------------------\n";
                    std::cout << result.output;
                }
            } else {
                if (!sample_errors.empty()) {
                    std::cout << "Sample errors (up to " << sample_errors.size() << "):\n";
                    for (const auto& err : sample_errors) {
                        std::cout << "----------------------------------------\n";
                        std::cout << err;
                    }
                }
            }

            if (connect_failed == requests.size()) {
                std::cerr << "Unable to reach TCP server " << server_ip << ':' << server_port
                          << ": every connection attempt failed in round " << round
                          << ". Verify the server IP address, listening port, server process, "
                             "network route, and firewall rules. Exiting client."
                          << std::endl;
                break;
            }
        } while (run_forever);

        return any_request_failed ? 2 : 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
