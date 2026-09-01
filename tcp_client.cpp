// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
// This software is provided solely for performance evaluation and educational purposes.
// See the repository LICENSE file for reuse terms.

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
#include <condition_variable>
#include <csignal>
#include <deque>
#include <memory>
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
constexpr std::size_t kMaxPrintedErrorsPerRound = 10;
constexpr std::size_t kMaxConcurrency = 4096;
constexpr std::size_t kMaxRequestsPerRound = 10'000'000;
constexpr std::size_t kMaxQueueCapacity = 1'000'000;
constexpr std::size_t kRequestsPerJob = 16;
constexpr int kMaxRoundDelayMs = 3'600'000;

volatile std::sig_atomic_t g_stop_requested = 0;
volatile std::sig_atomic_t g_signal_count = 0;

extern "C" void termination_signal_handler(int signal_number) {
    if (g_signal_count == 0) {
        g_signal_count = 1;
        g_stop_requested = signal_number;
        return;
    }

    // A second signal requests immediate termination. _exit is async-signal-safe.
    ::_exit(128 + signal_number);
}

void install_termination_signal_handlers() {
    struct sigaction action {};
    action.sa_handler = termination_signal_handler;
    ::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (::sigaction(SIGINT, &action, nullptr) < 0 ||
        ::sigaction(SIGTERM, &action, nullptr) < 0) {
        throw std::runtime_error(std::string("sigaction failed: ") + std::strerror(errno));
    }
}

// Uses the number of CPUs made available to this process as the conservative
// default concurrency. One blocking-I/O worker per CPU avoids the severe
// oversubscription caused by a fixed default on small machines. Callers can
// still raise --max-concurrency after measuring their network workload.
[[nodiscard]] std::size_t default_max_concurrency() noexcept {
    const unsigned int reported = std::thread::hardware_concurrency();
    const std::size_t available_cpus = reported == 0 ? 1 : reported;
    return std::min(available_cpus, kMaxConcurrency);
}

// Parses a base-10 command-line value; text is the raw value and arg_name is
// used to identify the option in validation errors.
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

// Distinguishes failures to establish a connection from later request I/O
// failures so benchmark summaries can report them separately.
class ConnectError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string payload_range_string();

// Move-only RAII owner for a socket file descriptor; construction accepts an
// already-open descriptor and destruction closes it.
class Socket {
public:
    Socket() = default;

    explicit Socket(int fd) : fd_(fd) {}

    ~Socket() noexcept {
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

// Runs one request/response exchange against a configured IPv4 server.
// server_ip and server_port identify the endpoint used by connect_to_server().
class TcpClient {
public:
    TcpClient(const std::string& server_ip, std::uint16_t server_port) noexcept
        : server_ip_(server_ip), server_port_(server_port) {}

    // Opens the configured endpoint with a bounded nonblocking connect, then
    // switches to blocking I/O with send and receive timeouts.
    void connect_to_server() {
        socket_.reset();
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

    [[nodiscard]] bool connected() const noexcept {
        return socket_.valid();
    }

    void disconnect() noexcept {
        socket_.reset();
    }

    // Sends request as the protocol's newline-terminated request key.
    void send_request(std::string_view request) {
        if (request.empty() || request.size() > tcp_common::kMaxRequestKeySize) {
            throw std::invalid_argument("request length is outside the supported range");
        }
        if (request.back() == '\n') {
            send_all(reinterpret_cast<const std::uint8_t*>(request.data()), request.size());
            return;
        }
        std::array<std::uint8_t, tcp_common::kMaxRequestKeySize + 1> framed_request{};
        std::memcpy(framed_request.data(), request.data(), request.size());
        framed_request[request.size()] = '\n';
        send_all(framed_request.data(), request.size() + 1);
    }

    // Reads one length-prefixed response while leaving the socket connected for
    // the next request handled by this worker.
    void receive_response(std::vector<std::uint8_t>& response) {
        std::array<std::uint8_t, sizeof(std::uint32_t)> header{};
        receive_exact(header.data(), header.size());
        const std::uint32_t payload_size =
            (static_cast<std::uint32_t>(header[0]) << 24U) |
            (static_cast<std::uint32_t>(header[1]) << 16U) |
            (static_cast<std::uint32_t>(header[2]) << 8U) |
            static_cast<std::uint32_t>(header[3]);
        if (payload_size < tcp_common::kMinPayloadSize ||
            payload_size > tcp_common::kMaxPayloadSize) {
            throw std::runtime_error(
                "response payload length is outside expected range " +
                payload_range_string());
        }
        response.resize(payload_size);
        receive_exact(response.data(), response.size());
    }

private:
    // Formats the configured address for diagnostics.
    [[nodiscard]] std::string endpoint() const {
        return server_ip_ + ":" + std::to_string(server_port_);
    }

    // Converts a socket error_code into an endpoint-specific ConnectError and
    // closes the unusable socket before throwing.
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

    // Waits for a nonblocking connect to finish and validates SO_ERROR before
    // the shared client I/O timeout expires.
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

    // Applies timeout to both receive and send operations on fd.
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

    // Sends exactly size bytes beginning at data, retrying interrupted and
    // partial writes.
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

    // Receives exactly size bytes or reports a stale/failed persistent socket.
    void receive_exact(std::uint8_t* data, std::size_t size) {
        std::size_t received = 0;
        while (received < size) {
            const ssize_t n = ::recv(socket_.get(), data + received, size - received, 0);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("recv failed: ") + std::strerror(errno));
            }
            if (n == 0) {
                throw std::runtime_error("server closed persistent connection during response");
            }
            received += static_cast<std::size_t>(n);
        }
    }

    const std::string& server_ip_;
    std::uint16_t server_port_;
    Socket socket_;
};

// Converts binary response data into a review-friendly, 16-byte-per-line hex
// dump for verbose benchmark output.
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

// Formats the shared minimum and maximum payload sizes for error messages.
std::string payload_range_string() {
    return "[" + std::to_string(tcp_common::kMinPayloadSize) + ", " +
           std::to_string(tcp_common::kMaxPayloadSize) + "]";
}

// Loads and validates newline-delimited request keys from keys_file, enforcing
// the protocol's file, entry-count, and key-length limits.
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

// Selects request_count keys uniformly with replacement from all_requests for
// one benchmark round.
std::vector<std::string> pick_random_requests(const std::vector<std::string>& all_requests,
                                              std::size_t request_count,
                                              std::mt19937& rng) {
    if (all_requests.empty()) {
        throw std::runtime_error("no requests available for random selection");
    }

    std::vector<std::string> selected;
    selected.reserve(request_count);

    std::uniform_int_distribution<std::size_t> idx_dist(0, all_requests.size() - 1);

    for (std::size_t i = 0; i < request_count; ++i) {
        selected.push_back(all_requests[idx_dist(rng)]);
    }

    return selected;
}

} // namespace

// Captures one request's verbose output and outcome; populated only when
// detailed per-request reporting is enabled.
struct RequestResult {
    std::string request;
    std::string output;
    bool connect_failed = false;
    bool success = false;
    std::size_t response_bytes = 0;
};

// Owns all data and counters for one reporting round. Jobs keep this object
// alive while they are queued or executing in the persistent worker pool.
struct RoundState {
    RoundState(std::vector<std::string> selected_requests, bool verbose)
        : requests(std::move(selected_requests)),
          verbose_output(verbose),
          remaining(requests.size()) {
        if (verbose_output) {
            results.resize(requests.size());
        }
        sample_errors.reserve(kMaxPrintedErrorsPerRound);
    }

    void record_error(std::string message) {
        std::lock_guard<std::mutex> lock(sample_errors_mutex);
        if (sample_errors.size() < kMaxPrintedErrorsPerRound) {
            sample_errors.push_back(std::move(message));
        }
    }

    void complete(std::size_t count) noexcept {
        std::lock_guard<std::mutex> lock(completion_mutex);
        const std::size_t completed = std::min(count, remaining);
        remaining -= completed;
        if (remaining == 0) {
            completion_cv.notify_all();
        }
    }

    [[nodiscard]] bool wait_until_complete_or_stopped() {
        std::unique_lock<std::mutex> lock(completion_mutex);
        while (remaining != 0 && g_stop_requested == 0) {
            completion_cv.wait_for(lock, std::chrono::milliseconds(50));
        }
        return remaining == 0;
    }

    std::vector<std::string> requests;
    bool verbose_output = false;
    std::vector<RequestResult> results;
    std::atomic<std::size_t> success_count{0};
    std::atomic<std::size_t> connect_failed_count{0};
    std::atomic<std::size_t> failed_count{0};
    std::atomic<std::size_t> bytes_received_total{0};
    std::vector<std::string> sample_errors;
    std::mutex sample_errors_mutex;

private:
    std::mutex completion_mutex;
    std::condition_variable completion_cv;
    std::size_t remaining;
};

struct RequestJob {
    std::shared_ptr<RoundState> round;
    std::size_t begin = 0;
    std::size_t end = 0;
};

// Fixed-size worker pool with a bounded FIFO. Threads are created once and
// sleep on condition variables when no work is available.
class BoundedWorkerPool {
public:
    BoundedWorkerPool(std::size_t worker_count,
                      std::size_t queue_capacity,
                      std::string server_ip,
                      std::uint16_t server_port)
        : queue_capacity_(queue_capacity),
          server_ip_(std::move(server_ip)),
          server_port_(server_port) {
        workers_.reserve(worker_count);
        try {
            for (std::size_t i = 0; i < worker_count; ++i) {
                workers_.emplace_back([this] { worker_loop(); });
            }
        } catch (...) {
            request_stop();
            join();
            throw;
        }
    }

    ~BoundedWorkerPool() noexcept {
        request_stop();
        join();
    }

    BoundedWorkerPool(const BoundedWorkerPool&) = delete;
    BoundedWorkerPool& operator=(const BoundedWorkerPool&) = delete;
    BoundedWorkerPool(BoundedWorkerPool&&) = delete;
    BoundedWorkerPool& operator=(BoundedWorkerPool&&) = delete;

    [[nodiscard]] bool submit(RequestJob job) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_not_full_.wait(lock, [this] {
            return stopping_ || g_stop_requested != 0 || queue_.size() < queue_capacity_;
        });
        if (stopping_ || g_stop_requested != 0) {
            return false;
        }
        queue_.push_back(std::move(job));
        queue_not_empty_.notify_one();
        return true;
    }

    // Discards queued work. Active requests finish under their socket timeout.
    void request_stop() noexcept {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (stopping_) {
                return;
            }
            stopping_ = true;
            queue_.clear();
        }
        queue_not_empty_.notify_all();
        queue_not_full_.notify_all();
    }

    void join() noexcept {
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    void worker_loop() noexcept {
        TcpClient client(server_ip_, server_port_);
        std::vector<std::uint8_t> response;
        response.reserve(tcp_common::kMaxPayloadSize);
        for (;;) {
            RequestJob job;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_not_empty_.wait(lock, [this] {
                    return stopping_ || !queue_.empty();
                });
                if (stopping_ && queue_.empty()) {
                    return;
                }
                job = std::move(queue_.front());
                queue_.pop_front();
                queue_not_full_.notify_one();
            }

            for (std::size_t index = job.begin; index < job.end; ++index) {
                process(*job.round, index, client, response);
            }
            job.round->complete(job.end - job.begin);
        }
    }

    void process(RoundState& round,
                 std::size_t i,
                 TcpClient& client,
                 std::vector<std::uint8_t>& response) noexcept {
        constexpr std::size_t kMaxAttempts = 2;
        for (std::size_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
            try {
                if (attempt == 0 && round.verbose_output) {
                    round.results[i].request = round.requests[i];
                }
                if (!client.connected()) {
                    client.connect_to_server();
                }
                client.send_request(round.requests[i]);
                client.receive_response(response);
                round.bytes_received_total.fetch_add(response.size(), std::memory_order_relaxed);
                round.success_count.fetch_add(1, std::memory_order_relaxed);

                if (round.verbose_output) {
                    std::ostringstream out;
                    out << "Request: " << round.requests[i] << '\n';
                    out << "Received " << response.size() << " byte(s) from server\n";
                    out << render_hex_dump(response);
                    round.results[i].output = out.str();
                    round.results[i].connect_failed = false;
                    round.results[i].success = true;
                    round.results[i].response_bytes = response.size();
                }
                return;
            } catch (const ConnectError& error) {
                client.disconnect();
                if (attempt + 1 < kMaxAttempts) {
                    continue;
                }
                round.connect_failed_count.fetch_add(1, std::memory_order_relaxed);
                round.failed_count.fetch_add(1, std::memory_order_relaxed);
                record_failure(round, i, error.what(), true);
                return;
            } catch (const std::exception& error) {
                client.disconnect();
                if (attempt + 1 < kMaxAttempts) {
                    continue;
                }
                round.failed_count.fetch_add(1, std::memory_order_relaxed);
                record_failure(round, i, error.what(), false);
                return;
            } catch (...) {
                client.disconnect();
                if (attempt + 1 < kMaxAttempts) {
                    continue;
                }
                round.failed_count.fetch_add(1, std::memory_order_relaxed);
                record_failure(round, i, "unknown non-standard exception", false);
                return;
            }
        }
    }

    static void record_failure(RoundState& round,
                               std::size_t index,
                               const std::string& reason,
                               bool connect_failed) noexcept {
        try {
            const std::string error_line =
                "Request: " + round.requests[index] + "\nError: " + reason + '\n';
            round.record_error(error_line);
            if (round.verbose_output) {
                round.results[index].output = error_line;
                round.results[index].connect_failed = connect_failed;
                round.results[index].success = false;
            }
        } catch (...) {
            // Statistics remain correct even if diagnostic allocation fails.
        }
    }

    std::size_t queue_capacity_;
    std::string server_ip_;
    std::uint16_t server_port_;
    std::mutex queue_mutex_;
    std::condition_variable queue_not_empty_;
    std::condition_variable queue_not_full_;
    std::deque<RequestJob> queue_;
    bool stopping_ = false;
    std::vector<std::thread> workers_;
};

bool wait_between_rounds(int delay_ms) {
    auto remaining = std::chrono::milliseconds(delay_ms);
    constexpr auto check_interval = std::chrono::milliseconds(50);
    while (remaining.count() > 0 && g_stop_requested == 0) {
        const auto sleep_time = std::min(remaining, check_interval);
        std::this_thread::sleep_for(sleep_time);
        remaining -= sleep_time;
    }
    return g_stop_requested == 0;
}

// Parses benchmark options, loads request keys, and runs bounded-concurrency
// request rounds. argc/argv contain the server endpoint and optional controls.
void print_client_usage(std::ostream& output, std::string_view program) {
    output
        << "Usage:\n"
        << "  " << program << " <server-ip> <server-port> [options]\n\n"
        << "Arguments:\n"
        << "  <server-ip>                  IPv4 address of tcp_server_epoll\n"
        << "  <server-port>                Server TCP port in range 1..65535\n\n"
        << "Options:\n"
        << "  -h, --help                   Show this help and exit\n"
        << "  --keys-file <path>           Request-key file (default: "
        << tcp_common::kDefaultClientKeysFile << ")\n"
        << "  --request-count <count>      Requests per round (default: "
        << kDefaultRequestCount << ", maximum: " << kMaxRequestsPerRound << ")\n"
        << "  --forever                    Repeat request rounds until interrupted\n"
        << "  --verbose                    Print every request and response\n"
        << "  --max-concurrency <count>    Persistent worker/socket count\n"
        << "                                (default: available CPU count, maximum: "
        << kMaxConcurrency << ")\n"
        << "  --queue-capacity <count>     Maximum queued jobs (default: 2 per worker,\n"
        << "                                maximum: " << kMaxQueueCapacity << ")\n"
        << "  --round-delay-ms <ms>        Delay between --forever rounds (default: 0,\n"
        << "                                maximum: " << kMaxRoundDelayMs << ")\n\n"
        << "Examples:\n"
        << "  " << program << " 127.0.0.1 23456\n"
        << "  " << program
        << " 127.0.0.1 23456 --request-count 1000 --max-concurrency 8\n"
        << "  " << program
        << " 127.0.0.1 23456 --request-count 1000 --forever --round-delay-ms 1000\n\n"
        << "Options use a space between the option and its value; for example,\n"
        << "--request-count 1000 (not --request-count=1000).\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc == 2 &&
            (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h")) {
            print_client_usage(std::cout, argv[0]);
            return 0;
        }
        if (argc < 3) {
            throw std::invalid_argument("server IP address and port are required");
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
        const std::size_t detected_cpu_count = default_max_concurrency();
        std::size_t max_concurrency = detected_cpu_count;
        std::size_t queue_capacity = 0; // Derived from worker count unless explicitly set.
        int round_delay_ms = 0;

        for (int i = 3; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                print_client_usage(std::cout, argv[0]);
                return 0;
            } else if (arg == "--keys-file") {
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
                if (request_count > kMaxRequestsPerRound) {
                    throw std::invalid_argument("--request-count exceeds hard safety limit " +
                                                std::to_string(kMaxRequestsPerRound));
                }
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
                if (max_concurrency > kMaxConcurrency) {
                    throw std::invalid_argument("--max-concurrency exceeds hard safety limit " +
                                                std::to_string(kMaxConcurrency));
                }
                ++i;
            } else if (arg == "--queue-capacity") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--queue-capacity requires a numeric value");
                }
                const int parsed = parse_int_arg(argv[i + 1], "--queue-capacity");
                if (parsed <= 0) {
                    throw std::invalid_argument("--queue-capacity must be positive");
                }
                queue_capacity = static_cast<std::size_t>(parsed);
                if (queue_capacity > kMaxQueueCapacity) {
                    throw std::invalid_argument("--queue-capacity exceeds hard safety limit " +
                                                std::to_string(kMaxQueueCapacity));
                }
                ++i;
            } else if (arg == "--round-delay-ms") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--round-delay-ms requires a numeric value");
                }
                round_delay_ms = parse_int_arg(argv[i + 1], "--round-delay-ms");
                if (round_delay_ms < 0 || round_delay_ms > kMaxRoundDelayMs) {
                    throw std::invalid_argument("--round-delay-ms must be in range 0.." +
                                                std::to_string(kMaxRoundDelayMs));
                }
                ++i;
            } else {
                throw std::invalid_argument("Unknown argument: " + std::string(arg));
            }
        }

        install_termination_signal_handlers();
        const std::vector<std::string> all_requests = load_request_keys(keys_file);
        const std::size_t worker_count = std::min(request_count, max_concurrency);
        const std::size_t target_job_count = worker_count * 4;
        const std::size_t requests_per_job = std::min(
            kRequestsPerJob,
            std::max<std::size_t>(
                1, (request_count + target_job_count - 1) / target_job_count));
        if (queue_capacity == 0) {
            queue_capacity = std::min(
                kMaxQueueCapacity,
                std::max<std::size_t>(1, std::min(request_count, worker_count * 2)));
        }
        std::cout << "Loaded " << all_requests.size() << " request key(s) from " << keys_file
                  << ". Sending " << request_count << " request(s) per round"
                  << (run_forever ? " forever" : "")
                  << " with " << worker_count << " persistent worker thread(s)"
                  << " and queue capacity " << queue_capacity
                  << ", up to " << requests_per_job << " request(s) per queued job"
                  << " (CPU-aware default detects " << detected_cpu_count << " CPU(s))"
                  << (round_delay_ms != 0
                          ? ", round delay " + std::to_string(round_delay_ms) + " ms"
                          : "")
                  << (verbose_output ? " (verbose mode)." : " (summary mode).")
                  << '\n';

        std::random_device random_device;
        std::mt19937 rng(random_device());
        BoundedWorkerPool pool(worker_count, queue_capacity, server_ip, server_port);

        std::size_t round = 0;
        bool any_request_failed = false;
        do {
            if (g_stop_requested != 0) {
                break;
            }
            ++round;
            auto round_state = std::make_shared<RoundState>(
                pick_random_requests(all_requests, request_count, rng), verbose_output);
            const auto round_started = std::chrono::steady_clock::now();

            bool submitted_all = true;
            for (std::size_t begin = 0; begin < round_state->requests.size();
                 begin += requests_per_job) {
                const std::size_t end =
                    std::min(begin + requests_per_job, round_state->requests.size());
                if (!pool.submit(RequestJob{round_state, begin, end})) {
                    submitted_all = false;
                    break;
                }
            }
            if (!submitted_all || !round_state->wait_until_complete_or_stopped()) {
                pool.request_stop();
                break;
            }

            const auto round_finished = std::chrono::steady_clock::now();
            const double elapsed_seconds =
                std::chrono::duration<double>(round_finished - round_started).count();

            const std::size_t success = round_state->success_count.load(std::memory_order_relaxed);
            const std::size_t connect_failed =
                round_state->connect_failed_count.load(std::memory_order_relaxed);
            const std::size_t failed = round_state->failed_count.load(std::memory_order_relaxed);
            const std::size_t total_bytes =
                round_state->bytes_received_total.load(std::memory_order_relaxed);
            any_request_failed = any_request_failed || failed != 0;
            const double requests_per_second =
                elapsed_seconds > 0.0
                    ? static_cast<double>(round_state->requests.size()) / elapsed_seconds
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
                for (const auto& result : round_state->results) {
                    std::cout << "----------------------------------------\n";
                    std::cout << result.output;
                }
            } else {
                if (!round_state->sample_errors.empty()) {
                    std::cout << "Sample errors (up to " << round_state->sample_errors.size()
                              << "):\n";
                    for (const auto& err : round_state->sample_errors) {
                        std::cout << "----------------------------------------\n";
                        std::cout << err;
                    }
                }
            }

            if (connect_failed == round_state->requests.size()) {
                std::cerr << "Unable to reach TCP server " << server_ip << ':' << server_port
                          << ": every connection attempt failed in round " << round
                          << ". Verify the server IP address, listening port, server process, "
                             "network route, and firewall rules. Exiting client."
                          << std::endl;
                break;
            }

            if (run_forever && round_delay_ms > 0 && !wait_between_rounds(round_delay_ms)) {
                break;
            }
        } while (run_forever);

        pool.request_stop();
        pool.join();

        if (g_stop_requested != 0) {
            std::cerr << "Termination signal " << g_stop_requested
                      << " received; worker pool stopped and joined.\n";
            return 128 + g_stop_requested;
        }

        return any_request_failed ? 2 : 0;
    } catch (const std::invalid_argument& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        std::cerr << '\n';
        print_client_usage(std::cerr, argc > 0 ? argv[0] : "tcp_client");
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
