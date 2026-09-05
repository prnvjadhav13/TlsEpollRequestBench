// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stop_token>

#include "epoll_runtime/protocol.h"
#include "secure_transport.h"

namespace epoll_runtime {

struct EventLoopStats {
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t closed = 0;
    std::uint64_t tls_handshakes_succeeded = 0;
    std::uint64_t tls_handshakes_failed = 0;
    std::uint64_t tls_handshakes_rejected_capacity = 0;
    std::uint64_t protocol_exceptions = 0;
};

// One thread-confined, level-triggered Linux epoll worker. Protocol instances
// never cross worker threads. The pImpl keeps Linux and OpenSSL details out of
// consumers that embed the runtime.
class EventLoop {
public:
    EventLoop(std::size_t loop_id,
              int listen_port,
              std::chrono::seconds idle_timeout,
              std::size_t max_connections,
              secure_transport::Mode transport_mode,
              std::shared_ptr<secure_transport::TlsContextStore> tls_contexts,
              std::shared_ptr<const ProtocolFactory> protocol_factory);
    ~EventLoop() noexcept;

    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) = delete;
    EventLoop& operator=(EventLoop&&) = delete;

    void run(std::stop_token stop_token = {});
    void wake() noexcept;
    [[nodiscard]] EventLoopStats stats() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace epoll_runtime

// Source compatibility for the original example while applications migrate to
// the namespaced reusable API.
using EventLoop = epoll_runtime::EventLoop;
using EventLoopStats = epoll_runtime::EventLoopStats;
