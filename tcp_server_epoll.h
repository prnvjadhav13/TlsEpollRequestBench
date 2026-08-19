#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stop_token>

struct EventLoopStats {
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t closed = 0;
};

// Owns one epoll-based TCP event loop.  The implementation details are kept
// private so callers only need this small, stable interface.
class EventLoop {
public:
    EventLoop(std::size_t loop_id,
              int listen_port,
              std::chrono::seconds idle_timeout,
              std::size_t max_connections);
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
