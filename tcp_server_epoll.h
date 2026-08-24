// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
// This software is provided solely for performance evaluation and educational purposes.
// See the repository LICENSE file for reuse terms.

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stop_token>

// Aggregate lifecycle counters produced by one event-loop worker.
struct EventLoopStats {
    std::uint64_t accepted = 0;
    std::uint64_t rejected = 0;
    std::uint64_t closed = 0;
};

// Owns one epoll-based TCP event loop.  The implementation details are kept
// private so callers only need this small, stable interface.
class EventLoop {
public:
    // Creates a worker identified by loop_id that listens on listen_port,
    // expires clients after idle_timeout, and enforces max_connections.
    EventLoop(std::size_t loop_id,
              int listen_port,
              std::chrono::seconds idle_timeout,
              std::size_t max_connections);
    ~EventLoop() noexcept;

    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;
    EventLoop(EventLoop&&) = delete;
    EventLoop& operator=(EventLoop&&) = delete;

    // Processes epoll events until stop_token is requested or global shutdown.
    void run(std::stop_token stop_token = {});
    // Interrupts a blocked epoll wait so the worker can observe state changes.
    void wake() noexcept;
    // Returns this worker's accepted, rejected, and closed connection totals.
    [[nodiscard]] EventLoopStats stats() const noexcept;

private:
    // Holds Linux-specific networking state behind the public interface.
    class Impl;
    std::unique_ptr<Impl> impl_;
};
