// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <stop_token>
#include <thread>
#include <vector>

namespace epoll_runtime {

// Optional executor for application work that must not run on an event-loop
// thread. Rejection at the bounded queue is deliberate overload backpressure.
// Jobs must return their result through an application-owned completion queue;
// that completion must carry ConnectionId and be validated before delivery.
class BoundedExecutor {
public:
    using Job = std::move_only_function<void()>;
    enum class ShutdownMode : unsigned char { Drain, CancelPending };

    BoundedExecutor(std::size_t thread_count, std::size_t queue_capacity);
    ~BoundedExecutor() noexcept;

    BoundedExecutor(const BoundedExecutor&) = delete;
    BoundedExecutor& operator=(const BoundedExecutor&) = delete;
    BoundedExecutor(BoundedExecutor&&) = delete;
    BoundedExecutor& operator=(BoundedExecutor&&) = delete;

    [[nodiscard]] bool try_submit(Job job);
    // Drain executes queued jobs before joining. CancelPending discards jobs
    // that have not started; an active job is always allowed to finish.
    void stop(ShutdownMode mode = ShutdownMode::CancelPending) noexcept;
    [[nodiscard]] std::size_t pending() const noexcept;
    [[nodiscard]] bool stopping() const noexcept;

private:
    void worker(std::stop_token stop_token) noexcept;

    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable_any ready_;
    std::queue<Job> jobs_;
    bool stopping_ = false;
    bool cancel_pending_ = false;
    std::vector<std::jthread> threads_;
};

} // namespace epoll_runtime
