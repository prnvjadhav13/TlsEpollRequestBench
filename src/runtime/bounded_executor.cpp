// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#include "epoll_runtime/bounded_executor.h"

#include <stdexcept>
#include <utility>

namespace epoll_runtime {

BoundedExecutor::BoundedExecutor(std::size_t thread_count, std::size_t queue_capacity)
    : capacity_(queue_capacity) {
    if (thread_count == 0 || queue_capacity == 0) {
        throw std::invalid_argument("executor thread count and capacity must be nonzero");
    }
    threads_.reserve(thread_count);
    for (std::size_t index = 0; index < thread_count; ++index) {
        threads_.emplace_back([this](std::stop_token token) { worker(token); });
    }
}

BoundedExecutor::~BoundedExecutor() noexcept {
    stop(ShutdownMode::CancelPending);
}

bool BoundedExecutor::try_submit(Job job) {
    if (!job) {
        return false;
    }
    {
        std::lock_guard lock(mutex_);
        if (stopping_ || jobs_.size() >= capacity_) {
            return false;
        }
        jobs_.push(std::move(job));
    }
    ready_.notify_one();
    return true;
}

void BoundedExecutor::stop(ShutdownMode mode) noexcept {
    std::queue<Job> abandoned;
    {
        std::lock_guard lock(mutex_);
        if (stopping_) {
            return;
        }
        stopping_ = true;
        cancel_pending_ = mode == ShutdownMode::CancelPending;
        if (cancel_pending_) {
            jobs_.swap(abandoned);
        }
    }
    for (auto& thread : threads_) {
        thread.request_stop();
    }
    ready_.notify_all();
    threads_.clear();
}

std::size_t BoundedExecutor::pending() const noexcept {
    std::lock_guard lock(mutex_);
    return jobs_.size();
}

bool BoundedExecutor::stopping() const noexcept {
    std::lock_guard lock(mutex_);
    return stopping_;
}

void BoundedExecutor::worker(std::stop_token stop_token) noexcept {
    for (;;) {
        Job job;
        {
            std::unique_lock lock(mutex_);
            ready_.wait(lock, stop_token, [this] { return stopping_ || !jobs_.empty(); });
            if ((stopping_ || stop_token.stop_requested()) &&
                (cancel_pending_ || jobs_.empty())) {
                return;
            }
            if (jobs_.empty()) {
                continue;
            }
            job = std::move(jobs_.front());
            jobs_.pop();
        }
        try {
            job();
        } catch (...) {
            // Jobs form an exception boundary. Applications communicate errors
            // through their completion result rather than killing a worker.
        }
    }
}

} // namespace epoll_runtime
