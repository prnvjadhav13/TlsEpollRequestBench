// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include "epoll_runtime/connection_id.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <sys/eventfd.h>
#include <unistd.h>

namespace epoll_runtime {

// Bounded multi-producer/single-consumer return path from application workers
// to one event loop. Register notification_fd() with that loop's epoll set,
// then call drain() when readable. The callback must validate ConnectionId
// against the current connection before applying the result.
template <typename Result>
class CompletionQueue {
public:
    struct Completion {
        ConnectionId connection;
        Result result;
    };

    explicit CompletionQueue(std::size_t capacity) : capacity_(capacity) {
        if (capacity == 0) {
            throw std::invalid_argument("completion queue capacity must be nonzero");
        }
        notification_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (notification_fd_ < 0) {
            throw std::system_error(errno, std::generic_category(), "eventfd");
        }
    }

    ~CompletionQueue() noexcept {
        if (notification_fd_ >= 0) {
            ::close(notification_fd_);
        }
    }

    CompletionQueue(const CompletionQueue&) = delete;
    CompletionQueue& operator=(const CompletionQueue&) = delete;
    CompletionQueue(CompletionQueue&&) = delete;
    CompletionQueue& operator=(CompletionQueue&&) = delete;

    [[nodiscard]] int notification_fd() const noexcept { return notification_fd_; }

    [[nodiscard]] bool try_push(Completion completion) {
        std::lock_guard lock(mutex_);
        if (items_.size() >= capacity_) {
            return false;
        }
        items_.push_back(std::move(completion));
        const std::uint64_t one = 1;
        for (;;) {
            const ssize_t written = ::write(notification_fd_, &one, sizeof(one));
            if (written == static_cast<ssize_t>(sizeof(one))) {
                return true;
            }
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // A previous notification is already pending and will cause the
                // consumer to drain this item as well.
                return true;
            }
            // Preserve the try_push contract: on an unexpected notification
            // failure, roll back while the consumer is excluded by mutex_.
            items_.pop_back();
            return false;
        }
    }

    template <typename Consumer>
    std::size_t drain(Consumer&& consumer) {
        drain_notifications();
        std::deque<Completion> ready;
        {
            std::lock_guard lock(mutex_);
            items_.swap(ready);
        }
        const std::size_t count = ready.size();
        for (auto& completion : ready) {
            consumer(std::move(completion));
        }
        return count;
    }

    [[nodiscard]] std::size_t pending() const noexcept {
        std::lock_guard lock(mutex_);
        return items_.size();
    }

private:
    void drain_notifications() noexcept {
        std::uint64_t value = 0;
        for (;;) {
            const ssize_t result = ::read(notification_fd_, &value, sizeof(value));
            if (result == static_cast<ssize_t>(sizeof(value))) {
                continue;
            }
            if (result < 0 && errno == EINTR) {
                continue;
            }
            return;
        }
    }

    const std::size_t capacity_;
    int notification_fd_ = -1;
    mutable std::mutex mutex_;
    std::deque<Completion> items_;
};

} // namespace epoll_runtime
