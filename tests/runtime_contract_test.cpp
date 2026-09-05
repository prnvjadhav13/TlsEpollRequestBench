#include "epoll_runtime/bounded_executor.h"
#include "epoll_runtime/connection_id.h"
#include "epoll_runtime/completion_queue.h"
#include "epoll_runtime/protocol.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

int main() {
    constexpr epoll_runtime::ConnectionId original{.descriptor = 1234, .generation = 77};
    static_assert(epoll_runtime::decode(epoll_runtime::encode(original)) == original);

    auto owner = std::make_shared<int>(42);
    epoll_runtime::OutputBatch batch;
    batch.lifetime = owner;
    owner.reset();
    assert(batch.lifetime.use_count() == 1);

    {
        epoll_runtime::BoundedExecutor executor(1, 2);
        std::atomic<int> completed{0};
        assert(executor.try_submit([&completed] { completed.fetch_add(1); }));
        assert(executor.try_submit([&completed] { completed.fetch_add(1); }));
        executor.stop(epoll_runtime::BoundedExecutor::ShutdownMode::Drain);
        assert(completed.load() == 2);
        assert(!executor.try_submit([] {}));
    }

    {
        epoll_runtime::BoundedExecutor executor(1, 4);
        std::promise<void> started;
        std::promise<void> release;
        auto started_future = started.get_future();
        auto release_future = release.get_future().share();
        std::atomic<int> pending_executed{0};
        assert(executor.try_submit([&started, release_future] {
            started.set_value();
            release_future.wait();
        }));
        assert(started_future.wait_for(std::chrono::seconds(2)) ==
               std::future_status::ready);
        assert(executor.try_submit([&pending_executed] { ++pending_executed; }));
        std::thread stopper([&executor] {
            executor.stop(epoll_runtime::BoundedExecutor::ShutdownMode::CancelPending);
        });
        while (!executor.stopping()) {
            std::this_thread::yield();
        }
        release.set_value();
        stopper.join();
        assert(pending_executed.load() == 0);
    }

    epoll_runtime::CompletionQueue<int> completions(2);
    assert(completions.try_push({original, 99}));
    assert(completions.try_push({original, 100}));
    assert(!completions.try_push({original, 101}));
    bool delivered = false;
    int result_sum = 0;
    assert(completions.drain([&](auto completion_value) {
        assert(completion_value.connection == original);
        result_sum += completion_value.result;
        delivered = true;
    }) == 2);
    assert(delivered);
    assert(result_sum == 199);
}
