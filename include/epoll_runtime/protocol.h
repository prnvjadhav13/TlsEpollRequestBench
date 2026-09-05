// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <span>

namespace epoll_runtime {

// Up to two immutable slices allow header+payload transmission without first
// combining them. `lifetime` is optional: borrowed storage may omit it when the
// ProtocolConnection itself guarantees stability; generated/asynchronous data
// should set it to an object owning every referenced byte.
struct OutputBatch {
    std::array<std::span<const std::byte>, 2> slices{};
    std::size_t count = 0;
    std::shared_ptr<const void> lifetime;
};

class ProtocolConnection {
public:
    virtual ~ProtocolConnection() = default;

    // Called only by the connection's event-loop thread. Returning false asks
    // the runtime to close the connection. Exceptions are contained by the
    // runtime and close only this connection.
    [[nodiscard]] virtual bool consume(std::span<const std::byte> input) = 0;
    [[nodiscard]] virtual bool has_partial_input() const noexcept = 0;
    [[nodiscard]] virtual bool has_output() const noexcept = 0;
    [[nodiscard]] virtual OutputBatch output() const noexcept = 0;
    virtual void consume_output(std::size_t bytes) noexcept = 0;
};

class ProtocolFactory {
public:
    virtual ~ProtocolFactory() = default;
    [[nodiscard]] virtual std::unique_ptr<ProtocolConnection> create() const = 0;
};

} // namespace epoll_runtime

// Compatibility alias for code written against the original prototype API.
namespace server_runtime = epoll_runtime;
