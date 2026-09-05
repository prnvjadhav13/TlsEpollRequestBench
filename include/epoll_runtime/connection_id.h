// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <cstdint>

namespace epoll_runtime {

// Stable identity for a live connection. File descriptors are reused by the
// kernel; the generation prevents an old epoll event or asynchronous completion
// from being delivered to a newer connection that happens to have the same fd.
struct ConnectionId {
    std::uint32_t descriptor = 0;
    std::uint32_t generation = 0;

    [[nodiscard]] constexpr bool valid() const noexcept {
        return generation != 0;
    }

    friend constexpr bool operator==(ConnectionId, ConnectionId) noexcept = default;
};

[[nodiscard]] constexpr std::uint64_t encode(ConnectionId id) noexcept {
    return (static_cast<std::uint64_t>(id.generation) << 32U) |
           static_cast<std::uint64_t>(id.descriptor);
}

[[nodiscard]] constexpr ConnectionId decode(std::uint64_t value) noexcept {
    return ConnectionId{
        .descriptor = static_cast<std::uint32_t>(value),
        .generation = static_cast<std::uint32_t>(value >> 32U)};
}

} // namespace epoll_runtime
