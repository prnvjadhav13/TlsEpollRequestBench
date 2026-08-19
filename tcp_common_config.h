#pragma once

#include <cstddef>
#include <cstdint>

namespace tcp_common {
inline constexpr const char* kDefaultServerMappingFile = "server_request_response_mapping.bin";
inline constexpr const char* kDefaultClientKeysFile = "client_request_keys.txt";
inline constexpr std::size_t kMinPayloadSize = 2000;
inline constexpr std::size_t kMaxPayloadSize = 4000;
inline constexpr std::uint32_t kMappingFileMagic = 0x4D415031;  // "MAP1"
inline constexpr std::uint32_t kMappingFileVersion = 1;
inline constexpr std::size_t kMappingFileHeaderBytes = sizeof(std::uint32_t) * 3;
inline constexpr std::size_t kMaxMappingFileSizeBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::uint32_t kMaxMappingEntries = 500000;
inline constexpr std::size_t kMaxRequestKeySize = 1024;
inline constexpr std::size_t kMaxRequestKeysFileSizeBytes =
    static_cast<std::size_t>(kMaxMappingEntries) *
        (kMaxRequestKeySize + 1);
} // namespace tcp_common
