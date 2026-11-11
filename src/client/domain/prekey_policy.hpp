#pragma once

#include <chrono>
#include <cstddef>

namespace securecloud::client::domain {

struct PrekeyPolicy {
    static constexpr std::size_t kEd25519PublicKeySize = 32;
    static constexpr std::size_t kEd25519PrivateKeySize = 32;
    static constexpr std::size_t kEd25519SignatureSize = 64;

    static constexpr std::size_t kX25519PublicKeySize = 32;
    static constexpr std::size_t kX25519PrivateKeySize = 32;

    static constexpr std::size_t kAes256KeySize = 32;
    static constexpr std::size_t kAeadGcmIvSize = 12;
    static constexpr std::size_t kAeadGcmTagSize = 16;
    static constexpr std::size_t kSharedSecretSize = 32;

    static constexpr std::size_t kInitialPrekeyBatchSize = 100;
    static constexpr std::size_t kLowPrekeyThreshold = 20;
    static constexpr std::size_t kReplenishmentBatchSize = 50;

    static constexpr std::chrono::seconds kSignedPrekeyMaxAge = std::chrono::hours(24 * 7); // 7 days
};

} // namespace securecloud::client::domain
