#pragma once

#include "messaging/repository/message_repository_interface.hpp"
#include "service/sequence_allocator_interface.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace securecloud::messaging::service {

/**
 * @brief Production sequence allocator backed by authoritative ScyllaDB persistence.
 *
 * Implements striped lock concurrency and cold-start recovery:
 * - Concurrency: 64 lock stripes prevent cross-conversation contention.
 * - Cold Start: Queries IMessageRepository::get_last_sequence on first access or cache miss.
 * - In-Memory: Subsequent increments for the active bucket execute in nanoseconds.
 * - Partition Rollover: Distinct message buckets (YYYYMM) maintain isolated counters automatically.
 */
class ConversationSequenceAllocator : public ISequenceAllocator {
  public:
    static constexpr std::size_t kNumStripes = 64;

    /**
     * @brief Constructs allocator backed by the given message repository.
     * @throws std::invalid_argument if message_repo is nullptr.
     */
    explicit ConversationSequenceAllocator(std::shared_ptr<repository::IMessageRepository> message_repo);

    [[nodiscard]] uint64_t allocate_sequence(const domain::ConversationId& conversation_id,
                                             const domain::MessageBucket& message_bucket) override;

    [[nodiscard]] uint64_t peek_sequence(const domain::ConversationId& conversation_id,
                                         const domain::MessageBucket& message_bucket) override;

    /// Invalidates cached counter for a given conversation bucket (forcing reload on next access)
    void invalidate(const domain::ConversationId& conversation_id, const domain::MessageBucket& message_bucket);

    /// Clears all cached in-memory counters
    void clear();

  private:
    [[nodiscard]] static std::string make_key(const domain::ConversationId& conversation_id,
                                              const domain::MessageBucket& message_bucket);

    [[nodiscard]] static std::size_t get_stripe_index(const std::string& key) noexcept;

    struct Stripe {
        mutable std::mutex mtx;
        std::unordered_map<std::string, uint64_t> counters;
    };

    std::shared_ptr<repository::IMessageRepository> message_repo_;
    std::array<Stripe, kNumStripes> stripes_;
};

} // namespace securecloud::messaging::service
