#include "messaging/domain/message_bucket.hpp"
#include "messaging/repository/message_repository_interface.hpp"
#include "messaging/service/conversation_sequence_allocator.hpp"
#include "messaging/service/in_memory_sequence_allocator.hpp"

#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service::test {
namespace {

using domain::ConversationId;
using domain::MessageBucket;
using domain::MessageEntity;
using domain::MessageId;

class MockMessageRepository : public repository::IMessageRepository {
  public:
    void save_message(const MessageEntity& msg) override {
        saved_messages.push_back(msg);
        uint64_t& last = last_sequences[msg.conversation_id.to_string() + ":" + msg.message_bucket.value()];
        if (msg.message_sequence > last) {
            last = msg.message_sequence;
        }
    }

    std::optional<MessageEntity> find_by_id(const ConversationId&, const MessageBucket&, const MessageId&) override {
        return std::nullopt;
    }

    std::vector<MessageEntity> list_messages_by_sequence_range(const ConversationId&, const MessageBucket&, uint64_t,
                                                               uint64_t, size_t) override {
        return {};
    }

    uint64_t get_last_sequence(const ConversationId& conversation_id, const MessageBucket& message_bucket) override {
        ++get_last_sequence_calls;
        auto it = last_sequences.find(conversation_id.to_string() + ":" + message_bucket.value());
        if (it != last_sequences.end()) {
            return it->second;
        }
        return default_last_sequence;
    }

    uint64_t default_last_sequence{0};
    std::atomic<int> get_last_sequence_calls{0};
    std::unordered_map<std::string, uint64_t> last_sequences;
    std::vector<MessageEntity> saved_messages;
};

// ============================================================================
// 1. ConversationSequenceAllocator Tests
// ============================================================================

TEST(ConversationSequenceAllocatorTest, RejectsNullRepository) {
    EXPECT_THROW(ConversationSequenceAllocator(nullptr), std::invalid_argument);
}

TEST(ConversationSequenceAllocatorTest, ColdStartFromEmptyRepository) {
    auto repo = std::make_shared<MockMessageRepository>();
    ConversationSequenceAllocator allocator(repo);

    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);

    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 0U);
    EXPECT_EQ(repo->get_last_sequence_calls.load(), 1);

    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 2U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 3U);
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 3U);

    // Ensure get_last_sequence was only called once on cold start; subsequent allocations hit cache
    EXPECT_EQ(repo->get_last_sequence_calls.load(), 1);
}

TEST(ConversationSequenceAllocatorTest, ColdStartFromExistingMaxSequence) {
    auto repo = std::make_shared<MockMessageRepository>();
    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);
    repo->last_sequences[conv_id.to_string() + ":" + bucket.value()] = 150;

    ConversationSequenceAllocator allocator(repo);

    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 150U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 151U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 152U);
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 152U);
}

TEST(ConversationSequenceAllocatorTest, MonthlyBucketRolloverIsolation) {
    auto repo = std::make_shared<MockMessageRepository>();
    ConversationSequenceAllocator allocator(repo);

    auto conv_id = ConversationId::generate_v7();
    auto bucket_oct = MessageBucket::from_year_month(2026, 10);
    auto bucket_nov = MessageBucket::from_year_month(2026, 11);

    // October partition allocates 1, 2, 3
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket_oct), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket_oct), 2U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket_oct), 3U);

    // November partition starts fresh at 1, 2
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket_nov), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket_nov), 2U);

    // Verification: each partition retains its distinct counter
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket_oct), 3U);
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket_nov), 2U);
}

TEST(ConversationSequenceAllocatorTest, InvalidationForcesReloadFromRepository) {
    auto repo = std::make_shared<MockMessageRepository>();
    ConversationSequenceAllocator allocator(repo);

    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);

    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 2U);
    EXPECT_EQ(repo->get_last_sequence_calls.load(), 1);

    // Simulate external database mutation and cache invalidation
    repo->last_sequences[conv_id.to_string() + ":" + bucket.value()] = 99;
    allocator.invalidate(conv_id, bucket);

    // Next allocation re-queries repository
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 100U);
    EXPECT_EQ(repo->get_last_sequence_calls.load(), 2);
}

TEST(ConversationSequenceAllocatorTest, ClearResetsAllStripes) {
    auto repo = std::make_shared<MockMessageRepository>();
    ConversationSequenceAllocator allocator(repo);

    auto conv1 = ConversationId::generate_v7();
    auto conv2 = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);

    EXPECT_EQ(allocator.allocate_sequence(conv1, bucket), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv2, bucket), 1U);

    allocator.clear();

    // After clear, next allocate re-queries repository
    EXPECT_EQ(allocator.allocate_sequence(conv1, bucket), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv2, bucket), 1U);
    EXPECT_EQ(repo->get_last_sequence_calls.load(), 4);
}

TEST(ConversationSequenceAllocatorTest, HighConcurrencySingleConversation) {
    auto repo = std::make_shared<MockMessageRepository>();
    ConversationSequenceAllocator allocator(repo);

    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);

    constexpr int kNumThreads = 10;
    constexpr int kAllocationsPerThread = 100;
    constexpr int kTotalAllocations = kNumThreads * kAllocationsPerThread;

    std::vector<std::vector<uint64_t>> thread_results(kNumThreads);
    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&, t]() {
            thread_results[static_cast<std::size_t>(t)].reserve(kAllocationsPerThread);
            for (int i = 0; i < kAllocationsPerThread; ++i) {
                thread_results[static_cast<std::size_t>(t)].push_back(allocator.allocate_sequence(conv_id, bucket));
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // Collect all results and verify strict monotonically sequential numbering (1 to 1000)
    std::set<uint64_t> all_sequences;
    for (const auto& res : thread_results) {
        for (uint64_t seq : res) {
            auto [it, inserted] = all_sequences.insert(seq);
            EXPECT_TRUE(inserted) << "Duplicate sequence allocated: " << seq;
        }
    }

    EXPECT_EQ(all_sequences.size(), static_cast<std::size_t>(kTotalAllocations));
    EXPECT_EQ(*all_sequences.begin(), 1U);
    EXPECT_EQ(*all_sequences.rbegin(), static_cast<uint64_t>(kTotalAllocations));
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), static_cast<uint64_t>(kTotalAllocations));
}

TEST(ConversationSequenceAllocatorTest, HighConcurrencyMultipleConversations) {
    auto repo = std::make_shared<MockMessageRepository>();
    ConversationSequenceAllocator allocator(repo);

    constexpr int kNumConversations = 5;
    constexpr int kNumThreads = 10;
    constexpr int kAllocationsPerThread = 50;

    std::vector<ConversationId> convs;
    for (int c = 0; c < kNumConversations; ++c) {
        convs.push_back(ConversationId::generate_v7());
    }
    auto bucket = MessageBucket::from_year_month(2026, 10);

    std::vector<std::thread> threads;
    threads.reserve(kNumThreads);

    for (int t = 0; t < kNumThreads; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < kAllocationsPerThread; ++i) {
                for (const auto& conv : convs) {
                    static_cast<void>(allocator.allocate_sequence(conv, bucket));
                }
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    const uint64_t expected_total_per_conv = static_cast<uint64_t>(kNumThreads * kAllocationsPerThread);
    for (const auto& conv : convs) {
        EXPECT_EQ(allocator.peek_sequence(conv, bucket), expected_total_per_conv);
    }
}

// ============================================================================
// 2. InMemorySequenceAllocator Tests
// ============================================================================

TEST(InMemorySequenceAllocatorTest, BasicAllocationAndPeek) {
    InMemorySequenceAllocator allocator;
    auto conv_id = ConversationId::generate_v7();
    auto bucket = MessageBucket::from_year_month(2026, 10);

    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 0U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 1U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 2U);
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 2U);

    allocator.set_sequence(conv_id, bucket, 50);
    EXPECT_EQ(allocator.peek_sequence(conv_id, bucket), 50U);
    EXPECT_EQ(allocator.allocate_sequence(conv_id, bucket), 51U);
}

} // namespace
} // namespace securecloud::messaging::service::test
