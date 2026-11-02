#include "files/storage/bounded_storage_engine.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <thread>
#include <vector>

namespace securecloud::files::storage {
namespace {

class MockStorageEngine : public service::IStorageEngine {
  public:
    std::atomic<size_t> active_ops{0};
    std::atomic<size_t> max_concurrent_ops{0};
    std::chrono::milliseconds artificial_delay{0};

    bool put_chunk(const std::string&, uint32_t, std::string_view, const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    std::optional<std::string> get_chunk(const std::string&, uint32_t) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return "encrypted_chunk_data";
    }

    bool delete_chunk(const std::string&, uint32_t) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    bool put_file_object(const std::string&, uint32_t, std::string_view, const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    std::optional<std::string> get_file_object(const std::string&, uint32_t,
                                               std::optional<storage::ByteRange>) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return "file_data";
    }

    bool delete_file_objects(const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

    bool delete_transfer_chunks(const std::string&) override {
        record_enter();
        if (artificial_delay.count() > 0)
            std::this_thread::sleep_for(artificial_delay);
        record_exit();
        return true;
    }

  private:
    void record_enter() {
        size_t current = ++active_ops;
        size_t prev = max_concurrent_ops.load();
        while (current > prev && !max_concurrent_ops.compare_exchange_weak(prev, current)) {
        }
    }

    void record_exit() { --active_ops; }
};

TEST(BoundedStorageEngineTest, RejectsNullArgumentsInConstructor) {
    auto bulkhead = ConcurrencyBulkhead::create("storage", 5);
    auto mock = std::make_shared<MockStorageEngine>();

    EXPECT_THROW(BoundedStorageEngine(nullptr, bulkhead), std::invalid_argument);
    EXPECT_THROW(BoundedStorageEngine(mock, nullptr), std::invalid_argument);
}

TEST(BoundedStorageEngineTest, ForwardsOperationsWhenWithinLimit) {
    auto mock = std::make_shared<MockStorageEngine>();
    auto bulkhead = ConcurrencyBulkhead::create("storage", 5);
    BoundedStorageEngine engine(mock, bulkhead);

    EXPECT_TRUE(engine.put_chunk("tx1", 0, "data", "sha"));
    auto chunk = engine.get_chunk("tx1", 0);
    ASSERT_TRUE(chunk.has_value());
    EXPECT_EQ(chunk.value(), "encrypted_chunk_data");

    EXPECT_TRUE(engine.delete_chunk("tx1", 0));
    EXPECT_TRUE(engine.put_file_object("f1", 1, "data", "sha"));
    EXPECT_TRUE(engine.get_file_object("f1", 1).has_value());
    EXPECT_TRUE(engine.delete_file_objects("f1"));
    EXPECT_TRUE(engine.delete_transfer_chunks("tx1"));

    // Bulkhead permits should all be released back to 0
    EXPECT_EQ(bulkhead->active_permits(), 0);
}

TEST(BoundedStorageEngineTest, EnforcesConcurrencyLimitAndThrottles) {
    constexpr size_t k_limit = 3;
    auto mock = std::make_shared<MockStorageEngine>();
    mock->artificial_delay = std::chrono::milliseconds(20);

    auto bulkhead = ConcurrencyBulkhead::create("storage", k_limit, std::chrono::milliseconds(500));
    BoundedStorageEngine engine(mock, bulkhead);

    std::vector<std::thread> workers;
    for (size_t i = 0; i < 10; ++i) {
        workers.emplace_back([&engine] { engine.put_chunk("tx", 0, "payload", "sha"); });
    }

    for (auto& w : workers) {
        w.join();
    }

    EXPECT_LE(mock->max_concurrent_ops.load(), k_limit);
    EXPECT_EQ(bulkhead->active_permits(), 0);
}

TEST(BoundedStorageEngineTest, ThrowsStorageCapacityExhaustedWhenTimedOut) {
    auto mock = std::make_shared<MockStorageEngine>();
    // Bulkhead capacity of 1 with 30ms timeout
    auto bulkhead = ConcurrencyBulkhead::create("storage", 1, std::chrono::milliseconds(30));
    BoundedStorageEngine engine(mock, bulkhead);

    // Manually hold the only permit
    auto permit = bulkhead->try_acquire();
    ASSERT_TRUE(permit.holds_permit());

    // Storage call should time out and throw StorageCapacityExhaustedException
    EXPECT_THROW(engine.get_chunk("tx", 0), StorageCapacityExhaustedException);

    permit.release();
    // After releasing, should succeed
    EXPECT_NO_THROW(engine.get_chunk("tx", 0));
}

} // namespace
} // namespace securecloud::files::storage
