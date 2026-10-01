#include "http/streaming/streaming_buffer.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <random>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace securecloud::gateway::http {
namespace {

// =============================================================================
// StreamingBuffer Unit Tests
// =============================================================================

TEST(StreamingBufferTest, BasicReadWrite) {
    StreamingBuffer buffer(1024, std::chrono::milliseconds(1000));
    EXPECT_TRUE(buffer.is_open());
    EXPECT_EQ(buffer.buffered_bytes(), 0u);

    std::string payload = "Hello SecureCloud Streaming Proxy!";
    auto write_res = buffer.write(payload);
    EXPECT_TRUE(write_res.ok());
    EXPECT_EQ(write_res.bytes_written, payload.size());
    EXPECT_EQ(buffer.buffered_bytes(), payload.size());

    auto read_res = buffer.read(500);
    EXPECT_TRUE(read_res.ok());
    EXPECT_EQ(read_res.bytes_read, payload.size());
    EXPECT_EQ(read_res.data, payload);
    EXPECT_EQ(buffer.buffered_bytes(), 0u);
}

TEST(StreamingBufferTest, PartialReadsPreserveOrdering) {
    StreamingBuffer buffer(2048, std::chrono::milliseconds(1000));
    std::string payload(300, 'x');
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<char>('A' + (i % 26));
    }

    auto write_res = buffer.write(payload);
    EXPECT_TRUE(write_res.ok());
    EXPECT_EQ(write_res.bytes_written, 300u);

    std::string accumulated;
    while (accumulated.size() < payload.size()) {
        auto read_res = buffer.read(64);
        ASSERT_TRUE(read_res.ok());
        ASSERT_GT(read_res.bytes_read, 0u);
        accumulated += read_res.data;
    }

    EXPECT_EQ(accumulated, payload);
    EXPECT_EQ(buffer.buffered_bytes(), 0u);
}

TEST(StreamingBufferTest, CapacityAndBackpressureBlocking) {
    const size_t capacity = 512;
    StreamingBuffer buffer(capacity, std::chrono::milliseconds(2000));

    // Fill buffer to capacity
    std::string chunk1(512, '1');
    auto res1 = buffer.write(chunk1);
    EXPECT_TRUE(res1.ok());
    EXPECT_EQ(buffer.buffered_bytes(), 512u);

    std::atomic<bool> producer_started{false};
    std::atomic<bool> producer_finished{false};
    std::string chunk2(256, '2');

    // Launch producer thread attempting to write past capacity
    std::thread producer([&]() {
        producer_started = true;
        auto res2 = buffer.write(chunk2);
        EXPECT_TRUE(res2.ok());
        EXPECT_EQ(res2.bytes_written, 256u);
        producer_finished = true;
    });

    // Wait until producer has started and blocked
    while (!producer_started) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(producer_finished); // Must be blocked due to backpressure

    // Consumer drains 512 bytes, unblocking producer
    auto read_res = buffer.read(512);
    EXPECT_TRUE(read_res.ok());
    EXPECT_EQ(read_res.bytes_read, 512u);

    producer.join();
    EXPECT_TRUE(producer_finished);
    EXPECT_EQ(buffer.buffered_bytes(), 256u);

    auto drain_res = buffer.read(256);
    EXPECT_TRUE(drain_res.ok());
    EXPECT_EQ(drain_res.data, chunk2);
}

TEST(StreamingBufferTest, EofDrainAndPostCloseBehavior) {
    StreamingBuffer buffer(1024, std::chrono::milliseconds(1000));
    std::string payload = "Pending bytes before EOF";
    ASSERT_TRUE(buffer.write(payload).ok());

    buffer.close();
    EXPECT_TRUE(buffer.is_closed());
    EXPECT_FALSE(buffer.is_open());

    // Write after close must fail with Closed
    auto post_close_write = buffer.write("Should not be accepted");
    EXPECT_EQ(post_close_write.status, StreamStatus::Closed);

    // Reader drains buffered content cleanly
    auto read1 = buffer.read(500);
    EXPECT_TRUE(read1.ok());
    EXPECT_EQ(read1.data, payload);

    // Subsequent read returns EOF
    auto read_eof = buffer.read(500);
    EXPECT_TRUE(read_eof.eof());
    EXPECT_EQ(read_eof.bytes_read, 0u);
}

TEST(StreamingBufferTest, AbortImmediateUnblock) {
    StreamingBuffer buffer(1024, std::chrono::milliseconds(5000));

    std::atomic<bool> reader_started{false};
    std::atomic<bool> reader_finished{false};
    StreamReadResult read_result;

    std::thread reader([&]() {
        reader_started = true;
        read_result = buffer.read(256);
        reader_finished = true;
    });

    while (!reader_started) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(reader_finished);

    buffer.abort("Client reset connection");
    EXPECT_TRUE(buffer.is_aborted());
    EXPECT_EQ(buffer.abort_reason(), "Client reset connection");

    reader.join();
    EXPECT_TRUE(reader_finished);
    EXPECT_TRUE(read_result.aborted());

    // Subsequent operations return Aborted immediately
    EXPECT_TRUE(buffer.write("data").aborted());
    EXPECT_TRUE(buffer.read(100).aborted());
}

TEST(StreamingBufferTest, IdleTimeoutDetection) {
    StreamingBuffer buffer(1024, std::chrono::milliseconds(50));

    // Waiting on empty buffer with 50 ms timeout
    auto read_res = buffer.read(100, std::chrono::milliseconds(50));
    EXPECT_TRUE(read_res.timed_out());
    EXPECT_EQ(read_res.bytes_read, 0u);

    // Check stalled detection
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_TRUE(buffer.is_stalled(std::chrono::milliseconds(50)));
}

// =============================================================================
// StreamingSha256Validator Unit Tests
// =============================================================================

TEST(StreamingSha256ValidatorTest, KnownVectors) {
    // 1. Empty string
    EXPECT_EQ(StreamingSha256Validator::compute_hex(""),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    // 2. Standard NIST sentence
    const std::string text = "The quick brown fox jumps over the lazy dog";
    const std::string expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
    EXPECT_EQ(StreamingSha256Validator::compute_hex(text), expected);

    // 3. Verify method with case insensitivity
    StreamingSha256Validator val;
    val.update(text);
    EXPECT_TRUE(val.verify(expected));
    EXPECT_TRUE(val.verify("D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592"));
    EXPECT_FALSE(val.verify("0000000000000000000000000000000000000000000000000000000000000000"));
}

TEST(StreamingSha256ValidatorTest, IncrementalSlicesMatchOneShot) {
    const std::string text = "SecureCloud distributed high-throughput streaming transfer pipeline!";
    const std::string expected = StreamingSha256Validator::compute_hex(text);

    StreamingSha256Validator incremental_val;
    // Feed in irregular slices (1 byte, 4 bytes, 7 bytes, remainder)
    size_t offset = 0;
    std::vector<size_t> slice_sizes = {1, 4, 7, 13, 2, 5};

    for (size_t size : slice_sizes) {
        if (offset + size <= text.size()) {
            incremental_val.update(std::string_view(text.data() + offset, size));
            offset += size;
        }
    }
    if (offset < text.size()) {
        incremental_val.update(std::string_view(text.data() + offset, text.size() - offset));
    }

    EXPECT_EQ(incremental_val.finalize_hex(), expected);
}

TEST(StreamingSha256ValidatorTest, ResetEnablesReusability) {
    StreamingSha256Validator val;
    val.update("first message");
    const std::string hash1 = val.finalize_hex();

    val.reset();
    val.update("second message");
    const std::string hash2 = val.finalize_hex();

    EXPECT_NE(hash1, hash2);
    EXPECT_EQ(hash2, StreamingSha256Validator::compute_hex("second message"));
}

// =============================================================================
// Concurrent Multi-Threaded Stress Test
// =============================================================================

TEST(StreamingBufferStressTest, ConcurrentProducerConsumerIntegrity) {
    const size_t total_bytes = 1024 * 1024;   // 1 MiB
    const size_t buffer_capacity = 32 * 1024; // 32 KiB bounded buffer

    StreamingBuffer buffer(buffer_capacity, std::chrono::milliseconds(5000));

    // Generate random source payload
    std::string source_data(total_bytes, '\0');
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < total_bytes; ++i) {
        source_data[i] = static_cast<char>(dist(rng));
    }

    const std::string expected_sha256 = StreamingSha256Validator::compute_hex(source_data);

    StreamingSha256Validator consumer_hash;
    std::string received_data;
    received_data.reserve(total_bytes);

    // Producer thread
    std::thread producer([&]() {
        size_t sent = 0;
        const size_t chunk_size = 4096; // 4 KiB writes
        while (sent < total_bytes) {
            size_t to_write = std::min(chunk_size, total_bytes - sent);
            auto res = buffer.write(std::string_view(source_data.data() + sent, to_write));
            ASSERT_TRUE(res.ok());
            sent += res.bytes_written;
        }
        buffer.close();
    });

    // Consumer thread
    std::thread consumer([&]() {
        while (true) {
            auto res = buffer.read(8192); // 8 KiB reads
            if (res.eof()) {
                break;
            }
            ASSERT_TRUE(res.ok());
            consumer_hash.update(res.data);
            received_data += res.data;
        }
    });

    producer.join();
    consumer.join();

    EXPECT_EQ(received_data.size(), total_bytes);
    EXPECT_EQ(received_data, source_data);
    EXPECT_EQ(consumer_hash.finalize_hex(), expected_sha256);
}

} // namespace
} // namespace securecloud::gateway::http

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
