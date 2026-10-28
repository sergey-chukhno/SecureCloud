#pragma once

#include "ingestion/ingestion_envelope.hpp"

#include <grpcpp/grpcpp.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <vector>

namespace securecloud::audit::ingestion {

    class BoundedIngestionQueue {
    public:
        explicit BoundedIngestionQueue(size_t capacity = 10000);
        ~BoundedIngestionQueue();

        BoundedIngestionQueue(const BoundedIngestionQueue&) = delete;
        BoundedIngestionQueue& operator=(const BoundedIngestionQueue&) = delete;

        [[nodiscard]] bool try_push(IngestionEnvelope item);

        [[nodiscard]] bool push_with_timeout(IngestionEnvelope item, std::chrono::milliseconds timeout);

        [[nodiscard]] std::optional<IngestionEnvelope> pop(std::chrono::milliseconds timeout);

        [[nodiscard]] std::vector<IngestionEnvelope> pop_batch(size_t max_items, std::chrono::milliseconds timeout);

        [[nodiscard]] size_t size() const noexcept;

        [[nodiscard]] size_t capacity() const noexcept;

        [[nodiscard]] bool is_shutdown() const noexcept;

        void shutdown() noexcept;

        [[nodiscard]] size_t total_enqueued() const noexcept;

        [[nodiscard]] size_t total_rejected() const noexcept;

        [[nodiscard]] size_t peak_watermark() const noexcept;

    private:
        const size_t capacity_;
        mutable std::mutex mutex_;
        std::condition_variable cv_not_full_;
        std::condition_variable cv_not_empty_;
        std::deque<IngestionEnvelope> queue_;
        bool shutdown_{false};

        std::atomic<size_t> total_enqueued_{0};
        std::atomic<size_t> total_rejected_{0};
        std::atomic<size_t> peak_watermark_{0};
    };

    [[nodiscard]] grpc::Status create_backpressure_status(grpc::ServerContext* context = nullptr);

} // namespace securecloud::audit::ingestion