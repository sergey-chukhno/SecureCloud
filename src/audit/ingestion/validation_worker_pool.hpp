#pragma once

#include "ingestion/bounded_ingestion_queue.hpp"
#include "ingestion/deduplication_interface.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::audit::ingestion {

    class ValidationWorkerPool {
    public:
        ValidationWorkerPool(
            size_t num_workers,
            std::shared_ptr<BoundedIngestionQueue> input_queue,
            std::shared_ptr<BoundedIngestionQueue> output_queue,
            std::shared_ptr<IDeduplicationManager> dedup_manager = nullptr);

        ~ValidationWorkerPool();

        ValidationWorkerPool(const ValidationWorkerPool&) = delete;
        ValidationWorkerPool& operator=(const ValidationWorkerPool&) = delete;

        void start();
        void stop() noexcept;

        [[nodiscard]] bool is_running() const noexcept;
        [[nodiscard]] size_t total_validated() const noexcept;
        [[nodiscard]] size_t total_rejected() const noexcept;
        [[nodiscard]] size_t total_duplicates() const noexcept;

    private:
        void worker_loop();

        const size_t num_workers_;
        std::shared_ptr<BoundedIngestionQueue> input_queue_;
        std::shared_ptr<BoundedIngestionQueue> output_queue_;
        std::shared_ptr<IDeduplicationManager> dedup_manager_;

        std::atomic<bool> running_{false};
        std::vector<std::thread> workers_;

        std::atomic<size_t> total_validated_{0};
        std::atomic<size_t> total_rejected_{0};
        std::atomic<size_t> total_duplicates_{0};
    };

} // namespace securecloud::audit::ingestion