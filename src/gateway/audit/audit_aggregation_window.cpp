#include "audit/audit_aggregation_window.hpp"

namespace securecloud::gateway::audit {

AuditAggregationWindow::AuditAggregationWindow(uint32_t window_sec, size_t max_keys, FlushCallback flush_cb)
    : window_sec_(window_sec), max_keys_(max_keys), flush_cb_(std::move(flush_cb)) {
    flush_thread_ = std::thread(&AuditAggregationWindow::background_flush_loop, this);
}

AuditAggregationWindow::~AuditAggregationWindow() {
    running_.store(false, std::memory_order_release);
    cv_.notify_all();
    if (flush_thread_.joinable()) {
        flush_thread_.join();
    }
    flush_all();
}

void AuditAggregationWindow::add(GatewayAuditObservation observation) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);

        const std::string key = std::to_string(static_cast<uint8_t>(observation.type)) + ":" + observation.client_ip +
                                ":" + observation.route_class;

        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second.count++;
            lru_list_.erase(it->second.lru_iter);
            lru_list_.push_front(key);
            it->second.lru_iter = lru_list_.begin();
        } else {
            // Enforce max_keys via LRU eviction flush
            if (map_.size() >= max_keys_ && !lru_list_.empty()) {
                const std::string oldest_key = lru_list_.back();
                auto oldest_it = map_.find(oldest_key);
                if (oldest_it != map_.end()) {
                    if (flush_cb_) {
                        flush_cb_(oldest_it->second.observation, oldest_it->second.count);
                    }
                    map_.erase(oldest_it);
                }
                lru_list_.pop_back();
            }

            lru_list_.push_front(key);
            WindowEntry entry{.observation = std::move(observation),
                              .count = 1,
                              .window_start = std::chrono::steady_clock::now(),
                              .lru_iter = lru_list_.begin()};
            map_.emplace(key, std::move(entry));
        }
    } catch (...) {
        // Guarantee noexceptions on observation path
    }
}

void AuditAggregationWindow::flush_all() noexcept {
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [key, entry] : map_) {
            if (flush_cb_) {
                flush_cb_(entry.observation, entry.count);
            }
        }
        map_.clear();
        lru_list_.clear();
    } catch (...) {
    }
}

void AuditAggregationWindow::background_flush_loop() {
    while (running_.load(std::memory_order_acquire)) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::seconds(window_sec_),
                         [this] { return !running_.load(std::memory_order_relaxed); });
        }

        if (!running_.load(std::memory_order_relaxed)) {
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        std::vector<std::pair<GatewayAuditObservation, uint32_t>> to_flush;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = map_.begin(); it != map_.end();) {
                if (now - it->second.window_start >= std::chrono::seconds(window_sec_)) {
                    to_flush.emplace_back(it->second.observation, it->second.count);
                    lru_list_.erase(it->second.lru_iter);
                    it = map_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        for (auto& [obs, count] : to_flush) {
            if (flush_cb_) {
                flush_cb_(obs, count);
            }
        }
    }
}

} // namespace securecloud::gateway::audit
