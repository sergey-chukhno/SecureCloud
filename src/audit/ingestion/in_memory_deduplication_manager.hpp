#pragma once

#include "ingestion/deduplication_interface.hpp"

#include <list>
#include <mutex>
#include <unordered_map>

namespace securecloud::audit::ingestion {

/// No-op implementation of IDeduplicationManager that treats all events as unique.
class NoopDeduplicationManager : public IDeduplicationManager {
  public:
    [[nodiscard]] bool is_duplicate(const domain::EventId& /*event_id*/, uint64_t /*occurred_at_ms*/) override {
        return false;
    }

    void record_processed(const domain::EventId& /*event_id*/, uint64_t /*occurred_at_ms*/) override {}
};

/// Thread-safe in-memory LRU cache deduplication manager (default capacity: 10,000 entries).
class InMemoryLruDeduplicationManager : public IDeduplicationManager {
  public:
    explicit InMemoryLruDeduplicationManager(size_t capacity = 10000) : capacity_(capacity == 0 ? 1 : capacity) {}

    [[nodiscard]] bool is_duplicate(const domain::EventId& event_id, uint64_t /*occurred_at_ms*/) override {
        std::lock_guard<std::mutex> lock(mutex_);
        return lookup_map_.find(event_id.to_string()) != lookup_map_.end();
    }

    void record_processed(const domain::EventId& event_id, uint64_t /*occurred_at_ms*/) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string id_str = event_id.to_string();

        auto it = lookup_map_.find(id_str);
        if (it != lookup_map_.end()) {
            lru_list_.erase(it->second);
        } else if (lru_list_.size() >= capacity_) {
            std::string oldest = lru_list_.back();
            lru_list_.pop_back();
            lookup_map_.erase(oldest);
        }

        lru_list_.push_front(id_str);
        lookup_map_[id_str] = lru_list_.begin();
    }

  private:
    const size_t capacity_;
    mutable std::mutex mutex_;
    std::list<std::string> lru_list_;
    std::unordered_map<std::string, std::list<std::string>::iterator> lookup_map_;
};

} // namespace securecloud::audit::ingestion