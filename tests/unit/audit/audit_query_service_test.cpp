#include "query/audit_query_application_service.hpp"
#include "repository/audit_repository_exceptions.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <set>

namespace securecloud::audit::query::testing {

class MemoryAuditRepository : public repository::IAuditEventRepository {
  public:
    bool insert_batch(const std::vector<domain::AuditEvent>& events) override {
        storage_.insert(storage_.end(), events.begin(), events.end());
        return true;
    }

    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point,
                                                        std::chrono::system_clock::time_point, uint32_t) override {
        return {};
    }
    std::vector<domain::AuditEvent> query_by_producer(const std::string&, std::chrono::system_clock::time_point,
                                                      std::chrono::system_clock::time_point, uint32_t) override {
        return {};
    }
    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string&, uint32_t) override { return {}; }

    std::vector<domain::AuditEvent> execute_paged_query(const AuditQueryFilter& filter,
                                                        const std::optional<AuditPageCursor>& cursor, uint32_t,
                                                        size_t) override {

        if (should_timeout)
            throw repository::ClickHouseTimeoutException("Query timeout");
        if (should_fail)
            throw repository::ClickHouseConnectionException("Connection refused");

        std::vector<domain::AuditEvent> filtered;
        for (const auto& ev : storage_) {
            if (filter.start_occurred_at && ev.occurred_at < *filter.start_occurred_at)
                continue;
            if (filter.end_occurred_at && ev.occurred_at >= *filter.end_occurred_at)
                continue;

            if (!filter.producer_services.empty() &&
                std::find(filter.producer_services.begin(), filter.producer_services.end(), ev.producer_service) ==
                    filter.producer_services.end()) {
                continue;
            }

            if (!filter.event_types.empty() && std::find(filter.event_types.begin(), filter.event_types.end(),
                                                         ev.event_type) == filter.event_types.end()) {
                continue;
            }

            if (filter.correlation_id && ev.correlation_id != *filter.correlation_id)
                continue;

            // Keyset cursor predicate evaluation
            if (cursor.has_value()) {
                int64_t ev_ts =
                    std::chrono::duration_cast<std::chrono::milliseconds>(ev.occurred_at.time_since_epoch()).count();
                if (filter.sort_order == SortOrder::Descending) {
                    if (ev_ts > cursor->last_occurred_at_ms)
                        continue;
                    if (ev_ts == cursor->last_occurred_at_ms &&
                        ev.event_id.to_string() >= cursor->last_event_id.to_string())
                        continue;
                } else {
                    if (ev_ts < cursor->last_occurred_at_ms)
                        continue;
                    if (ev_ts == cursor->last_occurred_at_ms &&
                        ev.event_id.to_string() <= cursor->last_event_id.to_string())
                        continue;
                }
            }

            filtered.push_back(ev);
        }

        // Sorting
        std::sort(filtered.begin(), filtered.end(),
                  [order = filter.sort_order](const domain::AuditEvent& a, const domain::AuditEvent& b) {
                      if (a.occurred_at != b.occurred_at) {
                          return order == SortOrder::Descending ? a.occurred_at > b.occurred_at
                                                                : a.occurred_at < b.occurred_at;
                      }
                      return order == SortOrder::Descending ? a.event_id.to_string() > b.event_id.to_string()
                                                            : a.event_id.to_string() < b.event_id.to_string();
                  });

        // Limit L + 1 for lookahead
        uint32_t limit = filter.page_size + 1;
        if (filtered.size() > limit) {
            filtered.resize(limit);
        }

        return filtered;
    }

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId& id) override {
        if (should_timeout)
            throw repository::ClickHouseTimeoutException("Lookup timeout");
        if (should_fail)
            throw repository::ClickHouseConnectionException("Connection refused");

        for (const auto& ev : storage_) {
            if (ev.event_id == id)
                return ev;
        }
        return std::nullopt;
    }

    std::vector<domain::AuditEvent> storage_;
    bool should_timeout{false};
    bool should_fail{false};
};

class AuditQueryServiceTest : public ::testing::Test {
  protected:
    void SetUp() override {
        repo_ = std::make_shared<MemoryAuditRepository>();
        config_.workers = 4;
        config_.default_page_limit = 100;
        config_.max_page_limit = 1000;
        service_ = std::make_unique<AuditQueryApplicationService>(repo_, config_);
    }

    domain::PeerIdentity audit_peer() {
        domain::PeerIdentity peer;
        peer.is_authenticated = true;
        peer.common_name = "audit.securecloud.internal";
        return peer;
    }

    std::shared_ptr<MemoryAuditRepository> repo_;
    QueryConfig config_;
    std::unique_ptr<AuditQueryApplicationService> service_;
};

TEST_F(AuditQueryServiceTest, MultiPageKeysetPaginationAcross250EventsZeroDuplicatesOrOmissions) {
    auto base_ts = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));

    // Seed 250 events with repeating timestamps to test multi-event collision handling
    for (size_t i = 0; i < 250; ++i) {
        domain::AuditEvent ev;
        ev.event_id = domain::EventId::generate_v7();
        ev.occurred_at = base_ts + std::chrono::milliseconds((i / 5) * 1000); // 5 events per second
        ev.producer_service = domain::ProducerService::Auth;
        ev.event_type = "user.login";
        repo_->storage_.push_back(ev);
    }

    AuditQueryFilter filter;
    filter.start_occurred_at = base_ts;
    filter.end_occurred_at = base_ts + std::chrono::hours(1);
    filter.page_size = 100;
    filter.sort_order = SortOrder::Descending;

    std::vector<domain::AuditEvent> retrieved_events;
    std::set<std::string> retrieved_ids;
    std::string page_token;
    size_t pages_count = 0;

    do {
        filter.page_token = page_token;
        AuditQueryPageResult page_result;

        auto status = service_->execute_query(audit_peer(), filter, page_result);
        ASSERT_TRUE(status.ok());

        pages_count++;
        for (const auto& ev : page_result.events) {
            std::string id_str = ev.event_id.to_string();
            EXPECT_TRUE(retrieved_ids.insert(id_str).second) << "Duplicate event detected: " << id_str;
            retrieved_events.push_back(ev);
        }

        page_token = page_result.next_page_token;
    } while (!page_token.empty());

    EXPECT_EQ(pages_count, 3);
    EXPECT_EQ(retrieved_events.size(), 250);
}

TEST_F(AuditQueryServiceTest, GetAuditEventByIdTimestampPruningAndNonExistentId) {
    domain::AuditEvent ev;
    ev.event_id = domain::EventId::generate_v7();
    ev.occurred_at = std::chrono::system_clock::now();
    ev.producer_service = domain::ProducerService::Auth;
    ev.event_type = "user.login";
    repo_->storage_.push_back(ev);

    // 1. Existing ID lookup
    std::optional<domain::AuditEvent> result;
    auto status = service_->get_event_by_id(audit_peer(), ev.event_id.to_string(), result);
    EXPECT_TRUE(status.ok());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->event_id, ev.event_id);

    // 2. Non-existent ID lookup
    std::optional<domain::AuditEvent> empty_result;
    auto random_id = domain::EventId::generate_v7().to_string();
    auto status_missing = service_->get_event_by_id(audit_peer(), random_id, empty_result);
    EXPECT_TRUE(status_missing.ok());
    EXPECT_FALSE(empty_result.has_value());
}

} // namespace securecloud::audit::query::testing