#pragma once

#include "audit_event_repository_interface.hpp"
#include "clickhouse_client.hpp"

#include <memory>

namespace securecloud::audit::repository {

/// Authoritative ClickHouse repository implementing IAuditEventRepository.
class ClickHouseAuditEventRepository : public IAuditEventRepository {
  public:
    explicit ClickHouseAuditEventRepository(std::shared_ptr<ClickHouseClient> client);
    ~ClickHouseAuditEventRepository() override = default;

    bool insert_batch(const std::vector<domain::AuditEvent>& events) override;

    std::vector<domain::AuditEvent> query_by_time_range(std::chrono::system_clock::time_point start,
                                                        std::chrono::system_clock::time_point end,
                                                        uint32_t limit) override;

    std::vector<domain::AuditEvent> query_by_producer(const std::string& producer_service,
                                                      std::chrono::system_clock::time_point start,
                                                      std::chrono::system_clock::time_point end,
                                                      uint32_t limit) override;

    std::vector<domain::AuditEvent> query_by_correlation_id(const std::string& correlation_id, uint32_t limit) override;

    std::optional<domain::AuditEvent> find_by_event_id(const domain::EventId& event_id) override;

  private:
    std::shared_ptr<ClickHouseClient> client_;
    static constexpr uint32_t kMaxQueryLimit = 1000;

    [[nodiscard]] uint32_t clamp_limit(uint32_t limit) const noexcept;
    [[nodiscard]] static std::string escape_sql_string(const std::string& str);
};

} // namespace securecloud::audit::repository