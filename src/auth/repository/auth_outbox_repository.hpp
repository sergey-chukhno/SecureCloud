#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/auth_outbox_entity.hpp"
#include "auth/repository/exceptions.hpp"

#include <chrono>
#include <cstddef>
#include <pqxx/pqxx>
#include <string_view>
#include <vector>

namespace securecloud::auth::repository {

/// Abstract interface contract for Auth Transactional Outbox persistence.
class IAuthOutboxRepository {
  public:
    virtual ~IAuthOutboxRepository() = default;

    /// Category A: Stages an event inside an active business PostgreSQL transaction.
    virtual void stage_event(const domain::AuthOutboxEntity& event, pqxx::transaction_base& tx) = 0;

    /// Category B: Stages an event using a dedicated autonomous transaction with immediate commit.
    virtual void stage_event(const domain::AuthOutboxEntity& event) = 0;

    /// Atomically claims and leases a batch of pending events using SELECT ... FOR UPDATE SKIP LOCKED.
    [[nodiscard]] virtual std::vector<domain::AuthOutboxEntity>
    fetch_and_lease_pending_batch(std::size_t limit, std::chrono::seconds lease_duration) = 0;

    /// Marks an event as successfully delivered and acknowledged by Audit Service.
    virtual bool mark_published(const domain::Uuid& event_id) = 0;

    /// Records a transient failure error and keeps event eligible for future retry.
    virtual bool mark_failed(const domain::Uuid& event_id, std::string_view error) = 0;

    /// Quarantines a terminally rejected event so it will not be retried.
    virtual bool mark_quarantined(const domain::Uuid& event_id, std::string_view reason) = 0;

    /// Deletes historically published events older than cutoff in bounded batches.
    virtual std::size_t purge_published_older_than(std::chrono::system_clock::time_point cutoff,
                                                   std::size_t batch_size) = 0;

    /// Counts currently pending records in the outbox table.
    [[nodiscard]] virtual std::size_t count_pending() = 0;
};

/// PostgreSQL-backed implementation of IAuthOutboxRepository.
class PostgresAuthOutboxRepository : public IAuthOutboxRepository {
  public:
    explicit PostgresAuthOutboxRepository(db::PostgresConnectionPool& pool);

    void stage_event(const domain::AuthOutboxEntity& event, pqxx::transaction_base& tx) override;
    void stage_event(const domain::AuthOutboxEntity& event) override;

    [[nodiscard]] std::vector<domain::AuthOutboxEntity>
    fetch_and_lease_pending_batch(std::size_t limit, std::chrono::seconds lease_duration) override;

    bool mark_published(const domain::Uuid& event_id) override;
    bool mark_failed(const domain::Uuid& event_id, std::string_view error) override;
    bool mark_quarantined(const domain::Uuid& event_id, std::string_view reason) override;

    std::size_t purge_published_older_than(std::chrono::system_clock::time_point cutoff,
                                           std::size_t batch_size) override;

    [[nodiscard]] std::size_t count_pending() override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
