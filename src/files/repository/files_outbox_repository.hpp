#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/repository/file_repository.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::files {

/// Abstract interface for transactional outbox persistence and lease-based relay operations (`AUDIT-015`).
class IFilesOutboxRepository {
  public:
    virtual ~IFilesOutboxRepository() = default;

    /// Category A: Stages a new audit event inside an active business transaction `tx`.
    virtual void stage_event(const FilesOutboxEntity& event, pqxx::work& tx) = 0;

    /// Category B: Stages a new audit event in an autonomous committed transaction.
    virtual void stage_event(const FilesOutboxEntity& event) = 0;

    /// Atomically claims up to `limit` eligible PENDING rows (`leased_until IS NULL OR leased_until < NOW()`),
    /// extends `leased_until = NOW() + lease_duration`, increments `retry_count`, and commits immediately.
    [[nodiscard]] virtual std::vector<FilesOutboxEntity>
    fetch_and_lease_pending_batch(size_t limit, std::chrono::seconds lease_duration) = 0;

    /// Backward-compatible wrapper delegating to `fetch_and_lease_pending_batch(limit, 30s)`.
    [[nodiscard]] virtual std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit) = 0;

    /// Transitions an event to `PUBLISHED`, recording `processed_at = NOW()` and clearing `leased_until`.
    virtual bool mark_published(const std::string& event_id) = 0;

    /// Records a transient delivery failure while keeping `status = 'PENDING'` and clearing `leased_until`
    /// so the event is never stranded and can be retried after exponential backoff.
    virtual bool record_transient_failure(const std::string& event_id, std::string_view sanitized_error) = 0;

    /// Isolates a permanently rejected or poison-pill event into `QUARANTINED` state so healthy
    /// throughput is never blocked.
    virtual bool mark_quarantined(const std::string& event_id, std::string_view sanitized_reason) = 0;

    /// Deletes up to `batch_size` acknowledged `PUBLISHED` rows older than `cutoff` in a single bounded transaction.
    virtual size_t purge_published_older_than(std::chrono::system_clock::time_point cutoff, size_t batch_size) = 0;

    /// Returns current count of `PENDING` outbox rows.
    [[nodiscard]] virtual size_t count_pending() = 0;

    /// Returns age in seconds of the oldest `PENDING` outbox row (0.0 if none).
    [[nodiscard]] virtual double oldest_pending_age_seconds() = 0;

    /// Finds an outbox event by its canonical `event_id`.
    [[nodiscard]] virtual std::optional<FilesOutboxEntity> find_by_id(const std::string& event_id) = 0;
};

/// Authoritative PostgreSQL repository managing transactional outbox audit events (`V002`).
/// Enforces guaranteed at-least-once dispatching, atomic domain-event persistence,
/// `FOR UPDATE SKIP LOCKED` multi-worker leasing, and poison-pill quarantine (`ADR-005`, `ADR-007`).
class FilesOutboxRepository : public IFilesOutboxRepository {
  public:
    explicit FilesOutboxRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);
    ~FilesOutboxRepository() override = default;

    void stage_event(const FilesOutboxEntity& event, pqxx::work& tx) override;
    void stage_event(const FilesOutboxEntity& event) override;

    [[nodiscard]] std::vector<FilesOutboxEntity>
    fetch_and_lease_pending_batch(size_t limit, std::chrono::seconds lease_duration) override;

    /// Transaction-bound variant for callers managing an explicit `pqxx::work`.
    [[nodiscard]] virtual std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit, pqxx::work& tx);
    [[nodiscard]] std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit) override;

    virtual bool mark_published(const std::string& event_id, pqxx::work& tx);
    bool mark_published(const std::string& event_id) override;

    bool record_transient_failure(const std::string& event_id, std::string_view sanitized_error) override;
    bool mark_quarantined(const std::string& event_id, std::string_view sanitized_reason) override;

    /// Legacy M5 failure marker retained for backward compatibility with existing M5 unit tests.
    virtual bool mark_failed(const std::string& event_id, pqxx::work& tx);
    virtual bool mark_failed(const std::string& event_id);

    size_t purge_published_older_than(std::chrono::system_clock::time_point cutoff, size_t batch_size) override;

    [[nodiscard]] size_t count_pending() override;
    [[nodiscard]] double oldest_pending_age_seconds() override;

    [[nodiscard]] virtual std::optional<FilesOutboxEntity> find_by_id(const std::string& event_id, pqxx::work& tx);
    [[nodiscard]] std::optional<FilesOutboxEntity> find_by_id(const std::string& event_id) override;

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
