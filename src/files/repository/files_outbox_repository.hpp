#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/db/pqxx_compat.hpp"
#include "files/db/pqxx_mappers.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/repository/file_repository.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::files {

/// Authoritative repository managing transactional outbox audit events.
/// Enforces guaranteed at-least-once dispatching and atomic domain-event persistence
/// (ADR-005, Files Design 6.22).
/// Maps 1:1 to the `files_outbox` PostgreSQL table.
class FilesOutboxRepository {
  public:
    explicit FilesOutboxRepository(std::shared_ptr<db::FilesDbConnectionPool> pool = nullptr);

    /// Stages a new audit event into the outbox within transaction `tx`.
    /// Must be called within the same transaction as domain model mutations.
    void stage_event(const FilesOutboxEntity& event, pqxx::work& tx);

    /// Stages an audit event (creates autonomous work session).
    void stage_event(const FilesOutboxEntity& event);

    /// Fetches a batch of pending events ordered by creation timestamp ascending.
    /// Utilizes `SELECT ... FOR UPDATE SKIP LOCKED` for concurrency without row lock contention.
    [[nodiscard]] std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit, pqxx::work& tx);

    /// Fetches pending events (creates autonomous work session).
    [[nodiscard]] std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit);

    /// Marks an outbox event as published, setting processed_at = NOW() within transaction `tx`.
    /// Returns true if updated; returns false if event_id does not exist.
    bool mark_published(const std::string& event_id, pqxx::work& tx);

    /// Marks an event as published (creates autonomous work session).
    bool mark_published(const std::string& event_id);

    /// Marks an event as failed and increments retry_count within transaction `tx`.
    /// Returns true if updated; returns false if event_id does not exist.
    bool mark_failed(const std::string& event_id, pqxx::work& tx);

    /// Marks an event as failed (creates autonomous work session).
    bool mark_failed(const std::string& event_id);

    /// Finds an outbox event by its ID within transaction `tx`.
    [[nodiscard]] std::optional<FilesOutboxEntity> find_by_id(const std::string& event_id, pqxx::work& tx);

    /// Finds an outbox event by its ID (creates autonomous work session).
    [[nodiscard]] std::optional<FilesOutboxEntity> find_by_id(const std::string& event_id);

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
};

} // namespace securecloud::files
