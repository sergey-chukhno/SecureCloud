#include "files/repository/files_outbox_repository.hpp"

#include <chrono>

namespace securecloud::files {

FilesOutboxRepository::FilesOutboxRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

void FilesOutboxRepository::stage_event(const FilesOutboxEntity& event, pqxx::work& tx) {
    if (event.event_id.empty()) {
        throw RepositoryException("Event ID cannot be empty");
    }
    if (event.aggregate_id.empty()) {
        throw RepositoryException("Aggregate ID cannot be empty");
    }
    if (event.event_type.empty()) {
        throw RepositoryException("Event type cannot be empty");
    }
    if (event.payload_json.empty()) {
        throw RepositoryException("Payload JSON cannot be empty");
    }

    std::optional<std::string> processed_str;
    if (event.processed_at.has_value()) {
        processed_str = db::to_iso8601(*event.processed_at);
    }

    tx.exec_params(
        "INSERT INTO files_outbox (event_id, aggregate_type, aggregate_id, event_type, payload_json, status, retry_count, created_at, processed_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        event.event_id,
        event.aggregate_type.empty() ? "FILE" : event.aggregate_type,
        event.aggregate_id,
        event.event_type,
        event.payload_json,
        db::to_string(event.status),
        event.retry_count,
        db::to_iso8601(event.created_at),
        processed_str
    );
}

void FilesOutboxRepository::stage_event(const FilesOutboxEntity& event) {
    pqxx::work tx;
    stage_event(event, tx);
    tx.commit();
}

std::vector<FilesOutboxEntity> FilesOutboxRepository::fetch_pending_events(size_t limit, pqxx::work& tx) {
    auto res = tx.exec_params(
        "SELECT event_id, aggregate_type, aggregate_id, event_type, payload_json, status, retry_count, created_at, processed_at "
        "FROM files_outbox WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED",
        static_cast<uint64_t>(limit)
    );

    std::vector<FilesOutboxEntity> events;
    events.reserve(res.size());
    for (const auto& row : res) {
        events.push_back(db::files_outbox_from_row(row));
    }
    return events;
}

std::vector<FilesOutboxEntity> FilesOutboxRepository::fetch_pending_events(size_t limit) {
    pqxx::work tx;
    return fetch_pending_events(limit, tx);
}

bool FilesOutboxRepository::mark_published(const std::string& event_id, pqxx::work& tx) {
    if (event_id.empty()) {
        return false;
    }

    auto now_iso = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec_params(
        "UPDATE files_outbox SET status = 'PUBLISHED', processed_at = $1 WHERE event_id = $2",
        now_iso,
        event_id
    );

    return res.affected_rows() > 0;
}

bool FilesOutboxRepository::mark_published(const std::string& event_id) {
    pqxx::work tx;
    bool marked = mark_published(event_id, tx);
    if (marked) {
        tx.commit();
    }
    return marked;
}

bool FilesOutboxRepository::mark_failed(const std::string& event_id, pqxx::work& tx) {
    if (event_id.empty()) {
        return false;
    }

    auto res = tx.exec_params(
        "UPDATE files_outbox SET status = 'FAILED', retry_count = retry_count + 1 WHERE event_id = $1",
        event_id
    );

    return res.affected_rows() > 0;
}

bool FilesOutboxRepository::mark_failed(const std::string& event_id) {
    pqxx::work tx;
    bool marked = mark_failed(event_id, tx);
    if (marked) {
        tx.commit();
    }
    return marked;
}

std::optional<FilesOutboxEntity> FilesOutboxRepository::find_by_id(const std::string& event_id, pqxx::work& tx) {
    if (event_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params(
        "SELECT event_id, aggregate_type, aggregate_id, event_type, payload_json, status, retry_count, created_at, processed_at "
        "FROM files_outbox WHERE event_id = $1",
        event_id
    );

    if (res.empty()) {
        return std::nullopt;
    }

    return db::files_outbox_from_row(res[0]);
}

std::optional<FilesOutboxEntity> FilesOutboxRepository::find_by_id(const std::string& event_id) {
    pqxx::work tx;
    return find_by_id(event_id, tx);
}

} // namespace securecloud::files
