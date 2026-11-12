#include "auth/repository/auth_outbox_repository.hpp"

#include "auth/domain/timestamp.hpp"

#include <string>

namespace securecloud::auth::repository {

namespace {

constexpr std::string_view kInsertOutboxEventSql =
    "INSERT INTO auth_outbox ("
    "    event_id, aggregate_type, aggregate_id, event_type, severity,"
    "    payload_json, status, retry_count, created_at, processed_at, last_error, leased_until"
    ") VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12);";

constexpr std::string_view kFetchAndLeaseBatchSql =
    "UPDATE auth_outbox "
    "SET leased_until = NOW() + ($2 || ' seconds')::interval, "
    "    retry_count = retry_count + 1 "
    "WHERE event_id IN ("
    "    SELECT event_id "
    "    FROM auth_outbox "
    "    WHERE status = 'PENDING' "
    "      AND (leased_until IS NULL OR leased_until < NOW()) "
    "    ORDER BY created_at ASC "
    "    LIMIT $1 "
    "    FOR UPDATE SKIP LOCKED"
    ") "
    "RETURNING event_id, aggregate_type, aggregate_id, event_type, severity, "
    "          payload_json::text, status, retry_count, created_at, "
    "          processed_at, last_error, leased_until;";

constexpr std::string_view kMarkPublishedSql =
    "UPDATE auth_outbox "
    "SET status = 'PUBLISHED', "
    "    processed_at = NOW(), "
    "    leased_until = NULL, "
    "    last_error = NULL "
    "WHERE event_id = $1 AND status = 'PENDING';";

constexpr std::string_view kMarkFailedSql =
    "UPDATE auth_outbox "
    "SET last_error = $2, "
    "    leased_until = NULL "
    "WHERE event_id = $1 AND status = 'PENDING';";

constexpr std::string_view kMarkQuarantinedSql =
    "UPDATE auth_outbox "
    "SET status = 'QUARANTINED', "
    "    processed_at = NOW(), "
    "    last_error = $2, "
    "    leased_until = NULL "
    "WHERE event_id = $1 AND status IN ('PENDING', 'FAILED');";

constexpr std::string_view kPurgePublishedSql =
    "DELETE FROM auth_outbox "
    "WHERE event_id IN ("
    "    SELECT event_id "
    "    FROM auth_outbox "
    "    WHERE status = 'PUBLISHED' AND processed_at < $1 "
    "    LIMIT $2"
    ");";

constexpr std::string_view kCountPendingSql =
    "SELECT COUNT(*) FROM auth_outbox WHERE status = 'PENDING';";

domain::AuthOutboxEntity outbox_entity_from_row(const pqxx::row& row) {
    domain::AuthOutboxEntity entity;

    auto parsed_event_id = domain::Uuid::from_string(row[0].as<std::string>());
    if (!parsed_event_id) {
        throw DatabaseExecutionException("Corrupted event_id UUID in auth_outbox");
    }
    entity.event_id = *parsed_event_id;
    entity.aggregate_type = row[1].as<std::string>();

    if (!row[2].is_null()) {
        auto parsed_agg_id = domain::Uuid::from_string(row[2].as<std::string>());
        if (!parsed_agg_id) {
            throw DatabaseExecutionException("Corrupted aggregate_id UUID in auth_outbox");
        }
        entity.aggregate_id = *parsed_agg_id;
    }

    entity.event_type = row[3].as<std::string>();

    auto parsed_sev = domain::parse_outbox_severity(row[4].as<std::string>());
    entity.severity = parsed_sev.value_or(domain::OutboxSeverity::Info);

    entity.payload_json = row[5].as<std::string>();

    auto parsed_status = domain::parse_outbox_status(row[6].as<std::string>());
    entity.status = parsed_status.value_or(domain::OutboxStatus::Pending);

    entity.retry_count = row[7].as<int32_t>();

    auto parsed_created_at = domain::from_iso8601(row[8].as<std::string>());
    if (!parsed_created_at) {
        throw DatabaseExecutionException("Corrupted created_at timestamp in auth_outbox");
    }
    entity.created_at = *parsed_created_at;

    if (!row[9].is_null()) {
        entity.processed_at = domain::from_iso8601(row[9].as<std::string>());
    }
    if (!row[10].is_null()) {
        entity.last_error = row[10].as<std::string>();
    }
    if (!row[11].is_null()) {
        entity.leased_until = domain::from_iso8601(row[11].as<std::string>());
    }

    return entity;
}

} // namespace

PostgresAuthOutboxRepository::PostgresAuthOutboxRepository(db::PostgresConnectionPool& pool) : pool_(pool) {}

void PostgresAuthOutboxRepository::stage_event(const domain::AuthOutboxEntity& event, pqxx::transaction_base& tx) {
    try {
        const std::optional<std::string> agg_id_str =
            event.aggregate_id.has_value() ? std::optional<std::string>{event.aggregate_id->to_string()} : std::nullopt;

        const std::optional<std::string> processed_at_str =
            event.processed_at.has_value() ? std::optional<std::string>{domain::to_iso8601(*event.processed_at)}
                                           : std::nullopt;

        const std::optional<std::string> leased_until_str =
            event.leased_until.has_value() ? std::optional<std::string>{domain::to_iso8601(*event.leased_until)}
                                           : std::nullopt;

        db::exec_sql(tx, kInsertOutboxEventSql,
                     pqxx::params{event.event_id.to_string(), event.aggregate_type, agg_id_str, event.event_type,
                                  domain::to_string(event.severity), event.payload_json,
                                  domain::to_string(event.status), event.retry_count,
                                  domain::to_iso8601(event.created_at), processed_at_str, event.last_error,
                                  leased_until_str});
    } catch (const pqxx::unique_violation&) {
        throw DuplicateEntityException("Duplicate outbox event_id: " + event.event_id.to_string());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to stage outbox event: " + std::string(ex.what()));
    }
}

void PostgresAuthOutboxRepository::stage_event(const domain::AuthOutboxEntity& event) {
    auto conn = pool_.acquire();
    pqxx::work tx(*conn);
    stage_event(event, tx);
    tx.commit();
}

std::vector<domain::AuthOutboxEntity>
PostgresAuthOutboxRepository::fetch_and_lease_pending_batch(std::size_t limit, std::chrono::seconds lease_duration) {
    if (limit == 0) {
        return {};
    }

    try {
        auto conn = pool_.acquire();
        pqxx::work tx(*conn);

        auto res = db::exec_sql(tx, kFetchAndLeaseBatchSql,
                                pqxx::params{static_cast<int64_t>(limit), static_cast<int64_t>(lease_duration.count())});

        std::vector<domain::AuthOutboxEntity> entities;
        entities.reserve(static_cast<std::size_t>(res.size()));
        for (const auto& row : res) {
            entities.push_back(outbox_entity_from_row(pqxx::row(row)));
        }

        tx.commit();
        return entities;
    } catch (const RepositoryException&) {
        throw;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to fetch and lease pending outbox batch: " + std::string(ex.what()));
    }
}

bool PostgresAuthOutboxRepository::mark_published(const domain::Uuid& event_id) {
    try {
        auto conn = pool_.acquire();
        pqxx::work tx(*conn);
        auto res = db::exec_sql(tx, kMarkPublishedSql, pqxx::params{event_id.to_string()});
        tx.commit();
        return res.affected_rows() > 0;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to mark outbox event published: " + std::string(ex.what()));
    }
}

bool PostgresAuthOutboxRepository::mark_failed(const domain::Uuid& event_id, std::string_view error) {
    try {
        auto conn = pool_.acquire();
        pqxx::work tx(*conn);
        auto res = db::exec_sql(tx, kMarkFailedSql, pqxx::params{event_id.to_string(), std::string(error)});
        tx.commit();
        return res.affected_rows() > 0;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to mark outbox event failed: " + std::string(ex.what()));
    }
}

bool PostgresAuthOutboxRepository::mark_quarantined(const domain::Uuid& event_id, std::string_view reason) {
    try {
        auto conn = pool_.acquire();
        pqxx::work tx(*conn);
        auto res = db::exec_sql(tx, kMarkQuarantinedSql, pqxx::params{event_id.to_string(), std::string(reason)});
        tx.commit();
        return res.affected_rows() > 0;
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to mark outbox event quarantined: " + std::string(ex.what()));
    }
}

std::size_t PostgresAuthOutboxRepository::purge_published_older_than(std::chrono::system_clock::time_point cutoff,
                                                                     std::size_t batch_size) {
    if (batch_size == 0) {
        return 0;
    }

    try {
        auto conn = pool_.acquire();
        pqxx::work tx(*conn);
        auto res = db::exec_sql(
            tx, kPurgePublishedSql,
            pqxx::params{domain::to_iso8601(cutoff), static_cast<int64_t>(batch_size)});
        tx.commit();
        return static_cast<std::size_t>(res.affected_rows());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to purge old published outbox events: " + std::string(ex.what()));
    }
}

std::size_t PostgresAuthOutboxRepository::count_pending() {
    try {
        auto conn = pool_.acquire();
        pqxx::work tx(*conn);
        auto res = db::exec_sql(tx, kCountPendingSql, pqxx::params{});
        tx.commit();
        if (res.empty()) {
            return 0;
        }
        return static_cast<std::size_t>(res[0][0].as<int64_t>());
    } catch (const pqxx::sql_error& ex) {
        throw DatabaseExecutionException("Failed to count pending outbox events: " + std::string(ex.what()));
    }
}

} // namespace securecloud::auth::repository
