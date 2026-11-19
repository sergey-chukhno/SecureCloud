#include "files/repository/files_outbox_repository.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace securecloud::files {

namespace {

constexpr size_t k_max_error_length = 512;
constexpr std::chrono::seconds k_default_lease_duration{30};

std::string sanitize_diagnostic_message(std::string_view raw) {
    if (raw.empty()) {
        return "unspecified_error";
    }
    std::string out;
    out.reserve(std::min(raw.size(), k_max_error_length));
    for (char c : raw) {
        if (out.size() >= k_max_error_length) {
            break;
        }
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F) {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

#if defined(SECURECLOUD_FILES_USE_REAL_PQXX) && __has_include(<pqxx/pqxx>)
template <typename S> std::string extract_secret_value(const S& secret) {
    if constexpr (requires { secret.reveal(); }) {
        return std::string(secret.reveal());
    } else if constexpr (requires { secret.unmask(); }) {
        return std::string(secret.unmask());
    } else if constexpr (requires { secret.value(); }) {
        return std::string(secret.value());
    } else if constexpr (requires { secret.get(); }) {
        return std::string(secret.get());
    } else {
        return {};
    }
}

std::string build_pg_conninfo(const db::ConnectionPoolConfig& cfg) {
    std::ostringstream oss;
    oss << "host=" << cfg.host << " port=" << cfg.port << " dbname=" << cfg.db_name << " user=" << cfg.db_user;
    const std::string pwd = extract_secret_value(cfg.db_password);
    if (!pwd.empty()) {
        std::string escaped;
        escaped.reserve(pwd.size());
        for (char c : pwd) {
            if (c == '\'' || c == '\\') {
                escaped.push_back('\\');
            }
            escaped.push_back(c);
        }
        oss << " password='" << escaped << "'";
    }
    const auto connect_sec = std::max<int64_t>(1, cfg.connect_timeout.count() / 1000);
    oss << " connect_timeout=" << connect_sec;
    return oss.str();
}

template <typename Fn> auto with_autonomous_tx(const std::shared_ptr<db::FilesDbConnectionPool>& pool, Fn&& fn) {
    if (!pool) {
        throw RepositoryException("FilesDbConnectionPool is required when SECURECLOUD_FILES_USE_REAL_PQXX is enabled");
    }
    auto lease = pool->acquire();
    pqxx::connection conn(build_pg_conninfo(pool->config()));
    pqxx::work tx(conn);
    return fn(tx);
}
#else
template <typename Fn> auto with_autonomous_tx(const std::shared_ptr<db::FilesDbConnectionPool>& /*pool*/, Fn&& fn) {
    pqxx::work tx;
    return fn(tx);
}
#endif

} // namespace

FilesOutboxRepository::FilesOutboxRepository(std::shared_ptr<db::FilesDbConnectionPool> pool)
    : pool_(std::move(pool)) {}

void FilesOutboxRepository::stage_event(const FilesOutboxEntity& event, pqxx::work& tx) {
    if (event.event_id.empty()) {
        throw RepositoryException("Event ID cannot be empty");
    }
    if (event.event_type.empty()) {
        throw RepositoryException("Event type cannot be empty");
    }
    if (event.payload_json.empty()) {
        throw RepositoryException("Payload JSON cannot be empty");
    }

    std::optional<std::string> normalized_agg_id;
    if (event.aggregate_id.has_value() && !event.aggregate_id->empty()) {
        normalized_agg_id = *event.aggregate_id;
    }

    std::optional<std::string> processed_str;
    if (event.processed_at.has_value()) {
        processed_str = db::to_iso8601(*event.processed_at);
    }

    std::optional<std::string> leased_until_str;
    if (event.leased_until.has_value()) {
        leased_until_str = db::to_iso8601(*event.leased_until);
    }

    const auto created_tp = (event.created_at == std::chrono::system_clock::time_point{})
                                ? std::chrono::system_clock::now()
                                : event.created_at;

    tx.exec_params("INSERT INTO files_outbox ("
                   "event_id, aggregate_type, aggregate_id, event_type, severity, payload_json, "
                   "status, retry_count, created_at, processed_at, last_error, leased_until"
                   ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                   event.event_id, event.aggregate_type.empty() ? "FILE" : event.aggregate_type, normalized_agg_id,
                   event.event_type, db::to_string(event.severity), event.payload_json, db::to_string(event.status),
                   event.retry_count, db::to_iso8601(created_tp), processed_str, event.last_error, leased_until_str);
}

void FilesOutboxRepository::stage_event(const FilesOutboxEntity& event) {
    with_autonomous_tx(pool_, [&](pqxx::work& tx) {
        stage_event(event, tx);
        tx.commit();
    });
}

std::vector<FilesOutboxEntity>
FilesOutboxRepository::fetch_and_lease_pending_batch(size_t limit, std::chrono::seconds lease_duration) {
    if (limit == 0) {
        return {};
    }

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) {
        const auto now = std::chrono::system_clock::now();
        const auto effective_lease = (lease_duration.count() > 0) ? lease_duration : k_default_lease_duration;
        const std::string now_iso = db::to_iso8601(now);
        const std::string lease_until_iso = db::to_iso8601(now + effective_lease);

        auto res = tx.exec_params("WITH claimed AS ("
                                  "  SELECT event_id "
                                  "  FROM files_outbox "
                                  "  WHERE status = 'PENDING' "
                                  "    AND (leased_until IS NULL OR leased_until < $1::timestamptz) "
                                  "  ORDER BY created_at ASC "
                                  "  LIMIT $2 "
                                  "  FOR UPDATE SKIP LOCKED"
                                  ") "
                                  "UPDATE files_outbox AS o "
                                  "SET leased_until = $3::timestamptz, "
                                  "    retry_count = o.retry_count + 1 "
                                  "FROM claimed "
                                  "WHERE o.event_id = claimed.event_id "
                                  "RETURNING o.event_id, o.aggregate_type, o.aggregate_id, o.event_type, o.severity, "
                                  "          o.payload_json, o.status, o.retry_count, o.created_at, o.processed_at, "
                                  "          o.last_error, o.leased_until",
                                  now_iso, static_cast<int64_t>(limit), lease_until_iso);

        std::vector<FilesOutboxEntity> events;
        events.reserve(res.size());
        for (const auto& row : res) {
            events.push_back(db::files_outbox_from_row(row));
        }
        tx.commit();
        return events;
    });
}

std::vector<FilesOutboxEntity> FilesOutboxRepository::fetch_pending_events(size_t limit, pqxx::work& tx) {
    if (limit == 0) {
        return {};
    }

    const auto now = std::chrono::system_clock::now();
    const std::string now_iso = db::to_iso8601(now);
    const std::string lease_until_iso = db::to_iso8601(now + k_default_lease_duration);

    auto res = tx.exec_params("WITH claimed AS ("
                              "  SELECT event_id "
                              "  FROM files_outbox "
                              "  WHERE status = 'PENDING' "
                              "    AND (leased_until IS NULL OR leased_until < $1::timestamptz) "
                              "  ORDER BY created_at ASC "
                              "  LIMIT $2 "
                              "  FOR UPDATE SKIP LOCKED"
                              ") "
                              "UPDATE files_outbox AS o "
                              "SET leased_until = $3::timestamptz, "
                              "    retry_count = o.retry_count + 1 "
                              "FROM claimed "
                              "WHERE o.event_id = claimed.event_id "
                              "RETURNING o.event_id, o.aggregate_type, o.aggregate_id, o.event_type, o.severity, "
                              "          o.payload_json, o.status, o.retry_count, o.created_at, o.processed_at, "
                              "          o.last_error, o.leased_until",
                              now_iso, static_cast<int64_t>(limit), lease_until_iso);

    std::vector<FilesOutboxEntity> events;
    events.reserve(res.size());
    for (const auto& row : res) {
        events.push_back(db::files_outbox_from_row(row));
    }
    return events;
}

std::vector<FilesOutboxEntity> FilesOutboxRepository::fetch_pending_events(size_t limit) {
    return fetch_and_lease_pending_batch(limit, k_default_lease_duration);
}

bool FilesOutboxRepository::mark_published(const std::string& event_id, pqxx::work& tx) {
    if (event_id.empty()) {
        return false;
    }

    const auto now_iso = db::to_iso8601(std::chrono::system_clock::now());
    auto res = tx.exec_params("UPDATE files_outbox "
                              "SET status = 'PUBLISHED', processed_at = $1::timestamptz, leased_until = NULL "
                              "WHERE event_id = $2",
                              now_iso, event_id);

    return res.affected_rows() > 0;
}

bool FilesOutboxRepository::mark_published(const std::string& event_id) {
    if (event_id.empty()) {
        return false;
    }

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) {
        bool marked = mark_published(event_id, tx);
        if (marked) {
            tx.commit();
        }
        return marked;
    });
}

bool FilesOutboxRepository::record_transient_failure(const std::string& event_id, std::string_view sanitized_error) {
    if (event_id.empty()) {
        return false;
    }

    const std::string clean_err = sanitize_diagnostic_message(sanitized_error);

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) {
        auto res = tx.exec_params("UPDATE files_outbox "
                                  "SET status = 'PENDING', leased_until = NULL, last_error = $1 "
                                  "WHERE event_id = $2 AND status = 'PENDING'",
                                  clean_err, event_id);
        const bool updated = res.affected_rows() > 0;
        if (updated) {
            tx.commit();
        }
        return updated;
    });
}

bool FilesOutboxRepository::mark_quarantined(const std::string& event_id, std::string_view sanitized_reason) {
    if (event_id.empty()) {
        return false;
    }

    const std::string clean_reason = sanitize_diagnostic_message(sanitized_reason);
    const std::string now_iso = db::to_iso8601(std::chrono::system_clock::now());

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) {
        auto res = tx.exec_params("UPDATE files_outbox "
                                  "SET status = 'QUARANTINED', processed_at = $1::timestamptz, "
                                  "    leased_until = NULL, last_error = $2 "
                                  "WHERE event_id = $3",
                                  now_iso, clean_reason, event_id);
        const bool updated = res.affected_rows() > 0;
        if (updated) {
            tx.commit();
        }
        return updated;
    });
}

bool FilesOutboxRepository::mark_failed(const std::string& event_id, pqxx::work& tx) {
    if (event_id.empty()) {
        return false;
    }

    auto res = tx.exec_params("UPDATE files_outbox "
                              "SET status = 'FAILED', retry_count = retry_count + 1, leased_until = NULL "
                              "WHERE event_id = $1",
                              event_id);

    return res.affected_rows() > 0;
}

bool FilesOutboxRepository::mark_failed(const std::string& event_id) {
    if (event_id.empty()) {
        return false;
    }

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) {
        bool marked = mark_failed(event_id, tx);
        if (marked) {
            tx.commit();
        }
        return marked;
    });
}

size_t FilesOutboxRepository::purge_published_older_than(std::chrono::system_clock::time_point cutoff,
                                                         size_t batch_size) {
    if (batch_size == 0) {
        return 0;
    }

    const std::string cutoff_iso = db::to_iso8601(cutoff);

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) -> size_t {
        auto res = tx.exec_params("DELETE FROM files_outbox "
                                  "WHERE ctid IN ("
                                  "  SELECT ctid FROM files_outbox "
                                  "  WHERE status = 'PUBLISHED' "
                                  "    AND processed_at IS NOT NULL "
                                  "    AND processed_at < $1::timestamptz "
                                  "  LIMIT $2"
                                  ")",
                                  cutoff_iso, static_cast<int64_t>(batch_size));
        const size_t deleted = res.affected_rows();
        tx.commit();
        return deleted;
    });
}

size_t FilesOutboxRepository::count_pending() {
    return with_autonomous_tx(pool_, [&](pqxx::work& tx) -> size_t {
        auto res = tx.exec("SELECT COUNT(*) AS cnt FROM files_outbox WHERE status = 'PENDING'");
        if (res.empty() || res[0]["cnt"].is_null()) {
            return 0;
        }
        return res[0]["cnt"].as<size_t>();
    });
}

double FilesOutboxRepository::oldest_pending_age_seconds() {
    return with_autonomous_tx(pool_, [&](pqxx::work& tx) -> double {
        auto res = tx.exec("SELECT MIN(created_at) AS oldest_created_at FROM files_outbox WHERE status = 'PENDING'");
        if (res.empty() || res[0]["oldest_created_at"].is_null()) {
            return 0.0;
        }
        const auto oldest_tp = db::from_iso8601(res[0]["oldest_created_at"].as<std::string>());
        const auto now = std::chrono::system_clock::now();
        const double age = std::chrono::duration<double>(now - oldest_tp).count();
        return age > 0.0 ? age : 0.0;
    });
}

std::optional<FilesOutboxEntity> FilesOutboxRepository::find_by_id(const std::string& event_id, pqxx::work& tx) {
    if (event_id.empty()) {
        return std::nullopt;
    }

    auto res = tx.exec_params("SELECT event_id, aggregate_type, aggregate_id, event_type, severity, payload_json, "
                              "       status, retry_count, created_at, processed_at, last_error, leased_until "
                              "FROM files_outbox WHERE event_id = $1",
                              event_id);

    if (res.empty()) {
        return std::nullopt;
    }

    return db::files_outbox_from_row(res[0]);
}

std::optional<FilesOutboxEntity> FilesOutboxRepository::find_by_id(const std::string& event_id) {
    if (event_id.empty()) {
        return std::nullopt;
    }

    return with_autonomous_tx(pool_, [&](pqxx::work& tx) { return find_by_id(event_id, tx); });
}

} // namespace securecloud::files
