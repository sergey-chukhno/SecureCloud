#include "query/audit_query_application_service.hpp"

#include "domain/audit_event_mapper.hpp"
#include "query/audit_page_cursor.hpp"
#include "repository/audit_repository_exceptions.hpp"

#include <chrono>

namespace securecloud::audit::query {

AuditQueryApplicationService::AuditQueryApplicationService(
    std::shared_ptr<repository::IAuditEventRepository> repository, QueryConfig config)
    : repository_(std::move(repository)), config_(config), bulkhead_(config.workers) {}

grpc::Status AuditQueryApplicationService::execute_query(const domain::PeerIdentity& caller, AuditQueryFilter filter,
                                                         AuditQueryPageResult& out_result) {

    // 1. Authorization Policy Check
    auto auth_status = AuditQueryAuthorizer::authorize_query(caller, filter);
    if (!auth_status.ok()) {
        metrics_.queries_denied_total.fetch_add(1, std::memory_order_relaxed);
        return auth_status;
    }

    // 2. Filter Validation & Time Window Normalization
    auto val_status = AuditQueryValidator::validate_and_normalize(filter, config_);
    if (!val_status.ok()) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        return val_status;
    }

    // Decode existing page cursor if token provided
    std::optional<AuditPageCursor> cursor;
    if (!filter.page_token.empty()) {
        auto expected_hash = AuditPageCursorCodec::compute_filter_hash(filter);
        cursor = AuditPageCursorCodec::decode(filter.page_token, expected_hash);
        if (!cursor.has_value()) {
            metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidPageToken: Cursor filter fingerprint mismatch");
        }
    }

    // 3. Concurrency Bulkhead Acquisition
    auto lease = bulkhead_.try_acquire();
    if (!lease.is_acquired()) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                            "ResourceExhausted: Query execution bulkhead saturated");
    }

    // 4. Repository Query Execution
    uint32_t timeout_sec = config_.query_timeout_ms / 1000;
    if (timeout_sec == 0)
        timeout_sec = 1;

    std::vector<domain::AuditEvent> raw_events;
    try {
        raw_events = repository_->execute_paged_query(filter, cursor, timeout_sec, config_.max_result_bytes);
    } catch (const repository::ClickHouseException&) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        throw;
    } catch (...) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        return grpc::Status(grpc::StatusCode::INTERNAL, "Database query execution failed");
    }

    // 5. Lookahead & Keyset Pagination Result Mapping
    out_result = AuditQueryPageResult{};

    if (raw_events.size() == filter.page_size + 1) {
        out_result.has_more = true;
        raw_events.pop_back(); // Remove the (L+1)-th lookahead row

        const auto& last_event = raw_events.back();
        AuditPageCursor next_cursor;
        next_cursor.last_occurred_at_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(last_event.occurred_at.time_since_epoch()).count();
        next_cursor.last_producer_service = domain::to_string(last_event.producer_service);
        next_cursor.last_event_type = last_event.event_type;
        next_cursor.last_event_id = last_event.event_id;
        next_cursor.sort_order = filter.sort_order;
        next_cursor.filter_hash = AuditPageCursorCodec::compute_filter_hash(filter);

        out_result.next_page_token = AuditPageCursorCodec::encode(next_cursor);
    } else {
        out_result.has_more = false;
        out_result.next_page_token = "";
    }

    out_result.events = std::move(raw_events);
    out_result.effective_page_size = static_cast<uint32_t>(out_result.events.size());

    metrics_.queries_executed_total.fetch_add(1, std::memory_order_relaxed);
    return grpc::Status::OK;
}

grpc::Status AuditQueryApplicationService::get_event_by_id(const domain::PeerIdentity& caller,
                                                           std::string_view event_id_str,
                                                           std::optional<domain::AuditEvent>& out_event) {

    if (!caller.is_authenticated) {
        metrics_.queries_denied_total.fetch_add(1, std::memory_order_relaxed);
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Unauthenticated");
    }

    auto id_opt = domain::EventId::from_string(event_id_str);
    if (!id_opt.has_value()) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid EventId UUIDv7 format");
    }

    // Authorize peer access (Global or self-scope)
    AuditQueryFilter dummy_filter;
    auto auth_status = AuditQueryAuthorizer::authorize_query(caller, dummy_filter);
    if (!auth_status.ok()) {
        metrics_.queries_denied_total.fetch_add(1, std::memory_order_relaxed);
        return auth_status;
    }

    auto lease = bulkhead_.try_acquire();
    if (!lease.is_acquired()) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED,
                            "ResourceExhausted: Query execution bulkhead saturated");
    }

    try {
        out_event = repository_->find_by_event_id(*id_opt);
    } catch (const repository::ClickHouseException&) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        throw;
    } catch (...) {
        metrics_.queries_failed_total.fetch_add(1, std::memory_order_relaxed);
        return grpc::Status(grpc::StatusCode::INTERNAL, "Database lookup failed");
    }

    metrics_.queries_executed_total.fetch_add(1, std::memory_order_relaxed);
    return grpc::Status::OK;
}

} // namespace securecloud::audit::query