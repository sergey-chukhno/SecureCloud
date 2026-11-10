#include "audit/audit_delivery_dispatcher.hpp"

#include "domain/event_id.hpp"
#include "grpc/client_call_context.hpp"

#include <algorithm>
#include <set>

namespace securecloud::gateway::audit {

AuditDeliveryDispatcher::AuditDeliveryDispatcher(
    std::shared_ptr<IAuditPendingStore> pending_store,
    std::shared_ptr<securecloud::gateway::grpc::IAuditIngestionClient> audit_client,
    std::shared_ptr<securecloud::gateway::http::CircuitBreaker> circuit_breaker, AuditDeliveryDispatcherConfig config)
    : pending_store_(std::move(pending_store)), audit_client_(std::move(audit_client)),
      circuit_breaker_(std::move(circuit_breaker)), config_(config) {}

AuditDeliveryDispatcher::~AuditDeliveryDispatcher() {
    stop();
}

void AuditDeliveryDispatcher::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_.load(std::memory_order_relaxed)) {
        return;
    }

    running_.store(true, std::memory_order_release);
    stop_requested_.store(false, std::memory_order_release);
    worker_thread_ = std::thread(&AuditDeliveryDispatcher::worker_loop, this);
}

void AuditDeliveryDispatcher::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_.load(std::memory_order_relaxed)) {
            return;
        }
        stop_requested_.store(true, std::memory_order_release);
        cv_.notify_all();
    }

    const auto drain_start = std::chrono::steady_clock::now();
    const auto drain_budget = std::chrono::milliseconds(config_.audit_drain_budget_ms);

    while (std::chrono::steady_clock::now() - drain_start < drain_budget) {
        if (!process_next_batch()) {
            break;
        }
    }

    running_.store(false, std::memory_order_release);
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

void AuditDeliveryDispatcher::notify_new_records() {
    std::lock_guard<std::mutex> lock(mutex_);
    cv_.notify_one();
}

void AuditDeliveryDispatcher::worker_loop() {
    while (!stop_requested_.load(std::memory_order_acquire)) {
        bool had_work = process_next_batch();

        if (!had_work) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(config_.poll_interval_ms),
                         [this] { return stop_requested_.load(std::memory_order_relaxed); });
        }
    }
}

bool AuditDeliveryDispatcher::process_next_batch() {
    auto claimed_records = pending_store_->claim_batch(config_.batch_max_records);
    if (claimed_records.empty()) {
        return false;
    }

    ::securecloud::audit::v1::BatchSubmitAuditEventsRequest request;
    std::vector<securecloud::audit::domain::EventId> valid_ids;
    valid_ids.reserve(claimed_records.size());

    for (const auto& rec : claimed_records) {
        ::securecloud::audit::v1::AuditEventProto proto_event;
        if (!proto_event.ParseFromArray(rec.proto_bytes.data(), static_cast<int>(rec.proto_bytes.size()))) {
            pending_store_->mark_terminal(rec.event_id, TerminalReason::FormatCorrupted);
            continue;
        }
        *request.add_events() = std::move(proto_event);
        valid_ids.push_back(rec.event_id);
    }

    if (valid_ids.empty()) {
        return true;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        pending_store_->release(valid_ids);
        return true;
    }

    securecloud::gateway::grpc::ClientCallContext ctx(std::chrono::milliseconds(config_.audit_timeout_ms));

    auto result = audit_client_->batch_submit_events(request, ctx);

    if (result) {
        if (circuit_breaker_) {
            circuit_breaker_->record_success();
        }

        const auto& response = result.value();
        if (response.rejected_event_ids_size() > 0) {
            std::set<securecloud::audit::domain::EventId> rejected_set;
            for (int i = 0; i < response.rejected_event_ids_size(); ++i) {
                if (auto parsed = securecloud::audit::domain::EventId::from_string(response.rejected_event_ids(i))) {
                    rejected_set.insert(*parsed);
                    pending_store_->mark_terminal(*parsed, TerminalReason::ValidationFailed);
                }
            }

            std::vector<securecloud::audit::domain::EventId> accepted_ids;
            accepted_ids.reserve(valid_ids.size() - rejected_set.size());
            for (const auto& id : valid_ids) {
                if (rejected_set.find(id) == rejected_set.end()) {
                    accepted_ids.push_back(id);
                }
            }
            if (!accepted_ids.empty()) {
                pending_store_->mark_delivered(accepted_ids);
            }
        } else {
            pending_store_->mark_delivered(valid_ids);
        }
    } else {
        const auto grpc_code = result.error().grpc_code;
        if (circuit_breaker_) {
            circuit_breaker_->record_status(grpc_code);
        }

        switch (grpc_code) {
        case ::grpc::StatusCode::INVALID_ARGUMENT:
        case ::grpc::StatusCode::ALREADY_EXISTS:
        case ::grpc::StatusCode::FAILED_PRECONDITION:
            for (const auto& id : valid_ids) {
                pending_store_->mark_terminal(id, TerminalReason::ValidationFailed);
            }
            break;

        case ::grpc::StatusCode::UNAUTHENTICATED:
        case ::grpc::StatusCode::PERMISSION_DENIED:
        case ::grpc::StatusCode::UNAVAILABLE:
        case ::grpc::StatusCode::DEADLINE_EXCEEDED:
        case ::grpc::StatusCode::RESOURCE_EXHAUSTED:
        case ::grpc::StatusCode::INTERNAL:
        case ::grpc::StatusCode::UNKNOWN:
        default:
            pending_store_->release(valid_ids);
            break;
        }
    }

    return true;
}

} // namespace securecloud::gateway::audit
