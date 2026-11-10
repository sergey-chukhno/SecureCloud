#include "audit/gateway_audit_producer.hpp"

#include "audit/audit_aggregation_window.hpp"
#include "audit/audit_pending_store.hpp"
#include "audit/gateway_audit_event_factory.hpp"

#include <atomic>
#include <memory>

namespace securecloud::gateway::audit {

class GatewayAuditProducer final : public IGatewayAuditProducer {
  public:
    GatewayAuditProducer(std::shared_ptr<IAuditPendingStore> pending_store,
                         std::shared_ptr<GatewayAuditEventFactory> factory,
                         bool enabled = true,
                         uint32_t aggregation_window_sec = 10,
                         size_t aggregation_max_keys = 1000)
        : pending_store_(std::move(pending_store)),
          factory_(std::move(factory)),
          enabled_(enabled),
          aggregation_window_(aggregation_window_sec, aggregation_max_keys,
                              [this](GatewayAuditObservation obs, uint32_t count) { emit_observation(obs, count); }) {}

    ~GatewayAuditProducer() override = default;

    AdmissionResult record_observation(const GatewayAuditObservation& observation) noexcept override {
        if (!enabled_) {
            return AdmissionResult::RejectedDisabled;
        }

        try {
            if (!pending_store_) {
                return AdmissionResult::RejectedSpoolFull;
            }

            // Aggregate high-frequency rate limiting (E5) and request rejection (E6) observations
            if (observation.type == GatewayAuditEventType::RateLimitExceeded ||
                observation.type == GatewayAuditEventType::RequestRejected) {
                aggregation_window_.add(observation);
                return AdmissionResult::AcceptedPendingSync;
            }

            return emit_observation(observation, 1);
        } catch (...) {
            return AdmissionResult::RejectedSpoolFull;
        }
    }

    void flush() override { aggregation_window_.flush_all(); }

    [[nodiscard]] bool is_degraded() const noexcept override {
        if (!pending_store_) {
            return true;
        }
        return pending_store_->stats().dropped_records > 0;
    }

    [[nodiscard]] uint64_t enqueued_count() const noexcept override {
        return enqueued_count_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] uint64_t dropped_count() const noexcept override {
        return dropped_count_.load(std::memory_order_relaxed);
    }

  private:
    AdmissionResult emit_observation(const GatewayAuditObservation& obs, uint32_t count) noexcept {
        try {
            if (!factory_ || !pending_store_) {
                dropped_count_.fetch_add(1, std::memory_order_relaxed);
                return AdmissionResult::RejectedSpoolFull;
            }

            const auto domain_event = factory_->create_domain_event(obs);
            auto proto = factory_->to_protobuf(domain_event);

            if (count > 1) {
                (*proto.mutable_metadata())["aggregate_count"] = std::to_string(count);
            }

            PendingRecord record;
            record.event_id = domain_event.event_id;
            record.durability_class = AuditEventClass::Mandatory;

            record.proto_bytes.resize(proto.ByteSizeLong());
            if (!proto.SerializeToArray(record.proto_bytes.data(), static_cast<int>(record.proto_bytes.size()))) {
                dropped_count_.fetch_add(1, std::memory_order_relaxed);
                return AdmissionResult::RejectedSpoolFull;
            }

            const auto result = pending_store_->append(std::move(record));
            if (result == AdmissionResult::AcceptedNonDurable ||
                result == AdmissionResult::AcceptedPendingSync ||
                result == AdmissionResult::DurablyQueued) {
                enqueued_count_.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            dropped_count_.fetch_add(1, std::memory_order_relaxed);
            return result;
        } catch (...) {
            dropped_count_.fetch_add(1, std::memory_order_relaxed);
            return AdmissionResult::RejectedSpoolFull;
        }
    }

    std::shared_ptr<IAuditPendingStore> pending_store_;
    std::shared_ptr<GatewayAuditEventFactory> factory_;
    bool enabled_{true};
    AuditAggregationWindow aggregation_window_;

    std::atomic<uint64_t> enqueued_count_{0};
    std::atomic<uint64_t> dropped_count_{0};
};

std::shared_ptr<IGatewayAuditProducer> create_gateway_audit_producer(std::shared_ptr<IAuditPendingStore> store,
                                                                     std::shared_ptr<GatewayAuditEventFactory> factory,
                                                                     bool enabled,
                                                                     uint32_t aggregation_window_sec,
                                                                     size_t aggregation_max_keys) {
    return std::make_shared<GatewayAuditProducer>(std::move(store), std::move(factory), enabled, aggregation_window_sec,
                                                  aggregation_max_keys);
}

} // namespace securecloud::gateway::audit
