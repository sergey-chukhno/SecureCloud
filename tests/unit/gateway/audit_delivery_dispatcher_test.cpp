#include "audit/audit_delivery_dispatcher.hpp"
#include "audit/bounded_memory_pending_store.hpp"
#include "grpc/audit_client_interface.hpp"
#include "grpc/dependency_error.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace securecloud::gateway::audit {

namespace {

class MockAuditIngestionClient : public securecloud::gateway::grpc::IAuditIngestionClient {
  public:
    securecloud::gateway::grpc::Result<securecloud::audit::v1::SubmitAuditEventResponse>
    submit_event(const securecloud::audit::v1::SubmitAuditEventRequest&,
                 securecloud::gateway::grpc::ClientCallContext&) override {
        return securecloud::audit::v1::SubmitAuditEventResponse{};
    }

    securecloud::gateway::grpc::Result<securecloud::audit::v1::BatchSubmitAuditEventsResponse>
    batch_submit_events(const securecloud::audit::v1::BatchSubmitAuditEventsRequest& req,
                        securecloud::gateway::grpc::ClientCallContext&) override {
        last_request_ = req;
        ++call_count_;
        if (should_fail_) {
            return securecloud::gateway::grpc::DependencyError::from_grpc_status(
                ::grpc::Status(fail_code_, "Mock transient error"));
        }

        securecloud::audit::v1::BatchSubmitAuditEventsResponse resp;
        resp.set_accepted_count(static_cast<uint32_t>(req.events_size()));
        resp.set_rejected_count(0);
        return resp;
    }

    bool should_fail_{false};
    ::grpc::StatusCode fail_code_{::grpc::StatusCode::UNAVAILABLE};
    size_t call_count_{0};
    securecloud::audit::v1::BatchSubmitAuditEventsRequest last_request_;
};

} // namespace

TEST(AuditDeliveryDispatcherTest, DispatchesAndAcknowledgesEvents) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto client = std::make_shared<MockAuditIngestionClient>();

    AuditDeliveryDispatcherConfig config;
    config.poll_interval_ms = 10;
    AuditDeliveryDispatcher dispatcher(store, client, nullptr, config);

    // Build valid serialized event
    ::securecloud::audit::v1::AuditEventProto event;
    const auto id = securecloud::audit::domain::EventId::generate_v7();
    event.set_event_id(id.to_string());
    event.set_event_type("security.token.rejected");

    std::vector<uint8_t> bytes(event.ByteSizeLong());
    event.SerializeToArray(bytes.data(), static_cast<int>(bytes.size()));

    PendingRecord rec;
    rec.event_id = id;
    rec.proto_bytes = bytes;

    EXPECT_EQ(store->append(rec), AdmissionResult::AcceptedNonDurable);

    dispatcher.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    dispatcher.stop();

    EXPECT_GE(client->call_count_, 1);
    EXPECT_EQ(store->stats().total_records, 0);
}

TEST(AuditDeliveryDispatcherTest, RetriesOnTransientError) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto client = std::make_shared<MockAuditIngestionClient>();
    client->should_fail_ = true;
    client->fail_code_ = ::grpc::StatusCode::UNAVAILABLE;

    AuditDeliveryDispatcherConfig config;
    config.poll_interval_ms = 10;
    AuditDeliveryDispatcher dispatcher(store, client, nullptr, config);

    ::securecloud::audit::v1::AuditEventProto event;
    const auto id = securecloud::audit::domain::EventId::generate_v7();
    event.set_event_id(id.to_string());
    std::vector<uint8_t> bytes(event.ByteSizeLong());
    event.SerializeToArray(bytes.data(), static_cast<int>(bytes.size()));

    PendingRecord rec;
    rec.event_id = id;
    rec.proto_bytes = bytes;
    EXPECT_EQ(store->append(rec), AdmissionResult::AcceptedNonDurable);

    dispatcher.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    dispatcher.stop();

    // Event should remain in store for retry
    EXPECT_GE(store->stats().total_records, 1);
}

} // namespace securecloud::gateway::audit
