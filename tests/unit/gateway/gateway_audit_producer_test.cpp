#include "audit/bounded_memory_pending_store.hpp"
#include "audit/gateway_audit_event_factory.hpp"
#include "audit/gateway_audit_producer.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <thread>

namespace securecloud::gateway::audit {

TEST(GatewayAuditProducerTest, AggregatesRateLimitEventsInWindow) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto factory = std::make_shared<GatewayAuditEventFactory>("test-gateway-node-1");

    // Producer avec fenêtre d'agrégation de 1 seconde et capacité LRU de 10 clés max
    auto producer = create_gateway_audit_producer(store, factory, true, 1, 10);

    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::RateLimitExceeded;
    obs.client_ip = "192.168.1.100";
    obs.route_class = "/api/v1/auth/login";

    // Envoi de 10 000 observations de dépassement de rate limit pour la même IP et route (E5)
    for (int i = 0; i < 10000; ++i) {
        const auto result = producer->record_observation(obs);
        EXPECT_EQ(result, AdmissionResult::AcceptedPendingSync);
    }

    // Le Pending Store ne doit recevoir aucun enregistrement direct immédiat pendant la fenêtre
    EXPECT_EQ(store->stats().total_records, 0);

    // Attente de l'expiration de la fenêtre d'agrégation (1 seconde + marge)
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Exactement 1 événement agrégé doit avoir été émis dans le store pour les 10 000 observations
    EXPECT_EQ(store->stats().total_records, 1);
    EXPECT_EQ(producer->enqueued_count(), 1);
    EXPECT_EQ(producer->dropped_count(), 0);
}

TEST(GatewayAuditProducerTest, EmitsNonAggregatedEventsImmediately) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto factory = std::make_shared<GatewayAuditEventFactory>("test-gateway-node-1");

    auto producer = create_gateway_audit_producer(store, factory, true, 10, 1000);

    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::TokenRejected;
    obs.client_ip = "10.0.0.1";
    obs.route_class = "/api/v1/auth/login";

    const auto result = producer->record_observation(obs);

    EXPECT_EQ(result, AdmissionResult::AcceptedNonDurable);
    EXPECT_EQ(store->stats().total_records, 1);
    EXPECT_EQ(producer->enqueued_count(), 1);
}

TEST(GatewayAuditProducerTest, DisabledProducerRejectsObservations) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto factory = std::make_shared<GatewayAuditEventFactory>("test-gateway-node-1");

    // Producer désactivé
    auto producer = create_gateway_audit_producer(store, factory, false, 10, 1000);

    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::TokenRejected;
    obs.client_ip = "10.0.0.1";
    obs.route_class = "/api/v1/auth/login";

    const auto result = producer->record_observation(obs);

    EXPECT_EQ(result, AdmissionResult::RejectedDisabled);
    EXPECT_EQ(store->stats().total_records, 0);
}

TEST(GatewayAuditProducerTest, ManualFlushEmitsAggregatedWindowEntries) {
    auto store = std::make_shared<BoundedMemoryPendingStore>(100, 102400);
    auto factory = std::make_shared<GatewayAuditEventFactory>("test-gateway-node-1");

    // Longue fenêtre (60 s) pour tester le flush manuel
    auto producer = create_gateway_audit_producer(store, factory, true, 60, 1000);

    GatewayAuditObservation obs;
    obs.type = GatewayAuditEventType::RequestRejected;
    obs.client_ip = "172.16.0.5";
    obs.route_class = "/api/v1/files/upload";

    for (int i = 0; i < 50; ++i) {
        producer->record_observation(obs);
    }

    EXPECT_EQ(store->stats().total_records, 0);

    // Flush manuel synchrone
    producer->flush();

    EXPECT_EQ(store->stats().total_records, 1);
    EXPECT_EQ(producer->enqueued_count(), 1);
}

} // namespace securecloud::gateway::audit
