#include "application/client_config.hpp"
#include "application/managers/delivery_retry_engine.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/device_private_bundle.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <memory>

namespace securecloud::client::application::managers::test {
namespace {

using namespace domain;
using namespace infrastructure::adapters;
using namespace std::chrono_literals;

TEST(DeliveryRetryEngineTest, ExponentialBackoffRespectsCapAndJitterBounds) {
    RetryPolicyConfig cfg;
    cfg.initial_backoff = 100ms;
    cfg.max_backoff = 500ms;
    cfg.jitter_ratio = 0.25;
    DeliveryRetryEngine engine(cfg);

    for (int i = 0; i < 20; ++i) {
        const auto d1 = engine.compute_backoff(1);
        EXPECT_GE(d1.count(), 75);
        EXPECT_LE(d1.count(), 125);

        const auto d2 = engine.compute_backoff(2);
        EXPECT_GE(d2.count(), 150);
        EXPECT_LE(d2.count(), 250);

        // Attempt 4 -> raw 800ms capped to 500ms ± 25% => [375, 625]
        const auto d4 = engine.compute_backoff(4);
        EXPECT_GE(d4.count(), 375);
        EXPECT_LE(d4.count(), 625);
    }
}

TEST(DeliveryRetryEngineTest, TransientNetworkFailureRetriesWithSameIdempotencyKeyAndSucceeds) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage alice_storage;
    MemoryLocalStore alice_store;
    ASSERT_TRUE(alice_store.open("").is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");

    auto bob_ik = crypto.generate_identity_keypair().value();
    auto bob_spk = crypto.generate_signed_prekey(bob_ik.private_key).value();
    auto bob_otk = crypto.generate_dh_keypair().value();
    gateway.set_simulated_user_directory(bob, {interfaces::DeviceCryptoDirectoryEntry{
                                                  .device_id = bob_dev,
                                                  .identity_key = bob_ik.public_key,
                                                  .signed_prekey = bob_spk.public_key,
                                                  .signed_prekey_signature = bob_spk.signature,
                                                  .one_time_prekey = bob_otk.public_key,
                                                  .one_time_prekey_id = "bob-otk-1",
                                                  .identity_key_fingerprint = "",
                                              }});

    auto alice_ik = crypto.generate_identity_keypair().value();
    auto alice_spk = crypto.generate_signed_prekey(alice_ik.private_key).value();
    DevicePrivateBundle alice_bundle(alice_dev, alice_ik.public_key, std::move(alice_ik.private_key),
                                     alice_spk.public_key, std::move(alice_spk.private_key), alice_spk.signature);
    ASSERT_TRUE(KeyStorageHelper::save_bundle(alice_storage, alice_bundle).is_ok());

    RatchetSessionManager ratchet(gateway, alice_storage, crypto, alice, alice_dev);
    MessagingManager mm(gateway, alice_store, crypto, &ratchet, &alice_storage);

    RetryPolicyConfig cfg;
    cfg.initial_backoff = 100ms;
    cfg.max_backoff = 1000ms;
    cfg.jitter_ratio = 0.2;
    cfg.max_attempts = 4;
    mm.set_retry_policy(cfg);

    auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();

    // Establish pairwise X3DH/Double Ratchet session before simulating outage
    ASSERT_TRUE(mm.stage_outbound_message(conv.conversation_id(), alice, alice_dev, "Session warmup").is_ok());
    gateway.clear_submitted_fanouts();

    // Simulate Gateway network outage on outbound submission
    gateway.set_simulated_submission_failure(true, "Simulated transient outage");
    auto staged = mm.stage_outbound_message(conv.conversation_id(), alice, alice_dev, "Retry me idempotently");
    ASSERT_TRUE(staged.is_ok());
    EXPECT_EQ(staged.value().delivery_state(), DeliveryState::LocalPending);
    EXPECT_EQ(mm.pending_retry_count(), 1u);
    EXPECT_TRUE(gateway.submitted_fanouts().empty());

    // Before backoff window elapses -> nothing retried yet
    EXPECT_EQ(mm.process_retry_queue(std::chrono::steady_clock::now()), 0u);
    EXPECT_EQ(mm.pending_retry_count(), 1u);

    // Network recovers and backoff window elapses -> succeeds with original idempotency_key
    gateway.set_simulated_submission_failure(false);
    const auto processed = mm.process_retry_queue(std::chrono::steady_clock::now() + 5s);
    EXPECT_EQ(processed, 1u);
    EXPECT_EQ(mm.pending_retry_count(), 0u);

    ASSERT_EQ(gateway.submitted_fanouts().size(), 1u);
    EXPECT_EQ(gateway.submitted_fanouts()[0].idempotency_key, staged.value().idempotency_key());

    auto persisted = alice_store.get_message(conv.conversation_id(), staged.value().message_id()).value();
    EXPECT_EQ(persisted.delivery_state(), DeliveryState::Accepted);
}

TEST(DeliveryRetryEngineTest, ExceedingMaxAttemptsOrTtlTransitionsToFailed) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage alice_storage;
    MemoryLocalStore alice_store;
    ASSERT_TRUE(alice_store.open("").is_ok());
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const UserId alice("alice");
    const DeviceId alice_dev("alice-dev-1");
    const UserId bob("bob");
    const DeviceId bob_dev("bob-dev-1");

    auto bob_ik = crypto.generate_identity_keypair().value();
    auto bob_spk = crypto.generate_signed_prekey(bob_ik.private_key).value();
    auto bob_otk = crypto.generate_dh_keypair().value();
    gateway.set_simulated_user_directory(bob, {interfaces::DeviceCryptoDirectoryEntry{
                                                  .device_id = bob_dev,
                                                  .identity_key = bob_ik.public_key,
                                                  .signed_prekey = bob_spk.public_key,
                                                  .signed_prekey_signature = bob_spk.signature,
                                                  .one_time_prekey = bob_otk.public_key,
                                                  .one_time_prekey_id = "bob-otk-1",
                                                  .identity_key_fingerprint = "",
                                              }});

    auto alice_ik = crypto.generate_identity_keypair().value();
    auto alice_spk = crypto.generate_signed_prekey(alice_ik.private_key).value();
    DevicePrivateBundle alice_bundle(alice_dev, alice_ik.public_key, std::move(alice_ik.private_key),
                                     alice_spk.public_key, std::move(alice_spk.private_key), alice_spk.signature);
    ASSERT_TRUE(KeyStorageHelper::save_bundle(alice_storage, alice_bundle).is_ok());

    RatchetSessionManager ratchet(gateway, alice_storage, crypto, alice, alice_dev);
    MessagingManager mm(gateway, alice_store, crypto, &ratchet, &alice_storage);

    RetryPolicyConfig cfg;
    cfg.initial_backoff = 50ms;
    cfg.max_backoff = 200ms;
    cfg.jitter_ratio = 0.0;
    cfg.max_attempts = 2;
    cfg.expiration_ttl = 10s;
    mm.set_retry_policy(cfg);

    auto conv = mm.open_direct_conversation(alice, bob, "Bob").value();
    ASSERT_TRUE(mm.stage_outbound_message(conv.conversation_id(), alice, alice_dev, "Session warmup").is_ok());
    gateway.set_simulated_submission_failure(true, "Persistent outage");
    auto staged = mm.stage_outbound_message(conv.conversation_id(), alice, alice_dev, "Will expire");
    ASSERT_TRUE(staged.is_ok());
    EXPECT_EQ(mm.pending_retry_count(), 1u);

    // Attempt 2 hits max_attempts = 2 and transitions permanently to Failed
    mm.process_retry_queue(std::chrono::steady_clock::now() + 1s);
    EXPECT_EQ(mm.pending_retry_count(), 0u);

    auto persisted = alice_store.get_message(conv.conversation_id(), staged.value().message_id()).value();
    EXPECT_EQ(persisted.delivery_state(), DeliveryState::Failed);
}

} // namespace
} // namespace securecloud::client::application::managers::test
