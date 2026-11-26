#include "audit/messaging_audit_client.hpp"
#include "audit/messaging_outbox_relay.hpp"
#include "client/auth_crypto_directory_client.hpp"
#include "concurrency/bounded_worker_pool.hpp"
#include "db/scylla_session.hpp"
#include "messaging_config.hpp"
#include "repository/scylla_conversation_repository.hpp"
#include "repository/scylla_delivery_state_repository.hpp"
#include "repository/scylla_idempotency_repository.hpp"
#include "repository/scylla_membership_repository.hpp"
#include "repository/scylla_message_repository.hpp"
#include "repository/scylla_messaging_audit_outbox_repository.hpp"
#include "repository/scylla_outbox_repository.hpp"
#include "repository/scylla_sync_cursor_repository.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/common/version.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"
#include "service/conversation_authorization_service.hpp"
#include "service/conversation_sequence_allocator.hpp"
#include "service/conversation_service.hpp"
#include "service/delivery_service.hpp"
#include "service/e2e_envelope_validator.hpp"
#include "service/idempotency_guard.hpp"
#include "service/message_submission_service.hpp"
#include "service/message_sync_service.hpp"
#include "service/messaging_service_impl.hpp"
#include "service/presence_coordinator.hpp"
#include "service/read_receipt_service.hpp"
#include "service/recipient_device_resolution_service.hpp"
#include "service/sync_cursor_manager.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace {

constexpr auto k_poll_interval = std::chrono::milliseconds(100);

std::atomic<bool> g_shutdown_requested{false};

// Signal handler: Strictly async-signal-safe (relaxed atomic store only).
// No logging, no mutexes, no allocations, no gRPC calls.
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_shutdown_requested.store(true, std::memory_order_relaxed);
    }
}

int run_service() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    securecloud::common::configuration::ProcessEnvironmentSource env_source;
    securecloud::common::configuration::ValidationResult config_errors;
    auto config = securecloud::messaging::MessagingConfig::load(env_source, config_errors);

    if (!config_errors.is_valid()) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Configuration validation failed:\n"
                  << config_errors.to_string() << "\n";
        return 1;
    }

    std::cout << "[SecureCloud] Starting " << config.common.service_display_name << " (" << config.common.service_name
              << ") v" << securecloud::common::get_version_string() << "\n";

    // 1. Initialize mTLS server credentials
    std::shared_ptr<grpc::ServerCredentials> server_creds;
    try {
        server_creds = securecloud::common::security::MtlsCredentialLoader::create_server_credentials(
            config.common.tls_credentials);
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << config.common.service_name
                  << "] FATAL: Failed to load mTLS server credentials: " << ex.what() << "\n";
        return 1;
    }

    if (!server_creds) {
        std::cerr << "[SecureCloud] [" << config.common.service_name
                  << "] FATAL: Failed to construct mTLS server credentials\n";
        return 1;
    }

    // 2. Initialize bounded worker pools with configured bounds (ADR-009, ADR-010)
    auto submission_pool = std::make_shared<securecloud::messaging::concurrency::BoundedWorkerPool>(
        config.workers.submission_workers, config.workers.max_queued_submissions, "submission");
    auto delivery_pool = std::make_shared<securecloud::messaging::concurrency::BoundedWorkerPool>(
        config.workers.delivery_workers, config.workers.max_queued_deliveries, "delivery");
    auto sync_pool = std::make_shared<securecloud::messaging::concurrency::BoundedWorkerPool>(
        config.workers.sync_workers, config.workers.max_queued_syncs, "sync");

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Initialized bounded worker pools: "
              << "submission (" << config.workers.submission_workers << " workers, queue "
              << config.workers.max_queued_submissions << "), delivery (" << config.workers.delivery_workers
              << " workers, queue " << config.workers.max_queued_deliveries << "), sync ("
              << config.workers.sync_workers << " workers, queue " << config.workers.max_queued_syncs << ")\n";

    // 3. Construct ScyllaDB session & verify live CQL connectivity before preparing repository statements
    auto scylla_session = std::make_shared<securecloud::messaging::db::ScyllaSession>(config.scylla);
    try {
        auto probe = scylla_session->execute("SELECT release_version FROM system.local",
                                             securecloud::messaging::db::ConsistencyLevel::One);
        const std::string release = (!probe.empty() && !probe.front().is_null("release_version"))
                                        ? probe.front().get_string("release_version")
                                        : "unknown";
        std::cout << "[SecureCloud] [" << config.common.service_name << "] Connected to ScyllaDB ("
                  << config.scylla.host << ":" << config.scylla.port << ", release=" << release << ")\n";
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [" << config.common.service_name
                  << "] WARN: Initial ScyllaDB CQL probe failed (will retry lazily on first RPC): " << ex.what()
                  << "\n";
    }

    // 4. Construct ScyllaDB persistence repositories
    auto conversation_repo =
        std::make_shared<securecloud::messaging::repository::ScyllaConversationRepository>(scylla_session);
    auto membership_repo =
        std::make_shared<securecloud::messaging::repository::ScyllaMembershipRepository>(scylla_session);
    auto message_repo = std::make_shared<securecloud::messaging::repository::ScyllaMessageRepository>(scylla_session);
    auto delivery_repo =
        std::make_shared<securecloud::messaging::repository::ScyllaDeliveryStateRepository>(scylla_session);
    auto idempotency_repo =
        std::make_shared<securecloud::messaging::repository::ScyllaIdempotencyRepository>(scylla_session);
    auto outbox_repo = std::make_shared<securecloud::messaging::repository::ScyllaOutboxRepository>(scylla_session);
    auto sync_cursor_repo =
        std::make_shared<securecloud::messaging::repository::ScyllaSyncCursorRepository>(scylla_session);
    auto audit_outbox =
        std::make_shared<securecloud::messaging::repository::ScyllaMessagingAuditOutboxRepository>(scylla_session);

    // 5. Construct the durable audit outbox relay. Audit is not a startup dependency;
    // unavailable Audit leaves rows pending in ScyllaDB for background retry.
    securecloud::messaging::audit::AuditClientConfig audit_client_config;
    audit_client_config.target_address = config.audit.endpoint;
    audit_client_config.client_cert_path = config.common.tls_credentials.service_cert_path.string();
    audit_client_config.client_key_path = config.common.tls_credentials.service_key_path.string();
    audit_client_config.ca_cert_path = config.common.tls_credentials.ca_cert_path.string();
    audit_client_config.expected_peer_san = config.audit.expected_peer_san;
    audit_client_config.timeout = std::chrono::milliseconds(config.audit.rpc_timeout_ms);
    auto audit_client = std::make_shared<securecloud::messaging::audit::MessagingAuditClient>(audit_client_config);

    securecloud::messaging::audit::OutboxRelayConfig audit_relay_config;
    audit_relay_config.worker_threads = config.audit.worker_threads;
    audit_relay_config.batch_size = config.audit.batch_size;
    audit_relay_config.max_retries = static_cast<int32_t>(config.audit.max_retries);
    audit_relay_config.producer_instance = config.audit.producer_instance;
    audit_relay_config.active_poll_interval = std::chrono::milliseconds(config.audit.active_poll_interval_ms);
    audit_relay_config.idle_poll_interval = std::chrono::milliseconds(config.audit.idle_poll_interval_ms);
    audit_relay_config.lease_duration = std::chrono::seconds(config.audit.lease_duration_sec);
    auto audit_relay = std::make_unique<securecloud::messaging::audit::MessagingOutboxRelay>(audit_outbox, audit_client,
                                                                                             audit_relay_config);

    // 6. Initialize mTLS Auth Crypto Directory client & all domain services
    auto auth_channel = securecloud::common::security::MtlsCredentialLoader::create_mtls_channel(
        config.auth.endpoint, config.common.tls_credentials, config.auth.expected_peer_san);
    auto auth_crypto_client = std::make_shared<securecloud::messaging::client::AuthCryptoDirectoryClient>(auth_channel);
    auto device_status_checker =
        [auth_crypto_client](const securecloud::messaging::domain::DeviceId& device_id) -> bool {
        auto res = auth_crypto_client->get_device_crypto_identity(device_id);
        return res.has_value() && res.value().status == securecloud::auth::v1::DEVICE_STATUS_ACTIVE;
    };

    auto conv_auth_service = std::make_shared<securecloud::messaging::service::ConversationAuthorizationService>(
        *conversation_repo, *membership_repo);
    auto conversation_service = std::make_shared<securecloud::messaging::service::ConversationService>(
        *conversation_repo, *membership_repo, *conv_auth_service, audit_outbox);
    auto sequence_allocator =
        std::make_shared<securecloud::messaging::service::ConversationSequenceAllocator>(message_repo);
    auto idempotency_guard =
        std::make_shared<securecloud::messaging::service::MessageSubmissionIdempotencyGuard>(idempotency_repo);
    auto resolution_service =
        std::make_shared<securecloud::messaging::service::RecipientDeviceResolutionService>(auth_crypto_client);
    auto envelope_validator =
        std::make_shared<securecloud::messaging::service::E2EEnvelopeValidator>(resolution_service);
    auto submission_service = std::make_shared<securecloud::messaging::service::MessageSubmissionService>(
        conv_auth_service, sequence_allocator, idempotency_guard, message_repo, delivery_repo, outbox_repo,
        audit_outbox, envelope_validator, resolution_service);
    auto delivery_service = std::make_shared<securecloud::messaging::service::DeliveryService>(
        delivery_repo, outbox_repo, device_status_checker);
    auto read_receipt_service = std::make_shared<securecloud::messaging::service::ReadReceiptService>(
        delivery_repo, membership_repo, outbox_repo, audit_outbox, device_status_checker);
    auto cursor_manager = std::make_shared<securecloud::messaging::service::SyncCursorManager>(
        sync_cursor_repo, message_repo, sequence_allocator);
    auto sync_service = std::make_shared<securecloud::messaging::service::MessageSyncService>(
        message_repo, cursor_manager, conv_auth_service, delivery_repo);
    auto presence_coordinator = std::make_shared<securecloud::messaging::service::PresenceCoordinator>();

    if (config.audit.relay_enabled) {
        audit_relay->start();
    }

    // 7. Instantiate MessagingServiceImpl with full live production service graph
    securecloud::messaging::service::MessagingServiceImpl messaging_service(
        submission_pool, delivery_pool, sync_pool, conversation_service, submission_service, delivery_service,
        read_receipt_service, sync_service, cursor_manager, presence_coordinator, resolution_service);

    // 8. Initialize health status manager and health service
    const std::string server_address = config.common.listen_address();
    securecloud::common::health::HealthStatusManager health_manager(config.common.service_name);
    health_manager.set_readiness_evaluator([&config] {
        return securecloud::common::health::probe_tcp_connectivity(config.scylla.host, config.scylla.port);
    });
    securecloud::common::health::HealthServiceImpl health_service(config.common.service_name, health_manager);

    // 9. Construct and start gRPC server strictly over mTLS
    grpc::ServerBuilder builder;
    builder.AddListeningPort(server_address, server_creds);
    builder.RegisterService(&messaging_service);
    builder.RegisterService(&health_service);

    std::unique_ptr<grpc::Server> server = builder.BuildAndStart();
    if (!server) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Failed to start gRPC mTLS server on "
                  << server_address << "\n";
        return 1;
    }

    health_manager.set_live(true);
    health_manager.set_ready(true);

    std::cout << "[SecureCloud] [" << config.common.service_name << "] mTLS server listening strictly on "
              << server_address << " with service identity 'DNS:" << config.common.service_name << "'\n";

    // 10. Main service loop waiting for shutdown signal
    while (!g_shutdown_requested.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(k_poll_interval);
    }

    // 11. Deterministic Graceful Drain Sequence (ADR-009, ADR-010)
    std::cout << "[SecureCloud] [" << config.common.service_name
              << "] Shutdown signal received; initiating graceful drain...\n";
    health_manager.set_shutting_down(true);

    const auto drain_deadline =
        std::chrono::system_clock::now() + std::chrono::milliseconds(config.shutdown_grace_period_ms);
    std::cout << "[SecureCloud] [" << config.common.service_name
              << "] Draining gRPC server (deadline: " << config.shutdown_grace_period_ms << "ms)...\n";
    server->Shutdown(drain_deadline);

    audit_relay->stop();

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Draining bounded worker pools...\n";
    submission_pool->drain_and_stop();
    delivery_pool->drain_and_stop();
    sync_pool->drain_and_stop();
    scylla_session->close();

    std::cout << "[SecureCloud] [" << config.common.service_name << "] Graceful shutdown completed successfully.\n";
    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [messaging] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [messaging] Unknown fatal error occurred\n";
        return 1;
    }
}
