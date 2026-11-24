#include "audit/audit_diagnostics.hpp"
#include "audit/canonical_audit_mapper.hpp"
#include "audit/messaging_audit_client.hpp"
#include "audit/messaging_audit_metrics.hpp"
#include "audit/messaging_outbox_relay.hpp"
#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/delivery_worker.hpp"
#include "delivery/device_connection_registry.hpp"
#include "delivery/mock_device_delivery_channel.hpp"
#include "domain/audit_event.hpp"
#include "domain/audit_event_id.hpp"
#include "messaging/db/scylla_error_mapper.hpp"
#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/db/scylla_session_pool.hpp"
#include "messaging/repository/in_memory_conversation_repository.hpp"
#include "messaging/repository/in_memory_membership_repository.hpp"
#include "messaging/repository/scylla_messaging_audit_outbox_repository.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "service/conversation_service.hpp"
#include "service/delivery_retry_policy.hpp"
#include "service/in_memory_sequence_allocator.hpp"
#include "service/message_submission_service.hpp"
#include "service/read_receipt_service.hpp"
#include "util/zero_plaintext_guard.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace securecloud::messaging::test {
namespace {

using audit::AuditDiagnostics;
using audit::AuditQuarantineReason;
using audit::IMessagingAuditClient;
using audit::map_outbox_record_to_canonical_proto;
using audit::MessagingAuditMetrics;
using audit::MessagingOutboxRelay;
using audit::OutboxRelayConfig;
using domain::compute_outbox_bucket_utc;
using domain::compute_outbox_shard_id;
using domain::MessagingAuditEventType;
using domain::MessagingAuditSeverity;
using repository::AuditOutboxRecord;
using repository::ScyllaMessagingAuditOutboxRepository;

// ============================================================================
// 1. Ephemeral OpenSSL mTLS PKI Bundle (CA + Server + Client Certificates)
// ============================================================================

struct EphemeralMtlsBundle {
    std::string ca_cert_pem;
    std::string server_cert_pem;
    std::string server_key_pem;
    std::string client_cert_pem;
    std::string client_key_pem;
};

class OpenSslPkiGenerator {
  public:
    static EphemeralMtlsBundle generate() {
        EphemeralMtlsBundle bundle;

        auto ca_key = generate_ec_key();
        auto ca_cert = create_cert(ca_key.get(), ca_key.get(), nullptr, "SecureCloud Test Root CA", true, "");

        auto server_key = generate_ec_key();
        auto server_cert = create_cert(server_key.get(), ca_key.get(), ca_cert.get(), "audit.securecloud.internal",
                                       false, "DNS:audit.securecloud.internal,DNS:localhost,IP:127.0.0.1");

        auto client_key = generate_ec_key();
        auto client_cert = create_cert(client_key.get(), ca_key.get(), ca_cert.get(), "messaging.securecloud.internal",
                                       false, "DNS:messaging.securecloud.internal");

        bundle.ca_cert_pem = cert_to_pem(ca_cert.get());
        bundle.server_cert_pem = cert_to_pem(server_cert.get());
        bundle.server_key_pem = key_to_pem(server_key.get());
        bundle.client_cert_pem = cert_to_pem(client_cert.get());
        bundle.client_key_pem = key_to_pem(client_key.get());
        return bundle;
    }

  private:
    using EvpKeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    static EvpKeyPtr generate_ec_key() {
        EVP_PKEY_CTX* raw_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EXPECT_NE(raw_ctx, nullptr);
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(raw_ctx, &EVP_PKEY_CTX_free);

        EXPECT_EQ(EVP_PKEY_keygen_init(ctx.get()), 1);
        EXPECT_EQ(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1), 1);

        EVP_PKEY* raw_key = nullptr;
        EXPECT_EQ(EVP_PKEY_keygen(ctx.get(), &raw_key), 1);
        return EvpKeyPtr(raw_key, &EVP_PKEY_free);
    }

    static X509Ptr create_cert(EVP_PKEY* subject_key, EVP_PKEY* issuer_key, X509* issuer_cert, const char* common_name,
                               bool is_ca, const char* san_value) {
        X509Ptr cert(X509_new(), &X509_free);
        EXPECT_NE(cert, nullptr);

        X509_set_version(cert.get(), 2); // v3

        static std::atomic<long> serial_counter{100};
        ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial_counter.fetch_add(1));

        X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);

        X509_set_pubkey(cert.get(), subject_key);

        std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> subj(X509_NAME_new(), &X509_NAME_free);
        EXPECT_NE(subj, nullptr);
        X509_NAME_add_entry_by_txt(subj.get(), "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("SecureCloud"),
                                   -1, -1, 0);
        X509_NAME_add_entry_by_txt(subj.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name),
                                   -1, -1, 0);
        X509_set_subject_name(cert.get(), subj.get());

        if (issuer_cert != nullptr) {
            X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer_cert));
        } else {
            X509_set_issuer_name(cert.get(), subj.get());
        }

        X509V3_CTX ext_ctx;
        X509V3_set_ctx_nodb(&ext_ctx);
        X509V3_set_ctx(&ext_ctx, issuer_cert != nullptr ? issuer_cert : cert.get(), cert.get(), nullptr, nullptr, 0);

        add_ext(cert.get(), &ext_ctx, NID_basic_constraints, is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
        add_ext(cert.get(), &ext_ctx, NID_key_usage,
                is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment");

        if (san_value != nullptr && san_value[0] != '\0') {
            add_ext(cert.get(), &ext_ctx, NID_subject_alt_name, san_value);
        }

        EXPECT_GT(X509_sign(cert.get(), issuer_key, EVP_sha256()), 0);
        return cert;
    }

    static void add_ext(X509* cert, X509V3_CTX* ctx, int nid, const char* value) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, ctx, nid, value);
        if (ext != nullptr) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    static std::string cert_to_pem(X509* cert) {
        BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
        PEM_write_bio_X509(bio.get(), cert);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        return std::string(data, static_cast<size_t>(len));
    }

    static std::string key_to_pem(EVP_PKEY* key) {
        BioPtr bio(BIO_new(BIO_s_mem()), &BIO_free);
        PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        return std::string(data, static_cast<size_t>(len));
    }
};

// ============================================================================
// 2. Stateful In-Memory ScyllaDB Session for Outbox Partition/Clustering CQL
// ============================================================================

class StatefulScyllaOutboxSession final : public db::IScyllaSession {
  public:
    struct StoredOutboxRow {
        std::string outbox_bucket;
        int32_t shard_id{0};
        int64_t created_at_ms{0};
        std::string event_id;
        std::string event_type;
        std::string severity;
        std::string actor_user_id;
        std::string actor_device_id;
        std::string target_resource;
        std::vector<uint8_t> payload_proto_bin;
        std::string publish_status{"PENDING"};
        int32_t attempt_count{0};
        bool has_last_attempt_at{false};
        int64_t last_attempt_at_ms{0};
        bool has_last_error{false};
        std::string last_error;
        bool has_leased_until{false};
        int64_t leased_until_ms{0};
    };

    db::ScyllaQueryResult execute(std::string_view /*cql*/,
                                  db::ConsistencyLevel /*cl*/ = db::ConsistencyLevel::LocalQuorum) override {
        return {};
    }

    db::PreparedStatementId prepare(std::string_view query_id, std::string_view /*cql*/) override {
        return db::PreparedStatementId(std::string(query_id));
    }

    db::ScyllaQueryResult execute_prepared(const db::PreparedStatementId& id, const db::ScyllaParams& params,
                                           db::ConsistencyLevel /*cl*/ = db::ConsistencyLevel::LocalQuorum) override {
        std::lock_guard<std::mutex> lock(mutex_);

        if (fail_next_writes_ > 0 && id.value() == "audit_outbox_enqueue") {
            --fail_next_writes_;
            throw db::ScyllaException(db::ScyllaErrorCode::InternalError,
                                      "Injected ScyllaDB LOCAL_QUORUM write timeout on messaging_audit_outbox");
        }

        if (id.value() == "audit_outbox_enqueue") {
            static const std::vector<std::string> kCols = {
                "outbox_bucket",  "shard_id",      "created_at",      "event_id",        "event_type",
                "severity",       "actor_user_id", "actor_device_id", "target_resource", "payload_proto_bin",
                "publish_status", "attempt_count", "last_attempt_at", "last_error",      "leased_until"};
            db::ScyllaRow r(kCols, params.values());

            StoredOutboxRow rec;
            rec.outbox_bucket = r.get_string("outbox_bucket");
            rec.shard_id = r.get_int("shard_id");
            rec.created_at_ms = r.get_timestamp("created_at");
            rec.event_id = r.get_string("event_id");
            rec.event_type = r.get_string("event_type");
            rec.severity = r.get_string("severity");
            if (!r.is_null("actor_user_id")) {
                rec.actor_user_id = r.get_string("actor_user_id");
            }
            if (!r.is_null("actor_device_id")) {
                rec.actor_device_id = r.get_string("actor_device_id");
            }
            if (!r.is_null("target_resource")) {
                rec.target_resource = r.get_string("target_resource");
            }
            if (!r.is_null("payload_proto_bin")) {
                rec.payload_proto_bin = r.get_blob("payload_proto_bin");
            }
            rec.publish_status = r.is_null("publish_status") ? "PENDING" : r.get_string("publish_status");
            rec.attempt_count = r.is_null("attempt_count") ? 0 : r.get_int("attempt_count");
            if (!r.is_null("last_attempt_at")) {
                rec.has_last_attempt_at = true;
                rec.last_attempt_at_ms = r.get_timestamp("last_attempt_at");
            }
            if (!r.is_null("last_error")) {
                rec.has_last_error = true;
                rec.last_error = r.get_string("last_error");
            }
            if (!r.is_null("leased_until")) {
                rec.has_leased_until = true;
                rec.leased_until_ms = r.get_timestamp("leased_until");
            }

            // Upsert by primary key ((outbox_bucket, shard_id), created_at, event_id)
            bool updated = false;
            for (auto& existing : rows_) {
                if (existing.outbox_bucket == rec.outbox_bucket && existing.shard_id == rec.shard_id &&
                    existing.created_at_ms == rec.created_at_ms && existing.event_id == rec.event_id) {
                    existing = rec;
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                rows_.push_back(std::move(rec));
            }
            return {};
        }

        if (id.value() == "audit_outbox_fetch_pending") {
            db::ScyllaRow p({"outbox_bucket", "shard_id", "limit"}, params.values());
            const std::string bucket = p.get_string("outbox_bucket");
            const int32_t shard = p.get_int("shard_id");
            const size_t limit = static_cast<size_t>(std::max(0, p.get_int("limit")));

            static const std::vector<std::string> kCols = {
                "outbox_bucket",  "shard_id",      "created_at",      "event_id",        "event_type",
                "severity",       "actor_user_id", "actor_device_id", "target_resource", "payload_proto_bin",
                "publish_status", "attempt_count", "last_attempt_at", "last_error",      "leased_until"};

            std::vector<db::ScyllaRow> result_rows;
            for (const auto& rec : rows_) {
                if (rec.outbox_bucket == bucket && rec.shard_id == shard && rec.publish_status == "PENDING") {
                    std::vector<db::ScyllaValue> vals = {
                        db::ScyllaValue(rec.outbox_bucket),
                        db::ScyllaValue(rec.shard_id),
                        db::ScyllaValue(rec.created_at_ms),
                        db::ScyllaValue(rec.event_id),
                        db::ScyllaValue(rec.event_type),
                        db::ScyllaValue(rec.severity),
                        rec.actor_user_id.empty() ? db::ScyllaValue::null() : db::ScyllaValue(rec.actor_user_id),
                        rec.actor_device_id.empty() ? db::ScyllaValue::null() : db::ScyllaValue(rec.actor_device_id),
                        rec.target_resource.empty() ? db::ScyllaValue::null() : db::ScyllaValue(rec.target_resource),
                        db::ScyllaValue(rec.payload_proto_bin),
                        db::ScyllaValue(rec.publish_status),
                        db::ScyllaValue(rec.attempt_count),
                        rec.has_last_attempt_at ? db::ScyllaValue(rec.last_attempt_at_ms) : db::ScyllaValue::null(),
                        rec.has_last_error ? db::ScyllaValue(rec.last_error) : db::ScyllaValue::null(),
                        rec.has_leased_until ? db::ScyllaValue(rec.leased_until_ms) : db::ScyllaValue::null(),
                    };
                    result_rows.emplace_back(kCols, std::move(vals));
                    if (result_rows.size() >= limit) {
                        break;
                    }
                }
            }
            return db::ScyllaQueryResult(std::move(result_rows));
        }

        if (id.value() == "audit_outbox_lease_event") {
            db::ScyllaRow p({"leased_until", "outbox_bucket", "shard_id", "created_at", "event_id"}, params.values());
            const int64_t leased_until = p.get_timestamp("leased_until");
            const std::string bucket = p.get_string("outbox_bucket");
            const int32_t shard = p.get_int("shard_id");
            const int64_t created_at = p.get_timestamp("created_at");
            const std::string event_id = p.get_string("event_id");

            for (auto& rec : rows_) {
                if (rec.outbox_bucket == bucket && rec.shard_id == shard && rec.created_at_ms == created_at &&
                    rec.event_id == event_id) {
                    rec.has_leased_until = true;
                    rec.leased_until_ms = leased_until;
                }
            }
            return {};
        }

        if (id.value() == "audit_outbox_mark_published") {
            db::ScyllaRow p({"outbox_bucket", "shard_id", "created_at", "event_id"}, params.values());
            const std::string bucket = p.get_string("outbox_bucket");
            const int32_t shard = p.get_int("shard_id");
            const int64_t created_at = p.get_timestamp("created_at");
            const std::string event_id = p.get_string("event_id");

            for (auto& rec : rows_) {
                if (rec.outbox_bucket == bucket && rec.shard_id == shard && rec.created_at_ms == created_at &&
                    rec.event_id == event_id) {
                    rec.publish_status = "PUBLISHED";
                    rec.has_leased_until = false;
                    rec.leased_until_ms = 0;
                }
            }
            return {};
        }

        if (id.value() == "audit_outbox_select_attempts") {
            db::ScyllaRow p({"outbox_bucket", "shard_id", "created_at", "event_id"}, params.values());
            const std::string bucket = p.get_string("outbox_bucket");
            const int32_t shard = p.get_int("shard_id");
            const int64_t created_at = p.get_timestamp("created_at");
            const std::string event_id = p.get_string("event_id");

            for (const auto& rec : rows_) {
                if (rec.outbox_bucket == bucket && rec.shard_id == shard && rec.created_at_ms == created_at &&
                    rec.event_id == event_id) {
                    return db::ScyllaQueryResult(
                        {db::ScyllaRow({"attempt_count"}, {db::ScyllaValue(rec.attempt_count)})});
                }
            }
            return {};
        }

        if (id.value() == "audit_outbox_record_failure") {
            db::ScyllaRow p({"publish_status", "attempt_count", "last_attempt_at", "last_error", "outbox_bucket",
                             "shard_id", "created_at", "event_id"},
                            params.values());
            const std::string next_status = p.get_string("publish_status");
            const int32_t next_attempts = p.get_int("attempt_count");
            const int64_t last_attempt_at = p.get_timestamp("last_attempt_at");
            const std::string last_error = p.get_string("last_error");
            const std::string bucket = p.get_string("outbox_bucket");
            const int32_t shard = p.get_int("shard_id");
            const int64_t created_at = p.get_timestamp("created_at");
            const std::string event_id = p.get_string("event_id");

            for (auto& rec : rows_) {
                if (rec.outbox_bucket == bucket && rec.shard_id == shard && rec.created_at_ms == created_at &&
                    rec.event_id == event_id) {
                    rec.publish_status = next_status;
                    rec.attempt_count = next_attempts;
                    rec.has_last_attempt_at = true;
                    rec.last_attempt_at_ms = last_attempt_at;
                    rec.has_last_error = true;
                    rec.last_error = last_error;
                    rec.has_leased_until = false;
                    rec.leased_until_ms = 0;
                }
            }
            return {};
        }

        if (id.value() == "audit_outbox_count_pending") {
            db::ScyllaRow p({"outbox_bucket", "shard_id"}, params.values());
            const std::string bucket = p.get_string("outbox_bucket");
            const int32_t shard = p.get_int("shard_id");

            int64_t count = 0;
            for (const auto& rec : rows_) {
                if (rec.outbox_bucket == bucket && rec.shard_id == shard && rec.publish_status == "PENDING") {
                    ++count;
                }
            }
            return db::ScyllaQueryResult({db::ScyllaRow({"pending_count"}, {db::ScyllaValue(count)})});
        }

        return {};
    }

    void execute_batch(const std::vector<db::BoundStatement>& /*batch*/,
                       db::BatchType /*type*/ = db::BatchType::Logged) override {}

    bool ping() override { return !closed_; }
    void close() override { closed_ = true; }
    [[nodiscard]] bool is_closed() const noexcept override { return closed_; }

    void inject_write_timeouts(int count) {
        std::lock_guard<std::mutex> lock(mutex_);
        fail_next_writes_ = count;
    }

    size_t count_by_status(std::string_view status) const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& r : rows_) {
            if (r.publish_status == status) {
                ++count;
            }
        }
        return count;
    }

    std::string status_of(std::string_view event_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& r : rows_) {
            if (r.event_id == event_id) {
                return r.publish_status;
            }
        }
        return "";
    }

    int32_t attempts_of(std::string_view event_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& r : rows_) {
            if (r.event_id == event_id) {
                return r.attempt_count;
            }
        }
        return -1;
    }

    std::string last_error_of(std::string_view event_id) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& r : rows_) {
            if (r.event_id == event_id) {
                return r.last_error;
            }
        }
        return "";
    }

  private:
    mutable std::mutex mutex_;
    bool closed_{false};
    int fail_next_writes_{0};
    std::vector<StoredOutboxRow> rows_;
};

// ============================================================================
// 3. Embedded mTLS AuditIngestionService gRPC Server + Client Adapter
// ============================================================================

class TestAuditIngestionServiceImpl final : public securecloud::audit::v1::AuditIngestionService::Service {
  public:
    ::grpc::Status SubmitAuditEvent(::grpc::ServerContext* /*context*/,
                                    const ::securecloud::audit::v1::SubmitAuditEventRequest* request,
                                    ::securecloud::audit::v1::SubmitAuditEventResponse* response) override {
        if (unavailable_.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Audit Service maintenance window");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        const auto& ev = request->event();
        if (poison_event_ids_.contains(ev.event_id())) {
            return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Poison pill event rejected");
        }

        if (ingested_by_id_.find(ev.event_id()) == ingested_by_id_.end()) {
            ingested_by_id_[ev.event_id()] = ev;
        }
        response->set_success(true);
        response->set_event_id(ev.event_id());
        response->set_received_at_ms(1763547600000);
        return ::grpc::Status::OK;
    }

    ::grpc::Status BatchSubmitAuditEvents(::grpc::ServerContext* /*context*/,
                                          const ::securecloud::audit::v1::BatchSubmitAuditEventsRequest* request,
                                          ::securecloud::audit::v1::BatchSubmitAuditEventsResponse* response) override {
        total_rpc_calls_.fetch_add(1);

        if (unavailable_.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Audit Service maintenance window");
        }

        uint32_t accepted = 0;
        uint32_t rejected = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& ev : request->events()) {
                if (poison_event_ids_.contains(ev.event_id())) {
                    ++rejected;
                    response->add_rejected_event_ids(ev.event_id());
                } else {
                    // Idempotent deduplication by event_id (UUIDv7)
                    if (ingested_by_id_.find(ev.event_id()) == ingested_by_id_.end()) {
                        ingested_by_id_[ev.event_id()] = ev;
                    }
                    ++accepted;
                }
            }
        }

        response->set_accepted_count(accepted);
        response->set_rejected_count(rejected);

        // Simulate crash/timeout AFTER durable ingestion on server side, BEFORE ack reaches caller
        if (drop_ack_once_.exchange(false)) {
            return ::grpc::Status(::grpc::StatusCode::DEADLINE_EXCEEDED,
                                  "Simulated network partition after ingestion prior to client ack");
        }

        return ::grpc::Status::OK;
    }

    void set_unavailable(bool down) noexcept { unavailable_.store(down); }
    void set_drop_ack_once(bool drop) noexcept { drop_ack_once_.store(drop); }

    void add_poison_event_id(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        poison_event_ids_.insert(id);
    }

    size_t unique_ingested_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return ingested_by_id_.size();
    }

    std::vector<securecloud::audit::v1::AuditEventProto> ingested_events() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<securecloud::audit::v1::AuditEventProto> out;
        out.reserve(ingested_by_id_.size());
        for (const auto& [_, ev] : ingested_by_id_) {
            out.push_back(ev);
        }
        return out;
    }

    uint64_t total_rpc_calls() const noexcept { return total_rpc_calls_.load(); }

  private:
    mutable std::mutex mutex_;
    std::atomic<bool> unavailable_{false};
    std::atomic<bool> drop_ack_once_{false};
    std::atomic<uint64_t> total_rpc_calls_{0};
    std::unordered_set<std::string> poison_event_ids_;
    std::unordered_map<std::string, securecloud::audit::v1::AuditEventProto> ingested_by_id_;
};

// ============================================================================
// 4. Helper Functions & Scenario In-Memory Repositories
// ============================================================================

AuditOutboxRecord build_canonical_outbox_record(const std::string& event_id, const std::string& event_type,
                                                const std::string& severity, const std::string& actor_user_id,
                                                const std::string& conversation_id, const std::string& metadata_json,
                                                std::chrono::system_clock::time_point created_at) {
    // 1. Enforce Zero-Plaintext Guard prior to staging
    util::ZeroPlaintextGuard::validate_audit_payload(metadata_json);

    // 2. Construct intermediate record with JSON payload and map to canonical AUDIT-002 Protobuf
    AuditOutboxRecord rec;
    rec.outbox_bucket = compute_outbox_bucket_utc(created_at);
    rec.shard_id = compute_outbox_shard_id(conversation_id);
    rec.created_at = created_at;
    rec.event_id = event_id;
    rec.event_type = event_type;
    rec.severity = severity;
    rec.actor_user_id = actor_user_id;
    rec.target_resource = conversation_id;
    rec.payload_proto_bin.assign(metadata_json.begin(), metadata_json.end());

    const auto canonical_proto = map_outbox_record_to_canonical_proto(rec);
    EXPECT_TRUE(canonical_proto.has_value());

    std::string serialized_wire;
    EXPECT_TRUE(canonical_proto->SerializeToString(&serialized_wire));
    rec.payload_proto_bin.assign(serialized_wire.begin(), serialized_wire.end());
    return rec;
}

class ScenarioIdempotencyRepo final : public repository::IIdempotencyRepository {
  public:
    std::optional<domain::IdempotencyRecord> find_submission(const domain::DeviceId& sender_device_id,
                                                             const std::string& idempotency_key) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = records_.find(sender_device_id.str() + ":" + idempotency_key);
        if (it == records_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void save_submission(const domain::IdempotencyRecord& record) override {
        std::lock_guard<std::mutex> lock(mutex_);
        records_[record.sender_device_id.str() + ":" + record.idempotency_key] = record;
    }

  private:
    std::mutex mutex_;
    std::unordered_map<std::string, domain::IdempotencyRecord> records_;
};

class ScenarioMessageRepo final : public repository::IMessageRepository {
  public:
    void save_message(const domain::MessageEntity& msg) override {
        std::lock_guard<std::mutex> lock(mutex_);
        messages_.push_back(msg);
    }

    std::optional<domain::MessageEntity> find_by_id(const domain::ConversationId& conversation_id,
                                                    const domain::MessageBucket& /*message_bucket*/,
                                                    const domain::MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& m : messages_) {
            if (m.conversation_id == conversation_id && m.message_id == message_id) {
                return m;
            }
        }
        return std::nullopt;
    }

    std::vector<domain::MessageEntity>
    list_messages_by_sequence_range(const domain::ConversationId& /*conversation_id*/,
                                    const domain::MessageBucket& /*message_bucket*/, uint64_t /*from_sequence*/,
                                    uint64_t /*to_sequence*/, size_t /*limit*/) override {
        return {};
    }

    uint64_t get_last_sequence(const domain::ConversationId& /*conversation_id*/,
                               const domain::MessageBucket& /*message_bucket*/) override {
        return 0;
    }

  private:
    std::mutex mutex_;
    std::vector<domain::MessageEntity> messages_;
};

class ScenarioDeliveryStateRepo final : public repository::IDeliveryStateRepository {
  public:
    void save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>& records) override {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_.insert(pending_.end(), records.begin(), records.end());
    }

    std::vector<domain::DeviceDeliveryRecord> fetch_pending_for_device(const domain::DeviceId& device_id,
                                                                       const std::string& delivery_bucket,
                                                                       size_t limit) override {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<domain::DeviceDeliveryRecord> out;
        for (const auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket) {
                out.push_back(rec);
                if (out.size() >= limit) {
                    break;
                }
            }
        }
        return out;
    }

    void update_device_delivery_status(const domain::DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& /*accepted_at*/,
                                       const domain::MessageId& message_id, domain::DeliveryState state,
                                       int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& rec : pending_) {
            if (rec.device_id == device_id && rec.delivery_bucket == delivery_bucket && rec.message_id == message_id) {
                rec.delivery_state = state;
                rec.attempt_count = attempt_count;
                rec.next_retry_at = next_retry;
            }
        }
    }

    void save_recipient_delivery_states(const std::vector<domain::RecipientDeliveryState>& states) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& state : states) {
            recipient_states_[state.message_id.to_string()].push_back(state);
        }
    }

    void record_delivery_ack(const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id.to_string());
        if (it == recipient_states_.end()) {
            return;
        }
        for (auto& s : it->second) {
            if (s.recipient_device_id == recipient_device_id) {
                s.delivery_state = domain::DeliveryState::Delivered;
                s.delivered_at = delivered_at;
            }
        }
    }

    void record_read_ack(const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recipient_states_.find(message_id.to_string());
        if (it == recipient_states_.end()) {
            return;
        }
        for (auto& s : it->second) {
            if (s.recipient_device_id == recipient_device_id) {
                s.delivery_state = domain::DeliveryState::Read;
                s.read_at = read_at;
            }
        }
    }

    std::vector<domain::RecipientDeliveryState>
    get_delivery_states_for_message(const domain::MessageId& message_id) override {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = recipient_states_.find(message_id.to_string());
        if (it == recipient_states_.end()) {
            return {};
        }
        return it->second;
    }

  private:
    std::mutex mutex_;
    std::vector<domain::DeviceDeliveryRecord> pending_;
    std::unordered_map<std::string, std::vector<domain::RecipientDeliveryState>> recipient_states_;
};

class ScenarioOutboxRepo final : public repository::IOutboxRepository {
  public:
    void enqueue_event(const domain::ConversationOutboxEvent& event, const std::string& outbox_bucket) override {
        std::lock_guard<std::mutex> lock(mutex_);
        repository::OutboxEventRecord rec;
        rec.outbox_bucket =
            outbox_bucket.empty() ? repository::outbox_bucket_from_time_point(event.created_at) : outbox_bucket;
        rec.created_at = event.created_at;
        rec.event_id = event.event_id;
        rec.conversation_id = event.conversation_id;
        rec.event_type = domain::to_string(event.event_type);
        rec.payload_json = event.payload_json;
        events_.push_back(std::move(rec));
    }

    std::vector<repository::OutboxEventRecord> fetch_pending_events(const std::string& /*outbox_bucket*/,
                                                                    size_t /*limit*/) override {
        return {};
    }

    void mark_event_published(const std::string& /*outbox_bucket*/,
                              std::chrono::system_clock::time_point /*created_at*/, const std::string& /*event_id*/,
                              std::chrono::system_clock::time_point /*published_at*/) override {}

  private:
    std::mutex mutex_;
    std::vector<repository::OutboxEventRecord> events_;
};

bool is_scylla_reachable(const std::string& host = "127.0.0.1", uint16_t port = 9042, int timeout_ms = 250) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    bool ok = (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
    closesocket(sock);
    return ok;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return false;
    }
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    bool ok = (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0);
    close(sock);
    return ok;
#endif
}

// ============================================================================
// 5. Integration & Fault Injection Test Fixture
// ============================================================================

class MessagingAuditOutboxIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        MessagingAuditMetrics::instance().reset();
        AuditDiagnostics::set_log_sink([this](std::string_view line) {
            std::lock_guard<std::mutex> lock(logs_mutex_);
            captured_logs_.emplace_back(line);
        });

        pki_ = OpenSslPkiGenerator::generate();
        session_ = std::make_shared<StatefulScyllaOutboxSession>();

        simulated_now_ = std::chrono::system_clock::now();
        repo_ = std::make_shared<ScyllaMessagingAuditOutboxRepository>(session_,
                                                                       [this]() { return simulated_now_.load(); });

        audit_service_ = std::make_unique<TestAuditIngestionServiceImpl>();
        start_mtls_server();

        audit::AuditClientConfig client_cfg;
        client_cfg.target_address = server_address_;
        client_cfg.expected_peer_san = "audit.securecloud.internal";
        client_cfg.timeout = std::chrono::seconds(2);
        client_cfg.ca_cert_pem = pki_.ca_cert_pem;
        client_cfg.client_cert_pem = pki_.client_cert_pem;
        client_cfg.client_key_pem = pki_.client_key_pem;
        client_ = std::make_shared<audit::MessagingAuditClient>(client_cfg);
    }

    void TearDown() override {
        stop_mtls_server();
        AuditDiagnostics::reset_log_sink();
        MessagingAuditMetrics::instance().reset();
    }

    void start_mtls_server() {
        grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert_pair{pki_.server_key_pem, pki_.server_cert_pem};
        grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
        ssl_opts.pem_root_certs = pki_.ca_cert_pem;
        ssl_opts.pem_key_cert_pairs.push_back(std::move(key_cert_pair));

        int selected_port = 0;
        grpc::ServerBuilder builder;
        builder.AddListeningPort("127.0.0.1:0", grpc::SslServerCredentials(ssl_opts), &selected_port);
        builder.RegisterService(audit_service_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);
        ASSERT_GT(selected_port, 0);
        server_address_ = "127.0.0.1:" + std::to_string(selected_port);
    }

    void stop_mtls_server() {
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + std::chrono::milliseconds(200));
            server_->Wait();
            server_.reset();
        }
    }

    std::vector<std::string> logs() {
        std::lock_guard<std::mutex> lock(logs_mutex_);
        return captured_logs_;
    }

    EphemeralMtlsBundle pki_;
    std::shared_ptr<StatefulScyllaOutboxSession> session_;
    std::atomic<std::chrono::system_clock::time_point> simulated_now_{std::chrono::system_clock::now()};
    std::shared_ptr<ScyllaMessagingAuditOutboxRepository> repo_;
    std::unique_ptr<TestAuditIngestionServiceImpl> audit_service_;
    std::unique_ptr<grpc::Server> server_;
    std::string server_address_;
    std::shared_ptr<audit::MessagingAuditClient> client_;

    std::mutex logs_mutex_;
    std::vector<std::string> captured_logs_;
};

// ============================================================================
// Scenario 1: End-to-End Outbox -> Canonical Proto -> mTLS gRPC Ingestion
// ============================================================================

TEST_F(MessagingAuditOutboxIntegrationTest, EndToEndSubmissionAndCanonicalMappingOverRealMtlsGrpc) {
    const auto now = simulated_now_.load();

    struct EventSpec {
        std::string id;
        std::string type;
        std::string severity;
        std::string conv_id;
        std::string metadata;
    };

    const std::vector<EventSpec> specs = {
        {"01934400-0000-7000-8000-000000000001", "message.submitted", "INFO", "conv-alpha",
         R"({"message_id":"msg-01","recipient_count":2,"payload_size_bytes":256})"},
        {"01934400-0000-7000-8000-000000000002", "message.delivered", "INFO", "conv-beta",
         R"({"message_id":"msg-01","recipient_device_id":"dev-bob-1"})"},
        {"01934400-0000-7000-8000-000000000003", "message.read", "INFO", "conv-gamma", R"({"watermark_sequence":14})"},
        {"01934400-0000-7000-8000-000000000004", "conversation.created", "INFO", "conv-delta",
         R"({"conversation_type":"GROUP","initial_member_count":4})"},
        {"01934400-0000-7000-8000-000000000005", "security.authorization.denied", "SECURITY", "conv-epsilon",
         R"({"action":"ADD_PARTICIPANT","denial_reason":"INSUFFICIENT_ROLE"})"},
    };

    for (const auto& s : specs) {
        repo_->enqueue_audit_event(
            build_canonical_outbox_record(s.id, s.type, s.severity, "user-alice", s.conv_id, s.metadata, now));
    }

    ASSERT_EQ(session_->count_by_status("PENDING"), specs.size());

    OutboxRelayConfig cfg;
    cfg.worker_threads = 4;
    cfg.total_shards = 16;
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    MessagingOutboxRelay relay(repo_, client_, cfg);
    relay.start();

    for (int i = 0; i < 200 && session_->count_by_status("PUBLISHED") < specs.size(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    relay.stop();

    EXPECT_EQ(session_->count_by_status("PUBLISHED"), specs.size());
    EXPECT_EQ(session_->count_by_status("PENDING"), 0U);
    EXPECT_EQ(session_->count_by_status("QUARANTINED"), 0U);
    EXPECT_EQ(audit_service_->unique_ingested_count(), specs.size());

    for (const auto& proto : audit_service_->ingested_events()) {
        EXPECT_EQ(proto.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
        EXPECT_EQ(proto.actor_type(), securecloud::audit::v1::ACTOR_TYPE_USER);
        EXPECT_EQ(proto.actor_id(), "user-alice");
        EXPECT_EQ(proto.target_type(), securecloud::audit::v1::TARGET_TYPE_CONVERSATION);
        EXPECT_GT(proto.occurred_at_ms(), 0);
        EXPECT_FALSE(proto.metadata().empty());
    }
}

// ============================================================================
// Failure Window 1: Audit Service Down at Submission Time -> Zero Message Loss
// ============================================================================

TEST_F(MessagingAuditOutboxIntegrationTest, FailureWindow1_AuditServiceUnavailableAtSubmissionZeroMessageLoss) {
    // 1. Bring Audit Service down before any messaging events occur
    audit_service_->set_unavailable(true);

    const auto now = simulated_now_.load();
    constexpr size_t kEventCount = 12;

    const auto t_start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kEventCount; ++i) {
        const std::string id =
            "01934400-0001-7000-8000-0000000000" + (i < 10 ? "0" + std::to_string(i) : std::to_string(i));
        repo_->enqueue_audit_event(build_canonical_outbox_record(
            id, "message.submitted", "INFO", "user-sender", "conv-outage-" + std::to_string(i % 4),
            R"({"message_id":"msg-outage","recipient_count":1})", now));
    }
    const auto enqueue_elapsed = std::chrono::steady_clock::now() - t_start;

    // Outbox enqueue must be non-blocking and fast even while Audit Service is down
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(enqueue_elapsed).count(), 250);

    OutboxRelayConfig cfg;
    cfg.worker_threads = 2;
    cfg.total_shards = 16;
    cfg.max_retries = 50; // Survive outage window without premature quarantine
    cfg.lease_duration = std::chrono::seconds(1);
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    MessagingOutboxRelay relay(repo_, client_, cfg);
    relay.start();

    // Wait until relay has attempted dispatch during outage and recorded transient retries
    // Wait until relay has attempted dispatch during outage and recorded transient retries
    for (int i = 0;
         i < 150 && MessagingAuditMetrics::instance().retried_total(audit::AuditRetryReason::Unavailable) == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    EXPECT_GT(MessagingAuditMetrics::instance().retried_total(audit::AuditRetryReason::Unavailable), 0U);
    EXPECT_EQ(session_->count_by_status("PUBLISHED"), 0U);
    EXPECT_EQ(session_->count_by_status("QUARANTINED"), 0U);

    // 2. Restore Audit Service availability -> all buffered events must drain with 0% loss
    audit_service_->set_unavailable(false);

    for (int i = 0; i < 300 && session_->count_by_status("PUBLISHED") < kEventCount; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    relay.stop();

    EXPECT_EQ(session_->count_by_status("PUBLISHED"), kEventCount);
    EXPECT_EQ(session_->count_by_status("QUARANTINED"), 0U);
    EXPECT_EQ(audit_service_->unique_ingested_count(), kEventCount);
}

// ============================================================================
// Failure Window 2: Worker Crash After Ingestion Prior to Outbox Ack ->
// Lease Expiration Recovery & Idempotent Deduplication (Zero Duplicates)
// ============================================================================

TEST_F(MessagingAuditOutboxIntegrationTest, FailureWindow2_CrashAfterPartialAckRecoversViaLeaseAndDeduplicates) {
    const auto now = simulated_now_.load();
    constexpr size_t kEventCount = 6;

    for (size_t i = 0; i < kEventCount; ++i) {
        repo_->enqueue_audit_event(build_canonical_outbox_record(
            "01934400-0002-7000-8000-00000000000" + std::to_string(i), "message.submitted", "INFO", "user-alice",
            "conv-crash-recovery", R"({"message_id":"msg-crash","recipient_count":1})", now));
    }

    // Server ingests the first batch durably, then drops the network ack (simulating worker/network crash before
    // mark_published)
    audit_service_->set_drop_ack_once(true);

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 16;
    cfg.lease_duration = std::chrono::seconds(30);
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    auto relay_before_crash = std::make_unique<MessagingOutboxRelay>(repo_, client_, cfg);
    relay_before_crash->start();

    for (int i = 0; i < 150 && audit_service_->unique_ingested_count() < kEventCount; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Simulate abrupt worker stop before second retry cycle
    relay_before_crash->stop();
    relay_before_crash.reset();

    // Server already received all 6 events, while outbox still shows them PENDING
    EXPECT_EQ(audit_service_->unique_ingested_count(), kEventCount);
    EXPECT_EQ(session_->count_by_status("PENDING"), kEventCount);
    EXPECT_EQ(session_->count_by_status("PUBLISHED"), 0U);

    // Advance clock beyond lease_duration (30s -> +35s) and start replacement relay worker
    simulated_now_.store(now + std::chrono::seconds(35));

    MessagingOutboxRelay relay_after_crash(repo_, client_, cfg);
    relay_after_crash.start();

    for (int i = 0; i < 200 && session_->count_by_status("PUBLISHED") < kEventCount; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    relay_after_crash.stop();

    // Outbox transitions cleanly to PUBLISHED and Audit Service deduplicates by event_id (still exact count = 6)
    EXPECT_EQ(session_->count_by_status("PUBLISHED"), kEventCount);
    EXPECT_EQ(audit_service_->unique_ingested_count(), kEventCount);
    EXPECT_GE(audit_service_->total_rpc_calls(), 2U);
}

// ============================================================================
// Failure Window 3: ScyllaDB Write Timeout Propagates Failure (No Silent Drop)
// ============================================================================

TEST_F(MessagingAuditOutboxIntegrationTest, FailureWindow3_ScyllaDbWriteTimeoutPropagatesFailureWithoutSilentDrop) {
    const auto now = simulated_now_.load();
    const auto record = build_canonical_outbox_record("01934400-0003-7000-8000-000000000001", "message.submitted",
                                                      "INFO", "user-alice", "conv-scylla-timeout",
                                                      R"({"message_id":"msg-timeout","recipient_count":1})", now);

    // Inject transient ScyllaDB LOCAL_QUORUM write timeout
    session_->inject_write_timeouts(1);

    // Enqueue MUST throw ScyllaException so the caller rolls back / rejects message submission rather than dropping
    // audit
    EXPECT_THROW(repo_->enqueue_audit_event(record), db::ScyllaException);
    EXPECT_EQ(session_->count_by_status("PENDING"), 0U);

    // Once ScyllaDB recovers, retry succeeds and relay delivers to Audit Service
    ASSERT_NO_THROW(repo_->enqueue_audit_event(record));
    EXPECT_EQ(session_->count_by_status("PENDING"), 1U);

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 16;
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    MessagingOutboxRelay relay(repo_, client_, cfg);
    relay.start();

    for (int i = 0; i < 150 && session_->count_by_status("PUBLISHED") < 1; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    relay.stop();

    EXPECT_EQ(session_->count_by_status("PUBLISHED"), 1U);
    EXPECT_EQ(audit_service_->unique_ingested_count(), 1U);
}

// ============================================================================
// Failure Window 4: Poison-Pill Event Quarantined Without Blocking Healthy Batch
// ============================================================================

TEST_F(MessagingAuditOutboxIntegrationTest, FailureWindow4_PoisonPillQuarantinedWithoutHeadOfLineBlocking) {
    const auto now = simulated_now_.load();
    const std::string shared_conv = "conv-shared-shard";
    const std::string poison_id_1 = "01934400-0004-7000-8000-000000000098";
    const std::string poison_id_2 = "01934400-0004-7000-8000-000000000099";

    audit_service_->add_poison_event_id(poison_id_1);
    audit_service_->add_poison_event_id(poison_id_2);

    // Stage 8 healthy events interleaved with 2 poison-pill events on the exact same shard
    for (int i = 0; i < 4; ++i) {
        repo_->enqueue_audit_event(build_canonical_outbox_record(
            "01934400-0004-7000-8000-00000000000" + std::to_string(i), "message.submitted", "INFO", "user-alice",
            shared_conv, R"({"message_id":"msg-good","recipient_count":1})", now));
    }
    repo_->enqueue_audit_event(
        build_canonical_outbox_record(poison_id_1, "message.submitted", "INFO", "user-alice", shared_conv,
                                      R"({"message_id":"msg-poison-1","recipient_count":1})", now));
    for (int i = 4; i < 8; ++i) {
        repo_->enqueue_audit_event(build_canonical_outbox_record(
            "01934400-0004-7000-8000-00000000000" + std::to_string(i), "message.submitted", "INFO", "user-alice",
            shared_conv, R"({"message_id":"msg-good","recipient_count":1})", now));
    }
    repo_->enqueue_audit_event(
        build_canonical_outbox_record(poison_id_2, "message.submitted", "INFO", "user-alice", shared_conv,
                                      R"({"message_id":"msg-poison-2","recipient_count":1})", now));

    OutboxRelayConfig cfg;
    cfg.worker_threads = 1;
    cfg.total_shards = 16;
    cfg.active_poll_interval = std::chrono::milliseconds(5);
    cfg.idle_poll_interval = std::chrono::milliseconds(10);

    MessagingOutboxRelay relay(repo_, client_, cfg);
    relay.start();

    for (int i = 0;
         i < 200 && (session_->count_by_status("PUBLISHED") < 8 || session_->count_by_status("QUARANTINED") < 2); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    relay.stop();

    EXPECT_EQ(session_->count_by_status("PUBLISHED"), 8U);
    EXPECT_EQ(session_->count_by_status("QUARANTINED"), 2U);
    EXPECT_EQ(session_->count_by_status("PENDING"), 0U);
    EXPECT_EQ(session_->status_of(poison_id_1), "QUARANTINED");
    EXPECT_EQ(session_->status_of(poison_id_2), "QUARANTINED");
    EXPECT_FALSE(session_->last_error_of(poison_id_1).empty());
    EXPECT_EQ(audit_service_->unique_ingested_count(), 8U);
    EXPECT_EQ(MessagingAuditMetrics::instance().quarantined_total(AuditQuarantineReason::InvalidArgument), 2U);
}

TEST_F(MessagingAuditOutboxIntegrationTest, FullProducerPipelineServicesToRelayOverRealMtlsGrpc) {
    auto conv_repo = std::make_shared<repository::InMemoryConversationRepository>();
    auto memb_repo = std::make_shared<repository::InMemoryMembershipRepository>();
    auto auth_svc = std::make_shared<service::ConversationAuthorizationService>(*conv_repo, *memb_repo);
    auto seq_alloc = std::make_shared<service::InMemorySequenceAllocator>();
    auto idem_repo = std::make_shared<ScenarioIdempotencyRepo>();
    auto idem_guard = std::make_shared<service::MessageSubmissionIdempotencyGuard>(idem_repo);
    auto msg_repo = std::make_shared<ScenarioMessageRepo>();
    auto deliv_repo = std::make_shared<ScenarioDeliveryStateRepo>();
    auto outbox_repo = std::make_shared<ScenarioOutboxRepo>();

    service::ConversationService conv_svc(*conv_repo, *memb_repo, *auth_svc, repo_);
    service::MessageSubmissionService sub_svc(auth_svc, seq_alloc, idem_guard, msg_repo, deliv_repo, outbox_repo, repo_,
                                              nullptr, nullptr);
    service::ReadReceiptService read_svc(deliv_repo, memb_repo, outbox_repo, repo_);

    auto scheduler = std::make_shared<delivery::BoundedDeliveryScheduler>();
    auto registry = std::make_shared<delivery::DeviceConnectionRegistry>();
    auto retry_policy = std::make_shared<service::DeliveryRetryPolicy>();
    delivery::DeliveryWorker worker(scheduler, registry, deliv_repo, outbox_repo, repo_, retry_policy);

    const domain::UserId alice_id("01934400-0100-7000-8000-000000000001");
    const domain::UserId bob_id("01934400-0100-7000-8000-000000000002");
    const domain::UserId carol_id("01934400-0100-7000-8000-000000000003");
    const domain::DeviceId alice_dev("alice-dev-e2e");
    const domain::DeviceId bob_dev("bob-dev-e2e");

    auto bob_channel = std::make_shared<delivery::MockDeviceDeliveryChannel>(bob_dev, bob_id);
    bob_channel->set_next_result(domain::DeliveryAttemptResult::Success);
    registry->register_channel(bob_channel);

    // 1. Conversation creation & membership mutations (plaintext group title must never leak to audit metadata)
    const auto create_res = conv_svc.create_group_conversation(alice_id, "Top Secret Project Title", {bob_id});
    ASSERT_TRUE(create_res.success);
    const auto conv_id = create_res.value.conversation_id;
    ASSERT_TRUE(conv_svc.add_participant(alice_id, conv_id, carol_id).success);
    ASSERT_TRUE(conv_svc.remove_participant(alice_id, conv_id, carol_id).success);

    // 2. Normal & Emergency message submission (ciphertext must never leak to audit metadata)
    auto make_sub_cmd = [&](std::string token, domain::MessagePriority prio) {
        domain::MessageSubmissionCommand cmd;
        cmd.caller_user_id = alice_id;
        cmd.sender_device_id = alice_dev;
        cmd.conversation_id = conv_id;
        cmd.client_idempotency_token = std::move(token);
        cmd.priority = prio;

        domain::DeviceDeliveryTarget target;
        target.recipient_user_id = bob_id;
        target.recipient_device_id = bob_dev;
        target.ciphertext_blob = "SENSITIVE_CIPHERTEXT_SECRET_123";
        target.ephemeral_public_key = std::vector<uint8_t>(32, 0x11);
        target.iv = std::vector<uint8_t>(24, 0x22);
        target.auth_tag = std::vector<uint8_t>(16, 0x33);
        target.algorithm = "XChaCha20-Poly1305";
        cmd.delivery_targets.push_back(std::move(target));
        return cmd;
    };

    const auto normal_sub = sub_svc.submit_message(make_sub_cmd("e2e-norm-1", domain::MessagePriority::Normal));
    ASSERT_TRUE(normal_sub.success);
    const auto emerg_sub = sub_svc.submit_message(make_sub_cmd("e2e-emerg-1", domain::MessagePriority::Emergency));
    ASSERT_TRUE(emerg_sub.success);

    // 3. Delivery worker dispatches normal message
    domain::DeliveryTask task;
    task.message_id = normal_sub.value.message_id;
    task.conversation_id = conv_id;
    task.recipient_device_id = bob_dev;
    task.recipient_user_id = bob_id;
    task.priority = domain::MessagePriority::Normal;
    task.accepted_at = normal_sub.value.accepted_at;
    task.scheduled_at = normal_sub.value.accepted_at;
    task.envelope.ciphertext_blob = "SENSITIVE_CIPHERTEXT_SECRET_123";
    ASSERT_EQ(scheduler->schedule(task), delivery::SchedulerStatus::Enqueued);
    ASSERT_TRUE(worker.process_single_task(std::chrono::milliseconds(100)));

    // 4. Recipient records read receipt
    service::ReadReceiptCommand read_cmd;
    read_cmd.message_id = normal_sub.value.message_id;
    read_cmd.conversation_id = conv_id;
    read_cmd.caller_user_id = bob_id;
    read_cmd.reader_device_id = bob_dev;
    read_cmd.caller_device_id = bob_dev;
    read_cmd.read_at = std::chrono::system_clock::now();
    const auto read_res = read_svc.record_read_receipt(read_cmd);
    ASSERT_TRUE(read_res.success);

    // 8 canonical audit events staged into Scylla outbox:
    // conversation.created (1), conversation.membership.changed (2),
    // message.submitted (2), emergency.activated (1), message.delivered (1), message.read (1)
    ASSERT_EQ(session_->count_by_status("PENDING"), 8u);

    OutboxRelayConfig cfg;
    cfg.worker_threads = 2;
    cfg.total_shards = 16;
    cfg.active_poll_interval = std::chrono::milliseconds(10);
    cfg.idle_poll_interval = std::chrono::milliseconds(20);
    cfg.batch_size = 50;

    MessagingOutboxRelay relay(repo_, client_, cfg);
    relay.start();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        if (audit_service_->unique_ingested_count() >= 8u && session_->count_by_status("PENDING") == 0u) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    relay.stop();

    EXPECT_EQ(session_->count_by_status("PENDING"), 0u);
    EXPECT_EQ(session_->count_by_status("PUBLISHED"), 8u);
    EXPECT_EQ(audit_service_->unique_ingested_count(), 8u);

    const auto ingested = audit_service_->ingested_events();
    std::unordered_map<std::string, int> counts;
    bool saw_emergency_critical = false;
    for (const auto& ev : ingested) {
        EXPECT_TRUE(domain::is_valid_audit_uuid_v7(ev.event_id()));
        EXPECT_EQ(ev.producer_service(), securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING);
        counts[ev.event_type()] += 1;
        if (ev.event_type() == "emergency.activated" && ev.severity() == securecloud::audit::v1::SEVERITY_CRITICAL) {
            saw_emergency_critical = true;
        }
        const std::string wire = ev.SerializeAsString();
        EXPECT_EQ(wire.find("Top Secret Project Title"), std::string::npos);
        EXPECT_EQ(wire.find("SENSITIVE_CIPHERTEXT_SECRET_123"), std::string::npos);
    }
    EXPECT_EQ(counts["conversation.created"], 1);
    EXPECT_EQ(counts["conversation.membership.changed"], 2);
    EXPECT_EQ(counts["message.submitted"], 2);
    EXPECT_EQ(counts["emergency.activated"], 1);
    EXPECT_EQ(counts["message.delivered"], 1);
    EXPECT_EQ(counts["message.read"], 1);
    EXPECT_TRUE(saw_emergency_critical);
}

// ============================================================================
// Live ScyllaDB Cluster Verification (Guarded by Reachability)
// ============================================================================

TEST(ScyllaLiveAuditOutboxIntegrationTest, LiveScyllaOutboxTableRoundTripWhenClusterReachable) {
    if (!is_scylla_reachable("127.0.0.1", 9042, 250)) {
        GTEST_SKIP() << "ScyllaDB cluster on 127.0.0.1:9042 is offline. Skipping live container outbox test.";
    }

    messaging::ScyllaConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 9042;
    cfg.keyspace = "securecloud_messaging";

    auto live_session = std::make_shared<db::ScyllaSession>(cfg);
    ASSERT_TRUE(live_session->ping());

    ScyllaMessagingAuditOutboxRepository live_repo(live_session);
    const auto now = std::chrono::system_clock::now();
    const auto rec = build_canonical_outbox_record("01934400-0005-7000-8000-000000000001", "message.submitted", "INFO",
                                                   "user-live-test", "conv-live-outbox",
                                                   R"({"message_id":"msg-live","recipient_count":1})", now);

    ASSERT_NO_THROW(live_repo.enqueue_audit_event(rec));
    const auto fetched = live_repo.fetch_pending_events(rec.outbox_bucket, rec.shard_id, 10, std::chrono::seconds(5));
    EXPECT_FALSE(fetched.empty());

    ASSERT_NO_THROW(live_repo.mark_published(rec.outbox_bucket, rec.shard_id, rec.created_at, rec.event_id));
}

} // namespace
} // namespace securecloud::messaging::test
