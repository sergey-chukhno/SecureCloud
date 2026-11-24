#include "files/audit/grpc_audit_client.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace securecloud::files::audit {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

[[nodiscard]] std::string make_uuid_v7() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    const auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());

    std::array<uint8_t, 16> bytes{};
    bytes[0] = static_cast<uint8_t>((now_ms >> 40) & 0xFFu);
    bytes[1] = static_cast<uint8_t>((now_ms >> 32) & 0xFFu);
    bytes[2] = static_cast<uint8_t>((now_ms >> 24) & 0xFFu);
    bytes[3] = static_cast<uint8_t>((now_ms >> 16) & 0xFFu);
    bytes[4] = static_cast<uint8_t>((now_ms >> 8) & 0xFFu);
    bytes[5] = static_cast<uint8_t>(now_ms & 0xFFu);

    const uint64_t r1 = rng();
    const uint64_t r2 = rng();
    bytes[6] = static_cast<uint8_t>(0x70u | ((r1 >> 56) & 0x0Fu));
    bytes[7] = static_cast<uint8_t>((r1 >> 48) & 0xFFu);
    bytes[8] = static_cast<uint8_t>(0x80u | ((r2 >> 56) & 0x3Fu));
    bytes[9] = static_cast<uint8_t>((r2 >> 48) & 0xFFu);
    bytes[10] = static_cast<uint8_t>((r2 >> 40) & 0xFFu);
    bytes[11] = static_cast<uint8_t>((r2 >> 32) & 0xFFu);
    bytes[12] = static_cast<uint8_t>((r2 >> 24) & 0xFFu);
    bytes[13] = static_cast<uint8_t>((r2 >> 16) & 0xFFu);
    bytes[14] = static_cast<uint8_t>((r2 >> 8) & 0xFFu);
    bytes[15] = static_cast<uint8_t>(r2 & 0xFFu);

    char buf[37]{};
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0],
                  bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10],
                  bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

class MockAuditIngestionStub : public securecloud::audit::v1::AuditIngestionService::StubInterface {
  public:
    MOCK_METHOD(grpc::Status, SubmitAuditEvent,
                (grpc::ClientContext * context, const securecloud::audit::v1::SubmitAuditEventRequest& request,
                 securecloud::audit::v1::SubmitAuditEventResponse* response),
                (override));

    MOCK_METHOD(grpc::Status, BatchSubmitAuditEvents,
                (grpc::ClientContext * context, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 securecloud::audit::v1::BatchSubmitAuditEventsResponse* response),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::SubmitAuditEventResponse>*,
                AsyncSubmitAuditEventRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::SubmitAuditEventRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::SubmitAuditEventResponse>*,
                PrepareAsyncSubmitAuditEventRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::SubmitAuditEventRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::BatchSubmitAuditEventsResponse>*,
                AsyncBatchSubmitAuditEventsRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 grpc::CompletionQueue* cq),
                (override));

    MOCK_METHOD(grpc::ClientAsyncResponseReaderInterface<securecloud::audit::v1::BatchSubmitAuditEventsResponse>*,
                PrepareAsyncBatchSubmitAuditEventsRaw,
                (grpc::ClientContext * context, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& request,
                 grpc::CompletionQueue* cq),
                (override));
};

securecloud::audit::v1::AuditEventProto make_proto_event() {
    securecloud::audit::v1::AuditEventProto ev;
    ev.set_event_id(make_uuid_v7());
    ev.set_occurred_at_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    ev.set_event_type("file.created");
    ev.set_severity(securecloud::audit::v1::SEVERITY_INFO);
    ev.set_producer_service(securecloud::audit::v1::PRODUCER_SERVICE_FILES);
    ev.set_producer_instance("files-1");
    ev.set_actor_type(securecloud::audit::v1::ACTOR_TYPE_USER);
    ev.set_actor_id(make_uuid_v7());
    ev.set_target_type(securecloud::audit::v1::TARGET_TYPE_FILE);
    ev.set_target_id(make_uuid_v7());
    ev.set_correlation_id(ev.event_id());
    return ev;
}

struct EphemeralMtlsBundle {
    std::filesystem::path dir;
    std::filesystem::path ca_cert;
    std::filesystem::path files_cert;
    std::filesystem::path files_key;
    std::filesystem::path valid_audit_cert;
    std::filesystem::path valid_audit_key;
    std::filesystem::path mismatched_audit_cert;
    std::filesystem::path mismatched_audit_key;

    ~EphemeralMtlsBundle() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

EvpPkeyPtr generate_rsa_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
    }
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx_guard(ctx, &EVP_PKEY_CTX_free);
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        throw std::runtime_error("EVP_PKEY_keygen setup failed");
    }
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &raw_pkey) <= 0 || !raw_pkey) {
        throw std::runtime_error("EVP_PKEY_keygen failed");
    }
    return EvpPkeyPtr(raw_pkey, &EVP_PKEY_free);
}

void write_pem_key(const std::filesystem::path& path, EVP_PKEY* pkey) {
    BIO* bio = BIO_new_file(path.string().c_str(), "wb");
    if (!bio) {
        throw std::runtime_error("Failed to open key file for writing");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> bio_guard(bio, &BIO_free);
    if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("PEM_write_bio_PrivateKey failed");
    }
}

void write_pem_cert(const std::filesystem::path& path, X509* cert) {
    BIO* bio = BIO_new_file(path.string().c_str(), "wb");
    if (!bio) {
        throw std::runtime_error("Failed to open cert file for writing");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> bio_guard(bio, &BIO_free);
    if (PEM_write_bio_X509(bio, cert) != 1) {
        throw std::runtime_error("PEM_write_bio_X509 failed");
    }
}

void add_x509_ext(X509* issuer, X509* subject, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, subject, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (!ext) {
        throw std::runtime_error("X509V3_EXT_conf_nid failed");
    }
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext_guard(ext, &X509_EXTENSION_free);
    if (X509_add_ext(subject, ext, -1) != 1) {
        throw std::runtime_error("X509_add_ext failed");
    }
}

X509Ptr create_ca_cert(EVP_PKEY* ca_key) {
    X509Ptr cert(X509_new(), &X509_free);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), ca_key);

    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> name(X509_NAME_new(), &X509_NAME_free);
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("SecureCloud Test CA"), -1, -1, 0);
    X509_set_subject_name(cert.get(), name.get());
    X509_set_issuer_name(cert.get(), name.get());

    add_x509_ext(cert.get(), cert.get(), NID_basic_constraints, "critical,CA:TRUE");
    add_x509_ext(cert.get(), cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");

    if (X509_sign(cert.get(), ca_key, EVP_sha256()) <= 0) {
        throw std::runtime_error("Failed to sign CA cert");
    }
    return cert;
}

X509Ptr create_leaf_cert(EVP_PKEY* leaf_key, X509* ca_cert, EVP_PKEY* ca_key, long serial, const std::string& cn,
                         const std::string& san_dns) {
    X509Ptr cert(X509_new(), &X509_free);
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600);
    X509_set_pubkey(cert.get(), leaf_key);

    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> subj(X509_NAME_new(), &X509_NAME_free);
    X509_NAME_add_entry_by_txt(subj.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1,
                               -1, 0);
    X509_set_subject_name(cert.get(), subj.get());
    X509_set_issuer_name(cert.get(), const_cast<X509_NAME*>(X509_get_subject_name(ca_cert)));

    add_x509_ext(ca_cert, cert.get(), NID_basic_constraints, "CA:FALSE");
    add_x509_ext(ca_cert, cert.get(), NID_ext_key_usage, "serverAuth,clientAuth");
    const std::string san_value = "DNS:" + san_dns;
    add_x509_ext(ca_cert, cert.get(), NID_subject_alt_name, san_value.c_str());

    if (X509_sign(cert.get(), ca_key, EVP_sha256()) <= 0) {
        throw std::runtime_error("Failed to sign leaf cert");
    }
    return cert;
}

EphemeralMtlsBundle create_ephemeral_mtls_bundle() {
    EphemeralMtlsBundle bundle;
    bundle.dir = std::filesystem::temp_directory_path() / ("sc_files_mtls_" + make_uuid_v7());
    std::filesystem::create_directories(bundle.dir);

    auto ca_key = generate_rsa_key();
    auto ca_cert = create_ca_cert(ca_key.get());
    bundle.ca_cert = bundle.dir / "ca.crt";
    write_pem_cert(bundle.ca_cert, ca_cert.get());

    auto files_key = generate_rsa_key();
    auto files_cert = create_leaf_cert(files_key.get(), ca_cert.get(), ca_key.get(), 2, "files", "files");
    bundle.files_cert = bundle.dir / "files.crt";
    bundle.files_key = bundle.dir / "files.key";
    write_pem_cert(bundle.files_cert, files_cert.get());
    write_pem_key(bundle.files_key, files_key.get());

    auto audit_key = generate_rsa_key();
    auto audit_cert = create_leaf_cert(audit_key.get(), ca_cert.get(), ca_key.get(), 3, "audit", "audit");
    bundle.valid_audit_cert = bundle.dir / "audit.crt";
    bundle.valid_audit_key = bundle.dir / "audit.key";
    write_pem_cert(bundle.valid_audit_cert, audit_cert.get());
    write_pem_key(bundle.valid_audit_key, audit_key.get());

    auto wrong_key = generate_rsa_key();
    auto wrong_cert =
        create_leaf_cert(wrong_key.get(), ca_cert.get(), ca_key.get(), 4, "wrong-service", "wrong-service");
    bundle.mismatched_audit_cert = bundle.dir / "wrong.crt";
    bundle.mismatched_audit_key = bundle.dir / "wrong.key";
    write_pem_cert(bundle.mismatched_audit_cert, wrong_cert.get());
    write_pem_key(bundle.mismatched_audit_key, wrong_key.get());

    return bundle;
}

class FakeAuditIngestionService final : public securecloud::audit::v1::AuditIngestionService::Service {
  public:
    grpc::Status BatchSubmitAuditEvents(grpc::ServerContext* context,
                                        const securecloud::audit::v1::BatchSubmitAuditEventsRequest* request,
                                        securecloud::audit::v1::BatchSubmitAuditEventsResponse* response) override {
        if (!common::security::verify_peer_service_identity(*context->auth_context(), "files")) {
            return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Expected files peer SAN");
        }
        response->set_accepted_count(static_cast<uint32_t>(request->events_size()));
        response->set_rejected_count(0);
        return grpc::Status::OK;
    }
};

} // namespace

TEST(FilesGrpcAuditClientTest, ConstructorFailsClosedOnMissingCredentialsOrInvalidConfig) {
    GrpcAuditClientConfig default_cfg;
    EXPECT_EQ(default_cfg.target_endpoint, "audit:50055");
    EXPECT_EQ(default_cfg.timeout, std::chrono::milliseconds{2000});
    EXPECT_EQ(default_cfg.expected_peer_san, "audit");

    GrpcAuditClientConfig empty_endpoint;
    empty_endpoint.target_endpoint = "";
    EXPECT_THROW(GrpcAuditClient{empty_endpoint}, std::invalid_argument);

    GrpcAuditClientConfig missing_tls;
    missing_tls.target_endpoint = "audit:50055";
    missing_tls.tls_credentials.ca_cert_path = "/nonexistent/ca.crt";
    missing_tls.tls_credentials.service_cert_path = "/nonexistent/files.crt";
    missing_tls.tls_credentials.service_key_path = "/nonexistent/files.key";
    EXPECT_THROW(GrpcAuditClient{missing_tls}, std::runtime_error);

    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    GrpcAuditClientConfig zero_timeout;
    zero_timeout.timeout = std::chrono::milliseconds{0};
    EXPECT_THROW((GrpcAuditClient{zero_timeout, stub}), std::invalid_argument);
    EXPECT_THROW((GrpcAuditClient{GrpcAuditClientConfig{}, nullptr}), std::invalid_argument);
    EXPECT_THROW((GrpcAuditClient{nullptr, std::chrono::milliseconds{1000}}), std::invalid_argument);
}

TEST(FilesGrpcAuditClientTest, EmptyBatchReturnsSuccessWithoutRpc) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _)).Times(0);

    GrpcAuditClient client(GrpcAuditClientConfig{}, stub);
    const auto result = client.submit_batch({});

    EXPECT_TRUE(result.rpc_success);
    EXPECT_TRUE(result.status.ok());
    EXPECT_EQ(result.accepted_count, 0u);
    EXPECT_EQ(result.rejected_count, 0u);
    EXPECT_TRUE(result.rejected_event_ids.empty());
}

TEST(FilesGrpcAuditClientTest, OversizedBatchGreaterThan100FailsLocallyWithoutRpc) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _)).Times(0);

    std::vector<securecloud::audit::v1::AuditEventProto> oversized;
    oversized.reserve(101);
    for (int i = 0; i < 101; ++i) {
        oversized.push_back(make_proto_event());
    }

    GrpcAuditClient client(GrpcAuditClientConfig{}, stub);
    const auto result = client.submit_batch(oversized);

    EXPECT_FALSE(result.rpc_success);
    EXPECT_EQ(result.status.error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(FilesGrpcAuditClientTest, EnforcesDeadlineAndMapsPartialRejectionResponse) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    GrpcAuditClientConfig cfg;
    cfg.timeout = std::chrono::milliseconds{1500};

    const auto ev1 = make_proto_event();
    const auto ev2 = make_proto_event();

    securecloud::audit::v1::BatchSubmitAuditEventsResponse mock_resp;
    mock_resp.set_accepted_count(1);
    mock_resp.set_rejected_count(1);
    mock_resp.add_rejected_event_ids(ev2.event_id());

    const auto before_call = std::chrono::system_clock::now();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(DoAll(
            [&](grpc::ClientContext* ctx, const securecloud::audit::v1::BatchSubmitAuditEventsRequest& req,
                securecloud::audit::v1::BatchSubmitAuditEventsResponse*) {
                EXPECT_EQ(req.events_size(), 2);
                const auto deadline = ctx->deadline();
                EXPECT_GE(deadline, before_call + std::chrono::milliseconds{1000});
                EXPECT_LE(deadline, before_call + std::chrono::milliseconds{2500});
            },
            SetArgPointee<2>(mock_resp), Return(grpc::Status::OK)));

    GrpcAuditClient client(cfg, stub);
    const auto result = client.submit_batch({ev1, ev2});

    EXPECT_TRUE(result.rpc_success);
    EXPECT_TRUE(result.status.ok());
    EXPECT_EQ(result.accepted_count, 1u);
    EXPECT_EQ(result.rejected_count, 1u);
    ASSERT_EQ(result.rejected_event_ids.size(), 1u);
    EXPECT_EQ(result.rejected_event_ids[0], ev2.event_id());
}

TEST(FilesGrpcAuditClientTest, PropagatesGrpcFailureStatus) {
    auto stub = std::make_shared<NiceMock<MockAuditIngestionStub>>();
    EXPECT_CALL(*stub, BatchSubmitAuditEvents(_, _, _))
        .WillOnce(Return(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service down")));

    GrpcAuditClient client(GrpcAuditClientConfig{}, stub);
    const auto result = client.submit_batch({make_proto_event()});

    EXPECT_FALSE(result.rpc_success);
    EXPECT_EQ(result.status.error_code(), grpc::StatusCode::UNAVAILABLE);
    EXPECT_EQ(result.status.error_message(), "Audit service down");
}

TEST(FilesGrpcAuditClientTest, MtlsEndToEndAcceptsMatchingSanAndRejectsMismatchedSan) {
    const auto bundle = create_ephemeral_mtls_bundle();
    FakeAuditIngestionService service;

    // 1. Server presenting valid SAN `DNS:audit`
    auto valid_server_creds = common::security::MtlsCredentialLoader::create_server_credentials(
        {bundle.ca_cert, bundle.valid_audit_cert, bundle.valid_audit_key});

    int valid_port = 0;
    grpc::ServerBuilder valid_builder;
    valid_builder.AddListeningPort("127.0.0.1:0", valid_server_creds, &valid_port);
    valid_builder.RegisterService(&service);
    auto valid_server = valid_builder.BuildAndStart();
    ASSERT_NE(valid_server, nullptr);
    ASSERT_GT(valid_port, 0);

    GrpcAuditClientConfig client_cfg;
    client_cfg.target_endpoint = "127.0.0.1:" + std::to_string(valid_port);
    client_cfg.timeout = std::chrono::milliseconds{3000};
    client_cfg.tls_credentials = {bundle.ca_cert, bundle.files_cert, bundle.files_key};
    client_cfg.expected_peer_san = "audit";

    GrpcAuditClient valid_client(client_cfg);
    const auto ok_result = valid_client.submit_batch({make_proto_event()});
    valid_server->Shutdown();

    EXPECT_TRUE(ok_result.rpc_success) << ok_result.status.error_message();
    EXPECT_EQ(ok_result.accepted_count, 1u);
    EXPECT_EQ(ok_result.rejected_count, 0u);

    // 2. Server presenting mismatched SAN `DNS:wrong-service` signed by same CA -> must fail closed
    auto wrong_server_creds = common::security::MtlsCredentialLoader::create_server_credentials(
        {bundle.ca_cert, bundle.mismatched_audit_cert, bundle.mismatched_audit_key});

    int wrong_port = 0;
    grpc::ServerBuilder wrong_builder;
    wrong_builder.AddListeningPort("127.0.0.1:0", wrong_server_creds, &wrong_port);
    wrong_builder.RegisterService(&service);
    auto wrong_server = wrong_builder.BuildAndStart();
    ASSERT_NE(wrong_server, nullptr);
    ASSERT_GT(wrong_port, 0);

    GrpcAuditClientConfig mismatch_cfg = client_cfg;
    mismatch_cfg.target_endpoint = "127.0.0.1:" + std::to_string(wrong_port);

    GrpcAuditClient mismatch_client(mismatch_cfg);
    const auto rejected_result = mismatch_client.submit_batch({make_proto_event()});
    wrong_server->Shutdown();

    EXPECT_FALSE(rejected_result.rpc_success);
    EXPECT_FALSE(rejected_result.status.ok());
}

} // namespace securecloud::files::audit
