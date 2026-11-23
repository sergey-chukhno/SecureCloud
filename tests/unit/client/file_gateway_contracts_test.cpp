#include "application/client_config.hpp"
#include "domain/file_transfer.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/evp.h>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using securecloud::common::configuration::SecretString;

std::string compute_test_sha256_hex(std::span<const uint8_t> data) {
    static constexpr std::array<char, 16> kHex = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    EXPECT_NE(ctx, nullptr);
    EXPECT_EQ(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr), 1);
    if (!data.empty()) {
        EXPECT_EQ(EVP_DigestUpdate(ctx.get(), data.data(), data.size()), 1);
    }
    std::array<uint8_t, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;
    EXPECT_EQ(EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len), 1);
    EXPECT_EQ(digest_len, 32U);

    std::string out;
    out.reserve(64U);
    for (unsigned int i = 0; i < digest_len; ++i) {
        const uint8_t b = digest[i];
        out.push_back(kHex[static_cast<std::size_t>((b >> 4U) & 0x0FU)]);
        out.push_back(kHex[static_cast<std::size_t>(b & 0x0FU)]);
    }
    return out;
}

std::string repeated_hex(char ch) {
    return std::string(64U, ch);
}

TEST(FileTransferDomainTest, DirectionAndStatusStringConversions) {
    EXPECT_EQ(to_string(FileTransferDirection::Outbound), "Outbound");
    EXPECT_EQ(to_string(FileTransferDirection::Inbound), "Inbound");
    EXPECT_EQ(file_transfer_direction_from_string("Outbound"), FileTransferDirection::Outbound);
    EXPECT_EQ(file_transfer_direction_from_string("Inbound"), FileTransferDirection::Inbound);
    EXPECT_FALSE(file_transfer_direction_from_string("Sideways").has_value());

    const std::array<FileTransferStatus, 7> statuses = {
        FileTransferStatus::Pending,    FileTransferStatus::InProgress, FileTransferStatus::Paused,
        FileTransferStatus::Finalizing, FileTransferStatus::Completed,  FileTransferStatus::Cancelled,
        FileTransferStatus::Failed,
    };
    for (const auto st : statuses) {
        const auto parsed = file_transfer_status_from_string(to_string(st));
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(*parsed, st);
    }
    EXPECT_FALSE(file_transfer_status_from_string("UnknownStatus").has_value());
}

TEST(FileTransferDomainTest, TransferRecordJsonRoundTripAndProgressCalculation) {
    FileTransferRecord record;
    record.transfer_id = "tr-001";
    record.file_id = "file-001";
    record.upload_id = "upload-001";
    record.conversation_id = ConversationId("conv-files-1");
    record.peer_user_id = UserId("bob-user");
    record.local_path = "/tmp/vault/design.pdf";
    record.file_name = "design.pdf";
    record.mime_type = "application/pdf";
    record.cipher_suite = "AES-256-GCM-v1";
    record.direction = FileTransferDirection::Outbound;
    record.status = FileTransferStatus::InProgress;
    record.plaintext_size_bytes = 123456ULL;
    record.encrypted_size_bytes = 123540ULL;
    record.chunk_size_bytes = kDefaultFileWireChunkSize;
    record.total_chunks = 4U;
    record.completed_chunks = 3U;
    record.plaintext_sha256 = repeated_hex('a');
    record.ciphertext_sha256 = repeated_hex('b');
    record.error_message = "";
    record.created_at_ms = 1700000100000LL;
    record.updated_at_ms = 1700000105000LL;

    EXPECT_EQ(record.progress_percent(), 75U);

    const std::string json_str = record.to_json();
    const auto decoded = FileTransferRecord::from_json(json_str);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, record);
    EXPECT_EQ(decoded->progress_percent(), 75U);

    FileTransferRecord zero_chunks = record;
    zero_chunks.total_chunks = 0U;
    zero_chunks.completed_chunks = 0U;
    zero_chunks.status = FileTransferStatus::Pending;
    EXPECT_EQ(zero_chunks.progress_percent(), 0U);

    FileTransferRecord clamped = record;
    clamped.completed_chunks = 10U;
    EXPECT_EQ(clamped.progress_percent(), 100U);

    FileTransferRecord done = record;
    done.completed_chunks = 0U;
    done.status = FileTransferStatus::Completed;
    EXPECT_EQ(done.progress_percent(), 100U);
}

TEST(FileTransferDomainTest, TransferRecordRejectsMalformedJsonAndInvalidEnums) {
    EXPECT_FALSE(FileTransferRecord::from_json("not-json").has_value());
    EXPECT_FALSE(FileTransferRecord::from_json("[]").has_value());
    EXPECT_FALSE(
        FileTransferRecord::from_json(
            R"({"transfer_id":"","file_id":"f","conversation_id":"c","direction":"Outbound","status":"Pending"})")
            .has_value());
    EXPECT_FALSE(
        FileTransferRecord::from_json(
            R"({"transfer_id":"t","file_id":"f","conversation_id":"c","direction":"Invalid","status":"Pending"})")
            .has_value());
    EXPECT_FALSE(
        FileTransferRecord::from_json(
            R"({"transfer_id":"t","file_id":"f","conversation_id":"c","direction":"Outbound","status":"Bogus"})")
            .has_value());
    EXPECT_FALSE(
        FileTransferRecord::from_json(
            R"({"transfer_id":"t","file_id":"f","conversation_id":"c","direction":"Outbound","status":"Pending","total_chunks":"NaN"})")
            .has_value());
}

TEST(FileTransferDomainTest, AttachmentKeyEnvelopeRoundTripAndSecretRedaction) {
    FileAttachmentKeyEnvelope env;
    env.file_id = "file-secret-01";
    env.file_key_hex = SecretString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    env.file_name = "quarterly-report.pdf";
    env.mime_type = "application/pdf";
    env.plaintext_size_bytes = 2048ULL;
    env.encrypted_size_bytes = 2076ULL;
    env.chunk_size_bytes = kDefaultFileWireChunkSize;
    env.chunk_count = 1U;
    env.ciphertext_sha256 = repeated_hex('c');
    env.plaintext_sha256 = repeated_hex('d');
    env.cipher_suite = "AES-256-GCM-v1";

    std::ostringstream os;
    os << env.file_key_hex;
    EXPECT_EQ(os.str(), "[REDACTED]");

    const std::string wire = env.serialize();
    EXPECT_TRUE(FileAttachmentKeyEnvelope::is_file_attachment_envelope(wire));
    EXPECT_FALSE(FileAttachmentKeyEnvelope::is_file_attachment_envelope("hello plain message"));
    EXPECT_FALSE(FileAttachmentKeyEnvelope::is_file_attachment_envelope(R"({"type":"other.msg"})"));

    const auto decoded = FileAttachmentKeyEnvelope::deserialize(wire);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, env);
    EXPECT_EQ(decoded->file_key_hex.expose_unredacted_secret(), env.file_key_hex.expose_unredacted_secret());
}

TEST(FileTransferDomainTest, AttachmentKeyEnvelopeValidationFailClosed) {
    FileAttachmentKeyEnvelope valid;
    valid.file_id = "file-valid";
    valid.file_key_hex = SecretString(repeated_hex('1'));
    valid.file_name = "secret.bin";
    valid.plaintext_size_bytes = 100ULL;
    valid.encrypted_size_bytes = 128ULL;
    valid.chunk_size_bytes = 1024U;
    valid.chunk_count = 1U;
    valid.ciphertext_sha256 = repeated_hex('2');
    valid.plaintext_sha256 = repeated_hex('3');

    EXPECT_TRUE(FileAttachmentKeyEnvelope::deserialize(valid.serialize()).has_value());
    EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize("bad-json").has_value());

    {
        FileAttachmentKeyEnvelope bad = valid;
        bad.file_key_hex = SecretString("short-key");
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(bad.serialize()).has_value());
    }
    {
        FileAttachmentKeyEnvelope bad = valid;
        bad.file_key_hex = SecretString(std::string(64U, 'z'));
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(bad.serialize()).has_value());
    }
    {
        FileAttachmentKeyEnvelope bad = valid;
        bad.ciphertext_sha256 = "not-a-sha256";
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(bad.serialize()).has_value());
    }
    {
        FileAttachmentKeyEnvelope bad = valid;
        bad.chunk_count = 0U;
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(bad.serialize()).has_value());
    }
    {
        FileAttachmentKeyEnvelope bad = valid;
        bad.chunk_size_bytes = kFileChunkAeadOverheadBytes;
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(bad.serialize()).has_value());
    }
    {
        FileAttachmentKeyEnvelope bad = valid;
        bad.plaintext_size_bytes = bad.encrypted_size_bytes + 1ULL;
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(bad.serialize()).has_value());
    }
    {
        const std::string wrong_type =
            R"({"type":"wrong.type","version":1,"file_id":"f","file_key_hex":")" + repeated_hex('1') +
            R"(","file_name":"a","plaintext_size_bytes":10,"encrypted_size_bytes":38,"chunk_size_bytes":1024,"chunk_count":1,"ciphertext_sha256":")" +
            repeated_hex('2') + R"(","plaintext_sha256":")" + repeated_hex('3') +
            R"(","cipher_suite":"AES-256-GCM-v1"})";
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(wrong_type).has_value());
    }
    {
        const std::string wrong_ver =
            R"({"type":"securecloud.file_attachment_key.v1","version":2,"file_id":"f","file_key_hex":")" +
            repeated_hex('1') +
            R"(","file_name":"a","plaintext_size_bytes":10,"encrypted_size_bytes":38,"chunk_size_bytes":1024,"chunk_count":1,"ciphertext_sha256":")" +
            repeated_hex('2') + R"(","plaintext_sha256":")" + repeated_hex('3') +
            R"(","cipher_suite":"AES-256-GCM-v1"})";
        EXPECT_FALSE(FileAttachmentKeyEnvelope::deserialize(wrong_ver).has_value());
    }
}

TEST(FileGatewayContractsTest, FullUploadFinalizeMetadataDownloadDeleteLifecycle) {
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const std::string file_id = "file-e2e-001";
    const std::vector<uint8_t> chunk0(64U, 0xA1U);
    const std::vector<uint8_t> chunk1(48U, 0xB2U);
    std::vector<uint8_t> combined = chunk0;
    combined.insert(combined.end(), chunk1.begin(), chunk1.end());

    const std::string chunk0_sha = compute_test_sha256_hex(chunk0);
    const std::string chunk1_sha = compute_test_sha256_hex(chunk1);
    const std::string total_sha = compute_test_sha256_hex(combined);

    const auto init_res = gateway.init_file_upload(FileUploadInitRequest{
        .file_id = file_id,
        .owner_user_id = UserId("alice"),
        .owner_device_id = DeviceId("dev-alice-1"),
        .conversation_id = ConversationId("conv-alice-bob"),
        .encrypted_size_bytes = static_cast<uint64_t>(combined.size()),
        .expected_chunk_count = 2U,
        .encryption_version = "v1",
        .client_crypto_metadata = R"({"cipher_suite":"AES-256-GCM-v1"})",
    });
    ASSERT_TRUE(init_res.is_ok());
    EXPECT_FALSE(init_res.value().upload_id.empty());
    EXPECT_EQ(init_res.value().file_id, file_id);
    EXPECT_EQ(init_res.value().status, "TRANSFER_STATUS_PENDING");

    // Upload chunk 0 (and verify idempotent re-upload works cleanly for resume)
    const auto up0 = gateway.upload_file_chunk(FileChunkUploadRequest{
        .upload_id = init_res.value().upload_id,
        .chunk_index = 0U,
        .encrypted_data = chunk0,
        .ciphertext_sha256 = chunk0_sha,
    });
    ASSERT_TRUE(up0.is_ok());
    EXPECT_TRUE(up0.value().accepted);
    EXPECT_EQ(up0.value().received_sha256, chunk0_sha);

    const auto up0_retry = gateway.upload_file_chunk(FileChunkUploadRequest{
        .upload_id = init_res.value().upload_id,
        .chunk_index = 0U,
        .encrypted_data = chunk0,
        .ciphertext_sha256 = chunk0_sha,
    });
    ASSERT_TRUE(up0_retry.is_ok());

    const auto up1 = gateway.upload_file_chunk(FileChunkUploadRequest{
        .upload_id = init_res.value().upload_id,
        .chunk_index = 1U,
        .encrypted_data = chunk1,
        .ciphertext_sha256 = chunk1_sha,
    });
    ASSERT_TRUE(up1.is_ok());
    EXPECT_EQ(gateway.uploaded_chunk_call_count(file_id), 3U);

    const auto fin_res = gateway.finalize_file_upload(FileUploadFinalizeRequest{
        .upload_id = init_res.value().upload_id,
        .file_id = file_id,
        .expected_ciphertext_sha256 = total_sha,
    });
    ASSERT_TRUE(fin_res.is_ok());
    EXPECT_EQ(fin_res.value().lifecycle_state, "FILE_LIFECYCLE_STATE_AVAILABLE");
    EXPECT_TRUE(gateway.has_stored_file(file_id));
    EXPECT_EQ(gateway.stored_file_raw_bytes(file_id), combined);

    const auto meta_res = gateway.get_file_metadata(file_id);
    ASSERT_TRUE(meta_res.is_ok());
    EXPECT_EQ(meta_res.value().file_id, file_id);
    EXPECT_EQ(meta_res.value().chunk_count, 2U);
    EXPECT_EQ(meta_res.value().encrypted_size_bytes, static_cast<uint64_t>(combined.size()));
    EXPECT_EQ(meta_res.value().ciphertext_integrity_hash, total_sha);

    const auto dl0 = gateway.download_file_chunk(file_id, 0U);
    ASSERT_TRUE(dl0.is_ok());
    EXPECT_EQ(dl0.value().encrypted_data, chunk0);
    EXPECT_EQ(dl0.value().ciphertext_sha256, chunk0_sha);

    const auto dl1 = gateway.download_file_chunk(file_id, 1U);
    ASSERT_TRUE(dl1.is_ok());
    EXPECT_EQ(dl1.value().encrypted_data, chunk1);
    EXPECT_EQ(dl1.value().ciphertext_sha256, chunk1_sha);

    EXPECT_TRUE(gateway.download_file_chunk(file_id, 2U).is_error());

    const auto del_res = gateway.delete_file(file_id);
    ASSERT_TRUE(del_res.is_ok());
    EXPECT_FALSE(gateway.has_stored_file(file_id));
    EXPECT_TRUE(gateway.get_file_metadata(file_id).is_error());
    EXPECT_TRUE(gateway.download_file_chunk(file_id, 0U).is_error());
}

TEST(FileGatewayContractsTest, RejectsChunkAndFinalizedSha256MismatchesAndMissingChunks) {
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const auto init_res = gateway.init_file_upload(FileUploadInitRequest{
        .file_id = "file-mismatch-01",
        .owner_user_id = UserId("alice"),
        .owner_device_id = DeviceId("dev-1"),
        .conversation_id = ConversationId("conv-1"),
        .encrypted_size_bytes = 64ULL,
        .expected_chunk_count = 2U,
    });
    ASSERT_TRUE(init_res.is_ok());

    const std::vector<uint8_t> chunk0(32U, 0x11U);
    const auto bad_chunk_sha = gateway.upload_file_chunk(FileChunkUploadRequest{
        .upload_id = init_res.value().upload_id,
        .chunk_index = 0U,
        .encrypted_data = chunk0,
        .ciphertext_sha256 = repeated_hex('f'),
    });
    EXPECT_TRUE(bad_chunk_sha.is_error());

    ASSERT_TRUE(gateway
                    .upload_file_chunk(FileChunkUploadRequest{
                        .upload_id = init_res.value().upload_id,
                        .chunk_index = 0U,
                        .encrypted_data = chunk0,
                        .ciphertext_sha256 = compute_test_sha256_hex(chunk0),
                    })
                    .is_ok());

    // Finalizing with chunk 1 missing must fail
    EXPECT_TRUE(gateway
                    .finalize_file_upload(FileUploadFinalizeRequest{
                        .upload_id = init_res.value().upload_id,
                        .file_id = "file-mismatch-01",
                        .expected_ciphertext_sha256 = "",
                    })
                    .is_error());

    // Upload chunk 1, then fail finalize due to wrong total hash
    const std::vector<uint8_t> chunk1(32U, 0x22U);
    ASSERT_TRUE(gateway
                    .upload_file_chunk(FileChunkUploadRequest{
                        .upload_id = init_res.value().upload_id,
                        .chunk_index = 1U,
                        .encrypted_data = chunk1,
                        .ciphertext_sha256 = compute_test_sha256_hex(chunk1),
                    })
                    .is_ok());

    EXPECT_TRUE(gateway
                    .finalize_file_upload(FileUploadFinalizeRequest{
                        .upload_id = init_res.value().upload_id,
                        .file_id = "file-mismatch-01",
                        .expected_ciphertext_sha256 = repeated_hex('0'),
                    })
                    .is_error());
}

TEST(FileGatewayContractsTest, CancelUploadPurgesSessionAndBlocksFurtherChunks) {
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const auto init_res = gateway.init_file_upload(FileUploadInitRequest{
        .file_id = "file-cancel-01",
        .owner_user_id = UserId("alice"),
        .owner_device_id = DeviceId("dev-1"),
        .conversation_id = ConversationId("conv-1"),
        .encrypted_size_bytes = 32ULL,
        .expected_chunk_count = 2U,
    });
    ASSERT_TRUE(init_res.is_ok());

    ASSERT_TRUE(gateway
                    .upload_file_chunk(FileChunkUploadRequest{
                        .upload_id = init_res.value().upload_id,
                        .chunk_index = 0U,
                        .encrypted_data = std::vector<uint8_t>(16U, 0x55U),
                    })
                    .is_ok());

    ASSERT_TRUE(gateway.cancel_file_upload(init_res.value().upload_id, "user cancelled").is_ok());

    EXPECT_TRUE(gateway
                    .upload_file_chunk(FileChunkUploadRequest{
                        .upload_id = init_res.value().upload_id,
                        .chunk_index = 1U,
                        .encrypted_data = std::vector<uint8_t>(16U, 0x66U),
                    })
                    .is_error());
    EXPECT_TRUE(gateway
                    .finalize_file_upload(FileUploadFinalizeRequest{
                        .upload_id = init_res.value().upload_id,
                        .file_id = "file-cancel-01",
                    })
                    .is_error());
    EXPECT_FALSE(gateway.has_stored_file("file-cancel-01"));
}

TEST(FileGatewayContractsTest, SimulatedFailureHooksAndTamperMutationSupport) {
    DefaultGatewayClient gateway(ClientConfig::create_default());

    const auto init_res = gateway.init_file_upload(FileUploadInitRequest{
        .file_id = "file-hooks-01",
        .owner_user_id = UserId("alice"),
        .owner_device_id = DeviceId("dev-1"),
        .conversation_id = ConversationId("conv-1"),
        .encrypted_size_bytes = 64ULL,
        .expected_chunk_count = 2U,
    });
    ASSERT_TRUE(init_res.is_ok());

    const std::vector<uint8_t> chunk0(32U, 0x33U);
    const std::vector<uint8_t> chunk1(32U, 0x44U);

    gateway.set_simulated_chunk_failure(1U, "Dropped chunk 1");
    ASSERT_TRUE(gateway
                    .upload_file_chunk(FileChunkUploadRequest{
                        .upload_id = init_res.value().upload_id,
                        .chunk_index = 0U,
                        .encrypted_data = chunk0,
                    })
                    .is_ok());
    const auto fail_up1 = gateway.upload_file_chunk(FileChunkUploadRequest{
        .upload_id = init_res.value().upload_id,
        .chunk_index = 1U,
        .encrypted_data = chunk1,
    });
    ASSERT_TRUE(fail_up1.is_error());
    EXPECT_EQ(fail_up1.error().category(), ClientErrorCategory::Network);

    gateway.set_simulated_chunk_failure(std::nullopt);
    ASSERT_TRUE(gateway
                    .upload_file_chunk(FileChunkUploadRequest{
                        .upload_id = init_res.value().upload_id,
                        .chunk_index = 1U,
                        .encrypted_data = chunk1,
                    })
                    .is_ok());
    ASSERT_TRUE(gateway
                    .finalize_file_upload(FileUploadFinalizeRequest{
                        .upload_id = init_res.value().upload_id,
                        .file_id = "file-hooks-01",
                    })
                    .is_ok());

    std::vector<uint8_t> tampered_chunk0 = chunk0;
    tampered_chunk0[0] ^= 0xFFU;
    ASSERT_TRUE(gateway.mutate_stored_file_chunk_for_test("file-hooks-01", 0U, tampered_chunk0, false));

    const auto dl_tampered = gateway.download_file_chunk("file-hooks-01", 0U);
    ASSERT_TRUE(dl_tampered.is_ok());
    EXPECT_NE(compute_test_sha256_hex(dl_tampered.value().encrypted_data), dl_tampered.value().ciphertext_sha256);

    gateway.set_simulated_file_transfer_failure(true, "Gateway file proxy unavailable");
    const auto net_err = gateway.get_file_metadata("file-hooks-01");
    ASSERT_TRUE(net_err.is_error());
    EXPECT_EQ(net_err.error().category(), ClientErrorCategory::Network);
}

} // namespace
} // namespace securecloud::client::tests
