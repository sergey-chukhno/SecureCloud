#include "domain/crypto/file_crypto_engine.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"

#include <algorithm>
#include <cstdint>
#include <gtest/gtest.h>
#include <numeric>
#include <span>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::domain::crypto;
using securecloud::client::infrastructure::adapters::OpenSslCryptoProvider;
using securecloud::common::configuration::SecretString;

std::vector<uint8_t> make_pattern_bytes(std::size_t size, uint8_t seed) {
    std::vector<uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<uint8_t>((i * 131U + seed) & 0xFFU);
    }
    return out;
}

TEST(FileCryptoEngineTest, GenerateFileKeyEntropyAndHexRoundTrip) {
    const auto k1_res = FileCryptoEngine::generate_file_key();
    const auto k2_res = FileCryptoEngine::generate_file_key();
    ASSERT_TRUE(k1_res.is_ok());
    ASSERT_TRUE(k2_res.is_ok());
    EXPECT_EQ(k1_res.value().size(), FileCryptoEngine::kKeyBytes);
    EXPECT_EQ(k2_res.value().size(), FileCryptoEngine::kKeyBytes);
    EXPECT_NE(k1_res.value(), k2_res.value());

    const auto hex_res = FileCryptoEngine::encode_key_hex(k1_res.value());
    ASSERT_TRUE(hex_res.is_ok());
    EXPECT_EQ(hex_res.value().size(), 64U);

    const auto decoded_res = FileCryptoEngine::decode_key_hex(hex_res.value());
    ASSERT_TRUE(decoded_res.is_ok());
    EXPECT_EQ(decoded_res.value(), k1_res.value());

    // Malformed key length and non-hex rejection
    EXPECT_TRUE(FileCryptoEngine::encode_key_hex(SecretString("short")).is_error());
    EXPECT_TRUE(FileCryptoEngine::decode_key_hex(SecretString("short")).is_error());
    EXPECT_TRUE(FileCryptoEngine::decode_key_hex(SecretString(std::string(64U, 'g'))).is_error());
}

TEST(FileCryptoEngineTest, DefaultFourMiBWireFramingMatchesBackendContract) {
    OpenSslCryptoProvider crypto;
    const auto engine_res = FileCryptoEngine::create();
    ASSERT_TRUE(engine_res.is_ok());
    const FileCryptoEngine& engine = engine_res.value();

    EXPECT_EQ(engine.wire_chunk_size(), FileCryptoEngine::kDefaultWireChunkSize);
    EXPECT_EQ(engine.max_plaintext_chunk_size(), 4194276U);

    const auto key_res = FileCryptoEngine::generate_file_key();
    ASSERT_TRUE(key_res.is_ok());

    const std::string file_id = "file-4mib-contract-01";
    const std::vector<uint8_t> non_terminal_plaintext = make_pattern_bytes(engine.max_plaintext_chunk_size(), 0x17U);

    const auto frame_res = engine.encrypt_chunk(crypto, key_res.value(), file_id, 0U, false, non_terminal_plaintext);
    ASSERT_TRUE(frame_res.is_ok());
    // Must match FilesService k_standard_chunk_size (4 MiB = 4,194,304 B) on the wire
    EXPECT_EQ(frame_res.value().framed_bytes.size(), FileCryptoEngine::kDefaultWireChunkSize);
    EXPECT_EQ(frame_res.value().ciphertext_sha256.size(), 64U);

    const auto dec_res = engine.decrypt_chunk(crypto, key_res.value(), file_id, 0U, false,
                                              frame_res.value().framed_bytes, frame_res.value().ciphertext_sha256);
    ASSERT_TRUE(dec_res.is_ok());
    EXPECT_EQ(dec_res.value(), non_terminal_plaintext);

    // Geometry check: 2 chunks needed when plaintext exceeds 4,194,276 B
    const uint64_t two_chunk_plaintext = static_cast<uint64_t>(engine.max_plaintext_chunk_size()) + 1024ULL;
    const auto count_res = engine.calculate_chunk_count(two_chunk_plaintext);
    ASSERT_TRUE(count_res.is_ok());
    EXPECT_EQ(count_res.value(), 2U);

    const auto enc_size_res = engine.calculate_encrypted_size(two_chunk_plaintext);
    ASSERT_TRUE(enc_size_res.is_ok());
    EXPECT_EQ(enc_size_res.value(), two_chunk_plaintext + 2ULL * FileCryptoEngine::kChunkOverheadBytes);

    // 5 GiB boundary check (backend k_max_file_size_bytes)
    const uint64_t max_plaintext_for_5gib_wire =
        FileCryptoEngine::kMaxEncryptedFileSizeBytes - (1281ULL * FileCryptoEngine::kChunkOverheadBytes);
    const auto near_max_chunks = engine.calculate_chunk_count(max_plaintext_for_5gib_wire);
    ASSERT_TRUE(near_max_chunks.is_ok());
    const auto near_max_enc_size = engine.calculate_encrypted_size(max_plaintext_for_5gib_wire);
    ASSERT_TRUE(near_max_enc_size.is_ok());
    EXPECT_LE(near_max_enc_size.value(), FileCryptoEngine::kMaxEncryptedFileSizeBytes);

    // Raw 5 GiB plaintext would exceed 5 GiB once 28 B per-chunk AEAD overhead is added
    EXPECT_TRUE(engine.calculate_chunk_count(FileCryptoEngine::kMaxEncryptedFileSizeBytes).is_error());
}

TEST(FileCryptoEngineTest, HkdfIvUniquenessAcrossChunksAndFiles) {
    OpenSslCryptoProvider crypto;
    const auto key_res = FileCryptoEngine::generate_file_key();
    ASSERT_TRUE(key_res.is_ok());

    const auto iv_f1_c0 = FileCryptoEngine::derive_chunk_iv(crypto, key_res.value(), "file-alpha", 0U);
    const auto iv_f1_c0_replay = FileCryptoEngine::derive_chunk_iv(crypto, key_res.value(), "file-alpha", 0U);
    const auto iv_f1_c1 = FileCryptoEngine::derive_chunk_iv(crypto, key_res.value(), "file-alpha", 1U);
    const auto iv_f2_c0 = FileCryptoEngine::derive_chunk_iv(crypto, key_res.value(), "file-beta", 0U);

    ASSERT_TRUE(iv_f1_c0.is_ok());
    ASSERT_TRUE(iv_f1_c0_replay.is_ok());
    ASSERT_TRUE(iv_f1_c1.is_ok());
    ASSERT_TRUE(iv_f2_c0.is_ok());

    EXPECT_EQ(iv_f1_c0.value().size(), FileCryptoEngine::kIvBytes);
    EXPECT_EQ(iv_f1_c0.value(), iv_f1_c0_replay.value());
    EXPECT_NE(iv_f1_c0.value(), iv_f1_c1.value());
    EXPECT_NE(iv_f1_c0.value(), iv_f2_c0.value());
}

TEST(FileCryptoEngineTest, TamperSwapTruncationAndWrongKeyFailClosed) {
    OpenSslCryptoProvider crypto;
    const auto engine_res = FileCryptoEngine::create(1024U);
    ASSERT_TRUE(engine_res.is_ok());
    const FileCryptoEngine& engine = engine_res.value();

    const auto key_res = FileCryptoEngine::generate_file_key();
    const auto wrong_key_res = FileCryptoEngine::generate_file_key();
    ASSERT_TRUE(key_res.is_ok());
    ASSERT_TRUE(wrong_key_res.is_ok());

    const std::string file_id = "file-tamper-01";
    const std::vector<uint8_t> pt0 = make_pattern_bytes(engine.max_plaintext_chunk_size(), 0x10U);
    const auto frame0 = engine.encrypt_chunk(crypto, key_res.value(), file_id, 0U, false, pt0);
    ASSERT_TRUE(frame0.is_ok());

    // 1. Ciphertext bit flip with original expected SHA-256 -> caught at SHA-256 gate
    {
        std::vector<uint8_t> mutated = frame0.value().framed_bytes;
        mutated[FileCryptoEngine::kIvBytes + 4U] ^= 0x01U;
        EXPECT_TRUE(
            engine.decrypt_chunk(crypto, key_res.value(), file_id, 0U, false, mutated, frame0.value().ciphertext_sha256)
                .is_error());
    }

    // 2. Ciphertext bit flip without expected SHA-256 (or spoofed SHA-256) -> caught by GCM tag
    {
        std::vector<uint8_t> mutated = frame0.value().framed_bytes;
        mutated[FileCryptoEngine::kIvBytes + 8U] ^= 0x80U;
        const auto spoofed_sha = StreamingSha256::digest_hex(mutated);
        ASSERT_TRUE(spoofed_sha.is_ok());
        EXPECT_TRUE(
            engine.decrypt_chunk(crypto, key_res.value(), file_id, 0U, false, mutated, spoofed_sha.value()).is_error());
    }

    // 3. Wire IV flip -> caught by constant-time HKDF IV verification
    {
        std::vector<uint8_t> mutated = frame0.value().framed_bytes;
        mutated[0] ^= 0x40U;
        EXPECT_TRUE(engine.decrypt_chunk(crypto, key_res.value(), file_id, 0U, false, mutated).is_error());
    }

    // 4. Auth tag flip -> caught by GCM verification
    {
        std::vector<uint8_t> mutated = frame0.value().framed_bytes;
        mutated.back() ^= 0x20U;
        EXPECT_TRUE(engine.decrypt_chunk(crypto, key_res.value(), file_id, 0U, false, mutated).is_error());
    }

    // 5. Swapped chunk index -> fails IV/AAD binding
    EXPECT_TRUE(
        engine.decrypt_chunk(crypto, key_res.value(), file_id, 1U, false, frame0.value().framed_bytes).is_error());

    // 6. Cross-file splice -> fails IV/AAD binding
    EXPECT_TRUE(engine.decrypt_chunk(crypto, key_res.value(), "other-file-id", 0U, false, frame0.value().framed_bytes)
                    .is_error());

    // 7. Stream truncation (non-terminal chunk replayed as terminal is_final=true) -> fails AAD is_final binding
    EXPECT_TRUE(
        engine.decrypt_chunk(crypto, key_res.value(), file_id, 0U, true, frame0.value().framed_bytes).is_error());

    // 8. Wrong key -> fails closed
    EXPECT_TRUE(engine.decrypt_chunk(crypto, wrong_key_res.value(), file_id, 0U, false, frame0.value().framed_bytes)
                    .is_error());
}

TEST(FileCryptoEngineTest, MultiChunkStreamingWithDualSha256Attestation) {
    OpenSslCryptoProvider crypto;
    const auto engine_res = FileCryptoEngine::create(1024U);
    ASSERT_TRUE(engine_res.is_ok());
    const FileCryptoEngine& engine = engine_res.value();

    // 996 B max plaintext per chunk -> 3 full chunks + 1 tail chunk (300 B) = 3288 B plaintext
    const std::vector<uint8_t> full_plaintext =
        make_pattern_bytes(3U * engine.max_plaintext_chunk_size() + 300U, 0x5AU);
    const auto count_res = engine.calculate_chunk_count(full_plaintext.size());
    ASSERT_TRUE(count_res.is_ok());
    EXPECT_EQ(count_res.value(), 4U);

    const auto expected_enc_size = engine.calculate_encrypted_size(full_plaintext.size());
    ASSERT_TRUE(expected_enc_size.is_ok());

    const auto key_res = FileCryptoEngine::generate_file_key();
    ASSERT_TRUE(key_res.is_ok());
    const std::string file_id = "file-stream-attest-01";

    StreamingSha256 upload_pt_hasher;
    StreamingSha256 upload_ct_hasher;
    std::vector<EncryptedChunkFrame> wire_frames;
    std::vector<uint8_t> concatenated_wire;

    std::size_t offset = 0U;
    for (uint32_t idx = 0U; idx < count_res.value(); ++idx) {
        const std::size_t slice_len =
            std::min<std::size_t>(engine.max_plaintext_chunk_size(), full_plaintext.size() - offset);
        const bool is_final = (idx + 1U == count_res.value());
        const std::span<const uint8_t> slice(full_plaintext.data() + offset, slice_len);

        ASSERT_TRUE(upload_pt_hasher.update(slice).is_ok());
        const auto frame_res = engine.encrypt_chunk(crypto, key_res.value(), file_id, idx, is_final, slice);
        ASSERT_TRUE(frame_res.is_ok());
        ASSERT_TRUE(upload_ct_hasher.update(frame_res.value().framed_bytes).is_ok());

        if (!is_final) {
            EXPECT_EQ(frame_res.value().framed_bytes.size(), 1024U);
        }
        concatenated_wire.insert(concatenated_wire.end(), frame_res.value().framed_bytes.begin(),
                                 frame_res.value().framed_bytes.end());
        wire_frames.push_back(frame_res.value());
        offset += slice_len;
    }

    EXPECT_EQ(concatenated_wire.size(), expected_enc_size.value());
    const auto upload_pt_sha = upload_pt_hasher.finalize_hex();
    const auto upload_ct_sha = upload_ct_hasher.finalize_hex();
    ASSERT_TRUE(upload_pt_sha.is_ok());
    ASSERT_TRUE(upload_ct_sha.is_ok());

    const auto oneshot_pt_sha = StreamingSha256::digest_hex(full_plaintext);
    const auto oneshot_ct_sha = StreamingSha256::digest_hex(concatenated_wire);
    ASSERT_TRUE(oneshot_pt_sha.is_ok());
    ASSERT_TRUE(oneshot_ct_sha.is_ok());
    EXPECT_EQ(upload_pt_sha.value(), oneshot_pt_sha.value());
    EXPECT_EQ(upload_ct_sha.value(), oneshot_ct_sha.value());

    // Stream decrypt and verify dual attestation on receiver side
    StreamingSha256 download_pt_hasher;
    StreamingSha256 download_ct_hasher;
    std::vector<uint8_t> recovered_plaintext;

    for (uint32_t idx = 0U; idx < wire_frames.size(); ++idx) {
        const bool is_final = (idx + 1U == wire_frames.size());
        ASSERT_TRUE(download_ct_hasher.update(wire_frames[idx].framed_bytes).is_ok());
        const auto pt_res = engine.decrypt_chunk(crypto, key_res.value(), file_id, idx, is_final,
                                                 wire_frames[idx].framed_bytes, wire_frames[idx].ciphertext_sha256);
        ASSERT_TRUE(pt_res.is_ok());
        ASSERT_TRUE(download_pt_hasher.update(pt_res.value()).is_ok());
        recovered_plaintext.insert(recovered_plaintext.end(), pt_res.value().begin(), pt_res.value().end());
    }

    EXPECT_EQ(recovered_plaintext, full_plaintext);
    EXPECT_EQ(download_ct_hasher.finalize_hex().value(), upload_ct_sha.value());
    EXPECT_EQ(download_pt_hasher.finalize_hex().value(), upload_pt_sha.value());

    // Finalized StreamingSha256 rejects further update/finalize until reset()
    EXPECT_TRUE(download_pt_hasher.update(std::vector<uint8_t>{0x01U}).is_error());
    EXPECT_TRUE(download_pt_hasher.finalize_hex().is_error());
    ASSERT_TRUE(download_pt_hasher.reset().is_ok());
    ASSERT_TRUE(download_pt_hasher.update(full_plaintext).is_ok());
    EXPECT_EQ(download_pt_hasher.finalize_hex().value(), oneshot_pt_sha.value());
}

TEST(FileCryptoEngineTest, ConfigurationAndInputValidationRejectsInvalidBounds) {
    OpenSslCryptoProvider crypto;

    EXPECT_TRUE(FileCryptoEngine::create(0U).is_error());
    EXPECT_TRUE(FileCryptoEngine::create(FileCryptoEngine::kChunkOverheadBytes).is_error());
    EXPECT_TRUE(FileCryptoEngine::create(FileCryptoEngine::kMaxWireChunkSize + 1U).is_error());

    const auto engine_res = FileCryptoEngine::create(512U);
    ASSERT_TRUE(engine_res.is_ok());
    const FileCryptoEngine& engine = engine_res.value();

    EXPECT_TRUE(engine.calculate_chunk_count(0ULL).is_error());
    EXPECT_TRUE(engine.calculate_chunk_count(FileCryptoEngine::kMaxEncryptedFileSizeBytes + 1ULL).is_error());
    EXPECT_TRUE(engine.calculate_encrypted_size(0ULL).is_error());

    const auto key_res = FileCryptoEngine::generate_file_key();
    ASSERT_TRUE(key_res.is_ok());

    const std::vector<uint8_t> short_slice(64U, 0xAAU);
    const std::vector<uint8_t> oversized_slice(engine.max_plaintext_chunk_size() + 1U, 0xBBU);

    // Empty file_id, bad key size, empty/oversized slice, and short non-terminal chunk must all fail
    EXPECT_TRUE(engine.encrypt_chunk(crypto, key_res.value(), "", 0U, true, short_slice).is_error());
    EXPECT_TRUE(engine.encrypt_chunk(crypto, SecretString("bad-key"), "f1", 0U, true, short_slice).is_error());
    EXPECT_TRUE(engine.encrypt_chunk(crypto, key_res.value(), "f1", 0U, true, {}).is_error());
    EXPECT_TRUE(engine.encrypt_chunk(crypto, key_res.value(), "f1", 0U, true, oversized_slice).is_error());
    EXPECT_TRUE(engine.encrypt_chunk(crypto, key_res.value(), "f1", 0U, false, short_slice).is_error());

    EXPECT_TRUE(FileCryptoEngine::derive_chunk_iv(crypto, SecretString("short"), "f1", 0U).is_error());
    EXPECT_TRUE(FileCryptoEngine::derive_chunk_iv(crypto, key_res.value(), "", 0U).is_error());
}

} // namespace
} // namespace securecloud::client::tests
