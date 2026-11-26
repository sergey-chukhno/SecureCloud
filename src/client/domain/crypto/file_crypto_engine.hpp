#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "domain/file_transfer.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct evp_md_ctx_st;

namespace securecloud::client::domain::crypto {

struct EvpMdCtxDeleter {
    void operator()(evp_md_ctx_st* ctx) const noexcept;
};

class StreamingSha256 final {
  public:
    StreamingSha256();
    ~StreamingSha256();

    StreamingSha256(const StreamingSha256&) = delete;
    StreamingSha256& operator=(const StreamingSha256&) = delete;
    StreamingSha256(StreamingSha256&&) noexcept;
    StreamingSha256& operator=(StreamingSha256&&) noexcept;

    [[nodiscard]] bool is_valid() const noexcept;

    application::ClientResult<void> update(std::span<const uint8_t> data);
    application::ClientResult<std::string> finalize_hex();
    application::ClientResult<void> reset();

    [[nodiscard]] static application::ClientResult<std::string> digest_hex(std::span<const uint8_t> data);

  private:
    std::unique_ptr<evp_md_ctx_st, EvpMdCtxDeleter> ctx_;
    bool initialized_{false};
    bool finalized_{false};
};

struct EncryptedChunkFrame {
    std::vector<uint8_t> framed_bytes;
    std::string ciphertext_sha256;
};

class FileCryptoEngine {
  public:
    static constexpr uint32_t kDefaultWireChunkSize = domain::kDefaultFileWireChunkSize;
    static constexpr uint32_t kMaxWireChunkSize = domain::kMaxFileWireChunkSize;
    static constexpr uint32_t kKeyBytes = 32U;
    static constexpr uint32_t kIvBytes = 12U;
    static constexpr uint32_t kTagBytes = 16U;
    static constexpr uint32_t kChunkOverheadBytes = domain::kFileChunkAeadOverheadBytes;
    static constexpr uint32_t kDefaultPlaintextChunkSize = kDefaultWireChunkSize - kChunkOverheadBytes;
    static constexpr uint64_t kMaxEncryptedFileSizeBytes = domain::kMaxEncryptedFileSizeBytes;
    static constexpr std::string_view kIvDomainSeparator = "SC-FILE-CHUNK-IV-v1";
    static constexpr std::string_view kAadDomainSeparator = "SC-FILE-CHUNK-v1";

    static application::ClientResult<FileCryptoEngine> create(uint32_t wire_chunk_size = kDefaultWireChunkSize);

    [[nodiscard]] uint32_t wire_chunk_size() const noexcept { return wire_chunk_size_; }
    [[nodiscard]] uint32_t max_plaintext_chunk_size() const noexcept { return wire_chunk_size_ - kChunkOverheadBytes; }

    [[nodiscard]] application::ClientResult<uint32_t>
    calculate_chunk_count(uint64_t plaintext_size_bytes) const noexcept;
    [[nodiscard]] application::ClientResult<uint64_t>
    calculate_encrypted_size(uint64_t plaintext_size_bytes) const noexcept;

    static application::ClientResult<common::configuration::SecretString> generate_file_key();
    static application::ClientResult<common::configuration::SecretString>
    encode_key_hex(const common::configuration::SecretString& raw_key);
    static application::ClientResult<common::configuration::SecretString>
    decode_key_hex(const common::configuration::SecretString& hex_key);

    static application::ClientResult<std::vector<uint8_t>>
    derive_chunk_iv(application::interfaces::ICryptoProvider& crypto,
                    const common::configuration::SecretString& file_key, std::string_view file_id,
                    uint32_t chunk_index);

    static std::vector<uint8_t> build_chunk_aad(std::string_view file_id, uint32_t chunk_index, bool is_final);

    [[nodiscard]] application::ClientResult<EncryptedChunkFrame>
    encrypt_chunk(application::interfaces::ICryptoProvider& crypto, const common::configuration::SecretString& file_key,
                  std::string_view file_id, uint32_t chunk_index, bool is_final,
                  std::span<const uint8_t> plaintext) const;

    [[nodiscard]] application::ClientResult<std::string>
    encrypt_chunk_into(application::interfaces::ICryptoProvider& crypto,
                       const common::configuration::SecretString& file_key, std::string_view file_id,
                       uint32_t chunk_index, bool is_final, std::span<const uint8_t> plaintext,
                       std::vector<uint8_t>& out_framed_bytes) const;

    [[nodiscard]] application::ClientResult<std::vector<uint8_t>>
    decrypt_chunk(application::interfaces::ICryptoProvider& crypto, const common::configuration::SecretString& file_key,
                  std::string_view file_id, uint32_t chunk_index, bool is_final, std::span<const uint8_t> framed_bytes,
                  std::string_view expected_chunk_sha256 = {}) const;

  private:
    explicit FileCryptoEngine(uint32_t wire_chunk_size) noexcept : wire_chunk_size_(wire_chunk_size) {}

    uint32_t wire_chunk_size_{kDefaultWireChunkSize};
};

} // namespace securecloud::client::domain::crypto
