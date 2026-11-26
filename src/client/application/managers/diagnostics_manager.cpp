#include "application/managers/diagnostics_manager.hpp"

#include "application/managers/diagnostic_sanitizer.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/settings_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/file_transfer.hpp"
#include "domain/local_audit_event.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <span>

namespace securecloud::client::application::managers {
namespace {

constexpr std::array<uint8_t, 8> kBundleMagic = {'S', 'C', 'D', 'I', 'A', 'G', '1', '\0'};
constexpr uint8_t kKdfModePassphrasePbkdf2 = 0x01U;
constexpr uint8_t kKdfModeRandomExportKey = 0x02U;
constexpr std::size_t kSaltBytes = 16U;
constexpr std::size_t kIvBytes = 12U;
constexpr std::size_t kTagBytes = 16U;
constexpr std::size_t kKeyBytes = 32U;
constexpr std::size_t kHeaderBytes = kBundleMagic.size() + 1U + kSaltBytes + kIvBytes; // 37 bytes
constexpr std::size_t kMinBundleBytes = kHeaderBytes + kTagBytes + 1U;                 // 54 bytes

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ptr) const noexcept {
        if (ptr != nullptr) {
            EVP_CIPHER_CTX_free(ptr);
        }
    }
};

using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

[[nodiscard]] int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::string encode_hex_lower(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

[[nodiscard]] std::optional<uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<uint8_t>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

[[nodiscard]] bool decode_exact_hex_key(std::string_view hex, std::array<uint8_t, kKeyBytes>& out_key) {
    if (hex.size() != kKeyBytes * 2U) {
        return false;
    }
    for (std::size_t i = 0U; i < kKeyBytes; ++i) {
        const auto hi = hex_nibble(hex[i * 2U]);
        const auto lo = hex_nibble(hex[i * 2U + 1U]);
        if (!hi.has_value() || !lo.has_value()) {
            OPENSSL_cleanse(out_key.data(), out_key.size());
            return false;
        }
        out_key[i] = static_cast<uint8_t>((static_cast<unsigned int>(*hi) << 4U) | static_cast<unsigned int>(*lo));
    }
    return true;
}

[[nodiscard]] std::string consume_openssl_error() {
    char buf[256];
    const unsigned long err = ERR_get_error();
    ERR_clear_error();
    if (err == 0UL) {
        return "OpenSSL error unavailable";
    }
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

[[nodiscard]] bool derive_passphrase_key(std::string_view passphrase, std::span<const uint8_t> salt,
                                         std::array<uint8_t, kKeyBytes>& out_key) {
    if (passphrase.empty() || passphrase.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        salt.size() != kSaltBytes) {
        return false;
    }
    const int rc =
        PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()), salt.data(),
                          static_cast<int>(salt.size()), static_cast<int>(DiagnosticsManager::kBundlePbkdf2Iterations),
                          EVP_sha256(), static_cast<int>(out_key.size()), out_key.data());
    return rc == 1;
}

[[nodiscard]] bool is_transfer_active(domain::FileTransferStatus status) noexcept {
    return status == domain::FileTransferStatus::Pending || status == domain::FileTransferStatus::InProgress ||
           status == domain::FileTransferStatus::Paused || status == domain::FileTransferStatus::Finalizing;
}

} // namespace

DiagnosticsManager::DiagnosticsManager(const ClientConfig& config, LocalAuditLogger* audit_logger,
                                       MessagingManager* messaging_manager, FileManager* file_manager,
                                       SyncManager* sync_manager, SettingsManager* settings_manager,
                                       RatchetSessionManager* ratchet_session_manager,
                                       SelfTestReportProvider self_test_provider,
                                       TransportMetricsProvider transport_metrics_provider,
                                       LiveTransportProvider live_transport_provider)
    : config_(config), audit_logger_(audit_logger), messaging_manager_(messaging_manager), file_manager_(file_manager),
      sync_manager_(sync_manager), settings_manager_(settings_manager),
      ratchet_session_manager_(ratchet_session_manager), self_test_provider_(std::move(self_test_provider)),
      transport_metrics_provider_(std::move(transport_metrics_provider)),
      live_transport_provider_(std::move(live_transport_provider)) {}

void DiagnosticsManager::set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    ratchet_session_manager_ = ratchet_session_manager;
}

domain::TelemetrySnapshot DiagnosticsManager::collect_telemetry() {
    RatchetSessionManager* ratchet = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ratchet = ratchet_session_manager_;
    }

    const auto proc_sample = telemetry_collector_.sample();

    domain::TelemetrySnapshot snapshot;
    snapshot.rss_bytes = proc_sample.rss_bytes;
    snapshot.rss_megabytes = proc_sample.rss_megabytes;
    snapshot.cpu_percent = proc_sample.cpu_percent;
    snapshot.sampled_at_ms = proc_sample.sampled_at_ms;

    if (ratchet != nullptr) {
        snapshot.active_ratchet_sessions = ratchet->active_session_count();
    }
    if (messaging_manager_ != nullptr) {
        snapshot.pending_outbox_count = messaging_manager_->pending_outbox_count();
        snapshot.pending_retry_count = messaging_manager_->pending_retry_count();
    }
    if (file_manager_ != nullptr) {
        const auto transfers_res = file_manager_->list_transfers();
        if (transfers_res.is_ok()) {
            std::size_t active = 0U;
            for (const auto& rec : transfers_res.value()) {
                if (is_transfer_active(rec.status)) {
                    ++active;
                }
            }
            snapshot.active_file_transfers = active;
        }
    }
    if (sync_manager_ != nullptr) {
        snapshot.connectivity_state = sync_manager_->connectivity_state();
    }
    if (live_transport_provider_) {
        snapshot.live_gateway_transport = live_transport_provider_();
    } else {
        snapshot.live_gateway_transport = config_.use_live_gateway_transport;
    }
    if (transport_metrics_provider_) {
        const domain::GatewayTransportMetrics metrics = transport_metrics_provider_();
        snapshot.last_gateway_rtt_ms = metrics.last_rtt_ms;
        snapshot.avg_gateway_rtt_ms = metrics.avg_rtt_ms;
        snapshot.gateway_requests_total = metrics.requests_total;
        snapshot.gateway_requests_failed = metrics.requests_failed;
    }

    return snapshot;
}

ClientResult<domain::DiagnosticBundleExportResult> DiagnosticsManager::export_encrypted_bundle(
    const std::filesystem::path& output_path, std::optional<common::configuration::SecretString> passphrase,
    std::size_t max_audit_events, const std::vector<std::string>& extra_sensitive_literals) {
    if (output_path.empty()) {
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::validation("Diagnostic bundle output path cannot be empty"));
    }

    std::error_code ec;
    if (std::filesystem::is_directory(output_path, ec)) {
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::validation("Diagnostic bundle output path points to a directory"));
    }
    if (output_path.has_parent_path()) {
        const std::filesystem::path parent = output_path.parent_path();
        if (!std::filesystem::exists(parent, ec) || !std::filesystem::is_directory(parent, ec)) {
            return ClientResult<domain::DiagnosticBundleExportResult>::error(
                ClientError::storage("Diagnostic bundle parent directory does not exist"));
        }
    }
    if (passphrase.has_value() && passphrase->empty()) {
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::validation("Diagnostic bundle passphrase cannot be empty when supplied"));
    }

    std::vector<std::string> all_literals = extra_sensitive_literals;
    if (!config_.auth_token.empty()) {
        all_literals.push_back(config_.auth_token.expose_unredacted_secret());
    }
    if (!config_.proxy_password.empty()) {
        all_literals.push_back(config_.proxy_password.expose_unredacted_secret());
    }
    if (!config_.proxy_username.empty()) {
        all_literals.push_back(config_.proxy_username);
    }
    if (settings_manager_ != nullptr) {
        const auto profile_opt = settings_manager_->cached_profile();
        if (profile_opt.has_value()) {
            if (!profile_opt->display_name.empty()) {
                all_literals.push_back(profile_opt->display_name);
            }
            if (!profile_opt->public_handle.empty()) {
                all_literals.push_back(profile_opt->public_handle);
            }
            if (!profile_opt->bio_status.empty()) {
                all_literals.push_back(profile_opt->bio_status);
            }
        }
    }

    const domain::TelemetrySnapshot telemetry = collect_telemetry();
    const nlohmann::json telemetry_json = nlohmann::json::parse(telemetry.to_json(), nullptr, false);

    nlohmann::json self_test_json;
    self_test_json["executed"] = false;
    if (self_test_provider_) {
        const auto report_opt = self_test_provider_();
        if (report_opt.has_value()) {
            const nlohmann::json parsed_st = nlohmann::json::parse(report_opt->to_json(), nullptr, false);
            if (!parsed_st.is_discarded()) {
                self_test_json = parsed_st;
                self_test_json["executed"] = true;
            }
        }
    }

    nlohmann::json audit_verification_json;
    audit_verification_json["available"] = false;
    nlohmann::json audit_events_json = nlohmann::json::array();

    const std::size_t clamped_events = std::min(max_audit_events, kMaxBundleAuditEvents);
    if (audit_logger_ != nullptr) {
        const auto verify_res = audit_logger_->verify_chain_integrity();
        if (verify_res.is_ok()) {
            const auto& v = verify_res.value();
            audit_verification_json["available"] = true;
            audit_verification_json["valid"] = v.valid;
            audit_verification_json["verified_count"] = v.verified_count;
            audit_verification_json["latest_hash_sha256"] = v.latest_hash_sha256;
            audit_verification_json["failure_reason"] = DiagnosticSanitizer::scrub_text(v.failure_reason, all_literals);
            if (v.first_corrupted_sequence.has_value()) {
                audit_verification_json["first_corrupted_sequence"] = *v.first_corrupted_sequence;
            }
        }

        if (clamped_events > 0U) {
            const auto events_res = audit_logger_->recent_events(clamped_events);
            if (events_res.is_ok()) {
                for (const auto& ev : events_res.value()) {
                    nlohmann::json item;
                    item["sequence_id"] = ev.sequence_id;
                    item["occurred_at_ms"] = ev.occurred_at_ms;
                    item["category"] = domain::to_string(ev.category);
                    item["event_type"] = DiagnosticSanitizer::scrub_text(ev.event_type, all_literals);
                    item["outcome"] = domain::to_string(ev.outcome);
                    item["actor_opaque_id"] = DiagnosticSanitizer::scrub_text(ev.actor_opaque_id, all_literals);
                    item["target_opaque_id"] = DiagnosticSanitizer::scrub_text(ev.target_opaque_id, all_literals);
                    item["sanitized_summary"] = DiagnosticSanitizer::scrub_text(ev.sanitized_summary, all_literals);
                    item["prev_hash_sha256"] = ev.prev_hash_sha256;
                    item["entry_hash_sha256"] = ev.entry_hash_sha256;
                    audit_events_json.push_back(std::move(item));
                }
            }
        }
    }

    nlohmann::json root;
    root["format_version"] = 1;
    root["generated_at_ms"] = current_unix_ms();
    root["safe_config"] = DiagnosticSanitizer::scrub_text(config_.to_safe_string(), all_literals);
    root["crypto_self_test"] = self_test_json;
    root["telemetry"] = telemetry_json.is_discarded() ? nlohmann::json::object() : telemetry_json;
    root["audit_chain_verification"] = audit_verification_json;
    root["recent_audit_events"] = audit_events_json;

    std::string plaintext_json = DiagnosticSanitizer::scrub_text(root.dump(2), all_literals);
    if (DiagnosticSanitizer::contains_unredacted_secret_marker(plaintext_json)) {
        OPENSSL_cleanse(plaintext_json.data(), plaintext_json.size());
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::crypto("Diagnostic bundle aborted: unredacted secret marker detected before encryption"));
    }

    std::array<uint8_t, kSaltBytes> salt{};
    std::array<uint8_t, kIvBytes> iv{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1 ||
        RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        OPENSSL_cleanse(plaintext_json.data(), plaintext_json.size());
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::crypto("Failed to generate CSPRNG salt/IV for diagnostic bundle"));
    }

    std::array<uint8_t, kKeyBytes> aes_key{};
    uint8_t kdf_mode = kKdfModeRandomExportKey;
    common::configuration::SecretString generated_key_hex("");

    if (passphrase.has_value()) {
        kdf_mode = kKdfModePassphrasePbkdf2;
        if (!derive_passphrase_key(passphrase->expose_unredacted_secret(), salt, aes_key)) {
            OPENSSL_cleanse(aes_key.data(), aes_key.size());
            OPENSSL_cleanse(plaintext_json.data(), plaintext_json.size());
            return ClientResult<domain::DiagnosticBundleExportResult>::error(
                ClientError::crypto("Failed to derive AES-256 key from bundle passphrase"));
        }
    } else {
        kdf_mode = kKdfModeRandomExportKey;
        if (RAND_bytes(aes_key.data(), static_cast<int>(aes_key.size())) != 1) {
            OPENSSL_cleanse(aes_key.data(), aes_key.size());
            OPENSSL_cleanse(plaintext_json.data(), plaintext_json.size());
            return ClientResult<domain::DiagnosticBundleExportResult>::error(
                ClientError::crypto("Failed to generate CSPRNG diagnostic export key"));
        }
        generated_key_hex = common::configuration::SecretString(encode_hex_lower(aes_key));
    }

    std::array<uint8_t, kHeaderBytes> header{};
    std::memcpy(header.data(), kBundleMagic.data(), kBundleMagic.size());
    header[8] = kdf_mode;
    std::memcpy(header.data() + 9U, salt.data(), kSaltBytes);
    std::memcpy(header.data() + 25U, iv.data(), kIvBytes);

    std::vector<uint8_t> ciphertext(plaintext_json.size(), 0U);
    std::array<uint8_t, kTagBytes> tag{};
    int out_len = 0;
    int final_len = 0;

    {
        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
            EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, header.data(), static_cast<int>(header.size())) != 1 ||
            EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                              reinterpret_cast<const uint8_t*>(plaintext_json.data()),
                              static_cast<int>(plaintext_json.size())) != 1 ||
            EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + out_len, &final_len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
            OPENSSL_cleanse(aes_key.data(), aes_key.size());
            OPENSSL_cleanse(plaintext_json.data(), plaintext_json.size());
            return ClientResult<domain::DiagnosticBundleExportResult>::error(
                ClientError::crypto("AES-256-GCM diagnostic bundle encryption failed: " + consume_openssl_error()));
        }
        ciphertext.resize(static_cast<std::size_t>(out_len + final_len));
    }

    const std::size_t plaintext_size = plaintext_json.size();
    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    OPENSSL_cleanse(plaintext_json.data(), plaintext_json.size());

    std::vector<uint8_t> wire_blob;
    wire_blob.reserve(kHeaderBytes + kTagBytes + ciphertext.size());
    wire_blob.insert(wire_blob.end(), header.begin(), header.end());
    wire_blob.insert(wire_blob.end(), tag.begin(), tag.end());
    wire_blob.insert(wire_blob.end(), ciphertext.begin(), ciphertext.end());

    const auto digest_res = domain::crypto::StreamingSha256::digest_hex(wire_blob);
    if (digest_res.is_error()) {
        return ClientResult<domain::DiagnosticBundleExportResult>::error(digest_res.error());
    }

    const std::filesystem::path tmp_path(output_path.string() + ".tmp");
    std::ofstream ofs(tmp_path, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::storage("Failed to open temporary diagnostic bundle file for writing"));
    }
    ofs.write(reinterpret_cast<const char*>(wire_blob.data()), static_cast<std::streamsize>(wire_blob.size()));
    ofs.flush();
    const bool write_ok = ofs.good();
    ofs.close();

    if (!write_ok) {
        std::filesystem::remove(tmp_path, ec);
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::storage("Failed while writing encrypted diagnostic bundle to disk"));
    }

    std::filesystem::rename(tmp_path, output_path, ec);
    if (ec) {
        std::filesystem::remove(tmp_path, ec);
        return ClientResult<domain::DiagnosticBundleExportResult>::error(
            ClientError::storage("Failed to finalize atomic diagnostic bundle file rename"));
    }

    if (audit_logger_ != nullptr) {
        (void)audit_logger_->record_event(domain::LocalAuditCategory::SettingsNetwork, "diagnostics.bundle_exported",
                                          domain::LocalAuditOutcome::Success, "", "",
                                          "Encrypted sanitized .scdiag diagnostic bundle exported (" +
                                              std::to_string(wire_blob.size()) + " bytes)");
    }

    domain::DiagnosticBundleExportResult res;
    res.output_path = output_path.string();
    res.plaintext_bytes = plaintext_size;
    res.encrypted_bytes = wire_blob.size();
    res.bundle_sha256_hex = digest_res.value();
    res.used_passphrase = passphrase.has_value();
    res.generated_export_key_hex = std::move(generated_key_hex);
    return ClientResult<domain::DiagnosticBundleExportResult>::ok(std::move(res));
}

ClientResult<std::string>
DiagnosticsManager::decrypt_and_verify_bundle(const std::filesystem::path& bundle_path,
                                              const common::configuration::SecretString& key_or_passphrase) {
    if (bundle_path.empty() || key_or_passphrase.empty()) {
        return ClientResult<std::string>::error(
            ClientError::validation("Bundle path and key/passphrase are required for decryption"));
    }

    std::error_code ec;
    if (!std::filesystem::exists(bundle_path, ec) || !std::filesystem::is_regular_file(bundle_path, ec)) {
        return ClientResult<std::string>::error(ClientError::storage("Diagnostic bundle file does not exist"));
    }

    const uintmax_t file_size = std::filesystem::file_size(bundle_path, ec);
    if (ec || file_size < kMinBundleBytes || file_size > kMaxDecryptBundleBytes) {
        return ClientResult<std::string>::error(
            ClientError::validation("Diagnostic bundle file size is outside valid bounds"));
    }

    std::ifstream ifs(bundle_path, std::ios::binary);
    if (!ifs.is_open()) {
        return ClientResult<std::string>::error(ClientError::storage("Failed to open diagnostic bundle for reading"));
    }
    std::vector<uint8_t> raw(static_cast<std::size_t>(file_size), 0U);
    ifs.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
    const bool read_ok = ifs.good();
    ifs.close();
    if (!read_ok) {
        return ClientResult<std::string>::error(ClientError::storage("Failed to read diagnostic bundle bytes"));
    }

    if (std::memcmp(raw.data(), kBundleMagic.data(), kBundleMagic.size()) != 0) {
        return ClientResult<std::string>::error(ClientError::crypto("Invalid .scdiag diagnostic bundle magic header"));
    }

    const uint8_t kdf_mode = raw[8];
    const std::span<const uint8_t> header(raw.data(), kHeaderBytes);
    const std::span<const uint8_t> salt(raw.data() + 9U, kSaltBytes);
    const std::span<const uint8_t> iv(raw.data() + 25U, kIvBytes);
    const std::span<const uint8_t> tag(raw.data() + kHeaderBytes, kTagBytes);
    const std::span<const uint8_t> ciphertext(raw.data() + kHeaderBytes + kTagBytes,
                                              raw.size() - kHeaderBytes - kTagBytes);

    std::array<uint8_t, kKeyBytes> aes_key{};
    if (kdf_mode == kKdfModePassphrasePbkdf2) {
        if (!derive_passphrase_key(key_or_passphrase.expose_unredacted_secret(), salt, aes_key)) {
            OPENSSL_cleanse(aes_key.data(), aes_key.size());
            return ClientResult<std::string>::error(
                ClientError::crypto("Failed to derive AES-256 key from passphrase"));
        }
    } else if (kdf_mode == kKdfModeRandomExportKey) {
        if (!decode_exact_hex_key(key_or_passphrase.expose_unredacted_secret(), aes_key)) {
            return ClientResult<std::string>::error(
                ClientError::crypto("Expected 64-char hex export key for .scdiag decryption"));
        }
    } else {
        return ClientResult<std::string>::error(ClientError::crypto("Unsupported .scdiag bundle KDF mode"));
    }

    std::string plaintext(ciphertext.size(), '\0');
    int out_len = 0;
    int final_len = 0;
    {
        EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
        if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, aes_key.data(), iv.data()) != 1 ||
            EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, header.data(), static_cast<int>(header.size())) != 1 ||
            EVP_DecryptUpdate(ctx.get(), reinterpret_cast<uint8_t*>(plaintext.data()), &out_len, ciphertext.data(),
                              static_cast<int>(ciphertext.size())) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                const_cast<uint8_t*>(tag.data())) != 1 ||
            EVP_DecryptFinal_ex(ctx.get(), reinterpret_cast<uint8_t*>(plaintext.data()) + out_len, &final_len) != 1) {
            OPENSSL_cleanse(aes_key.data(), aes_key.size());
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            return ClientResult<std::string>::error(ClientError::crypto(
                "Diagnostic bundle authentication failed (wrong key or tampered file): " + consume_openssl_error()));
        }
        plaintext.resize(static_cast<std::size_t>(out_len + final_len));
    }

    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    return ClientResult<std::string>::ok(std::move(plaintext));
}

} // namespace securecloud::client::application::managers
