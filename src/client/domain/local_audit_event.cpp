#include "domain/local_audit_event.hpp"

#include "domain/crypto/file_crypto_engine.hpp"

#include <cctype>
#include <cstring>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <span>

namespace securecloud::client::domain {
namespace {

constexpr std::string_view kCanonicalAuditDomainTag = "securecloud.local_audit.v1";

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

bool contains_ascii_control(std::string_view sv) noexcept {
    for (const char ch : sv) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch < 0x20U || uch == 0x7FU) {
            return true;
        }
    }
    return false;
}

void feed_length_prefixed(crypto::StreamingSha256& hasher, std::string_view field) {
    const std::string prefix = std::to_string(field.size()) + ":";
    (void)hasher.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(prefix.data()), prefix.size()));
    if (!field.empty()) {
        (void)hasher.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(field.data()), field.size()));
    }
    const uint8_t newline = '\n';
    (void)hasher.update(std::span<const uint8_t>(&newline, 1U));
}

} // namespace

std::string_view to_string(LocalAuditCategory category) noexcept {
    switch (category) {
    case LocalAuditCategory::CryptoSelfTest:
        return "CryptoSelfTest";
    case LocalAuditCategory::Authentication:
        return "Authentication";
    case LocalAuditCategory::DeviceTrust:
        return "DeviceTrust";
    case LocalAuditCategory::KeyLifecycle:
        return "KeyLifecycle";
    case LocalAuditCategory::MessagingSecurity:
        return "MessagingSecurity";
    case LocalAuditCategory::EmergencyDefense:
        return "EmergencyDefense";
    case LocalAuditCategory::SettingsNetwork:
        return "SettingsNetwork";
    }
    return "Authentication";
}

std::optional<LocalAuditCategory> local_audit_category_from_string(std::string_view value) noexcept {
    const std::string lower = to_lower_ascii(value);
    if (lower == "cryptoselftest" || lower == "crypto_self_test") {
        return LocalAuditCategory::CryptoSelfTest;
    }
    if (lower == "authentication") {
        return LocalAuditCategory::Authentication;
    }
    if (lower == "devicetrust" || lower == "device_trust") {
        return LocalAuditCategory::DeviceTrust;
    }
    if (lower == "keylifecycle" || lower == "key_lifecycle") {
        return LocalAuditCategory::KeyLifecycle;
    }
    if (lower == "messagingsecurity" || lower == "messaging_security") {
        return LocalAuditCategory::MessagingSecurity;
    }
    if (lower == "emergencydefense" || lower == "emergency_defense") {
        return LocalAuditCategory::EmergencyDefense;
    }
    if (lower == "settingsnetwork" || lower == "settings_network") {
        return LocalAuditCategory::SettingsNetwork;
    }
    return std::nullopt;
}

std::string_view to_string(LocalAuditOutcome outcome) noexcept {
    switch (outcome) {
    case LocalAuditOutcome::Success:
        return "Success";
    case LocalAuditOutcome::Failure:
        return "Failure";
    case LocalAuditOutcome::Rejected:
        return "Rejected";
    case LocalAuditOutcome::Triggered:
        return "Triggered";
    }
    return "Failure";
}

std::optional<LocalAuditOutcome> local_audit_outcome_from_string(std::string_view value) noexcept {
    const std::string lower = to_lower_ascii(value);
    if (lower == "success") {
        return LocalAuditOutcome::Success;
    }
    if (lower == "failure") {
        return LocalAuditOutcome::Failure;
    }
    if (lower == "rejected") {
        return LocalAuditOutcome::Rejected;
    }
    if (lower == "triggered") {
        return LocalAuditOutcome::Triggered;
    }
    return std::nullopt;
}

bool LocalAuditEvent::is_valid_sha256_hex(std::string_view hex) noexcept {
    if (hex.size() != 64U) {
        return false;
    }
    for (const char ch : hex) {
        const bool is_lower_hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        if (!is_lower_hex) {
            return false;
        }
    }
    return true;
}

std::string LocalAuditEvent::compute_canonical_hash() const {
    crypto::StreamingSha256 hasher;
    if (!hasher.is_valid()) {
        return {};
    }

    feed_length_prefixed(hasher, kCanonicalAuditDomainTag);
    feed_length_prefixed(hasher, std::to_string(sequence_id));
    feed_length_prefixed(hasher, std::to_string(occurred_at_ms));
    feed_length_prefixed(hasher, to_string(category));
    feed_length_prefixed(hasher, event_type);
    feed_length_prefixed(hasher, to_string(outcome));
    feed_length_prefixed(hasher, actor_opaque_id);
    feed_length_prefixed(hasher, target_opaque_id);
    feed_length_prefixed(hasher, sanitized_summary);
    feed_length_prefixed(hasher, prev_hash_sha256);

    const auto digest_res = hasher.finalize_hex();
    if (digest_res.is_error()) {
        return {};
    }
    return digest_res.value();
}

bool LocalAuditEvent::has_valid_hash() const {
    if (!is_valid_sha256_hex(entry_hash_sha256)) {
        return false;
    }
    const std::string expected = compute_canonical_hash();
    if (expected.size() != 64U) {
        return false;
    }
    return CRYPTO_memcmp(entry_hash_sha256.data(), expected.data(), 64U) == 0;
}

std::vector<std::string> LocalAuditEvent::validate() const {
    std::vector<std::string> errors;
    if (sequence_id < 1) {
        errors.emplace_back("sequence_id must be >= 1");
    }
    if (occurred_at_ms <= 0) {
        errors.emplace_back("occurred_at_ms must be positive");
    }
    if (event_type.empty() || event_type.size() > kMaxAuditFieldBytes) {
        errors.emplace_back("event_type must be 1..128 bytes");
    } else if (contains_ascii_control(event_type)) {
        errors.emplace_back("event_type contains ASCII control characters");
    }
    if (actor_opaque_id.size() > kMaxAuditFieldBytes || contains_ascii_control(actor_opaque_id)) {
        errors.emplace_back("actor_opaque_id exceeds 128 bytes or contains control characters");
    }
    if (target_opaque_id.size() > kMaxAuditFieldBytes || contains_ascii_control(target_opaque_id)) {
        errors.emplace_back("target_opaque_id exceeds 128 bytes or contains control characters");
    }
    if (sanitized_summary.size() > kMaxAuditSummaryBytes || contains_ascii_control(sanitized_summary)) {
        errors.emplace_back("sanitized_summary exceeds 512 bytes or contains control characters");
    }
    if (!is_valid_sha256_hex(prev_hash_sha256)) {
        errors.emplace_back("prev_hash_sha256 must be 64 lowercase hex characters");
    } else if (sequence_id == 1 && prev_hash_sha256 != kGenesisAuditHash) {
        errors.emplace_back("sequence_id 1 must link to kGenesisAuditHash");
    }
    if (!is_valid_sha256_hex(entry_hash_sha256)) {
        errors.emplace_back("entry_hash_sha256 must be 64 lowercase hex characters");
    }
    return errors;
}

bool LocalAuditEvent::is_valid() const noexcept {
    return validate().empty();
}

std::string LocalAuditEvent::to_json() const {
    nlohmann::json j;
    j["sequence_id"] = sequence_id;
    j["occurred_at_ms"] = occurred_at_ms;
    j["category"] = to_string(category);
    j["event_type"] = event_type;
    j["outcome"] = to_string(outcome);
    j["actor_opaque_id"] = actor_opaque_id;
    j["target_opaque_id"] = target_opaque_id;
    j["sanitized_summary"] = sanitized_summary;
    j["prev_hash_sha256"] = prev_hash_sha256;
    j["entry_hash_sha256"] = entry_hash_sha256;
    return j.dump();
}

std::optional<LocalAuditEvent> LocalAuditEvent::from_json(std::string_view json_str) {
    const nlohmann::json j = nlohmann::json::parse(json_str.begin(), json_str.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return std::nullopt;
    }

    if (!j.contains("sequence_id") || !j["sequence_id"].is_number_integer() || !j.contains("occurred_at_ms") ||
        !j["occurred_at_ms"].is_number_integer() || !j.contains("category") || !j["category"].is_string() ||
        !j.contains("event_type") || !j["event_type"].is_string() || !j.contains("outcome") ||
        !j["outcome"].is_string() || !j.contains("prev_hash_sha256") || !j["prev_hash_sha256"].is_string() ||
        !j.contains("entry_hash_sha256") || !j["entry_hash_sha256"].is_string()) {
        return std::nullopt;
    }

    const auto category_opt = local_audit_category_from_string(j["category"].get<std::string>());
    const auto outcome_opt = local_audit_outcome_from_string(j["outcome"].get<std::string>());
    if (!category_opt.has_value() || !outcome_opt.has_value()) {
        return std::nullopt;
    }

    LocalAuditEvent ev;
    ev.sequence_id = j["sequence_id"].get<int64_t>();
    ev.occurred_at_ms = j["occurred_at_ms"].get<int64_t>();
    ev.category = *category_opt;
    ev.event_type = j["event_type"].get<std::string>();
    ev.outcome = *outcome_opt;
    if (j.contains("actor_opaque_id") && j["actor_opaque_id"].is_string()) {
        ev.actor_opaque_id = j["actor_opaque_id"].get<std::string>();
    }
    if (j.contains("target_opaque_id") && j["target_opaque_id"].is_string()) {
        ev.target_opaque_id = j["target_opaque_id"].get<std::string>();
    }
    if (j.contains("sanitized_summary") && j["sanitized_summary"].is_string()) {
        ev.sanitized_summary = j["sanitized_summary"].get<std::string>();
    }
    ev.prev_hash_sha256 = j["prev_hash_sha256"].get<std::string>();
    ev.entry_hash_sha256 = j["entry_hash_sha256"].get<std::string>();
    return ev;
}

} // namespace securecloud::client::domain
