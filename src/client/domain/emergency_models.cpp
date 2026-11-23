#include "domain/emergency_models.hpp"

#include <limits>
#include <nlohmann/json.hpp>

namespace securecloud::client::domain {
namespace {

bool is_hex_string(std::string_view sv) noexcept {
    if (sv.empty() || (sv.size() % 2U) != 0U) {
        return false;
    }
    for (const char ch : sv) {
        const bool is_hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
        if (!is_hex) {
            return false;
        }
    }
    return true;
}

} // namespace

std::string_view to_string(PanicTriggerSource source) noexcept {
    switch (source) {
    case PanicTriggerSource::Hotkey:
        return "Hotkey";
    case PanicTriggerSource::UiPanicButton:
        return "UiPanicButton";
    case PanicTriggerSource::DuressPin:
        return "DuressPin";
    case PanicTriggerSource::Programmatic:
        return "Programmatic";
    }
    return "Programmatic";
}

std::optional<PanicTriggerSource> panic_trigger_source_from_string(std::string_view str) noexcept {
    if (str == "Hotkey") {
        return PanicTriggerSource::Hotkey;
    }
    if (str == "UiPanicButton") {
        return PanicTriggerSource::UiPanicButton;
    }
    if (str == "DuressPin") {
        return PanicTriggerSource::DuressPin;
    }
    if (str == "Programmatic") {
        return PanicTriggerSource::Programmatic;
    }
    return std::nullopt;
}

std::string_view to_string(PostWipeMode mode) noexcept {
    switch (mode) {
    case PostWipeMode::EmergencyLocked:
        return "EmergencyLocked";
    case PostWipeMode::UnconfiguredReset:
        return "UnconfiguredReset";
    case PostWipeMode::DecoyWorkspace:
        return "DecoyWorkspace";
    }
    return "EmergencyLocked";
}

std::optional<PostWipeMode> post_wipe_mode_from_string(std::string_view str) noexcept {
    if (str == "EmergencyLocked") {
        return PostWipeMode::EmergencyLocked;
    }
    if (str == "UnconfiguredReset") {
        return PostWipeMode::UnconfiguredReset;
    }
    if (str == "DecoyWorkspace") {
        return PostWipeMode::DecoyWorkspace;
    }
    return std::nullopt;
}

std::string_view to_string(WipeStepStatus status) noexcept {
    switch (status) {
    case WipeStepStatus::Succeeded:
        return "Succeeded";
    case WipeStepStatus::Skipped:
        return "Skipped";
    case WipeStepStatus::Failed:
        return "Failed";
    }
    return "Failed";
}

std::optional<WipeStepStatus> wipe_step_status_from_string(std::string_view str) noexcept {
    if (str == "Succeeded") {
        return WipeStepStatus::Succeeded;
    }
    if (str == "Skipped") {
        return WipeStepStatus::Skipped;
    }
    if (str == "Failed") {
        return WipeStepStatus::Failed;
    }
    return std::nullopt;
}

std::string EmergencyWipeReport::to_safe_summary_json() const {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& step : step_results) {
        steps.push_back(nlohmann::json{
            {"artifact_category", step.artifact_category},
            {"items_processed", step.items_processed},
            {"status", std::string(to_string(step.status))},
            {"detail", step.detail},
        });
    }

    const nlohmann::json j{
        {"trigger_source", std::string(to_string(trigger_source))},
        {"post_wipe_mode", std::string(to_string(post_wipe_mode))},
        {"broadcast_attempted", broadcast_attempted},
        {"broadcast_acknowledged", broadcast_acknowledged},
        {"secrets_purged_count", secrets_purged_count},
        {"files_shredded_count", files_shredded_count},
        {"volatile_caches_cleared", volatile_caches_cleared},
        {"duration_ms", duration_ms},
        {"all_critical_steps_succeeded", all_critical_steps_succeeded},
        {"step_results", std::move(steps)},
    };
    return j.dump();
}

bool EmergencyBroadcastRequest::is_valid() const noexcept {
    if (conversation_id.empty() || sender_user_id.empty() || sender_device_id.empty() || alert_plaintext.empty()) {
        return false;
    }
    if (ack_timeout.count() <= 0 || ack_timeout > kMaxAckTimeout) {
        return false;
    }
    return true;
}

bool DuressPinConfig::is_valid() const noexcept {
    if (!enabled) {
        return pbkdf2_iterations >= kMinPbkdf2Iterations;
    }
    if (pbkdf2_iterations < kMinPbkdf2Iterations) {
        return false;
    }
    if (salt_hex.size() < kMinSaltHexLength || !is_hex_string(salt_hex)) {
        return false;
    }
    if (derived_hash_hex.size() != kExpectedHashHexLength || !is_hex_string(derived_hash_hex)) {
        return false;
    }
    return true;
}

std::string DuressPinConfig::to_json() const {
    const nlohmann::json j{
        {"enabled", enabled},
        {"post_wipe_mode", std::string(to_string(post_wipe_mode))},
        {"pbkdf2_iterations", pbkdf2_iterations},
        {"salt_hex", salt_hex},
        {"derived_hash_hex", derived_hash_hex},
        {"configured_at_ms", configured_at_ms},
    };
    return j.dump();
}

std::optional<DuressPinConfig> DuressPinConfig::from_json(std::string_view json_str) {
    const nlohmann::json j = nlohmann::json::parse(json_str.begin(), json_str.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        return std::nullopt;
    }

    DuressPinConfig out;

    const auto enabled_it = j.find("enabled");
    if (enabled_it == j.end() || !enabled_it->is_boolean()) {
        return std::nullopt;
    }
    out.enabled = enabled_it->get<bool>();

    const auto mode_it = j.find("post_wipe_mode");
    if (mode_it == j.end() || !mode_it->is_string()) {
        return std::nullopt;
    }
    const auto parsed_mode = post_wipe_mode_from_string(mode_it->get<std::string>());
    if (!parsed_mode.has_value()) {
        return std::nullopt;
    }
    out.post_wipe_mode = *parsed_mode;

    const auto iter_it = j.find("pbkdf2_iterations");
    if (iter_it == j.end() || !iter_it->is_number_integer()) {
        return std::nullopt;
    }
    const int64_t raw_iter = iter_it->get<int64_t>();
    if (raw_iter < 0 || raw_iter > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        return std::nullopt;
    }
    out.pbkdf2_iterations = static_cast<uint32_t>(raw_iter);

    const auto salt_it = j.find("salt_hex");
    if (salt_it == j.end() || !salt_it->is_string()) {
        return std::nullopt;
    }
    out.salt_hex = salt_it->get<std::string>();

    const auto hash_it = j.find("derived_hash_hex");
    if (hash_it == j.end() || !hash_it->is_string()) {
        return std::nullopt;
    }
    out.derived_hash_hex = hash_it->get<std::string>();

    const auto ts_it = j.find("configured_at_ms");
    if (ts_it != j.end()) {
        if (!ts_it->is_number_integer()) {
            return std::nullopt;
        }
        out.configured_at_ms = ts_it->get<int64_t>();
    }

    if (!out.is_valid()) {
        return std::nullopt;
    }
    return out;
}

} // namespace securecloud::client::domain
