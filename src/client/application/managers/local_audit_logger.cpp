#include "application/managers/local_audit_logger.hpp"

#include "infrastructure/client_logger.hpp"

#include <algorithm>
#include <chrono>
#include <openssl/crypto.h>

namespace securecloud::client::application::managers {
namespace {

constexpr std::size_t kVerificationPageSize = 500U;

[[nodiscard]] int64_t current_unix_ms() noexcept {
    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return now_ms > 0 ? now_ms : 1;
}

[[nodiscard]] std::string truncate_utf8_safe(std::string_view text, std::size_t max_bytes) {
    if (text.size() <= max_bytes) {
        return std::string(text);
    }
    std::size_t len = max_bytes;
    while (len > 0U && (static_cast<unsigned char>(text[len]) & 0xC0U) == 0x80U) {
        --len;
    }
    return std::string(text.substr(0U, len));
}

[[nodiscard]] std::string sanitize_audit_text(std::string_view raw, std::size_t max_bytes) {
    std::string clean = infrastructure::ClientLogger::sanitize(raw);
    for (char& ch : clean) {
        const auto uch = static_cast<unsigned char>(ch);
        if (uch < 0x20U || uch == 0x7FU) {
            ch = ' ';
        }
    }
    return truncate_utf8_safe(clean, max_bytes);
}

[[nodiscard]] domain::AuditChainVerificationResult make_failed_verification(int64_t corrupted_seq,
                                                                            std::size_t verified_count,
                                                                            std::string latest_hash,
                                                                            std::string reason) {
    domain::AuditChainVerificationResult res;
    res.valid = false;
    res.verified_count = verified_count;
    res.first_corrupted_sequence = corrupted_seq;
    res.latest_hash_sha256 = std::move(latest_hash);
    res.failure_reason = std::move(reason);
    return res;
}

} // namespace

LocalAuditLogger::LocalAuditLogger(interfaces::ILocalStore& local_store) : local_store_(local_store) {}

ClientResult<void> LocalAuditLogger::refresh_head_locked() {
    if (initialized_) {
        return ClientResult<void>::ok();
    }

    const auto latest_res = local_store_.get_latest_audit_event();
    if (latest_res.is_error()) {
        return ClientResult<void>::error(latest_res.error());
    }

    if (latest_res.value().has_value()) {
        last_sequence_id_ = latest_res.value()->sequence_id;
        last_hash_sha256_ = latest_res.value()->entry_hash_sha256;
    } else {
        last_sequence_id_ = 0;
        last_hash_sha256_ = std::string(domain::kGenesisAuditHash);
    }
    initialized_ = true;
    return ClientResult<void>::ok();
}

ClientResult<domain::LocalAuditEvent>
LocalAuditLogger::record_event(domain::LocalAuditCategory category, std::string_view event_type,
                               domain::LocalAuditOutcome outcome, std::string_view actor_opaque_id,
                               std::string_view target_opaque_id, std::string_view raw_summary,
                               int64_t occurred_at_ms) {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto init_res = refresh_head_locked();
    if (init_res.is_error()) {
        return ClientResult<domain::LocalAuditEvent>::error(init_res.error());
    }

    std::string clean_event_type = sanitize_audit_text(event_type, domain::kMaxAuditFieldBytes);
    if (clean_event_type.empty()) {
        clean_event_type = "security.event";
    }
    const std::string clean_actor = sanitize_audit_text(actor_opaque_id, domain::kMaxAuditFieldBytes);
    const std::string clean_target = sanitize_audit_text(target_opaque_id, domain::kMaxAuditFieldBytes);
    const std::string clean_summary = sanitize_audit_text(raw_summary, domain::kMaxAuditSummaryBytes);
    const int64_t ts_ms = (occurred_at_ms > 0) ? occurred_at_ms : current_unix_ms();

    auto build_candidate = [&]() {
        domain::LocalAuditEvent ev;
        ev.sequence_id = last_sequence_id_ + 1;
        ev.occurred_at_ms = ts_ms;
        ev.category = category;
        ev.event_type = clean_event_type;
        ev.outcome = outcome;
        ev.actor_opaque_id = clean_actor;
        ev.target_opaque_id = clean_target;
        ev.sanitized_summary = clean_summary;
        ev.prev_hash_sha256 = (last_sequence_id_ == 0) ? std::string(domain::kGenesisAuditHash) : last_hash_sha256_;
        ev.entry_hash_sha256 = ev.compute_canonical_hash();
        return ev;
    };

    domain::LocalAuditEvent candidate = build_candidate();
    auto append_res = local_store_.append_audit_event(candidate);
    if (append_res.is_error() && append_res.error().code() == ClientErrorCode::ValidationFailed) {
        // Resynchronize cached chain head once if underlying store state was replaced externally.
        initialized_ = false;
        const auto resync_res = refresh_head_locked();
        if (resync_res.is_error()) {
            return ClientResult<domain::LocalAuditEvent>::error(resync_res.error());
        }
        candidate = build_candidate();
        append_res = local_store_.append_audit_event(candidate);
    }

    if (append_res.is_error()) {
        return ClientResult<domain::LocalAuditEvent>::error(append_res.error());
    }

    last_sequence_id_ = candidate.sequence_id;
    last_hash_sha256_ = candidate.entry_hash_sha256;
    initialized_ = true;
    return ClientResult<domain::LocalAuditEvent>::ok(std::move(candidate));
}

ClientResult<domain::AuditChainVerificationResult> LocalAuditLogger::verify_chain_integrity() const {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto count_res = local_store_.count_audit_events();
    if (count_res.is_error()) {
        return ClientResult<domain::AuditChainVerificationResult>::error(count_res.error());
    }

    const std::size_t total_count = count_res.value();
    if (total_count == 0U) {
        domain::AuditChainVerificationResult empty_res;
        empty_res.valid = true;
        empty_res.verified_count = 0U;
        empty_res.latest_hash_sha256 = std::string(domain::kGenesisAuditHash);
        return ClientResult<domain::AuditChainVerificationResult>::ok(std::move(empty_res));
    }

    int64_t expected_seq = 1;
    std::string expected_prev(domain::kGenesisAuditHash);
    std::size_t verified_count = 0U;
    std::size_t offset = 0U;

    while (offset < total_count) {
        const auto page_res = local_store_.list_audit_events(kVerificationPageSize, offset);
        if (page_res.is_error()) {
            return ClientResult<domain::AuditChainVerificationResult>::error(page_res.error());
        }

        const auto& page = page_res.value();
        if (page.empty()) {
            return ClientResult<domain::AuditChainVerificationResult>::ok(make_failed_verification(
                expected_seq, verified_count, expected_prev, "Audit store returned empty page before total count"));
        }

        for (const auto& ev : page) {
            if (ev.sequence_id != expected_seq) {
                return ClientResult<domain::AuditChainVerificationResult>::ok(make_failed_verification(
                    expected_seq, verified_count, expected_prev, "Sequence gap or out-of-order audit entry"));
            }
            if (ev.prev_hash_sha256.size() != 64U || expected_prev.size() != 64U ||
                CRYPTO_memcmp(ev.prev_hash_sha256.data(), expected_prev.data(), 64U) != 0) {
                return ClientResult<domain::AuditChainVerificationResult>::ok(make_failed_verification(
                    ev.sequence_id, verified_count, expected_prev, "Previous hash linkage mismatch"));
            }

            const std::string recomputed_hash = ev.compute_canonical_hash();
            if (ev.entry_hash_sha256.size() != 64U || recomputed_hash.size() != 64U ||
                CRYPTO_memcmp(ev.entry_hash_sha256.data(), recomputed_hash.data(), 64U) != 0) {
                return ClientResult<domain::AuditChainVerificationResult>::ok(make_failed_verification(
                    ev.sequence_id, verified_count, expected_prev, "Entry SHA-256 digest mismatch"));
            }

            expected_prev = ev.entry_hash_sha256;
            ++expected_seq;
            ++verified_count;
        }

        offset += page.size();
    }

    if (verified_count != total_count) {
        return ClientResult<domain::AuditChainVerificationResult>::ok(make_failed_verification(
            expected_seq, verified_count, expected_prev, "Verified audit count mismatch against total row count"));
    }

    domain::AuditChainVerificationResult ok_res;
    ok_res.valid = true;
    ok_res.verified_count = verified_count;
    ok_res.first_corrupted_sequence = std::nullopt;
    ok_res.latest_hash_sha256 = std::move(expected_prev);
    return ClientResult<domain::AuditChainVerificationResult>::ok(std::move(ok_res));
}

ClientResult<std::vector<domain::LocalAuditEvent>> LocalAuditLogger::recent_events(std::size_t limit) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (limit == 0U) {
        return ClientResult<std::vector<domain::LocalAuditEvent>>::ok({});
    }

    const auto count_res = local_store_.count_audit_events();
    if (count_res.is_error()) {
        return ClientResult<std::vector<domain::LocalAuditEvent>>::error(count_res.error());
    }

    const std::size_t total = count_res.value();
    if (total == 0U) {
        return ClientResult<std::vector<domain::LocalAuditEvent>>::ok({});
    }

    const std::size_t offset = (total > limit) ? (total - limit) : 0U;
    auto list_res = local_store_.list_audit_events(limit, offset);
    if (list_res.is_error()) {
        return list_res;
    }

    auto events = std::move(list_res).value();
    std::reverse(events.begin(), events.end());
    return ClientResult<std::vector<domain::LocalAuditEvent>>::ok(std::move(events));
}

ClientResult<std::size_t> LocalAuditLogger::event_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_store_.count_audit_events();
}

void LocalAuditLogger::wipe_volatile_state() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!last_hash_sha256_.empty()) {
        OPENSSL_cleanse(last_hash_sha256_.data(), last_hash_sha256_.size());
        last_hash_sha256_.clear();
    }
    last_sequence_id_ = 0;
    initialized_ = false;
}

} // namespace securecloud::client::application::managers
