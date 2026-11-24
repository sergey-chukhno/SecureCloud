#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/device_pairing_coordinator.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "application/managers/settings_manager.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/local_audit_event.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "infrastructure/client_logger.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#if __has_include(<sqlcipher/sqlite3.h>)
#include <sqlcipher/sqlite3.h>
#else
#include <sqlite3.h>
#endif

namespace securecloud::client::application::managers::test {
namespace {

using common::configuration::SecretString;
using domain::LocalAuditCategory;
using domain::LocalAuditEvent;
using domain::LocalAuditOutcome;
using infrastructure::ClientLogger;
using infrastructure::adapters::MemoryLocalStore;
using infrastructure::adapters::MemorySecureStorage;
using infrastructure::adapters::OpenSslCryptoProvider;
using infrastructure::adapters::SqlCipherLocalStore;

class LocalAuditLogTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("securecloud_local_audit_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "audit_vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::string read_raw_bytes(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    static void exec_raw_sqlcipher(const std::string& db_path, const std::string& key_hex, const char* sql) {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open_v2(db_path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr),
                  SQLITE_OK);
        ASSERT_NE(db, nullptr);

        const std::string pragma_key = "PRAGMA key = \"x'" + key_hex + "'\";";
        ASSERT_EQ(sqlite3_exec(db, pragma_key.c_str(), nullptr, nullptr, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, "PRAGMA cipher_memory_security = ON;", nullptr, nullptr, nullptr), SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db, sql, nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close_v2(db);
    }

    static LocalAuditEvent make_valid_genesis_event() {
        LocalAuditEvent ev;
        ev.sequence_id = 1;
        ev.occurred_at_ms = 1760000000100LL;
        ev.category = LocalAuditCategory::DeviceTrust;
        ev.event_type = "device.registered";
        ev.outcome = LocalAuditOutcome::Success;
        ev.actor_opaque_id = "usr-opaque-1";
        ev.target_opaque_id = "dev-opaque-1";
        ev.sanitized_summary = "Local device registered";
        ev.prev_hash_sha256 = std::string(domain::kGenesisAuditHash);
        ev.entry_hash_sha256 = ev.compute_canonical_hash();
        return ev;
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(LocalAuditLogTest, DomainValidationAndCanonicalHashDeterminism) {
    EXPECT_EQ(domain::local_audit_category_from_string("CryptoSelfTest"), LocalAuditCategory::CryptoSelfTest);
    EXPECT_EQ(domain::local_audit_category_from_string("EmergencyDefense"), LocalAuditCategory::EmergencyDefense);
    EXPECT_EQ(domain::local_audit_category_from_string("unknown_cat"), std::nullopt);
    EXPECT_EQ(domain::local_audit_outcome_from_string("Success"), LocalAuditOutcome::Success);
    EXPECT_EQ(domain::local_audit_outcome_from_string("Triggered"), LocalAuditOutcome::Triggered);
    EXPECT_EQ(domain::local_audit_outcome_from_string("bogus"), std::nullopt);

    const LocalAuditEvent base = make_valid_genesis_event();
    EXPECT_TRUE(base.is_valid());
    EXPECT_TRUE(base.has_valid_hash());
    EXPECT_EQ(base.compute_canonical_hash(), base.entry_hash_sha256);

    const auto parsed = LocalAuditEvent::from_json(base.to_json());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, base);

    LocalAuditEvent bad_prev = base;
    bad_prev.prev_hash_sha256 = std::string(64U, 'a');
    EXPECT_FALSE(bad_prev.validate().empty());

    // Mutating any canonical field must invalidate entry_hash_sha256 verification.
    {
        LocalAuditEvent m = base;
        m.sequence_id = 2;
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.occurred_at_ms += 1;
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.category = LocalAuditCategory::KeyLifecycle;
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.event_type = "device.revoked";
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.outcome = LocalAuditOutcome::Failure;
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.actor_opaque_id = "usr-opaque-2";
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.target_opaque_id = "dev-opaque-2";
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.sanitized_summary = "Modified summary";
        EXPECT_FALSE(m.has_valid_hash());
    }
    {
        LocalAuditEvent m = base;
        m.prev_hash_sha256 = std::string(64U, 'b');
        EXPECT_FALSE(m.has_valid_hash());
    }
}

TEST_F(LocalAuditLogTest, SqlCipherMonotonicHashChainPersistsAndVerifiesAcrossRestart) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;

    std::string seq10_hash;
    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        LocalAuditLogger logger(store);

        const auto empty_check = logger.verify_chain_integrity();
        ASSERT_TRUE(empty_check.is_ok());
        EXPECT_TRUE(empty_check.value().valid);
        EXPECT_EQ(empty_check.value().verified_count, 0U);
        EXPECT_EQ(empty_check.value().latest_hash_sha256, domain::kGenesisAuditHash);

        std::string prev = std::string(domain::kGenesisAuditHash);
        for (int i = 1; i <= 10; ++i) {
            const auto rec = logger.record_event(
                LocalAuditCategory::DeviceTrust, "device.lifecycle_" + std::to_string(i), LocalAuditOutcome::Success,
                "usr-1", "dev-" + std::to_string(i), "Step " + std::to_string(i), 1760000000000LL + i);
            ASSERT_TRUE(rec.is_ok());
            EXPECT_EQ(rec.value().sequence_id, i);
            EXPECT_EQ(rec.value().prev_hash_sha256, prev);
            EXPECT_TRUE(rec.value().has_valid_hash());
            prev = rec.value().entry_hash_sha256;
        }
        seq10_hash = prev;

        // Direct out-of-order / forged-hash appends to store must be rejected.
        LocalAuditEvent bad_seq = make_valid_genesis_event();
        bad_seq.sequence_id = 12;
        bad_seq.prev_hash_sha256 = seq10_hash;
        bad_seq.entry_hash_sha256 = bad_seq.compute_canonical_hash();
        EXPECT_TRUE(store.append_audit_event(bad_seq).is_error());

        MemoryLocalStore mem_store;
        EXPECT_TRUE(mem_store.append_audit_event(bad_seq).is_error());

        const auto verify1 = logger.verify_chain_integrity();
        ASSERT_TRUE(verify1.is_ok());
        EXPECT_TRUE(verify1.value().valid);
        EXPECT_EQ(verify1.value().verified_count, 10U);
        EXPECT_FALSE(verify1.value().first_corrupted_sequence.has_value());
        EXPECT_EQ(verify1.value().latest_hash_sha256, seq10_hash);
        ASSERT_TRUE(store.close().is_ok());
    }

    // Reopen existing encrypted vault and continue the chain from sequence 10 -> 11.
    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        LocalAuditLogger logger(store);

        const auto verify_reopen = logger.verify_chain_integrity();
        ASSERT_TRUE(verify_reopen.is_ok());
        EXPECT_TRUE(verify_reopen.value().valid);
        EXPECT_EQ(verify_reopen.value().verified_count, 10U);

        const auto ev11 =
            logger.record_event(LocalAuditCategory::KeyLifecycle, "prekey.signed_rotated", LocalAuditOutcome::Success,
                                "usr-1", "dev-11", "Rotated SPK after restart", 1760000000999LL);
        ASSERT_TRUE(ev11.is_ok());
        EXPECT_EQ(ev11.value().sequence_id, 11);
        EXPECT_EQ(ev11.value().prev_hash_sha256, seq10_hash);

        const auto recent = logger.recent_events(3U);
        ASSERT_TRUE(recent.is_ok());
        ASSERT_EQ(recent.value().size(), 3U);
        EXPECT_EQ(recent.value()[0].sequence_id, 11);
        EXPECT_EQ(recent.value()[1].sequence_id, 10);
        EXPECT_EQ(recent.value()[2].sequence_id, 9);

        const auto verify_final = logger.verify_chain_integrity();
        ASSERT_TRUE(verify_final.is_ok());
        EXPECT_TRUE(verify_final.value().valid);
        EXPECT_EQ(verify_final.value().verified_count, 11U);
        EXPECT_EQ(verify_final.value().latest_hash_sha256, ev11.value().entry_hash_sha256);
        ASSERT_TRUE(store.close().is_ok());
    }
}

TEST_F(LocalAuditLogTest, DetectsRowModificationHashTamperMiddleDeletionAndSequenceGap) {
    struct TamperCase {
        std::string name;
        std::string sql;
        int64_t expected_corrupted_seq;
    };

    const std::vector<TamperCase> cases = {
        {
            "tampered_summary_row_3",
            "UPDATE local_audit_log SET payload_json = "
            "'{\"actor_opaque_id\":\"usr-1\",\"target_opaque_id\":\"dev-3\",\"sanitized_summary\":\"forged\"}' "
            "WHERE sequence_id = 3;",
            3,
        },
        {
            "tampered_outcome_row_2",
            "UPDATE local_audit_log SET outcome = 'Failure' WHERE sequence_id = 2;",
            2,
        },
        {
            "deleted_middle_row_3",
            "DELETE FROM local_audit_log WHERE sequence_id = 3;",
            3,
        },
        {
            "deleted_genesis_row_1",
            "DELETE FROM local_audit_log WHERE sequence_id = 1;",
            1,
        },
    };

    for (const auto& tc : cases) {
        const std::string case_db = (temp_dir_ / (tc.name + ".db")).string();
        MemorySecureStorage secure_storage;
        OpenSslCryptoProvider crypto;

        {
            SqlCipherLocalStore store(secure_storage, crypto);
            ASSERT_TRUE(store.open(case_db).is_ok());
            LocalAuditLogger logger(store);
            for (int i = 1; i <= 5; ++i) {
                ASSERT_TRUE(logger
                                .record_event(LocalAuditCategory::DeviceTrust, "device.event",
                                              LocalAuditOutcome::Success, "usr-1", "dev-" + std::to_string(i),
                                              "Valid entry " + std::to_string(i), 1760000010000LL + i)
                                .is_ok());
            }
            ASSERT_TRUE(store.close().is_ok());
        }

        const auto key_res = secure_storage.get_secret(SqlCipherLocalStore::kMasterKeyId);
        ASSERT_TRUE(key_res.is_ok());
        exec_raw_sqlcipher(case_db, key_res.value().expose_unredacted_secret(), tc.sql.c_str());

        {
            SqlCipherLocalStore store(secure_storage, crypto);
            ASSERT_TRUE(store.open(case_db).is_ok());
            LocalAuditLogger logger(store);
            const auto verify = logger.verify_chain_integrity();
            ASSERT_TRUE(verify.is_ok()) << tc.name;
            EXPECT_FALSE(verify.value().valid) << tc.name;
            ASSERT_TRUE(verify.value().first_corrupted_sequence.has_value()) << tc.name;
            EXPECT_EQ(*verify.value().first_corrupted_sequence, tc.expected_corrupted_seq) << tc.name;
            ASSERT_TRUE(store.close().is_ok());
        }
    }
}

TEST_F(LocalAuditLogTest, SanitizerAndAuditLoggerStripAllSecretAndPiiCanariesWithZeroDiskLeak) {
    const std::string canary_jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJjYW5hcnlfand0In0.c2lnbmF0dXJlX2NhbmFyeV8wMQ";
    const std::string canary_bearer = "canary_bearer_token_998877";
    const std::string canary_pem_body = "MC4CAQAwBQYDK2VwBCIEICanaryPrivateKeyMaterialHere";
    const std::string canary_proxy_pw = "canary_proxy_pw_5511";
    const std::string canary_duress = "994422_canary_duress";
    const std::string canary_verifier = "sc-bip39-v1:deadbeefcanarydigest0123456789";
    const std::string canary_mnemonic = "abandon ability able about above absent absorb abstract canaryword";
    const std::string canary_master_key = "mk_canary_deadbeefcafebabe01234567";
    const std::string canary_plaintext = "ultra_secret_plaintext_canary_payload";
    const std::string canary_email = "alice.canary@example.org";

    // Preserve canonical Bearer redaction even when bearer token starts with "eyJ..."
    const std::string bearer_jwt_sanitized = ClientLogger::sanitize("Authorization: Bearer " + canary_jwt);
    EXPECT_EQ(bearer_jwt_sanitized.find(canary_jwt), std::string::npos);
    EXPECT_NE(bearer_jwt_sanitized.find("Bearer [REDACTED]"), std::string::npos);

    const std::string raw_combined =
        "jwt=" + canary_jwt + " Authorization: Bearer " + canary_bearer + " -----BEGIN PRIVATE KEY-----\n" +
        canary_pem_body + "\n-----END PRIVATE KEY----- " + R"({"password":")" + canary_proxy_pw +
        R"(","duress_pin":")" + canary_duress + R"(","master_key":")" + canary_master_key + R"(","plaintext":")" +
        canary_plaintext + R"("})" + " verifier=" + canary_verifier + " mnemonic=\"" + canary_mnemonic +
        "\" user=" + canary_email;

    const std::string direct_sanitized = ClientLogger::sanitize(raw_combined);
    const std::vector<std::string> all_canaries = {
        canary_jwt,      canary_bearer, canary_pem_body,   canary_proxy_pw,  canary_duress, canary_verifier,
        canary_mnemonic, "canaryword",  canary_master_key, canary_plaintext, canary_email,
    };

    for (const auto& canary : all_canaries) {
        EXPECT_EQ(direct_sanitized.find(canary), std::string::npos) << "Canary leaked in direct sanitize: " << canary;
    }

    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;
    {
        SqlCipherLocalStore store(secure_storage, crypto);
        ASSERT_TRUE(store.open(db_path_).is_ok());
        LocalAuditLogger logger(store);

        const auto ev1 = logger.record_event(LocalAuditCategory::EmergencyDefense, "emergency.duress_pin_configured",
                                             LocalAuditOutcome::Success, canary_email, "dev-canary",
                                             "Configured duress_pin=" + canary_duress + " verifier=" + canary_verifier);
        ASSERT_TRUE(ev1.is_ok());

        const auto ev2 =
            logger.record_event(LocalAuditCategory::KeyLifecycle, "recovery.phrase_verified",
                                LocalAuditOutcome::Success, "usr-1", "dev-canary",
                                "Recovery mnemonic=\"" + canary_mnemonic + "\" password=" + canary_proxy_pw +
                                    " master_key=" + canary_master_key + " jwt=" + canary_jwt);
        ASSERT_TRUE(ev2.is_ok());

        const auto ev3 = logger.record_event(LocalAuditCategory::MessagingSecurity, "ratchet.decrypt_failed",
                                             LocalAuditOutcome::Failure, "usr-1", "dev-2",
                                             "Decrypt failed bearer Authorization: Bearer " + canary_bearer +
                                                 " plaintext=" + canary_plaintext + " -----BEGIN PRIVATE KEY-----\n" +
                                                 canary_pem_body + "\n-----END PRIVATE KEY-----");
        ASSERT_TRUE(ev3.is_ok());

        const auto verify = logger.verify_chain_integrity();
        ASSERT_TRUE(verify.is_ok());
        EXPECT_TRUE(verify.value().valid);

        const auto events = logger.recent_events(10U);
        ASSERT_TRUE(events.is_ok());
        ASSERT_EQ(events.value().size(), 3U);

        for (const auto& ev : events.value()) {
            const std::string serialized = ev.to_json();
            for (const auto& canary : all_canaries) {
                EXPECT_EQ(serialized.find(canary), std::string::npos) << "Canary leaked in LocalAuditEvent: " << canary;
            }
        }

        ASSERT_TRUE(store.close().is_ok());
    }

    // Raw encrypted SQLCipher file + sidecars on disk must never contain any canary byte sequence.
    const std::vector<std::filesystem::path> disk_paths = {
        std::filesystem::path(db_path_),
        std::filesystem::path(db_path_ + "-wal"),
        std::filesystem::path(db_path_ + "-shm"),
    };
    for (const auto& p : disk_paths) {
        const std::string raw_disk = read_raw_bytes(p);
        for (const auto& canary : all_canaries) {
            EXPECT_EQ(raw_disk.find(canary), std::string::npos) << "Canary leaked on disk in " << p << ": " << canary;
        }
    }
}

TEST_F(LocalAuditLogTest, SecurityManagersEmitChainedAuditEventsAndPanicWipeDestroysTrail) {
    ClientConfig cfg;
    cfg.database_path = db_path_;
    cfg.gateway_url = "https://127.0.0.1:8443";

    auto bootstrap = std::make_unique<ClientBootstrap>(cfg);
    const domain::UserId alice("usr-alice-audit");
    const domain::UserId bob("usr-bob-audit");

    // 1. DeviceManager: register + SPK rotation
    auto dev_res = bootstrap->device_manager().register_device(alice, "Workstation");
    ASSERT_TRUE(dev_res.is_ok());
    const domain::DeviceId local_dev_id = dev_res.value().device_id();
    ASSERT_TRUE(bootstrap->device_manager().rotate_signed_prekey().is_ok());

    // 2. RatchetSessionManager: decryption failure audit
    bootstrap->initialize_ratchet_session_manager(alice, local_dev_id);
    ASSERT_NE(bootstrap->ratchet_session_manager(), nullptr);
    domain::crypto::EncryptedMessageEnvelope invalid_env;
    const auto dec_fail =
        bootstrap->ratchet_session_manager()->decrypt_from_device(bob, domain::DeviceId("dev-bob-1"), invalid_env);
    EXPECT_TRUE(dec_fail.is_error());

    // 3. SafetyNumberEngine: verify peer + detect key change
    const std::vector<uint8_t> bob_key_1(32U, 0x11U);
    const std::vector<uint8_t> bob_key_2(32U, 0x22U);
    ASSERT_TRUE(bootstrap->safety_number_engine().set_verification_state(bob, bob_key_1, true).is_ok());
    const auto key_eval = bootstrap->safety_number_engine().evaluate_key_verification_status(bob, bob_key_2);
    ASSERT_TRUE(key_eval.is_ok());
    EXPECT_EQ(key_eval.value(), domain::KeyVerificationStatus::KeyChanged);

    // 4. DevicePairingCoordinator: pairing approval attempt
    PairingVerificationPrompt prompt;
    prompt.user_id = alice;
    prompt.device_id = domain::DeviceId("dev-companion-audit");
    prompt.pairing_code = "123456";
    prompt.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5);
    (void)bootstrap->device_pairing_coordinator().approve_companion_pairing(prompt, "mfa-totp-123456");

    // 5. SettingsManager: recovery challenge reject + verify + TLS SPKI pin
    auto gen_res = bootstrap->settings_manager().generate_recovery_phrase();
    ASSERT_TRUE(gen_res.is_ok());
    const auto& challenge = gen_res.value().challenge;
    ASSERT_FALSE(challenge.word_indices.empty());

    std::vector<std::pair<std::size_t, std::string>> bad_answers;
    bad_answers.emplace_back(challenge.word_indices.front(), "notavalidcanaryword");
    EXPECT_TRUE(
        bootstrap->settings_manager().confirm_recovery_phrase_backup(gen_res.value().mnemonic, bad_answers).is_error());

    std::vector<std::string> words;
    {
        std::istringstream iss(gen_res.value().mnemonic.expose_unredacted_secret());
        std::string w;
        while (iss >> w) {
            words.push_back(w);
        }
    }
    std::vector<std::pair<std::size_t, std::string>> good_answers;
    for (const std::size_t idx : challenge.word_indices) {
        ASSERT_LT(idx, words.size());
        good_answers.emplace_back(idx, words[idx]);
    }
    ASSERT_TRUE(
        bootstrap->settings_manager().confirm_recovery_phrase_backup(gen_res.value().mnemonic, good_answers).is_ok());
    ASSERT_TRUE(bootstrap->settings_manager().inspect_and_optionally_pin_gateway_tls("127.0.0.1", 8443U, true).is_ok());

    // 6. EmergencyManager: duress PIN configuration
    ASSERT_TRUE(bootstrap->emergency_manager().configure_duress_pin(SecretString("246810")).is_ok());

    ASSERT_NE(bootstrap->local_audit_logger(), nullptr);
    const auto verify = bootstrap->local_audit_logger()->verify_chain_integrity();
    ASSERT_TRUE(verify.is_ok());
    EXPECT_TRUE(verify.value().valid);
    EXPECT_GE(verify.value().verified_count, 9U);

    const auto recent = bootstrap->local_audit_logger()->recent_events(50U);
    ASSERT_TRUE(recent.is_ok());
    std::set<std::string> recorded_types;
    for (const auto& ev : recent.value()) {
        recorded_types.insert(ev.event_type);
    }
    EXPECT_TRUE(recorded_types.contains("device.registered"));
    EXPECT_TRUE(recorded_types.contains("prekey.signed_rotated"));
    EXPECT_TRUE(recorded_types.contains("ratchet.decrypt_failed"));
    EXPECT_TRUE(recorded_types.contains("peer.identity_verified"));
    EXPECT_TRUE(recorded_types.contains("peer.identity_key_changed"));
    EXPECT_TRUE(recorded_types.contains("device.pairing_approved"));
    EXPECT_TRUE(recorded_types.contains("recovery.phrase_verified"));
    EXPECT_TRUE(recorded_types.contains("network.tls_pin_saved"));
    EXPECT_TRUE(recorded_types.contains("emergency.duress_pin_configured"));

    // 7. Panic wipe must forensically shred SQLCipher local_audit_log and clear cached logger state.
    const auto wipe_res = bootstrap->emergency_manager().execute_panic_wipe(domain::PanicTriggerSource::UiPanicButton);
    ASSERT_TRUE(wipe_res.is_ok());
    EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
    EXPECT_FALSE(std::filesystem::exists(db_path_));

    // Recording onto closed/shredded store must fail gracefully without crashing.
    const auto closed_write = bootstrap->local_audit_logger()->record_event(
        LocalAuditCategory::Authentication, "session.post_wipe", LocalAuditOutcome::Failure, "", "", "Post-wipe");
    EXPECT_TRUE(closed_write.is_error());

    // Reopening a brand-new vault starts cleanly at sequence_id == 1 linked to kGenesisAuditHash.
    bootstrap.reset();
    MemorySecureStorage fresh_storage;
    OpenSslCryptoProvider fresh_crypto;
    SqlCipherLocalStore fresh_store(fresh_storage, fresh_crypto);
    ASSERT_TRUE(fresh_store.open(db_path_).is_ok());
    LocalAuditLogger fresh_logger(fresh_store);
    const auto fresh_ev = fresh_logger.record_event(LocalAuditCategory::Authentication, "vault.reinitialized",
                                                    LocalAuditOutcome::Success, "usr-alice", "", "Fresh vault created");
    ASSERT_TRUE(fresh_ev.is_ok());
    EXPECT_EQ(fresh_ev.value().sequence_id, 1);
    EXPECT_EQ(fresh_ev.value().prev_hash_sha256, domain::kGenesisAuditHash);
    const auto fresh_verify = fresh_logger.verify_chain_integrity();
    ASSERT_TRUE(fresh_verify.is_ok());
    EXPECT_TRUE(fresh_verify.value().valid);
    EXPECT_EQ(fresh_verify.value().verified_count, 1U);
    ASSERT_TRUE(fresh_store.close().is_ok());
}

} // namespace
} // namespace securecloud::client::application::managers::test
