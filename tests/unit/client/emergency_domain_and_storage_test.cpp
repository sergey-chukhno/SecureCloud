#include "domain/emergency_models.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;
using securecloud::common::configuration::SecretString;

class EmergencyDomainAndStorageTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_emergency_domain_test_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(EmergencyDomainAndStorageTest, EnumStringRoundTripsAndInvalidValues) {
    EXPECT_EQ(to_string(PanicTriggerSource::Hotkey), "Hotkey");
    EXPECT_EQ(to_string(PanicTriggerSource::UiPanicButton), "UiPanicButton");
    EXPECT_EQ(to_string(PanicTriggerSource::DuressPin), "DuressPin");
    EXPECT_EQ(to_string(PanicTriggerSource::Programmatic), "Programmatic");

    EXPECT_EQ(panic_trigger_source_from_string("Hotkey"), PanicTriggerSource::Hotkey);
    EXPECT_EQ(panic_trigger_source_from_string("UiPanicButton"), PanicTriggerSource::UiPanicButton);
    EXPECT_EQ(panic_trigger_source_from_string("DuressPin"), PanicTriggerSource::DuressPin);
    EXPECT_EQ(panic_trigger_source_from_string("Programmatic"), PanicTriggerSource::Programmatic);
    EXPECT_FALSE(panic_trigger_source_from_string("UnknownTrigger").has_value());

    EXPECT_EQ(to_string(PostWipeMode::EmergencyLocked), "EmergencyLocked");
    EXPECT_EQ(to_string(PostWipeMode::UnconfiguredReset), "UnconfiguredReset");
    EXPECT_EQ(to_string(PostWipeMode::DecoyWorkspace), "DecoyWorkspace");

    EXPECT_EQ(post_wipe_mode_from_string("EmergencyLocked"), PostWipeMode::EmergencyLocked);
    EXPECT_EQ(post_wipe_mode_from_string("UnconfiguredReset"), PostWipeMode::UnconfiguredReset);
    EXPECT_EQ(post_wipe_mode_from_string("DecoyWorkspace"), PostWipeMode::DecoyWorkspace);
    EXPECT_FALSE(post_wipe_mode_from_string("InvalidMode").has_value());

    EXPECT_EQ(to_string(WipeStepStatus::Succeeded), "Succeeded");
    EXPECT_EQ(to_string(WipeStepStatus::Skipped), "Skipped");
    EXPECT_EQ(to_string(WipeStepStatus::Failed), "Failed");

    EXPECT_EQ(wipe_step_status_from_string("Succeeded"), WipeStepStatus::Succeeded);
    EXPECT_EQ(wipe_step_status_from_string("Skipped"), WipeStepStatus::Skipped);
    EXPECT_EQ(wipe_step_status_from_string("Failed"), WipeStepStatus::Failed);
    EXPECT_FALSE(wipe_step_status_from_string("Pending").has_value());
}

TEST_F(EmergencyDomainAndStorageTest, DuressPinConfigValidationAndJsonRoundTrip) {
    DuressPinConfig disabled_cfg;
    EXPECT_FALSE(disabled_cfg.enabled);
    EXPECT_TRUE(disabled_cfg.is_valid());

    const auto disabled_parsed = DuressPinConfig::from_json(disabled_cfg.to_json());
    ASSERT_TRUE(disabled_parsed.has_value());
    EXPECT_EQ(*disabled_parsed, disabled_cfg);

    DuressPinConfig valid_cfg;
    valid_cfg.enabled = true;
    valid_cfg.post_wipe_mode = PostWipeMode::DecoyWorkspace;
    valid_cfg.pbkdf2_iterations = DuressPinConfig::kMinPbkdf2Iterations;
    valid_cfg.salt_hex = "00112233445566778899aabbccddeeff";
    valid_cfg.derived_hash_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    valid_cfg.configured_at_ms = 1763890000000LL;
    EXPECT_TRUE(valid_cfg.is_valid());

    const auto parsed = DuressPinConfig::from_json(valid_cfg.to_json());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, valid_cfg);

    // Reject weak PBKDF2 iterations.
    DuressPinConfig weak_iter = valid_cfg;
    weak_iter.pbkdf2_iterations = 50000U;
    EXPECT_FALSE(weak_iter.is_valid());
    EXPECT_FALSE(DuressPinConfig::from_json(weak_iter.to_json()).has_value());

    // Reject too-short salt or non-hex salt.
    DuressPinConfig short_salt = valid_cfg;
    short_salt.salt_hex = "00112233";
    EXPECT_FALSE(short_salt.is_valid());

    DuressPinConfig bad_hex_salt = valid_cfg;
    bad_hex_salt.salt_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    EXPECT_FALSE(bad_hex_salt.is_valid());

    // Reject wrong-length or non-hex derived hash.
    DuressPinConfig bad_hash = valid_cfg;
    bad_hash.derived_hash_hex = "0123456789abcdef";
    EXPECT_FALSE(bad_hash.is_valid());

    DuressPinConfig non_hex_hash = valid_cfg;
    non_hex_hash.derived_hash_hex = "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    EXPECT_FALSE(non_hex_hash.is_valid());

    EXPECT_FALSE(DuressPinConfig::from_json("{invalid json").has_value());
}

TEST_F(EmergencyDomainAndStorageTest, EmergencyBroadcastRequestValidation) {
    EmergencyBroadcastRequest req;
    req.conversation_id = ConversationId("conv-ops-001");
    req.sender_user_id = UserId("alice");
    req.sender_device_id = DeviceId("dev-alice-1");
    req.alert_plaintext = "Duress activated on workstation 04";
    req.encrypted_location_json = R"({"lat":46.948,"lon":7.447,"accuracy_m":12})";
    req.wait_for_acknowledgement = true;
    req.ack_timeout = std::chrono::milliseconds(1500);
    EXPECT_TRUE(req.is_valid());

    EmergencyBroadcastRequest no_location = req;
    no_location.encrypted_location_json.reset();
    EXPECT_TRUE(no_location.is_valid());

    EmergencyBroadcastRequest missing_conv = req;
    missing_conv.conversation_id = ConversationId{};
    EXPECT_FALSE(missing_conv.is_valid());

    EmergencyBroadcastRequest missing_text = req;
    missing_text.alert_plaintext.clear();
    EXPECT_FALSE(missing_text.is_valid());

    EmergencyBroadcastRequest zero_timeout = req;
    zero_timeout.ack_timeout = std::chrono::milliseconds(0);
    EXPECT_FALSE(zero_timeout.is_valid());

    EmergencyBroadcastRequest huge_timeout = req;
    huge_timeout.ack_timeout = std::chrono::milliseconds(30000);
    EXPECT_FALSE(huge_timeout.is_valid());
}

TEST_F(EmergencyDomainAndStorageTest, EmergencyWipeReportSafeSummarySerialization) {
    EmergencyWipeReport report;
    report.trigger_source = PanicTriggerSource::Hotkey;
    report.post_wipe_mode = PostWipeMode::EmergencyLocked;
    report.broadcast_attempted = true;
    report.broadcast_acknowledged = true;
    report.secrets_purged_count = 11;
    report.files_shredded_count = 4;
    report.volatile_caches_cleared = 5;
    report.duration_ms = 42;
    report.all_critical_steps_succeeded = true;
    report.step_results = {
        WipeArtifactResult{"volatile_managers", 5, WipeStepStatus::Succeeded, "Cleared ratchets and retry queues"},
        WipeArtifactResult{"secure_storage", 11, WipeStepStatus::Succeeded, "Purged all endpoint secret keys"},
        WipeArtifactResult{"local_database", 4, WipeStepStatus::Succeeded,
                           "Shredded SQLCipher vault and WAL artifacts"},
    };

    const std::string summary_json = report.to_safe_summary_json();
    const auto parsed = nlohmann::json::parse(summary_json);
    EXPECT_EQ(parsed.at("trigger_source"), "Hotkey");
    EXPECT_EQ(parsed.at("post_wipe_mode"), "EmergencyLocked");
    EXPECT_TRUE(parsed.at("broadcast_attempted").get<bool>());
    EXPECT_TRUE(parsed.at("broadcast_acknowledged").get<bool>());
    EXPECT_EQ(parsed.at("secrets_purged_count").get<std::size_t>(), 11U);
    EXPECT_EQ(parsed.at("files_shredded_count").get<std::size_t>(), 4U);
    EXPECT_EQ(parsed.at("volatile_caches_cleared").get<std::size_t>(), 5U);
    EXPECT_EQ(parsed.at("duration_ms").get<int64_t>(), 42);
    EXPECT_TRUE(parsed.at("all_critical_steps_succeeded").get<bool>());
    ASSERT_EQ(parsed.at("step_results").size(), 3U);
    EXPECT_EQ(parsed.at("step_results")[1].at("status"), "Succeeded");
}

TEST_F(EmergencyDomainAndStorageTest, MemorySecureStorageListKeysAndPurgeAllSecretsAcrossAllNamespaces) {
    MemorySecureStorage storage;

    const std::vector<std::string> all_namespaces = {
        "session_auth_token",
        "local_device_id",
        "device_private_bundle:dev-01",
        "local_store.sqlcipher.master_key",
        "ratchet_session:bob:dev-02",
        "ratchet_session_index",
        "sender_key:conv-grp-1:alice:dev-01",
        "file_transfer.key.file-99",
        "safety_number:bob",
        "privacy.read_receipts_enabled",
        std::string(DuressPinConfig::kStorageKey),
    };

    for (const auto& key : all_namespaces) {
        ASSERT_TRUE(storage.store_secret(key, SecretString("secret-material-for-" + key)).is_ok());
    }

    const auto listed = storage.list_secret_keys();
    ASSERT_TRUE(listed.is_ok());
    ASSERT_EQ(listed.value().size(), all_namespaces.size());

    // list_secret_keys() guarantees deterministic ascending order.
    EXPECT_TRUE(std::is_sorted(listed.value().begin(), listed.value().end()));

    const auto purge_res = storage.purge_all_secrets();
    ASSERT_TRUE(purge_res.is_ok());
    EXPECT_EQ(purge_res.value(), all_namespaces.size());

    const auto after_purge = storage.list_secret_keys();
    ASSERT_TRUE(after_purge.is_ok());
    EXPECT_TRUE(after_purge.value().empty());

    for (const auto& key : all_namespaces) {
        const auto has_res = storage.has_secret(key);
        ASSERT_TRUE(has_res.is_ok());
        EXPECT_FALSE(has_res.value()) << "Key leaked after purge: " << key;
    }

    // Second purge is idempotent and reports 0 keys removed.
    const auto second_purge = storage.purge_all_secrets();
    ASSERT_TRUE(second_purge.is_ok());
    EXPECT_EQ(second_purge.value(), 0U);
}

TEST_F(EmergencyDomainAndStorageTest, LocalStoreDatabasePathLifecycle) {
    MemorySecureStorage secure_storage;
    OpenSslCryptoProvider crypto;
    SqlCipherLocalStore sql_store(secure_storage, crypto);

    EXPECT_TRUE(sql_store.database_path().empty());
    ASSERT_TRUE(sql_store.open(db_path_).is_ok());
    EXPECT_EQ(sql_store.database_path(), db_path_);
    ASSERT_TRUE(sql_store.close().is_ok());
    EXPECT_TRUE(sql_store.database_path().empty());

    MemoryLocalStore mem_store;
    EXPECT_TRUE(mem_store.database_path().empty());
    ASSERT_TRUE(mem_store.open(db_path_).is_ok());
    EXPECT_TRUE(mem_store.database_path().empty());
    ASSERT_TRUE(mem_store.close().is_ok());
    EXPECT_TRUE(mem_store.database_path().empty());
}

} // namespace
} // namespace securecloud::client::tests
