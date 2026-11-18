#include "domain/contact.hpp"
#include "domain/directory_user_entry.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <vector>

using namespace securecloud::client;
using namespace securecloud::client::domain;
using namespace securecloud::client::infrastructure::adapters;

TEST(ContactDomainTest, DefaultInitializationAndGetters) {
    const UserId user_id("usr-alice-01");
    Contact contact(user_id, "Alice");

    EXPECT_EQ(contact.user_id(), user_id);
    EXPECT_EQ(contact.alias(), "Alice");
    EXPECT_EQ(contact.verification_status(), KeyVerificationStatus::Unverified);
    EXPECT_FALSE(contact.is_verified());
    EXPECT_FALSE(contact.has_key_changed());
    EXPECT_FALSE(contact.is_blocked());
    EXPECT_TRUE(contact.can_send_messages());
    EXPECT_EQ(contact.presence_status(), PresenceStatus::Offline);
    EXPECT_EQ(contact.authorized_device_count(), 1u);
    EXPECT_FALSE(contact.last_seen_at().has_value());
}

TEST(ContactDomainTest, VerificationStateAndMessagingSuspensionPredicates) {
    const UserId user_id("usr-bob-02");
    Contact contact(user_id, "Bob");

    // 1. Unverified (Baseline non-blocking per ADR-008 §18.1)
    contact.set_verification_status(KeyVerificationStatus::Unverified);
    EXPECT_FALSE(contact.is_verified());
    EXPECT_FALSE(contact.has_key_changed());
    EXPECT_TRUE(contact.can_send_messages());

    // 2. Verified
    contact.set_verification_status(KeyVerificationStatus::Verified);
    EXPECT_TRUE(contact.is_verified());
    EXPECT_FALSE(contact.has_key_changed());
    EXPECT_TRUE(contact.can_send_messages());

    // 3. KeyChanged (Suspended per ADR-008 §18)
    contact.set_verification_status(KeyVerificationStatus::KeyChanged);
    EXPECT_FALSE(contact.is_verified());
    EXPECT_TRUE(contact.has_key_changed());
    EXPECT_FALSE(contact.can_send_messages());

    // 4. Blocked (Suspended per ADR-008 §24)
    contact.set_verification_status(KeyVerificationStatus::Verified);
    contact.set_blocked(true);
    EXPECT_TRUE(contact.is_blocked());
    EXPECT_FALSE(contact.can_send_messages());

    // 5. Unblock restored
    contact.set_blocked(false);
    EXPECT_TRUE(contact.can_send_messages());
}

TEST(ContactDomainTest, LastSeenAtAndPresence) {
    Contact contact(UserId("usr-charlie-03"), "Charlie");

    const auto now = std::chrono::system_clock::now();
    contact.set_last_seen_at(now);
    ASSERT_TRUE(contact.last_seen_at().has_value());
    EXPECT_EQ(contact.last_seen_at().value(), now);

    contact.set_presence_status(PresenceStatus::Online);
    EXPECT_EQ(contact.presence_status(), PresenceStatus::Online);
    EXPECT_EQ(to_string(contact.presence_status()), "Online");

    contact.set_presence_status(PresenceStatus::Away);
    EXPECT_EQ(contact.presence_status(), PresenceStatus::Away);
    EXPECT_EQ(to_string(contact.presence_status()), "Away");

    contact.set_presence_status(PresenceStatus::Offline);
    EXPECT_EQ(contact.presence_status(), PresenceStatus::Offline);
    EXPECT_EQ(to_string(contact.presence_status()), "Offline");
}

TEST(ContactDomainTest, JsonSerializationRoundTrip) {
    const UserId user_id("usr-dan-04");
    const auto now = std::chrono::system_clock::now();
    const auto last_seen = now - std::chrono::hours(2);

    Contact original(user_id, "Dan", KeyVerificationStatus::Verified, "ABC123FINGERPRINT", false,
                     "12345 67890 11223 44556", "Security Lead", PresenceStatus::Online, 3, now, last_seen);

    const std::string json_str = original.to_json();
    EXPECT_FALSE(json_str.empty());

    const auto parsed = Contact::from_json(json_str);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->user_id(), original.user_id());
    EXPECT_EQ(parsed->alias(), original.alias());
    EXPECT_EQ(parsed->verification_status(), original.verification_status());
    EXPECT_EQ(parsed->identity_fingerprint(), original.identity_fingerprint());
    EXPECT_EQ(parsed->is_blocked(), original.is_blocked());
    EXPECT_EQ(parsed->safety_number(), original.safety_number());
    EXPECT_EQ(parsed->role_note(), original.role_note());
    EXPECT_EQ(parsed->presence_status(), original.presence_status());
    EXPECT_EQ(parsed->authorized_device_count(), original.authorized_device_count());
    ASSERT_TRUE(parsed->last_seen_at().has_value());

    // Verify millisecond-level timestamp precision
    const auto orig_ms = std::chrono::duration_cast<std::chrono::milliseconds>(last_seen.time_since_epoch()).count();
    const auto parsed_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(parsed->last_seen_at()->time_since_epoch()).count();
    EXPECT_EQ(parsed_ms, orig_ms);
}

TEST(ContactDomainTest, JsonDeserializationInvalidInputs) {
    EXPECT_FALSE(Contact::from_json("invalid json").has_value());
    EXPECT_FALSE(Contact::from_json("{}").has_value());
    EXPECT_FALSE(Contact::from_json(R"({"user_id": 12345})").has_value());
}

TEST(DirectoryUserEntryTest, ConstructionAndEquality) {
    const UserId user_id("usr-frances-05");
    const std::vector<uint8_t> pubkey(32, 0x42);
    const auto now = std::chrono::system_clock::now();

    DirectoryUserEntry entry1(user_id, "@frances.swann", "Frances Swann", pubkey, "FINGERPRINT_HEX", 2, now);
    DirectoryUserEntry entry2(user_id, "@frances.swann", "Frances Swann", pubkey, "FINGERPRINT_HEX", 2, now);

    EXPECT_EQ(entry1.user_id(), user_id);
    EXPECT_EQ(entry1.handle(), "@frances.swann");
    EXPECT_EQ(entry1.display_name(), "Frances Swann");
    EXPECT_EQ(entry1.identity_public_key(), pubkey);
    EXPECT_EQ(entry1.identity_fingerprint(), "FINGERPRINT_HEX");
    EXPECT_EQ(entry1.active_device_count(), 2u);
    EXPECT_EQ(entry1, entry2);

    entry2.set_display_name("Frances S.");
    EXPECT_NE(entry1, entry2);
}

TEST(GatewayDirectoryDiscoveryTest, SearchDirectoryUsers) {
    application::ClientConfig config;
    DefaultGatewayClient client(config);

    const std::vector<uint8_t> key_a(32, 0xAA);
    const std::vector<uint8_t> key_b(32, 0xBB);
    const std::vector<uint8_t> key_c(32, 0xCC);

    std::vector<DirectoryUserEntry> directory{
        DirectoryUserEntry(UserId("usr-alice"), "@alice.smith", "Alice Smith", key_a, "FP_ALICE", 1),
        DirectoryUserEntry(UserId("usr-bob"), "@bob.jones", "Bob Jones", key_b, "FP_BOB", 2),
        DirectoryUserEntry(UserId("usr-carol"), "@carol.danvers", "Carol Danvers", key_c, "FP_CAROL", 1),
    };
    client.set_simulated_directory_users(directory);

    // 1. Search all (empty query)
    auto all_res = client.search_directory_users("", 10);
    ASSERT_TRUE(all_res.is_ok());
    EXPECT_EQ(all_res.value().size(), 3u);

    // 2. Search by handle case-insensitive
    auto handle_res = client.search_directory_users("ALICE", 10);
    ASSERT_TRUE(handle_res.is_ok());
    ASSERT_EQ(handle_res.value().size(), 1u);
    EXPECT_EQ(handle_res.value()[0].handle(), "@alice.smith");

    // 3. Search by display name substring
    auto name_res = client.search_directory_users("jones", 10);
    ASSERT_TRUE(name_res.is_ok());
    ASSERT_EQ(name_res.value().size(), 1u);
    EXPECT_EQ(name_res.value()[0].display_name(), "Bob Jones");

    // 4. Limit clamping
    auto limit_res = client.search_directory_users("", 2);
    ASSERT_TRUE(limit_res.is_ok());
    EXPECT_EQ(limit_res.value().size(), 2u);

    // 5. No match
    auto none_res = client.search_directory_users("nonexistent", 10);
    ASSERT_TRUE(none_res.is_ok());
    EXPECT_TRUE(none_res.value().empty());

    // 6. Network failure simulation
    client.set_simulated_failure(true, "Gateway timeout");
    auto fail_res = client.search_directory_users("alice", 10);
    ASSERT_FALSE(fail_res.is_ok());
    EXPECT_EQ(fail_res.error().category(), application::ClientErrorCategory::Network);
}

TEST(GatewayDirectoryDiscoveryTest, LookupUserIdentity) {
    application::ClientConfig config;
    DefaultGatewayClient client(config);

    const std::vector<uint8_t> key_a(32, 0x11);
    const DirectoryUserEntry alice(UserId("usr-alice-99"), "@alice", "Alice", key_a, "FP_99", 1);
    client.set_simulated_directory_users({alice});

    // 1. Successful lookup
    auto found_res = client.lookup_user_identity(UserId("usr-alice-99"));
    ASSERT_TRUE(found_res.is_ok());
    EXPECT_EQ(found_res.value().handle(), "@alice");

    // 2. Unknown user lookup
    auto not_found_res = client.lookup_user_identity(UserId("usr-unknown"));
    ASSERT_FALSE(not_found_res.is_ok());
    EXPECT_EQ(not_found_res.error().code(), application::ClientErrorCode::ValidationFailed);

    // 3. Empty user ID validation error
    auto empty_res = client.lookup_user_identity(UserId{});
    ASSERT_FALSE(empty_res.is_ok());
    EXPECT_EQ(empty_res.error().category(), application::ClientErrorCategory::Validation);

    // 4. Simulated failure
    client.set_simulated_failure(true, "Network partition");
    auto fail_res = client.lookup_user_identity(UserId("usr-alice-99"));
    ASSERT_FALSE(fail_res.is_ok());
    EXPECT_EQ(fail_res.error().category(), application::ClientErrorCategory::Network);
}
