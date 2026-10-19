#include "domain/entities.hpp"
#include "domain/enums.hpp"
#include "domain/session_result.hpp"
#include "domain/timestamp.hpp"
#include "domain/uuid.hpp"

#include <chrono>
#include <gtest/gtest.h>

namespace securecloud::auth::domain::test {
namespace {

domain::SessionEntity create_sample_session() {
    domain::SessionEntity session;
    session.session_id = domain::Uuid::generate_v7();
    session.user_id = domain::Uuid::generate_v7();
    session.device_id = domain::Uuid::generate_v7();
    session.authentication_level = domain::AuthenticationLevel::PrimaryOnly;
    session.session_status = domain::SessionStatus::Active;
    session.created_at = std::chrono::system_clock::now();
    session.last_used_at = session.created_at;
    session.expires_at = session.created_at + std::chrono::hours(24);
    session.revoked_at = std::nullopt;
    return session;
}

// Test 1: Active to Revoked transition is allowed
TEST(SessionLifecycleTest, StateTransition_ActiveToRevoked_Allowed) {
    EXPECT_TRUE(can_transition(domain::SessionStatus::Active, domain::SessionStatus::Revoked));
}

// Test 2: Active to Expired transition is allowed
TEST(SessionLifecycleTest, StateTransition_ActiveToExpired_Allowed) {
    EXPECT_TRUE(can_transition(domain::SessionStatus::Active, domain::SessionStatus::Expired));
}

// Test 3: Terminal states cannot reactivate back to Active
TEST(SessionLifecycleTest, StateTransition_TerminalStatesCannotReactivate) {
    EXPECT_FALSE(can_transition(domain::SessionStatus::Revoked, domain::SessionStatus::Active));
    EXPECT_FALSE(can_transition(domain::SessionStatus::Expired, domain::SessionStatus::Active));
}

// Test 4: Terminal states cannot cross-transition between each other
TEST(SessionLifecycleTest, StateTransition_TerminalStatesCannotCrossTransition) {
    EXPECT_FALSE(can_transition(domain::SessionStatus::Revoked, domain::SessionStatus::Expired));
    EXPECT_FALSE(can_transition(domain::SessionStatus::Expired, domain::SessionStatus::Revoked));
}

// Test 5: Self-transitions are idempotent and allowed
TEST(SessionLifecycleTest, StateTransition_SelfTransitionsAllowed) {
    EXPECT_TRUE(can_transition(domain::SessionStatus::Active, domain::SessionStatus::Active));
    EXPECT_TRUE(can_transition(domain::SessionStatus::Revoked, domain::SessionStatus::Revoked));
    EXPECT_TRUE(can_transition(domain::SessionStatus::Expired, domain::SessionStatus::Expired));
}

// Test 6: IsTerminal accurately identifies terminal vs non-terminal states
TEST(SessionLifecycleTest, IsTerminal_AccuratelyIdentifiesTerminalStates) {
    EXPECT_FALSE(is_terminal(domain::SessionStatus::Active));
    EXPECT_TRUE(is_terminal(domain::SessionStatus::Revoked));
    EXPECT_TRUE(is_terminal(domain::SessionStatus::Expired));
}

// Test 7: SessionValidationResult valid factory preserves entity and reports valid
TEST(SessionLifecycleTest, SessionValidationResult_Valid_HasSessionAndSuccessStatus) {
    auto sample = create_sample_session();
    auto result = domain::SessionValidationResult::valid(sample);

    EXPECT_EQ(result.status, domain::SessionValidationStatus::Valid);
    EXPECT_TRUE(result.is_valid());
    ASSERT_TRUE(result.session.has_value());
    EXPECT_EQ(result.session->session_id, sample.session_id);
    EXPECT_EQ(result.session->user_id, sample.user_id);
    EXPECT_EQ(result.session->device_id, sample.device_id);
    EXPECT_FALSE(result.diagnostic_message.empty());
}

// Test 8: SessionValidationResult failure factories have nullopt session and is_valid == false
TEST(SessionLifecycleTest, SessionValidationResult_FailureFactories_DoNotContainSession) {
    auto r_not_found = domain::SessionValidationResult::not_found("Custom not found");
    EXPECT_EQ(r_not_found.status, domain::SessionValidationStatus::NotFound);
    EXPECT_FALSE(r_not_found.is_valid());
    EXPECT_FALSE(r_not_found.session.has_value());
    EXPECT_EQ(r_not_found.diagnostic_message, "Custom not found");

    auto r_revoked = domain::SessionValidationResult::revoked();
    EXPECT_EQ(r_revoked.status, domain::SessionValidationStatus::Revoked);
    EXPECT_FALSE(r_revoked.is_valid());
    EXPECT_FALSE(r_revoked.session.has_value());

    auto r_expired = domain::SessionValidationResult::expired();
    EXPECT_EQ(r_expired.status, domain::SessionValidationStatus::Expired);
    EXPECT_FALSE(r_expired.is_valid());
    EXPECT_FALSE(r_expired.session.has_value());

    auto r_dev_mismatch = domain::SessionValidationResult::device_mismatch("Mismatch");
    EXPECT_EQ(r_dev_mismatch.status, domain::SessionValidationStatus::DeviceMismatch);
    EXPECT_FALSE(r_dev_mismatch.is_valid());
    EXPECT_FALSE(r_dev_mismatch.session.has_value());

    auto r_dev_revoked = domain::SessionValidationResult::device_revoked();
    EXPECT_EQ(r_dev_revoked.status, domain::SessionValidationStatus::DeviceRevoked);
    EXPECT_FALSE(r_dev_revoked.is_valid());
    EXPECT_FALSE(r_dev_revoked.session.has_value());

    auto r_err = domain::SessionValidationResult::internal_error("DB fail");
    EXPECT_EQ(r_err.status, domain::SessionValidationStatus::InternalError);
    EXPECT_FALSE(r_err.is_valid());
    EXPECT_FALSE(r_err.session.has_value());
    EXPECT_EQ(r_err.diagnostic_message, "DB fail");
}

// Test 9: SessionRevocationResult factories and revocation counts
TEST(SessionLifecycleTest, SessionRevocationResult_FactoriesAndCount) {
    auto r_success = domain::SessionRevocationResult::success(3);
    EXPECT_EQ(r_success.status, domain::SessionRevocationStatus::Success);
    EXPECT_TRUE(r_success.is_success());
    EXPECT_EQ(r_success.revoked_count, 3);
    EXPECT_FALSE(r_success.diagnostic_message.empty());

    auto r_not_found = domain::SessionRevocationResult::not_found();
    EXPECT_EQ(r_not_found.status, domain::SessionRevocationStatus::NotFound);
    EXPECT_FALSE(r_not_found.is_success());
    EXPECT_EQ(r_not_found.revoked_count, 0);

    auto r_already = domain::SessionRevocationResult::already_revoked();
    EXPECT_EQ(r_already.status, domain::SessionRevocationStatus::AlreadyRevoked);
    EXPECT_FALSE(r_already.is_success());
    EXPECT_EQ(r_already.revoked_count, 0);

    auto r_err = domain::SessionRevocationResult::internal_error("Network down");
    EXPECT_EQ(r_err.status, domain::SessionRevocationStatus::InternalError);
    EXPECT_FALSE(r_err.is_success());
    EXPECT_EQ(r_err.revoked_count, 0);
    EXPECT_EQ(r_err.diagnostic_message, "Network down");
}

// Test 10: to_string produces valid, expected string representations for both enums
TEST(SessionLifecycleTest, ToString_ProducesCleanStringRepresentations) {
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::Valid), "Valid");
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::NotFound), "NotFound");
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::Revoked), "Revoked");
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::Expired), "Expired");
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::DeviceMismatch), "DeviceMismatch");
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::DeviceRevoked), "DeviceRevoked");
    EXPECT_EQ(domain::to_string(domain::SessionValidationStatus::InternalError), "InternalError");

    EXPECT_EQ(domain::to_string(domain::SessionRevocationStatus::Success), "Success");
    EXPECT_EQ(domain::to_string(domain::SessionRevocationStatus::NotFound), "NotFound");
    EXPECT_EQ(domain::to_string(domain::SessionRevocationStatus::AlreadyRevoked), "AlreadyRevoked");
    EXPECT_EQ(domain::to_string(domain::SessionRevocationStatus::InternalError), "InternalError");
}

} // namespace
} // namespace securecloud::auth::domain::test
