#include "security/anti_recursion_guard.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <thread>

namespace securecloud::audit::security::testing {

class AntiRecursionGuardTest : public ::testing::Test {
  protected:
    void SetUp() override {
        reset_recursion_prevented_count();
    }
};

TEST_F(AntiRecursionGuardTest, ReentrancyBlockedOnSameThread) {
    EXPECT_FALSE(AntiRecursionGuard::is_recording_in_progress());

    {
        AntiRecursionGuard guard1;
        EXPECT_TRUE(guard1.acquired());
        EXPECT_TRUE(AntiRecursionGuard::is_recording_in_progress());

        {
            AntiRecursionGuard guard2;
            EXPECT_FALSE(guard2.acquired());
            EXPECT_TRUE(AntiRecursionGuard::is_recording_in_progress());
            EXPECT_EQ(get_recursion_prevented_count(), 1);
        }

        EXPECT_TRUE(AntiRecursionGuard::is_recording_in_progress());
    }

    EXPECT_FALSE(AntiRecursionGuard::is_recording_in_progress());
}

TEST_F(AntiRecursionGuardTest, IndependentAcquisitionAcrossThreads) {
    AntiRecursionGuard main_guard;
    EXPECT_TRUE(main_guard.acquired());

    std::thread worker([&]() {
        EXPECT_FALSE(AntiRecursionGuard::is_recording_in_progress());
        AntiRecursionGuard worker_guard;
        EXPECT_TRUE(worker_guard.acquired());
        EXPECT_TRUE(AntiRecursionGuard::is_recording_in_progress());
    });

    worker.join();
    EXPECT_EQ(get_recursion_prevented_count(), 0);
}

TEST_F(AntiRecursionGuardTest, RaiiReleaseOnException) {
    EXPECT_FALSE(AntiRecursionGuard::is_recording_in_progress());

    try {
        AntiRecursionGuard guard;
        EXPECT_TRUE(guard.acquired());
        EXPECT_TRUE(AntiRecursionGuard::is_recording_in_progress());
        throw std::runtime_error("Simulated processing error");
    } catch (const std::exception&) {
        // Exception caught
    }

    EXPECT_FALSE(AntiRecursionGuard::is_recording_in_progress());
}

TEST_F(AntiRecursionGuardTest, ShouldRecordInternalEventFilter) {
    domain::AuditEvent valid_event{};
    valid_event.producer_service = domain::ProducerService::Audit;
    valid_event.event_type = "audit.security.auth.unauthenticated_connection";

    EXPECT_TRUE(should_record_internal_event(valid_event));

    domain::AuditEvent invalid_event{};
    invalid_event.producer_service = domain::ProducerService::Audit;
    invalid_event.event_type = "";

    EXPECT_FALSE(should_record_internal_event(invalid_event));
}

} // namespace securecloud::audit::security::testing