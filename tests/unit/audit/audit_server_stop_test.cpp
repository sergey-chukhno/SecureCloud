#include "audit_config.hpp"
#include "audit_server.hpp"

#include <gtest/gtest.h>
#include <thread>
#include <vector>

namespace securecloud::audit::testing {

class AuditServerStopTest : public ::testing::Test {
  protected:
    AuditConfig make_test_config() {
        AuditConfig config;
        config.common.service_name = "audit-test-service";
        config.common.service_display_name = "Audit Test Service";
        config.retention.shutdown_grace_period_ms = 500;
        return config;
    }
};

TEST_F(AuditServerStopTest, StopIsIdempotentAndThreadSafe) {
    AuditServer server(make_test_config());
    EXPECT_EQ(server.state(), ServiceState::Configured);

    // Call stop on configured server (CAS should prevent execution)
    server.stop();
    EXPECT_EQ(server.state(), ServiceState::Configured);

    // Concurrent calls to stop()
    constexpr int k_num_threads = 8;
    std::vector<std::thread> threads;
    threads.reserve(k_num_threads);

    for (int i = 0; i < k_num_threads; ++i) {
        threads.emplace_back([&server]() { server.stop(); });
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // No exception or crash should occur, state remains unchanged
    EXPECT_EQ(server.state(), ServiceState::Configured);
}

} // namespace securecloud::audit::testing
