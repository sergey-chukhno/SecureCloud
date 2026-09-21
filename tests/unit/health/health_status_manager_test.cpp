#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::common::health {
namespace {

constexpr int k_reader_threads = 4;
constexpr int k_iterations = 1000;
constexpr int k_live_stride = 2;
constexpr int k_ready_stride = 3;
constexpr int k_shutdown_stride = 5;

class TestAuthPropertyIterator : public grpc::AuthPropertyIterator {
  public:
    TestAuthPropertyIterator() = default;
};

class TestAuthContext : public grpc::AuthContext {
  public:
    explicit TestAuthContext(bool is_authenticated) : is_authenticated_(is_authenticated) {}

    [[nodiscard]] bool IsPeerAuthenticated() const override { return is_authenticated_; }

    [[nodiscard]] std::string GetPeerIdentityPropertyName() const override { return "x509_subject_alternative_name"; }

    [[nodiscard]] std::vector<grpc::string_ref> GetPeerIdentity() const override { return {}; }

    [[nodiscard]] std::vector<grpc::string_ref> FindPropertyValues(const std::string& /*name*/) const override {
        return {};
    }

    [[nodiscard]] grpc::AuthPropertyIterator begin() const override { return TestAuthPropertyIterator{}; }

    [[nodiscard]] grpc::AuthPropertyIterator end() const override { return TestAuthPropertyIterator{}; }

    void AddProperty(const std::string& /*name*/, const grpc::string_ref& /*value*/) override {}
    bool SetPeerIdentityPropertyName(const std::string& /*name*/) override { return false; }

  private:
    bool is_authenticated_;
};

TEST(HealthStatusManagerTest, ServiceNameInitialization) {
    HealthStatusManager manager("auth");
    EXPECT_EQ(manager.service_name(), "auth");

    HealthServiceImpl service("auth", manager);
    EXPECT_EQ(service.service_name(), "auth");
}

TEST(HealthStatusManagerTest, InitialStateIsNeitherLiveNorReady) {
    HealthStatusManager manager("gateway");
    EXPECT_FALSE(manager.is_live());
    EXPECT_FALSE(manager.is_ready());
    EXPECT_FALSE(manager.is_shutting_down());
    EXPECT_FALSE(manager.evaluate_readiness());
}

TEST(HealthStatusManagerTest, SetLiveAndReadyTransitions) {
    HealthStatusManager manager("messaging");

    manager.set_live(true);
    EXPECT_TRUE(manager.is_live());
    EXPECT_FALSE(manager.is_ready());
    EXPECT_FALSE(manager.evaluate_readiness());

    manager.set_ready(true);
    EXPECT_TRUE(manager.is_live());
    EXPECT_TRUE(manager.is_ready());
    EXPECT_TRUE(manager.evaluate_readiness());
}

TEST(HealthStatusManagerTest, ShutdownImmediateDegradation) {
    HealthStatusManager manager("files");
    manager.set_live(true);
    manager.set_ready(true);
    EXPECT_TRUE(manager.evaluate_readiness());

    manager.set_shutting_down(true);
    EXPECT_TRUE(manager.is_shutting_down());
    EXPECT_TRUE(manager.is_live());
    EXPECT_FALSE(manager.evaluate_readiness());
}

TEST(HealthStatusManagerTest, ReadinessEvaluatorSuccessAndFailure) {
    HealthStatusManager manager("audit");
    manager.set_live(true);
    manager.set_ready(true);

    bool dependency_up = true;
    manager.set_readiness_evaluator([&dependency_up] { return dependency_up; });

    EXPECT_TRUE(manager.evaluate_readiness());

    dependency_up = false;
    EXPECT_FALSE(manager.evaluate_readiness());
}

TEST(HealthStatusManagerTest, ReadinessEvaluatorExceptionSafety) {
    HealthStatusManager manager("audit");
    manager.set_live(true);
    manager.set_ready(true);

    manager.set_readiness_evaluator([]() -> bool { throw std::runtime_error("Simulated socket error"); });

    EXPECT_FALSE(manager.evaluate_readiness());
}

TEST(HealthStatusManagerTest, ConcurrencyThreadSafety) {
    HealthStatusManager manager("concurrent_svc");
    std::atomic<bool> stop_flag{false};

    auto reader = [&] {
        while (!stop_flag.load()) {
            (void)manager.is_live();
            (void)manager.is_ready();
            (void)manager.is_shutting_down();
            (void)manager.evaluate_readiness();
        }
    };

    std::vector<std::thread> readers;
    readers.reserve(static_cast<size_t>(k_reader_threads));
    for (int i = 0; i < k_reader_threads; ++i) {
        readers.emplace_back(reader);
    }

    for (int i = 0; i < k_iterations; ++i) {
        manager.set_live(i % k_live_stride == 0);
        manager.set_ready(i % k_ready_stride == 0);
        manager.set_shutting_down(i % k_shutdown_stride == 0);
    }

    stop_flag.store(true);
    for (auto& t : readers) {
        t.join();
    }
}

TEST(HealthServiceImplTest, RejectsUnauthenticatedCallers) {
    HealthStatusManager manager("auth");
    manager.set_live(true);
    manager.set_ready(true);
    HealthServiceImpl service("auth", manager);

    securecloud::common::v1::HealthCheckRequest req;
    securecloud::common::v1::HealthCheckResponse resp;

    // 1. Null context
    auto status = service.Check(static_cast<const grpc::AuthContext*>(nullptr), &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    // 2. Unauthenticated TestAuthContext
    TestAuthContext unauth_ctx(false);
    status = service.Check(&unauth_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);

    // 3. Default ServerContext (unauthenticated)
    grpc::ServerContext server_ctx;
    status = service.Check(&server_ctx, &req, &resp);
    EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAUTHENTICATED);
}

TEST(HealthServiceImplTest, RejectsNullArguments) {
    HealthStatusManager manager("gateway");
    HealthServiceImpl service("gateway", manager);
    TestAuthContext auth_ctx(true);

    securecloud::common::v1::HealthCheckRequest req;
    securecloud::common::v1::HealthCheckResponse resp;

    EXPECT_EQ(service.Check(&auth_ctx, nullptr, &resp).error_code(), grpc::StatusCode::INVALID_ARGUMENT);
    EXPECT_EQ(service.Check(&auth_ctx, &req, nullptr).error_code(), grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(HealthServiceImplTest, LivenessConventions) {
    HealthStatusManager manager("auth");
    HealthServiceImpl service("auth", manager);
    TestAuthContext auth_ctx(true);

    securecloud::common::v1::HealthCheckRequest req_empty;
    securecloud::common::v1::HealthCheckRequest req_auth;
    req_auth.set_service("auth");
    securecloud::common::v1::HealthCheckResponse resp;

    // Not live initially
    EXPECT_TRUE(service.Check(&auth_ctx, &req_empty, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::NOT_SERVING);

    EXPECT_TRUE(service.Check(&auth_ctx, &req_auth, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::NOT_SERVING);

    // Become live
    manager.set_live(true);

    EXPECT_TRUE(service.Check(&auth_ctx, &req_empty, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::SERVING);

    EXPECT_TRUE(service.Check(&auth_ctx, &req_auth, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::SERVING);
}

TEST(HealthServiceImplTest, ReadinessConventionsAndDependencyDegradation) {
    HealthStatusManager manager("files");
    HealthServiceImpl service("files", manager);
    TestAuthContext auth_ctx(true);

    securecloud::common::v1::HealthCheckRequest req_liveness;
    securecloud::common::v1::HealthCheckRequest req_readiness;
    req_readiness.set_service("readiness");
    securecloud::common::v1::HealthCheckResponse resp;

    // 1. Uninitialized
    EXPECT_TRUE(service.Check(&auth_ctx, &req_readiness, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::NOT_SERVING);

    // 2. Initialized with healthy dependency
    manager.set_live(true);
    manager.set_ready(true);
    bool dependency_healthy = true;
    manager.set_readiness_evaluator([&dependency_healthy] { return dependency_healthy; });

    EXPECT_TRUE(service.Check(&auth_ctx, &req_readiness, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::SERVING);

    // 3. Dependency outage: readiness fails, but liveness stays SERVING
    dependency_healthy = false;

    EXPECT_TRUE(service.Check(&auth_ctx, &req_readiness, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::NOT_SERVING);

    EXPECT_TRUE(service.Check(&auth_ctx, &req_liveness, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::SERVING);

    // 4. Shutdown initiated: readiness immediately NOT_SERVING
    dependency_healthy = true;
    manager.set_shutting_down(true);

    EXPECT_TRUE(service.Check(&auth_ctx, &req_readiness, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::NOT_SERVING);
}

TEST(HealthServiceImplTest, UnrecognizedServiceReturnsServiceUnknown) {
    HealthStatusManager manager("messaging");
    manager.set_live(true);
    manager.set_ready(true);
    HealthServiceImpl service("messaging", manager);
    TestAuthContext auth_ctx(true);

    securecloud::common::v1::HealthCheckRequest req;
    req.set_service("unknown_component_xyz");
    securecloud::common::v1::HealthCheckResponse resp;

    EXPECT_TRUE(service.Check(&auth_ctx, &req, &resp).ok());
    EXPECT_EQ(resp.status(), securecloud::common::v1::HealthCheckResponse::SERVICE_UNKNOWN);
}

} // namespace
} // namespace securecloud::common::health
