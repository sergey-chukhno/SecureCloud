#include "grpc/auth_service_client.hpp"
#include "grpc/client_call_context.hpp"

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <string>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace securecloud::gateway::grpc {
namespace {

class FakeAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    ::grpc::StatusCode return_code{::grpc::StatusCode::OK};
    std::string return_message{"Success"};

    ::grpc::Status Authenticate(::grpc::ServerContext* /*context*/,
                                const securecloud::auth::v1::AuthenticateRequest* request,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_session_id("mock-session-id");
        response->set_access_token("mock-access-token");
        response->set_refresh_token("mock-refresh-token");
        response->set_user_id("user-uuid-1234");
        (void)request;
        return ::grpc::Status::OK;
    }

    ::grpc::Status ValidateSession(::grpc::ServerContext* /*context*/,
                                   const securecloud::auth::v1::ValidateSessionRequest* /*request*/,
                                   securecloud::auth::v1::ValidateSessionResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_is_valid(true);
        response->set_user_id("user-uuid-1234");
        response->set_device_id("device-uuid-5678");
        return ::grpc::Status::OK;
    }

    ::grpc::Status RefreshSession(::grpc::ServerContext* /*context*/,
                                  const securecloud::auth::v1::RefreshSessionRequest* /*request*/,
                                  securecloud::auth::v1::RefreshSessionResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_session_id("mock-session-id");
        response->set_access_token("refreshed-access-token");
        response->set_new_refresh_token("new-refresh-token");
        return ::grpc::Status::OK;
    }

    ::grpc::Status RevokeSession(::grpc::ServerContext* /*context*/,
                                 const securecloud::auth::v1::RevokeSessionRequest* /*request*/,
                                 securecloud::auth::v1::RevokeSessionResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_revoked(true);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetUser(::grpc::ServerContext* /*context*/, const securecloud::auth::v1::GetUserRequest* request,
                           securecloud::auth::v1::GetUserResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->mutable_user()->set_user_id(request->user_id());
        return ::grpc::Status::OK;
    }

    ::grpc::Status RegisterDevice(::grpc::ServerContext* /*context*/,
                                  const securecloud::auth::v1::RegisterDeviceRequest* /*request*/,
                                  securecloud::auth::v1::RegisterDeviceResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_device_id("dev-registered-001");
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetCryptoIdentity(::grpc::ServerContext* /*context*/,
                                     const securecloud::auth::v1::GetCryptoIdentityRequest* request,
                                     securecloud::auth::v1::GetCryptoIdentityResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        response->set_device_id(request->device_id());
        return ::grpc::Status::OK;
    }

    ::grpc::Status
    GetDeviceCryptoDirectory(::grpc::ServerContext* /*context*/,
                             const securecloud::auth::v1::GetDeviceCryptoDirectoryRequest* /*request*/,
                             securecloud::auth::v1::GetDeviceCryptoDirectoryResponse* response) override {
        if (return_code != ::grpc::StatusCode::OK) {
            return ::grpc::Status(return_code, return_message);
        }
        auto* dev = response->add_devices();
        dev->set_device_id("dev-directory-001");
        return ::grpc::Status::OK;
    }
};

class AuthServiceClientTest : public ::testing::Test {
  protected:
    void SetUp() override {
        service_impl_ = std::make_unique<FakeAuthService>();

        ::grpc::ServerBuilder builder;
        builder.RegisterService(service_impl_.get());
        server_ = builder.BuildAndStart();
        ASSERT_NE(server_, nullptr);

        channel_ = server_->InProcessChannel(::grpc::ChannelArguments());
        ASSERT_NE(channel_, nullptr);

        stub_ = securecloud::auth::v1::AuthService::NewStub(channel_);
        ASSERT_NE(stub_, nullptr);

        client_ = std::make_unique<AuthServiceClient>(stub_);
    }

    void TearDown() override {
        if (server_) {
            server_->Shutdown();
            server_->Wait();
        }
    }

    std::unique_ptr<FakeAuthService> service_impl_;
    std::unique_ptr<::grpc::Server> server_;
    std::shared_ptr<::grpc::Channel> channel_;
    std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub_;
    std::unique_ptr<AuthServiceClient> client_;
};

TEST_F(AuthServiceClientTest, AuthenticateSuccess) {
    securecloud::auth::v1::AuthenticateRequest req;
    req.set_credential_identifier("user@example.com");
    req.set_password("secret-password");
    req.set_device_id("dev-uuid-1");

    ClientCallContext ctx;
    auto res = client_->authenticate(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_FALSE(res.has_error());
    EXPECT_EQ(res.value().session_id(), "mock-session-id");
    EXPECT_EQ(res.value().access_token(), "mock-access-token");
    EXPECT_EQ(res.value().refresh_token(), "mock-refresh-token");
    EXPECT_EQ(res.value().user_id(), "user-uuid-1234");
}

TEST_F(AuthServiceClientTest, ValidateSessionSuccess) {
    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_session_id("mock-session-id");
    req.set_access_token("mock-access-token");

    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res.value().is_valid());
    EXPECT_EQ(res.value().user_id(), "user-uuid-1234");
    EXPECT_EQ(res.value().device_id(), "device-uuid-5678");
}

TEST_F(AuthServiceClientTest, RefreshSessionSuccess) {
    securecloud::auth::v1::RefreshSessionRequest req;
    req.set_refresh_token("valid-refresh-token");
    req.set_device_id("dev-uuid-1");

    ClientCallContext ctx;
    auto res = client_->refresh_session(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().session_id(), "mock-session-id");
    EXPECT_EQ(res.value().access_token(), "refreshed-access-token");
    EXPECT_EQ(res.value().new_refresh_token(), "new-refresh-token");
}

TEST_F(AuthServiceClientTest, RevokeSessionSuccess) {
    securecloud::auth::v1::RevokeSessionRequest req;
    req.set_session_id("revoke-me");
    req.set_reason("user logout");

    ClientCallContext ctx;
    auto res = client_->revoke_session(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res.value().revoked());
}

TEST_F(AuthServiceClientTest, GetUserSuccess) {
    securecloud::auth::v1::GetUserRequest req;
    req.set_user_id("uuid-alice");

    ClientCallContext ctx;
    auto res = client_->get_user(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().user().user_id(), "uuid-alice");
}

TEST_F(AuthServiceClientTest, RegisterDeviceSuccess) {
    securecloud::auth::v1::RegisterDeviceRequest req;
    req.set_user_id("uuid-bob");

    ClientCallContext ctx;
    auto res = client_->register_device(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().device_id(), "dev-registered-001");
}

TEST_F(AuthServiceClientTest, GetCryptoIdentitySuccess) {
    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id("device-target");

    ClientCallContext ctx;
    auto res = client_->get_crypto_identity(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().device_id(), "device-target");
}

TEST_F(AuthServiceClientTest, GetDeviceCryptoDirectorySuccess) {
    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id("target-user");

    ClientCallContext ctx;
    auto res = client_->get_device_crypto_directory(req, ctx);

    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(res.value().devices_size(), 1);
    EXPECT_EQ(res.value().devices(0).device_id(), "dev-directory-001");
}

TEST_F(AuthServiceClientTest, TranslatesDeadlineExceeded) {
    service_impl_->return_code = ::grpc::StatusCode::DEADLINE_EXCEEDED;
    service_impl_->return_message = "Call timed out";

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::Timeout);
    EXPECT_EQ(res.error().grpc_code, ::grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST_F(AuthServiceClientTest, TranslatesUnavailable) {
    service_impl_->return_code = ::grpc::StatusCode::UNAVAILABLE;
    service_impl_->return_message = "Service pod offline";

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::ServiceUnavailable);
    EXPECT_EQ(res.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
}

TEST_F(AuthServiceClientTest, TranslatesUnauthenticated) {
    service_impl_->return_code = ::grpc::StatusCode::UNAUTHENTICATED;
    service_impl_->return_message = "Session signature invalid";

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::Unauthenticated);
}

TEST_F(AuthServiceClientTest, TranslatesPermissionDenied) {
    service_impl_->return_code = ::grpc::StatusCode::PERMISSION_DENIED;
    service_impl_->return_message = "Role insufficient";

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::PermissionDenied);
}

TEST_F(AuthServiceClientTest, TranslatesInvalidArgument) {
    service_impl_->return_code = ::grpc::StatusCode::INVALID_ARGUMENT;
    service_impl_->return_message = "Invalid UUID format";

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::InvalidArgument);
}

TEST_F(AuthServiceClientTest, TranslatesNotFound) {
    service_impl_->return_code = ::grpc::StatusCode::NOT_FOUND;
    service_impl_->return_message = "User not found";

    securecloud::auth::v1::GetUserRequest req;
    ClientCallContext ctx;
    auto res = client_->get_user(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::NotFound);
}

TEST_F(AuthServiceClientTest, TranslatesInternal) {
    service_impl_->return_code = ::grpc::StatusCode::INTERNAL;
    service_impl_->return_message = "Database disk failure";

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = client_->validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::Internal);
}

TEST_F(AuthServiceClientTest, NullStubReturnsServiceUnavailableSafely) {
    AuthServiceClient null_client(std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface>{nullptr});

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = null_client.validate_session(req, ctx);

    ASSERT_TRUE(res.has_error());
    EXPECT_EQ(res.error().kind, DependencyErrorKind::ServiceUnavailable);
    EXPECT_EQ(res.error().grpc_code, ::grpc::StatusCode::UNAVAILABLE);
}

TEST_F(AuthServiceClientTest, ChannelConstructorInstantiatesCleanly) {
    AuthServiceClient channel_client(channel_);

    securecloud::auth::v1::ValidateSessionRequest req;
    ClientCallContext ctx;
    auto res = channel_client.validate_session(req, ctx);

    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res.value().is_valid());
}

} // namespace
} // namespace securecloud::gateway::grpc

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
