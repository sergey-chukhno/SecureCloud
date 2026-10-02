#include "auth/service/auth_service_impl.hpp"

#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

namespace securecloud::auth::service::test {

class AuthServiceTest : public ::testing::Test {
  protected:
    AuthServiceImpl service_;
    grpc::ServerContext context_;
};

// Validates that all 12 Auth RPC methods return StatusCode::UNIMPLEMENTED
TEST_F(AuthServiceTest, AllTwelveRpcsReturnUnimplemented) {
    // 1. Authenticate
    {
        v1::AuthenticateRequest req;
        v1::AuthenticateResponse resp;
        auto status = service_.Authenticate(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 2. RefreshSession
    {
        v1::RefreshSessionRequest req;
        v1::RefreshSessionResponse resp;
        auto status = service_.RefreshSession(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 3. ValidateSession
    {
        v1::ValidateSessionRequest req;
        v1::ValidateSessionResponse resp;
        auto status = service_.ValidateSession(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 4. RevokeSession
    {
        v1::RevokeSessionRequest req;
        v1::RevokeSessionResponse resp;
        auto status = service_.RevokeSession(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 5. GetUser
    {
        v1::GetUserRequest req;
        v1::GetUserResponse resp;
        auto status = service_.GetUser(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 6. GetDevice
    {
        v1::GetDeviceRequest req;
        v1::GetDeviceResponse resp;
        auto status = service_.GetDevice(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 7. ListUserDevices
    {
        v1::ListUserDevicesRequest req;
        v1::ListUserDevicesResponse resp;
        auto status = service_.ListUserDevices(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 8. RegisterDevice
    {
        v1::RegisterDeviceRequest req;
        v1::RegisterDeviceResponse resp;
        auto status = service_.RegisterDevice(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 9. RevokeDevice
    {
        v1::RevokeDeviceRequest req;
        v1::RevokeDeviceResponse resp;
        auto status = service_.RevokeDevice(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 10. GetDeviceCryptoDirectory
    {
        v1::GetDeviceCryptoDirectoryRequest req;
        v1::GetDeviceCryptoDirectoryResponse resp;
        auto status = service_.GetDeviceCryptoDirectory(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 11. GetCryptoIdentity
    {
        v1::GetCryptoIdentityRequest req;
        v1::GetCryptoIdentityResponse resp;
        auto status = service_.GetCryptoIdentity(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
    // 12. UpdateCryptoPrekeys
    {
        v1::UpdateCryptoPrekeysRequest req;
        v1::UpdateCryptoPrekeysResponse resp;
        auto status = service_.UpdateCryptoPrekeys(&context_, &req, &resp);
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNIMPLEMENTED);
    }
}

} // namespace securecloud::auth::service::test
