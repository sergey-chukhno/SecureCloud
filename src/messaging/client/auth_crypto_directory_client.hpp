#pragma once

#include "client/auth_crypto_directory_client_interface.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::messaging::client {

class AuthCryptoDirectoryClient : public IAuthCryptoDirectoryClient {
  public:
    explicit AuthCryptoDirectoryClient(std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub);
    explicit AuthCryptoDirectoryClient(const std::shared_ptr<::grpc::Channel>& channel);

    ~AuthCryptoDirectoryClient() override = default;

    Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const domain::UserId& user_id,
                                   std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) override;

    Result<DeviceCryptoRecord, CryptoDirectoryError>
    get_device_crypto_identity(const domain::DeviceId& device_id,
                               std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) override;

  private:
    std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub_;
};

} // namespace securecloud::messaging::client
