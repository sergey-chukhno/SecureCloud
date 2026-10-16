#include "client/auth_crypto_directory_client.hpp"

namespace securecloud::messaging::client {

namespace {

DeviceCryptoRecord map_proto_to_domain(const securecloud::auth::v1::DeviceCryptoRecord& p) {
    DeviceCryptoRecord r;
    r.device_id = domain::DeviceId(p.device_id());
    r.identity_key.assign(p.identity_key().begin(), p.identity_key().end());
    r.signed_prekey.assign(p.signed_prekey().begin(), p.signed_prekey().end());
    r.signed_prekey_signature.assign(p.signed_prekey_signature().begin(), p.signed_prekey_signature().end());
    r.one_time_prekey.assign(p.one_time_prekey().begin(), p.one_time_prekey().end());
    r.one_time_prekey_id = p.one_time_prekey_id();
    r.status = p.status();
    r.identity_key_fingerprint = p.identity_key_fingerprint();
    r.signed_prekey_created_at_epoch_ms = p.signed_prekey_created_at_epoch_ms();
    r.remaining_one_time_prekeys = p.remaining_one_time_prekeys();
    return r;
}

DeviceCryptoRecord map_identity_to_domain(const securecloud::auth::v1::GetCryptoIdentityResponse& p) {
    DeviceCryptoRecord r;
    r.device_id = domain::DeviceId(p.device_id());
    r.user_id = domain::UserId(p.user_id());
    r.identity_key.assign(p.identity_key().begin(), p.identity_key().end());
    r.signed_prekey.assign(p.signed_prekey().begin(), p.signed_prekey().end());
    r.signed_prekey_signature.assign(p.signed_prekey_signature().begin(), p.signed_prekey_signature().end());
    r.status = p.status();
    r.identity_key_fingerprint = p.identity_key_fingerprint();
    r.signed_prekey_created_at_epoch_ms = p.signed_prekey_created_at_epoch_ms();
    return r;
}

CryptoDirectoryError null_stub_error() {
    return CryptoDirectoryError{
        .kind = CryptoDirectoryErrorKind::ServiceUnavailable,
        .message = "Auth service client stub is uninitialized",
        .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
    };
}

} // namespace

AuthCryptoDirectoryClient::AuthCryptoDirectoryClient(
    std::shared_ptr<securecloud::auth::v1::AuthService::StubInterface> stub)
    : stub_(std::move(stub)) {}

AuthCryptoDirectoryClient::AuthCryptoDirectoryClient(const std::shared_ptr<::grpc::Channel>& channel)
    : stub_(channel ? securecloud::auth::v1::AuthService::NewStub(channel) : nullptr) {}

Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
AuthCryptoDirectoryClient::get_user_device_crypto_records(const domain::UserId& user_id,
                                                          std::chrono::milliseconds timeout) {
    if (!stub_) {
        return null_stub_error();
    }

    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + timeout);

    securecloud::auth::v1::GetDeviceCryptoDirectoryRequest req;
    req.set_user_id(user_id.str());

    securecloud::auth::v1::GetDeviceCryptoDirectoryResponse resp;
    auto status = stub_->GetDeviceCryptoDirectory(&context, req, &resp);
    if (!status.ok()) {
        return CryptoDirectoryError::from_grpc_status(status);
    }

    std::vector<DeviceCryptoRecord> records;
    records.reserve(static_cast<size_t>(resp.devices_size()));
    for (const auto& dev : resp.devices()) {
        auto rec = map_proto_to_domain(dev);
        rec.user_id = user_id;
        records.push_back(std::move(rec));
    }

    return records;
}

Result<DeviceCryptoRecord, CryptoDirectoryError>
AuthCryptoDirectoryClient::get_device_crypto_identity(const domain::DeviceId& device_id,
                                                      std::chrono::milliseconds timeout) {
    if (!stub_) {
        return null_stub_error();
    }

    ::grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + timeout);

    securecloud::auth::v1::GetCryptoIdentityRequest req;
    req.set_device_id(device_id.str());

    securecloud::auth::v1::GetCryptoIdentityResponse resp;
    auto status = stub_->GetCryptoIdentity(&context, req, &resp);
    if (!status.ok()) {
        return CryptoDirectoryError::from_grpc_status(status);
    }

    return map_identity_to_domain(resp);
}

} // namespace securecloud::messaging::client
