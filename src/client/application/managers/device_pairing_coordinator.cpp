#include "application/managers/device_pairing_coordinator.hpp"

#include "infrastructure/adapters/key_storage_helper.hpp"

#include <chrono>
#include <random>
#include <sstream>

namespace securecloud::client::application::managers {

namespace {

std::string generate_companion_id() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(100000, 999999);
    return "dev-node-" + std::to_string(dis(gen));
}

} // namespace

DevicePairingCoordinator::DevicePairingCoordinator(interfaces::IGatewayClient& gateway,
                                                   interfaces::ISecureStorage& secure_storage,
                                                   interfaces::ICryptoProvider& crypto_provider,
                                                   DeviceManager& device_manager)
    : gateway_(gateway), secure_storage_(secure_storage), crypto_provider_(crypto_provider),
      device_manager_(device_manager) {}

ClientResult<CompanionPairingSession>
DevicePairingCoordinator::initiate_companion_pairing(const domain::UserId& user_id, std::string_view display_name) {
    if (user_id.empty()) {
        return ClientResult<CompanionPairingSession>::error(
            ClientError::validation("User ID cannot be empty to initiate companion pairing"));
    }
    if (display_name.empty()) {
        return ClientResult<CompanionPairingSession>::error(
            ClientError::validation("Companion display name cannot be empty"));
    }

    // 1. Generate local device identity keypair (Ed25519)
    auto id_res = crypto_provider_.generate_identity_keypair();
    if (id_res.is_error()) {
        return ClientResult<CompanionPairingSession>::error(id_res.error());
    }

    // 2. Generate ephemeral DH keypair (Curve25519) for the pairing handshake
    auto dh_res = crypto_provider_.generate_dh_keypair();
    if (dh_res.is_error()) {
        return ClientResult<CompanionPairingSession>::error(dh_res.error());
    }

    // 3. Generate companion device ID
    domain::DeviceId comp_id(generate_companion_id());

    // 4. Store companion private key material securely
    std::string key_id = "companion_pending_key:" + std::string(comp_id.str());
    auto store_res = secure_storage_.store_secret(key_id, id_res.value().private_key);
    if (store_res.is_error()) {
        return ClientResult<CompanionPairingSession>::error(store_res.error());
    }

    // 5. Call Gateway to initiate pairing and receive pairing token
    auto gate_res = gateway_.initiate_device_pairing(comp_id);
    if (gate_res.is_error()) {
        secure_storage_.delete_secret(key_id);
        return ClientResult<CompanionPairingSession>::error(gate_res.error());
    }
    const auto& init_val = gate_res.value();

    std::string dname = display_name.empty() ? "Companion Device" : std::string(display_name);

    // 6. Construct PairingChallengePayload
    domain::PairingChallengePayload payload(user_id, comp_id, dh_res.value().public_key, init_val.pairing_code,
                                            init_val.expires_at, dname);

    std::string qr_uri = payload.to_uri();

    // 7. Compute expected SAS from companion perspective
    auto sas = domain::ShortAuthenticationString::from_handshake_material(
        id_res.value().public_key, dh_res.value().public_key, init_val.pairing_code);

    CompanionPairingSession session{user_id,           comp_id, std::move(dname), std::move(payload), std::move(sas),
                                    std::move(qr_uri), false};

    return ClientResult<CompanionPairingSession>::ok(std::move(session));
}

ClientResult<bool> DevicePairingCoordinator::poll_companion_authorization(CompanionPairingSession& session) {
    if (session.device_id.empty() || session.user_id.empty()) {
        return ClientResult<bool>::error(ClientError::validation("Invalid session parameters for authorization poll"));
    }

    auto list_res = gateway_.list_user_devices(session.user_id);
    if (list_res.is_error()) {
        return ClientResult<bool>::error(list_res.error());
    }

    for (const auto& dev : list_res.value()) {
        if (dev.device_id() == session.device_id) {
            if (dev.status() == domain::DeviceAuthorizationStatus::Authorized) {
                session.is_authorized = true;
                std::string key_id = "companion_pending_key:" + std::string(session.device_id.str());
                secure_storage_.delete_secret(key_id);
                return ClientResult<bool>::ok(true);
            }
        }
    }

    return ClientResult<bool>::ok(false);
}

ClientResult<PairingVerificationPrompt>
DevicePairingCoordinator::inspect_pairing_challenge(std::string_view uri_or_payload) {
    // 1. Parse URI into PairingChallengePayload
    auto parse_res = domain::PairingChallengePayload::from_uri(uri_or_payload);
    if (parse_res.is_error()) {
        return ClientResult<PairingVerificationPrompt>::error(parse_res.error());
    }
    const auto& challenge = parse_res.value();

    // 2. Check expiration
    if (challenge.is_expired()) {
        return ClientResult<PairingVerificationPrompt>::error(ClientError::validation("Pairing challenge has expired"));
    }

    // 3. Obtain primary local device identity
    auto dev_res = device_manager_.get_local_device();
    if (dev_res.is_error()) {
        return ClientResult<PairingVerificationPrompt>::error(dev_res.error());
    }
    const auto& local_dev = dev_res.value();

    // 4. Assert user ID matches
    if (local_dev.user_id() != challenge.user_id()) {
        return ClientResult<PairingVerificationPrompt>::error(ClientError::validation(
            "Pairing challenge user mismatch: belongs to user " + std::string(challenge.user_id().str()) +
            ", expected " + std::string(local_dev.user_id().str())));
    }

    // 5. Compute matching SAS using primary device identity key and companion ephemeral key
    auto primary_pk = local_dev.crypto_identity().identity_key_bytes();
    auto sas = domain::ShortAuthenticationString::from_handshake_material(primary_pk, challenge.ephemeral_public_key(),
                                                                          challenge.pairing_code());

    PairingVerificationPrompt prompt{challenge.user_id(),
                                     challenge.device_id(),
                                     challenge.display_name(),
                                     challenge.pairing_code(),
                                     std::move(sas),
                                     challenge.expires_at(),
                                     challenge};

    return ClientResult<PairingVerificationPrompt>::ok(std::move(prompt));
}

ClientResult<void> DevicePairingCoordinator::approve_companion_pairing(const PairingVerificationPrompt& prompt,
                                                                       std::string_view mfa_token) {
    if (prompt.is_expired()) {
        return ClientResult<void>::error(ClientError::validation("Pairing verification prompt has expired"));
    }
    if (prompt.device_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Companion device ID cannot be empty"));
    }
    if (prompt.pairing_code.empty()) {
        return ClientResult<void>::error(ClientError::validation("Pairing code cannot be empty"));
    }

    // Submit authorization to Gateway with MFA token
    return gateway_.authorize_device_pairing(prompt.device_id, prompt.pairing_code, mfa_token);
}

} // namespace securecloud::client::application::managers
