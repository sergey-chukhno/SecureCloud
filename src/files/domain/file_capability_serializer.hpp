#pragma once

#include "auth/crypto/token_crypto.hpp"
#include "files/domain/file_capability_entity.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace securecloud::files {

/**
 * @brief Wire format serializer and cryptographic validator for File Access Capability tokens.
 *
 * Wire format follows RFC 7515 Base64URL compact token:
 *   <base64url(header)> . <base64url(payload)> . <base64url(signature)>
 *
 * Header carries algorithm identifier ("Ed25519") and token type ("sc-file-cap/v1").
 * Payload carries compact JSON claims bound to user_id, device_id, file_id, and operation.
 * Signature is computed over "<base64url(header)>.<base64url(payload)>" using Ed25519.
 */
class FileCapabilitySerializer {
  public:
    /**
     * @brief Serializes and cryptographically signs a capability claim set.
     * @param claims Claim set defining authorization parameters.
     * @param signer Asymmetric Ed25519 token signer.
     * @return Compact wire format token string.
     */
    [[nodiscard]] static std::string serialize(const FileAccessCapabilityClaims& claims,
                                               const auth::crypto::ITokenSigner& signer);

    /**
     * @brief Parses and cryptographically verifies a capability token string.
     * @param token Compact wire format token string.
     * @param verifier Asymmetric Ed25519 token verifier.
     * @param error_out Optional diagnostic error string if parsing/verification fails.
     * @return Deserialized claims on success, std::nullopt on signature mismatch or malformed token.
     */
    [[nodiscard]] static std::optional<FileAccessCapabilityClaims>
    deserialize_and_verify(std::string_view token, const auth::crypto::ITokenVerifier& verifier,
                           std::string* error_out = nullptr);
};

} // namespace securecloud::files
