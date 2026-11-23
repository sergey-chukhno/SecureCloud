#include "domain/crypto/sender_key_engine.hpp"

#include <array>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>

namespace securecloud::client::domain::crypto {

namespace {

constexpr std::size_t kChainKeyBytes = 32;
constexpr std::size_t kMessageKeyBytes = 32;
constexpr std::size_t kEd25519KeyBytes = 32;
constexpr std::size_t kEd25519SigBytes = 64;
constexpr std::size_t kAesGcmIvBytes = 12;

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* c) const noexcept { EVP_PKEY_CTX_free(c); }
};
struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* c) const noexcept { EVP_MD_CTX_free(c); }
};

using UniquePkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniquePkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using UniqueMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

std::vector<uint8_t> build_aad(const SenderKeyId& id, uint32_t iteration) {
    std::vector<uint8_t> aad;
    const auto append_str = [&aad](std::string_view s) {
        for (char ch : s) {
            aad.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch)));
        }
        aad.push_back(0x00);
    };
    append_str(id.conversation_id.value());
    append_str(id.sender_user_id.value());
    append_str(id.sender_device_id.value());
    for (int shift = 56; shift >= 0; shift -= 8) {
        aad.push_back(static_cast<uint8_t>((id.key_epoch >> static_cast<unsigned>(shift)) & 0xFFULL));
    }
    aad.push_back(static_cast<uint8_t>((iteration >> 24) & 0xFFu));
    aad.push_back(static_cast<uint8_t>((iteration >> 16) & 0xFFu));
    aad.push_back(static_cast<uint8_t>((iteration >> 8) & 0xFFu));
    aad.push_back(static_cast<uint8_t>(iteration & 0xFFu));
    return aad;
}

application::ClientResult<std::pair<common::configuration::SecretString, common::configuration::SecretString>>
step_chain_key(application::interfaces::ICryptoProvider& crypto,
               const common::configuration::SecretString& current_ck) {
    if (current_ck.size() != kChainKeyBytes) {
        return application::
            ClientResult<std::pair<common::configuration::SecretString, common::configuration::SecretString>>::error(
                application::ClientError::crypto("Invalid SenderKey chain_key length"));
    }

    std::vector<uint8_t> info;
    info.reserve(SenderKeyEngine::kChainStepInfo.size());
    for (char ch : SenderKeyEngine::kChainStepInfo) {
        info.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch)));
    }

    const auto derived_res = crypto.hkdf_extract_and_expand({}, current_ck, info, kChainKeyBytes + kMessageKeyBytes);
    if (derived_res.is_error()) {
        return application::ClientResult<std::pair<common::configuration::SecretString,
                                                   common::configuration::SecretString>>::error(derived_res.error());
    }

    const std::string& raw = derived_res.value().expose_unredacted_secret();
    if (raw.size() != kChainKeyBytes + kMessageKeyBytes) {
        return application::
            ClientResult<std::pair<common::configuration::SecretString, common::configuration::SecretString>>::error(
                application::ClientError::crypto("Unexpected HKDF output length in SenderKey step"));
    }

    common::configuration::SecretString next_ck(std::string_view(raw.data(), kChainKeyBytes));
    common::configuration::SecretString msg_key(std::string_view(raw.data() + kChainKeyBytes, kMessageKeyBytes));
    return application::ClientResult<
        std::pair<common::configuration::SecretString, common::configuration::SecretString>>::ok({std::move(next_ck),
                                                                                                  std::move(msg_key)});
}

application::ClientResult<std::vector<uint8_t>> sign_ed25519(const common::configuration::SecretString& private_key_raw,
                                                             std::span<const uint8_t> message) {
    if (private_key_raw.size() != kEd25519KeyBytes) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("Invalid Ed25519 private key length"));
    }

    const auto* key_bytes = reinterpret_cast<const uint8_t*>(private_key_raw.expose_unredacted_secret().data());
    UniquePkey pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, key_bytes, kEd25519KeyBytes));
    if (!pkey) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("EVP_PKEY_new_raw_private_key failed for Ed25519"));
    }

    UniqueMdCtx md_ctx(EVP_MD_CTX_new());
    if (!md_ctx || EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("EVP_DigestSignInit failed for Ed25519"));
    }

    std::size_t sig_len = kEd25519SigBytes;
    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSign(md_ctx.get(), sig.data(), &sig_len, message.data(), message.size()) <= 0 ||
        sig_len != kEd25519SigBytes) {
        return application::ClientResult<std::vector<uint8_t>>::error(
            application::ClientError::crypto("EVP_DigestSign failed for Ed25519"));
    }
    return application::ClientResult<std::vector<uint8_t>>::ok(std::move(sig));
}

bool verify_ed25519(std::span<const uint8_t> public_key_raw, std::span<const uint8_t> message,
                    std::span<const uint8_t> signature) {
    if (public_key_raw.size() != kEd25519KeyBytes || signature.size() != kEd25519SigBytes) {
        return false;
    }

    UniquePkey pkey(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key_raw.data(), public_key_raw.size()));
    if (!pkey) {
        return false;
    }

    UniqueMdCtx md_ctx(EVP_MD_CTX_new());
    if (!md_ctx || EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
        return false;
    }

    return EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

} // namespace

application::ClientResult<SenderKeyState> SenderKeyEngine::create_sender_key(const SenderKeyId& id) {
    if (id.conversation_id.empty() || id.sender_user_id.empty() || id.sender_device_id.empty() || id.key_epoch == 0) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::validation("Invalid SenderKeyId parameters"));
    }

    std::array<uint8_t, kChainKeyBytes> ck_raw{};
    if (RAND_bytes(ck_raw.data(), static_cast<int>(ck_raw.size())) != 1) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("RAND_bytes failed for SenderKey chain_key"));
    }

    UniquePkeyCtx pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
    EVP_PKEY* raw_pkey = nullptr;
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0 || EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0 || !raw_pkey) {
        OPENSSL_cleanse(ck_raw.data(), ck_raw.size());
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Ed25519 keygen failed for SenderKey"));
    }
    UniquePkey pkey(raw_pkey);

    std::vector<uint8_t> pub(kEd25519KeyBytes);
    std::size_t pub_len = pub.size();
    std::array<uint8_t, kEd25519KeyBytes> priv_raw{};
    std::size_t priv_len = priv_raw.size();

    if (EVP_PKEY_get_raw_public_key(pkey.get(), pub.data(), &pub_len) <= 0 || pub_len != kEd25519KeyBytes ||
        EVP_PKEY_get_raw_private_key(pkey.get(), priv_raw.data(), &priv_len) <= 0 || priv_len != kEd25519KeyBytes) {
        OPENSSL_cleanse(ck_raw.data(), ck_raw.size());
        OPENSSL_cleanse(priv_raw.data(), priv_raw.size());
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Failed to extract raw Ed25519 keys for SenderKey"));
    }

    SenderKeyState state;
    state.id = id;
    state.iteration = 0;
    state.chain_key = common::configuration::SecretString(
        std::string_view(reinterpret_cast<const char*>(ck_raw.data()), ck_raw.size()));
    state.signing_public_key = std::move(pub);
    state.signing_private_key = common::configuration::SecretString(
        std::string_view(reinterpret_cast<const char*>(priv_raw.data()), priv_raw.size()));

    OPENSSL_cleanse(ck_raw.data(), ck_raw.size());
    OPENSSL_cleanse(priv_raw.data(), priv_raw.size());
    return application::ClientResult<SenderKeyState>::ok(std::move(state));
}

application::ClientResult<SenderKeyDistributionMessage>
SenderKeyEngine::create_distribution_message(const SenderKeyState& state) {
    if (state.chain_key.size() != kChainKeyBytes || state.signing_public_key.size() != kEd25519KeyBytes) {
        return application::ClientResult<SenderKeyDistributionMessage>::error(
            application::ClientError::crypto("Cannot build SenderKeyDistributionMessage from invalid SenderKeyState"));
    }

    SenderKeyDistributionMessage dist;
    dist.id = state.id;
    dist.iteration = state.iteration;
    const auto* ck_ptr = reinterpret_cast<const uint8_t*>(state.chain_key.expose_unredacted_secret().data());
    dist.chain_key.assign(ck_ptr, ck_ptr + kChainKeyBytes);
    dist.signing_public_key = state.signing_public_key;
    return application::ClientResult<SenderKeyDistributionMessage>::ok(std::move(dist));
}

application::ClientResult<SenderKeyState>
SenderKeyEngine::process_distribution_message(const SenderKeyDistributionMessage& distribution) {
    if (distribution.id.conversation_id.empty() || distribution.id.sender_user_id.empty() ||
        distribution.id.sender_device_id.empty() || distribution.id.key_epoch == 0) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::validation("Invalid SenderKeyId in distribution message"));
    }
    if (distribution.chain_key.size() != kChainKeyBytes || distribution.signing_public_key.size() != kEd25519KeyBytes) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Invalid key lengths in SenderKeyDistributionMessage"));
    }

    SenderKeyState state;
    state.id = distribution.id;
    state.iteration = distribution.iteration;
    state.chain_key = common::configuration::SecretString(
        std::string_view(reinterpret_cast<const char*>(distribution.chain_key.data()), distribution.chain_key.size()));
    state.signing_public_key = distribution.signing_public_key;
    state.signing_private_key = std::nullopt;
    return application::ClientResult<SenderKeyState>::ok(std::move(state));
}

application::ClientResult<GroupEncryptedEnvelope>
SenderKeyEngine::encrypt(application::interfaces::ICryptoProvider& crypto, SenderKeyState& state,
                         std::span<const uint8_t> plaintext) {
    if (!state.signing_private_key.has_value()) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(
            application::ClientError::crypto("Cannot encrypt with receive-only SenderKeyState"));
    }

    auto step_res = step_chain_key(crypto, state.chain_key);
    if (step_res.is_error()) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(step_res.error());
    }

    std::vector<uint8_t> iv(kAesGcmIvBytes);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(
            application::ClientError::crypto("RAND_bytes failed for GroupEncryptedEnvelope IV"));
    }

    const uint32_t msg_iter = state.iteration;
    const auto aad = build_aad(state.id, msg_iter);
    const auto aead_res = crypto.encrypt_aes_gcm(step_res.value().second, iv, plaintext, aad);
    if (aead_res.is_error()) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(aead_res.error());
    }

    GroupEncryptedEnvelope env;
    env.id = state.id;
    env.iteration = msg_iter;
    env.iv = std::move(iv);
    env.auth_tag = aead_res.value().auth_tag;
    env.ciphertext = aead_res.value().ciphertext;

    const auto signed_bytes = env.canonical_signed_bytes();
    const auto sig_res = sign_ed25519(*state.signing_private_key, signed_bytes);
    if (sig_res.is_error()) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(sig_res.error());
    }
    env.signature = sig_res.value();

    // Advance chain state only after encryption and signature succeed
    state.chain_key = std::move(step_res.value().first);
    ++state.iteration;

    return application::ClientResult<GroupEncryptedEnvelope>::ok(std::move(env));
}

application::ClientResult<common::configuration::SecretString>
SenderKeyEngine::decrypt(application::interfaces::ICryptoProvider& crypto, SenderKeyState& state,
                         const GroupEncryptedEnvelope& envelope) {
    if (envelope.id != state.id) {
        return application::ClientResult<common::configuration::SecretString>::error(
            application::ClientError::crypto("GroupEncryptedEnvelope SenderKeyId mismatch"));
    }

    const auto signed_bytes = envelope.canonical_signed_bytes();
    if (!verify_ed25519(state.signing_public_key, signed_bytes, envelope.signature)) {
        return application::ClientResult<common::configuration::SecretString>::error(
            application::ClientError::crypto("GroupEncryptedEnvelope Ed25519 signature verification failed"));
    }

    const auto aad = build_aad(state.id, envelope.iteration);

    // Out-of-order previously skipped message
    if (envelope.iteration < state.iteration) {
        const auto it = state.skipped_message_keys.find(envelope.iteration);
        if (it == state.skipped_message_keys.end()) {
            return application::ClientResult<common::configuration::SecretString>::error(
                application::ClientError::crypto("Replay or missing skipped key for SenderKey iteration"));
        }
        auto pt_res = crypto.decrypt_aes_gcm(it->second, envelope.iv, envelope.ciphertext, envelope.auth_tag, aad);
        if (pt_res.is_error()) {
            return pt_res;
        }
        state.skipped_message_keys.erase(it);
        return pt_res;
    }

    const uint32_t skip_count = envelope.iteration - state.iteration;
    if (skip_count > kMaxGroupSkip || state.skipped_message_keys.size() + skip_count > kMaxGroupSkip) {
        return application::ClientResult<common::configuration::SecretString>::error(
            application::ClientError::crypto("SenderKey iteration skip exceeds kMaxGroupSkip"));
    }

    common::configuration::SecretString working_ck = state.chain_key;
    std::map<uint32_t, common::configuration::SecretString> pending_skipped;

    for (uint32_t iter = state.iteration; iter < envelope.iteration; ++iter) {
        auto step_res = step_chain_key(crypto, working_ck);
        if (step_res.is_error()) {
            return application::ClientResult<common::configuration::SecretString>::error(step_res.error());
        }
        working_ck = std::move(step_res.value().first);
        pending_skipped.emplace(iter, std::move(step_res.value().second));
    }

    auto target_step = step_chain_key(crypto, working_ck);
    if (target_step.is_error()) {
        return application::ClientResult<common::configuration::SecretString>::error(target_step.error());
    }

    auto pt_res =
        crypto.decrypt_aes_gcm(target_step.value().second, envelope.iv, envelope.ciphertext, envelope.auth_tag, aad);
    if (pt_res.is_error()) {
        return pt_res;
    }

    // Commit chain state and skipped keys only after AEAD authentication succeeds
    state.chain_key = std::move(target_step.value().first);
    state.iteration = envelope.iteration + 1;
    for (auto& [iter, mk] : pending_skipped) {
        state.skipped_message_keys.emplace(iter, std::move(mk));
    }
    return pt_res;
}

} // namespace securecloud::client::domain::crypto
