#pragma once

#include "application/interfaces/i_crypto_provider.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <vector>

namespace securecloud::client::domain::crypto {

struct RatchetState {
    securecloud::common::configuration::SecretString root_key;
    application::interfaces::DhKeyPair sending_dh_pair;
    std::vector<uint8_t> peer_dh_pub;
    securecloud::common::configuration::SecretString sending_chain_key;
    securecloud::common::configuration::SecretString receiving_chain_key;
    uint32_t ns{0};
    uint32_t nr{0};
    uint32_t pn{0};
};

} // namespace securecloud::client::domain::crypto

