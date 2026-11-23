#pragma once

#include "application/client_error.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::interfaces {

class ISecureStorage {
  public:
    virtual ~ISecureStorage() = default;

    virtual ClientResult<void> store_secret(std::string_view key_id,
                                            const securecloud::common::configuration::SecretString& secret) = 0;
    virtual ClientResult<securecloud::common::configuration::SecretString> get_secret(std::string_view key_id) = 0;
    virtual ClientResult<void> delete_secret(std::string_view key_id) = 0;
    virtual ClientResult<bool> has_secret(std::string_view key_id) = 0;
    virtual ClientResult<std::vector<std::string>> list_secret_keys() = 0;
    virtual ClientResult<std::size_t> purge_all_secrets() = 0;
};

} // namespace securecloud::client::application::interfaces
