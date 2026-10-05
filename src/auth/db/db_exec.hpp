#pragma once

#include <pqxx/pqxx>
#include <pqxx/version>
#include <string_view>

namespace securecloud::auth::db {

/// Cross-version SQL execution helper supporting both libpqxx 7.x (vcpkg / MSVC)
/// and libpqxx 8.x (macOS Homebrew / C++20).
inline pqxx::result exec_sql(pqxx::transaction_base& tx, std::string_view query, const pqxx::params& params) {
#if defined(PQXX_VERSION_MAJOR) && PQXX_VERSION_MAJOR >= 8
    return tx.exec(query, params);
#else
    return tx.exec_params(pqxx::zview{query}, params);
#endif
}

inline pqxx::result exec_sql(pqxx::transaction_base& tx, std::string_view query) {
    return tx.exec(query);
}

} // namespace securecloud::auth::db
