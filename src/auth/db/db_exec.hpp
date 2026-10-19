#pragma once

#include <pqxx/pqxx>
#include <pqxx/version>
#include <string_view>

namespace securecloud::auth::db {

/// Cross-version SQL execution helper supporting both libpqxx 7.x (vcpkg / MSVC / MinGW)
/// and libpqxx 8.x (macOS Homebrew / C++20).
inline pqxx::result exec_sql(pqxx::transaction_base& tx, std::string_view query, const pqxx::params& params) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

#if defined(PQXX_VERSION_MAJOR) && PQXX_VERSION_MAJOR >= 8
    return tx.exec(query, params);
#elif defined(PQXX_VERSION_MAJOR) && defined(PQXX_VERSION_MINOR) && (PQXX_VERSION_MAJOR == 7 && PQXX_VERSION_MINOR >= 9)
    // libpqxx 7.9+ introduced exec(zview, params) and deprecated exec_params
    return tx.exec(pqxx::zview{query}, params);
#else
    // libpqxx < 7.9 (e.g. vcpkg libpqxx 7.7.x / 7.8.x on MSVC) only provides exec_params
    return tx.exec_params(pqxx::zview{query}, params);
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
}

inline pqxx::result exec_sql(pqxx::transaction_base& tx, std::string_view query) {
    return tx.exec(query);
}

} // namespace securecloud::auth::db
