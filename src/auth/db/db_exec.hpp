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
#else
    // libpqxx 7.9+ recommends exec(zview, params) over exec_params
    return tx.exec(pqxx::zview{query}, params);
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
