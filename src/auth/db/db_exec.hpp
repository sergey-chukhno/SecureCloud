#pragma once

#include <pqxx/pqxx>
#include <pqxx/version>
#include <string_view>

namespace securecloud::auth::db {

namespace detail {

template <typename Tx, typename Q, typename P>
inline pqxx::result exec_sql_impl(Tx& tx, const Q& query, const P& params) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

    if constexpr (requires { tx.exec(query, params); }) {
        return tx.exec(query, params);
    } else if constexpr (requires { tx.exec(pqxx::zview{query}, params); }) {
        return tx.exec(pqxx::zview{query}, params);
    } else {
        return tx.exec_params(pqxx::zview{query}, params);
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
}

} // namespace detail

/// Cross-version SQL execution helper supporting both libpqxx 7.x (vcpkg / MSVC / MinGW)
/// and libpqxx 8.x (macOS Homebrew / C++20).
inline pqxx::result exec_sql(pqxx::transaction_base& tx, std::string_view query, const pqxx::params& params) {
    return detail::exec_sql_impl(tx, query, params);
}

inline pqxx::result exec_sql(pqxx::transaction_base& tx, std::string_view query) {
    return tx.exec(query);
}

} // namespace securecloud::auth::db
