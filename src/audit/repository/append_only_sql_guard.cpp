#include "repository/append_only_sql_guard.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>

namespace securecloud::audit::repository {

namespace {

std::string_view trim_leading_whitespace(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) {
        sv.remove_prefix(1);
    }
    return sv;
}

std::string_view trim_trailing_whitespace(std::string_view sv) {
    while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) {
        sv.remove_suffix(1);
    }
    return sv;
}

bool equals_case_insensitive(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::toupper(static_cast<unsigned char>(a[i])) != std::toupper(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool starts_with_case_insensitive(std::string_view sv, std::string_view prefix) {
    if (sv.size() < prefix.size())
        return false;
    return equals_case_insensitive(sv.substr(0, prefix.size()), prefix);
}

constexpr std::array<std::string_view, 13> kForbiddenKeywords = {"INSERT", "UPDATE", "DELETE", "ALTER",    "TRUNCATE",
                                                                 "DROP",   "CREATE", "RENAME", "OPTIMIZE", "GRANT",
                                                                 "REVOKE", "ATTACH", "DETACH"};

bool is_word_boundary(char c) {
    return !std::isalnum(static_cast<unsigned char>(c)) && c != '_';
}

void check_forbidden_keywords(std::string_view sql, bool allow_insert) {
    std::string upper_sql;
    upper_sql.reserve(sql.size());
    for (char c : sql) {
        upper_sql.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    for (std::string_view kw : kForbiddenKeywords) {
        if (allow_insert && kw == "INSERT") {
            continue;
        }

        size_t pos = 0;
        while ((pos = upper_sql.find(kw, pos)) != std::string::npos) {
            bool left_boundary = (pos == 0) || is_word_boundary(upper_sql[pos - 1]);
            bool right_boundary = (pos + kw.size() == upper_sql.size()) || is_word_boundary(upper_sql[pos + kw.size()]);

            if (left_boundary && right_boundary) {
                throw AppendOnlyViolationException("AppendOnlySqlGuard: Forbidden SQL keyword detected: " +
                                                   std::string(kw));
            }
            pos += kw.size();
        }
    }
}

void check_no_semicolon_chaining(std::string_view sql) {
    auto trimmed = trim_trailing_whitespace(sql);
    if (!trimmed.empty() && trimmed.back() == ';') {
        trimmed.remove_suffix(1);
    }
    trimmed = trim_trailing_whitespace(trimmed);
    if (trimmed.find(';') != std::string_view::npos) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Semicolon-chained multiple statements are forbidden");
    }
}

} // namespace

void AppendOnlySqlGuard::validate_query_sql(std::string_view sql) {
    auto trimmed = trim_leading_whitespace(sql);
    if (trimmed.empty()) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Empty SQL statement");
    }

    if (!starts_with_case_insensitive(trimmed, "SELECT")) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Read query must begin with SELECT statement");
    }

    if (trimmed.size() > 6 && !is_word_boundary(trimmed[6])) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Invalid statement opening keyword");
    }

    check_no_semicolon_chaining(sql);
    check_forbidden_keywords(sql, /*allow_insert=*/false);
}

void AppendOnlySqlGuard::validate_insert_sql(std::string_view sql) {
    auto trimmed = trim_leading_whitespace(sql);
    if (trimmed.empty()) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Empty SQL statement");
    }

    if (!starts_with_case_insensitive(trimmed, "INSERT INTO")) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Insert query must begin with INSERT INTO");
    }

    if (trimmed.find("audit_events") == std::string_view::npos) {
        throw AppendOnlyViolationException("AppendOnlySqlGuard: Insert query must target audit_events table");
    }

    check_no_semicolon_chaining(sql);
    check_forbidden_keywords(sql, /*allow_insert=*/true);
}

} // namespace securecloud::audit::repository