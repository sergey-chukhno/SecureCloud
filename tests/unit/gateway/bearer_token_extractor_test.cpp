#include "http/bearer_token_extractor.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <string>

namespace securecloud::gateway::http {
namespace {

// ============================================================================
// Test Suite: Positive Extraction & RFC 6750 Normalization
// ============================================================================

TEST(BearerTokenExtractorTest, ExtractsStandardJwtToken) {
    const std::string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
                            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    auto result = BearerTokenExtractor::extract_from_header("Bearer " + jwt);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), jwt);
}

TEST(BearerTokenExtractorTest, HandlesCaseInsensitiveBearerScheme) {
    const std::string token = "valid-token-12345";

    auto res_lower = BearerTokenExtractor::extract_from_header("bearer " + token);
    ASSERT_TRUE(res_lower.has_value());
    EXPECT_EQ(res_lower.value(), token);

    auto res_upper = BearerTokenExtractor::extract_from_header("BEARER " + token);
    ASSERT_TRUE(res_upper.has_value());
    EXPECT_EQ(res_upper.value(), token);

    auto res_mixed = BearerTokenExtractor::extract_from_header("bEaReR " + token);
    ASSERT_TRUE(res_mixed.has_value());
    EXPECT_EQ(res_mixed.value(), token);
}

TEST(BearerTokenExtractorTest, NormalizesSurroundingAndDelimiterWhitespace) {
    const std::string token = "normalized-session-token.abc_123";

    // Multiple spaces and tabs between scheme and token, plus leading/trailing spaces
    auto res1 = BearerTokenExtractor::extract_from_header("   Bearer    " + token + "   ");
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1.value(), token);

    auto res2 = BearerTokenExtractor::extract_from_header("\t\tBearer\t\t" + token + "\t\t");
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2.value(), token);
}

TEST(BearerTokenExtractorTest, AllowsAllValidB64TokenCharacters) {
    // RFC 6750 b64token characters: ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" and optional "="
    const std::string valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~+/==";

    auto result = BearerTokenExtractor::extract_from_header("Bearer " + valid_chars);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), valid_chars);
}

TEST(BearerTokenExtractorTest, ExtractsDirectlyFromHttplibRequest) {
    httplib::Request req;
    req.headers.emplace("Authorization", "Bearer request-token-987");

    auto result = BearerTokenExtractor::extract(req);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "request-token-987");
}

// ============================================================================
// Test Suite: Missing, Empty, and Invalid Scheme Rejections
// ============================================================================

TEST(BearerTokenExtractorTest, RejectsMissingAuthorizationHeaderInRequest) {
    httplib::Request req; // No headers added

    auto result = BearerTokenExtractor::extract(req);
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::MissingAuthorizationHeader);
}

TEST(BearerTokenExtractorTest, RejectsEmptyOrWhitespaceOnlyHeader) {
    auto res_empty = BearerTokenExtractor::extract_from_header("");
    ASSERT_TRUE(res_empty.has_error());
    EXPECT_EQ(res_empty.error().kind, TokenExtractionErrorKind::MissingAuthorizationHeader);

    auto res_ws = BearerTokenExtractor::extract_from_header("    \t   ");
    ASSERT_TRUE(res_ws.has_error());
    EXPECT_EQ(res_ws.error().kind, TokenExtractionErrorKind::MissingAuthorizationHeader);
}

TEST(BearerTokenExtractorTest, RejectsUnsupportedAuthenticationSchemes) {
    const std::vector<std::string> invalid_headers = {
        "Basic dXNlcjpwYXNzd29yZA==", "Digest username=\"MIME\", realm=\"myrealm\"",
        "ApiKey sec-key-123456",      "Token abcdef",
        "OAuth oauth-token",          "CustomScheme token",
    };

    for (const auto& header : invalid_headers) {
        auto result = BearerTokenExtractor::extract_from_header(header);
        ASSERT_TRUE(result.has_error()) << "Should have rejected scheme in header: " << header;
        EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::InvalidScheme);
    }
}

TEST(BearerTokenExtractorTest, RejectsSchemeWithoutWhitespaceDelimiter) {
    // Missing space delimiter between "Bearer" and the token
    auto result = BearerTokenExtractor::extract_from_header("Bearertoken123");
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::InvalidScheme);
}

TEST(BearerTokenExtractorTest, RejectsEmptyTokenPayload) {
    auto res1 = BearerTokenExtractor::extract_from_header("Bearer");
    ASSERT_TRUE(res1.has_error());
    EXPECT_EQ(res1.error().kind, TokenExtractionErrorKind::EmptyToken);

    auto res2 = BearerTokenExtractor::extract_from_header("Bearer ");
    ASSERT_TRUE(res2.has_error());
    EXPECT_EQ(res2.error().kind, TokenExtractionErrorKind::EmptyToken);

    auto res3 = BearerTokenExtractor::extract_from_header("Bearer    \t   ");
    ASSERT_TRUE(res3.has_error());
    EXPECT_EQ(res3.error().kind, TokenExtractionErrorKind::EmptyToken);
}

// ============================================================================
// Test Suite: Security Defenses (CRLF, Whitespace Smuggling, Injections, DoS)
// ============================================================================

TEST(BearerTokenExtractorTest, DefendsAgainstHeaderInjectionCrlf) {
    // Attempt CRLF injection to smuggle fake headers
    const std::vector<std::string> injection_attempts = {
        "Bearer valid_part\r\nX-Injected-Header: admin",
        "Bearer valid_part\nSet-Cookie: session=forged",
        "Bearer valid_part\rX-Spoofed: true",
        "Bearer \r\nBearer malicious",
    };

    for (const auto& attempt : injection_attempts) {
        auto result = BearerTokenExtractor::extract_from_header(attempt);
        ASSERT_TRUE(result.has_error()) << "CRLF attempt was not rejected: " << attempt;
        // Depending on delimiter position, CRLF in token part returns MalformedToken
        EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::MalformedToken);
    }
}

TEST(BearerTokenExtractorTest, DefendsAgainstNullByteInjection) {
    std::string null_byte_attack = "Bearer valid_token";
    null_byte_attack.push_back('\0');
    null_byte_attack.append("injected_payload");

    auto result = BearerTokenExtractor::extract_from_header(null_byte_attack);
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::MalformedToken);
}

TEST(BearerTokenExtractorTest, DefendsAgainstInternalSpacesAndMultiTokenSmuggling) {
    // Embedded spaces within the token payload indicate smuggling or corrupted input
    auto result = BearerTokenExtractor::extract_from_header("Bearer token_part_one token_part_two");
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::MalformedToken);
}

TEST(BearerTokenExtractorTest, DefendsAgainstForbiddenCharactersAndPunctuation) {
    const std::vector<std::string> invalid_tokens = {
        "Bearer token\"with\"quotes",
        "Bearer token'with'singlequotes",
        "Bearer <script>alert(1)</script>",
        "Bearer token;DROP TABLE users;--",
        "Bearer token(parentheses)",
        "Bearer token{curly_brackets}",
        "Bearer token[square_brackets]",
        "Bearer token\\backslash",
        "Bearer token@email.com",
        "Bearer token#hash",
        "Bearer token$dollar",
        "Bearer token%percent",
        "Bearer token&ampersand",
        "Bearer token!exclamation",
    };

    for (const auto& invalid_header : invalid_tokens) {
        auto result = BearerTokenExtractor::extract_from_header(invalid_header);
        ASSERT_TRUE(result.has_error()) << "Should have rejected token: " << invalid_header;
        EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::MalformedToken);
    }
}

TEST(BearerTokenExtractorTest, DefendsAgainstUnicodeAndHomoglyphAttacks) {
    // Cyrillic 'о' (U+043E, UTF-8: \xD0\xBE) instead of Latin 'o'
    std::string homoglyph_token = "Bearer t\xD0\xBEken_with_cyrillic";

    auto result = BearerTokenExtractor::extract_from_header(homoglyph_token);
    ASSERT_TRUE(result.has_error());
    EXPECT_EQ(result.error().kind, TokenExtractionErrorKind::MalformedToken);
}

TEST(BearerTokenExtractorTest, EnforcesMaxTokenLengthThreshold) {
    // 4096 bytes is the exact allowed boundary
    std::string exact_max_token(4096, 'A');
    auto res_boundary = BearerTokenExtractor::extract_from_header("Bearer " + exact_max_token);
    ASSERT_TRUE(res_boundary.has_value());
    EXPECT_EQ(res_boundary.value().length(), 4096);

    // 4097 bytes exceeds maximum allowable threshold
    std::string oversize_token(4097, 'A');
    auto res_oversize = BearerTokenExtractor::extract_from_header("Bearer " + oversize_token);
    ASSERT_TRUE(res_oversize.has_error());
    EXPECT_EQ(res_oversize.error().kind, TokenExtractionErrorKind::TokenTooLarge);

    // 10,000 bytes flood attack
    std::string huge_token(10000, 'X');
    auto res_huge = BearerTokenExtractor::extract_from_header("Bearer " + huge_token);
    ASSERT_TRUE(res_huge.has_error());
    EXPECT_EQ(res_huge.error().kind, TokenExtractionErrorKind::TokenTooLarge);
}

} // namespace
} // namespace securecloud::gateway::http
