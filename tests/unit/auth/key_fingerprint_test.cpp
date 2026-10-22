#include "auth/crypto/key_fingerprint.hpp"

#include <algorithm>
#include <gtest/gtest.h>
#include <regex>
#include <vector>

namespace securecloud::auth::crypto::test {
namespace {

// Standard NIST / RFC SHA-256 test vector for empty input:
// SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
constexpr std::string_view kEmptySha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
constexpr std::string_view kEmptySha256Formatted =
    "SHA256:E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55";

// NIST test vector for "abc":
// SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
constexpr std::string_view kAbcSha256Hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
constexpr std::string_view kAbcSha256Formatted =
    "SHA256:BA:78:16:BF:8F:01:CF:EA:41:41:40:DE:5D:AE:22:23:B0:03:61:A3:96:17:7A:9C:B4:10:FF:61:F2:00:15:AD";

TEST(KeyFingerprintTest, EmptyInputProducesKnownSha256Digest) {
    std::vector<uint8_t> empty_input;
    auto raw = KeyFingerprint::compute_raw_sha256(empty_input);
    ASSERT_EQ(raw.size(), KeyFingerprint::kDigestSize);

    auto hex = KeyFingerprint::compute_hex_sha256(empty_input);
    EXPECT_EQ(hex, kEmptySha256Hex);

    auto formatted = KeyFingerprint::compute_sha256(empty_input);
    EXPECT_EQ(formatted, kEmptySha256Formatted);
}

TEST(KeyFingerprintTest, StandardInputProducesKnownSha256Digest) {
    const std::string abc = "abc";
    std::vector<uint8_t> abc_bytes(abc.begin(), abc.end());

    auto hex = KeyFingerprint::compute_hex_sha256(abc_bytes);
    EXPECT_EQ(hex, kAbcSha256Hex);

    auto formatted = KeyFingerprint::compute_sha256(abc_bytes);
    EXPECT_EQ(formatted, kAbcSha256Formatted);
}

TEST(KeyFingerprintTest, FormattedFingerprintStructureAndLength) {
    // 32-byte dummy public key
    std::vector<uint8_t> key(32, 0x42);
    auto fp = KeyFingerprint::compute_sha256(key);

    // Expected length: "SHA256:" (7) + 32*2 hex chars (64) + 31 colons = 102 chars
    EXPECT_EQ(fp.size(), 102u);
    EXPECT_TRUE(fp.starts_with("SHA256:"));

    // Verify format via regex: SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}
    std::regex fp_regex(R"(^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$)");
    EXPECT_TRUE(std::regex_match(fp, fp_regex));
}

TEST(KeyFingerprintTest, DifferentKeysYieldDistinctFingerprints) {
    std::vector<uint8_t> key_a(32, 0x01);
    std::vector<uint8_t> key_b(32, 0x02);

    auto fp_a = KeyFingerprint::compute_sha256(key_a);
    auto fp_b = KeyFingerprint::compute_sha256(key_b);

    EXPECT_NE(fp_a, fp_b);
    EXPECT_FALSE(KeyFingerprint::constant_time_equals(fp_a, fp_b));
}

TEST(KeyFingerprintTest, ConstantTimeEqualsCorrectness) {
    std::string s1 = "SHA256:AA:BB:CC:DD";
    std::string s2 = "SHA256:AA:BB:CC:DD";
    std::string s3 = "SHA256:AA:BB:CC:DE";
    std::string s4 = "SHA256:AA:BB:CC";

    EXPECT_TRUE(KeyFingerprint::constant_time_equals(s1, s2));
    EXPECT_FALSE(KeyFingerprint::constant_time_equals(s1, s3));
    EXPECT_FALSE(KeyFingerprint::constant_time_equals(s1, s4));
    EXPECT_FALSE(KeyFingerprint::constant_time_equals("", s1));
    EXPECT_TRUE(KeyFingerprint::constant_time_equals("", ""));
}

TEST(KeyFingerprintTest, DeterminismAcrossInvocations) {
    std::vector<uint8_t> random_key = {0x1f, 0x82, 0x9c, 0xd4, 0xaa, 0x55, 0x01, 0x23, 0x45, 0x67, 0x89,
                                       0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};

    auto fp1 = KeyFingerprint::compute_sha256(random_key);
    auto fp2 = KeyFingerprint::compute_sha256(random_key);
    auto hex1 = KeyFingerprint::compute_hex_sha256(random_key);
    auto hex2 = KeyFingerprint::compute_hex_sha256(random_key);

    EXPECT_EQ(fp1, fp2);
    EXPECT_EQ(hex1, hex2);
    EXPECT_TRUE(KeyFingerprint::constant_time_equals(fp1, fp2));
}

} // namespace
} // namespace securecloud::auth::crypto::test
