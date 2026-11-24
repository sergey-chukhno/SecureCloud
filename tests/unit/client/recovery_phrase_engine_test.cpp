#include "domain/crypto/bip39_wordlist.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/crypto/recovery_phrase_engine.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <gtest/gtest.h>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace securecloud::client::domain::crypto;
using securecloud::common::configuration::SecretString;

[[nodiscard]] std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

[[nodiscard]] std::vector<uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0U; i < hex.size(); i += 2U) {
        auto nibble = [](char ch) -> uint8_t {
            if (ch >= '0' && ch <= '9') {
                return static_cast<uint8_t>(ch - '0');
            }
            return static_cast<uint8_t>(ch - 'a' + 10);
        };
        out.push_back(static_cast<uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1U])));
    }
    return out;
}

[[nodiscard]] std::vector<std::string> split_spaces(std::string_view sv) {
    std::vector<std::string> out;
    std::size_t start = 0U;
    while (start < sv.size()) {
        const std::size_t sp = sv.find(' ', start);
        if (sp == std::string_view::npos) {
            out.emplace_back(sv.substr(start));
            break;
        }
        if (sp > start) {
            out.emplace_back(sv.substr(start, sp - start));
        }
        start = sp + 1U;
    }
    return out;
}

TEST(RecoveryPhraseEngineTest, CanonicalWordlistMatchesBip39Sha256AndLexicographicalOrder) {
    EXPECT_EQ(kBip39EnglishWords.size(), 2048U);
    EXPECT_EQ(kBip39EnglishWords.front(), "abandon");
    EXPECT_EQ(kBip39EnglishWords.back(), "zoo");

    EXPECT_TRUE(std::is_sorted(kBip39EnglishWords.begin(), kBip39EnglishWords.end()));
    EXPECT_EQ(find_bip39_word_index("abandon"), std::optional<uint16_t>(0U));
    EXPECT_EQ(find_bip39_word_index("zoo"), std::optional<uint16_t>(2047U));
    EXPECT_FALSE(find_bip39_word_index("notabip39word").has_value());

    std::string joined;
    for (const std::string_view word : kBip39EnglishWords) {
        joined.append(word);
        joined.push_back('\n');
    }

    const std::vector<uint8_t> raw(joined.begin(), joined.end());
    const auto sha_res = StreamingSha256::digest_hex(raw);
    ASSERT_TRUE(sha_res.is_ok());
    EXPECT_EQ(sha_res.value(), "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");
}

TEST(RecoveryPhraseEngineTest, OfficialBip39TestVectorsMatchByteForByte) {
    struct Vector {
        const char* entropy_hex;
        const char* expected_mnemonic;
        const char* passphrase;
        const char* expected_seed_hex;
    };

    const std::array<Vector, 6> kVectors = {{
        {"00000000000000000000000000000000",
         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR",
         "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
         "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
        {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
         "legal winner thank year wave sausage worth useful legal winner thank yellow", "TREZOR",
         "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
         "a457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"},
        {"ffffffffffffffffffffffffffffffff", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "TREZOR",
         "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13"
         "332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"},
        {"0000000000000000000000000000000000000000000000000000000000000000",
         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
         "TREZOR",
         "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
         "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"},
        {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
         "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal "
         "winner thank year wave sausage worth title",
         "TREZOR",
         "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a40"
         "21b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"},
        {"00000000000000000000000000000000",
         "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "",
         "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19"
         "a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"},
    }};

    for (const auto& vec : kVectors) {
        const auto entropy = hex_to_bytes(vec.entropy_hex);
        const auto mn_res = RecoveryPhraseEngine::entropy_to_mnemonic(entropy);
        ASSERT_TRUE(mn_res.is_ok());
        EXPECT_EQ(mn_res.value().expose_unredacted_secret(), vec.expected_mnemonic);

        const auto valid_res = RecoveryPhraseEngine::validate_mnemonic(mn_res.value());
        ASSERT_TRUE(valid_res.is_ok());
        EXPECT_TRUE(valid_res.value());

        const auto seed_res = RecoveryPhraseEngine::derive_recovery_seed(mn_res.value(), SecretString(vec.passphrase));
        ASSERT_TRUE(seed_res.is_ok());
        EXPECT_EQ(seed_res.value().size(), RecoveryPhraseEngine::kSeedBytes);
        EXPECT_EQ(bytes_to_hex(seed_res.value()), vec.expected_seed_hex);
    }
}

TEST(RecoveryPhraseEngineTest, DefaultGenerationProducesValidUnique12WordAndOptional24WordPhrases) {
    // Default is 12 words.
    const auto p12_a = RecoveryPhraseEngine::generate_mnemonic();
    const auto p12_b = RecoveryPhraseEngine::generate_mnemonic();
    ASSERT_TRUE(p12_a.is_ok());
    ASSERT_TRUE(p12_b.is_ok());
    EXPECT_NE(p12_a.value(), p12_b.value());
    EXPECT_EQ(split_spaces(p12_a.value().expose_unredacted_secret()).size(), 12U);
    EXPECT_TRUE(RecoveryPhraseEngine::validate_mnemonic(p12_a.value()).value());

    // Optional 24 words also supported cleanly.
    const auto p24 = RecoveryPhraseEngine::generate_mnemonic(RecoveryPhraseLength::Words24);
    ASSERT_TRUE(p24.is_ok());
    EXPECT_EQ(split_spaces(p24.value().expose_unredacted_secret()).size(), 24U);
    EXPECT_TRUE(RecoveryPhraseEngine::validate_mnemonic(p24.value()).value());

    // Whitespace/case normalization validates and yields identical seed.
    const SecretString canonical("legal winner thank year wave sausage worth useful legal winner thank yellow");
    const SecretString messy("  LEGAL\t winner  thank\nyear  wave sausage worth useful legal winner thank YELLOW  ");
    EXPECT_TRUE(RecoveryPhraseEngine::validate_mnemonic(messy).value());
    EXPECT_EQ(RecoveryPhraseEngine::derive_recovery_seed(canonical).value(),
              RecoveryPhraseEngine::derive_recovery_seed(messy).value());

    // SecretString redaction guard.
    std::ostringstream oss;
    oss << p12_a.value();
    EXPECT_EQ(oss.str(), "[REDACTED]");
}

TEST(RecoveryPhraseEngineTest, RejectsInvalidEntropyTamperedChecksumsAndUnknownWords) {
    const std::vector<uint8_t> short_entropy(15U, 0xAAU);
    const std::vector<uint8_t> bad_24_byte_entropy(24U, 0xAAU);
    EXPECT_TRUE(RecoveryPhraseEngine::entropy_to_mnemonic({}).is_error());
    EXPECT_TRUE(RecoveryPhraseEngine::entropy_to_mnemonic(short_entropy).is_error());
    EXPECT_TRUE(RecoveryPhraseEngine::entropy_to_mnemonic(bad_24_byte_entropy).is_error());

    // Tamper checksum word on valid 12-word phrase ("about" -> "abandon").
    const SecretString bad_checksum(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    EXPECT_FALSE(RecoveryPhraseEngine::validate_mnemonic(bad_checksum).value());
    EXPECT_TRUE(RecoveryPhraseEngine::derive_recovery_seed(bad_checksum).is_error());

    // Unknown word.
    const SecretString unknown_word(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword");
    EXPECT_FALSE(RecoveryPhraseEngine::validate_mnemonic(unknown_word).value());

    // Wrong word counts (11 and 13).
    const SecretString eleven_words(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon");
    const SecretString thirteen_words(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon");
    EXPECT_FALSE(RecoveryPhraseEngine::validate_mnemonic(eleven_words).value());
    EXPECT_FALSE(RecoveryPhraseEngine::validate_mnemonic(thirteen_words).value());
}

TEST(RecoveryPhraseEngineTest, SaltedVerificationDigestVerifiesWithoutLeakingPhrase) {
    const auto mn_res = RecoveryPhraseEngine::generate_mnemonic(RecoveryPhraseLength::Words12);
    ASSERT_TRUE(mn_res.is_ok());
    const SecretString& mnemonic = mn_res.value();

    const auto digest1 = RecoveryPhraseEngine::compute_salted_verification_digest(mnemonic);
    const auto digest2 = RecoveryPhraseEngine::compute_salted_verification_digest(mnemonic);
    ASSERT_TRUE(digest1.is_ok());
    ASSERT_TRUE(digest2.is_ok());
    EXPECT_NE(digest1.value(), digest2.value()); // Random 16-byte salt per digest

    // Verify digest does not expose phrase words.
    for (const std::string& w : split_spaces(mnemonic.expose_unredacted_secret())) {
        if (w.size() >= 4U) {
            EXPECT_EQ(digest1.value().find(w), std::string::npos);
        }
    }

    EXPECT_TRUE(RecoveryPhraseEngine::verify_against_digest(mnemonic, digest1.value()).value());

    // Whitespace / case difference on valid input verifies cleanly.
    const SecretString padded("  " + mnemonic.expose_unredacted_secret() + "  ");
    EXPECT_TRUE(RecoveryPhraseEngine::verify_against_digest(padded, digest1.value()).value());

    // Different phrase fails closed.
    const auto other = RecoveryPhraseEngine::generate_mnemonic(RecoveryPhraseLength::Words12);
    ASSERT_TRUE(other.is_ok());
    if (other.value() != mnemonic) {
        EXPECT_FALSE(RecoveryPhraseEngine::verify_against_digest(other.value(), digest1.value()).value());
    }

    // Tampered or malformed digest strings fail closed.
    std::string tampered = digest1.value();
    tampered.back() = (tampered.back() == '0') ? '1' : '0';
    EXPECT_FALSE(RecoveryPhraseEngine::verify_against_digest(mnemonic, tampered).value());
    EXPECT_FALSE(RecoveryPhraseEngine::verify_against_digest(mnemonic, "malformed").value());
    EXPECT_FALSE(RecoveryPhraseEngine::verify_against_digest(mnemonic, "sc-bip39-v1:10:00:00").value());
}

TEST(RecoveryPhraseEngineTest, SpotCheckChallengeGenerationAndConstantTimeVerification) {
    EXPECT_TRUE(RecoveryPhraseEngine::build_challenge(10U, 3U).is_error());
    EXPECT_TRUE(RecoveryPhraseEngine::build_challenge(12U, 0U).is_error());
    EXPECT_TRUE(RecoveryPhraseEngine::build_challenge(12U, 13U).is_error());

    const auto ch12 = RecoveryPhraseEngine::build_challenge(12U, 3U);
    ASSERT_TRUE(ch12.is_ok());
    ASSERT_EQ(ch12.value().word_indices.size(), 3U);
    EXPECT_TRUE(std::is_sorted(ch12.value().word_indices.begin(), ch12.value().word_indices.end()));
    const std::set<std::size_t> unique12(ch12.value().word_indices.begin(), ch12.value().word_indices.end());
    EXPECT_EQ(unique12.size(), 3U);
    for (const std::size_t idx : ch12.value().word_indices) {
        EXPECT_LT(idx, 12U);
    }

    const auto ch24 = RecoveryPhraseEngine::build_challenge(24U, 3U);
    ASSERT_TRUE(ch24.is_ok());
    ASSERT_EQ(ch24.value().word_indices.size(), 3U);
    for (const std::size_t idx : ch24.value().word_indices) {
        EXPECT_LT(idx, 24U);
    }

    const SecretString vector12("legal winner thank year wave sausage worth useful legal winner thank yellow");
    const std::vector<std::string> words = split_spaces(vector12.expose_unredacted_secret());

    std::vector<std::pair<std::size_t, std::string>> good_answers;
    for (const std::size_t idx : ch12.value().word_indices) {
        std::string w = words[idx];
        if (good_answers.empty()) {
            w = "  " + w + " ";
        }
        good_answers.emplace_back(idx, std::move(w));
    }
    EXPECT_TRUE(RecoveryPhraseEngine::verify_challenge_words(vector12, good_answers).value());

    // Case-insensitive user typing also succeeds.
    auto upper_answers = good_answers;
    upper_answers[0].second = "  " + [&] {
        std::string u = words[ch12.value().word_indices[0]];
        for (char& c : u) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
        return u;
    }() + " ";
    EXPECT_TRUE(RecoveryPhraseEngine::verify_challenge_words(vector12, upper_answers).value());

    // Wrong answer fails closed.
    auto bad_answers = good_answers;
    bad_answers[1].second = (bad_answers[1].second == "abandon") ? "zoo" : "abandon";
    EXPECT_FALSE(RecoveryPhraseEngine::verify_challenge_words(vector12, bad_answers).value());

    // Structural errors (empty, duplicate index, out of range).
    EXPECT_TRUE(RecoveryPhraseEngine::verify_challenge_words(vector12, {}).is_error());
    const auto dup_res = RecoveryPhraseEngine::verify_challenge_words(vector12, {{0U, words[0]}, {0U, words[0]}});
    EXPECT_TRUE(dup_res.is_error());
    EXPECT_TRUE(RecoveryPhraseEngine::verify_challenge_words(vector12, {{12U, "abandon"}}).is_error());
}

} // namespace
