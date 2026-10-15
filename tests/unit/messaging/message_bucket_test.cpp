#include "messaging/domain/message_bucket.hpp"

#include <chrono>
#include <gtest/gtest.h>
#include <unordered_set>

namespace securecloud::messaging::domain::test {

TEST(MessageBucketTest, FromYearMonthValid) {
    auto b = MessageBucket::from_year_month(2026, 10);
    EXPECT_EQ(b.value(), "202610");
    EXPECT_EQ(b.to_string(), "202610");
    EXPECT_EQ(b.year(), 2026);
    EXPECT_EQ(b.month(), 10);
    EXPECT_FALSE(b.empty());
}

TEST(MessageBucketTest, FromYearMonthRejectsInvalid) {
    EXPECT_THROW(MessageBucket::from_year_month(1969, 5), std::invalid_argument);
    EXPECT_THROW(MessageBucket::from_year_month(10000, 5), std::invalid_argument);
    EXPECT_THROW(MessageBucket::from_year_month(2026, 0), std::invalid_argument);
    EXPECT_THROW(MessageBucket::from_year_month(2026, 13), std::invalid_argument);
}

TEST(MessageBucketTest, FromStringValidAndInvalid) {
    auto valid = MessageBucket::from_string("202610");
    ASSERT_TRUE(valid.has_value());
    EXPECT_EQ(valid->value(), "202610");
    EXPECT_EQ(valid->year(), 2026);
    EXPECT_EQ(valid->month(), 10);

    // Invalid length
    EXPECT_FALSE(MessageBucket::from_string("20261").has_value());
    EXPECT_FALSE(MessageBucket::from_string("2026100").has_value());

    // Non-digits
    EXPECT_FALSE(MessageBucket::from_string("2026AB").has_value());
    EXPECT_FALSE(MessageBucket::from_string("2026-1").has_value());

    // Invalid month
    EXPECT_FALSE(MessageBucket::from_string("202600").has_value());
    EXPECT_FALSE(MessageBucket::from_string("202613").has_value());

    // Invalid year (< 1970)
    EXPECT_FALSE(MessageBucket::from_string("196912").has_value());
}

TEST(MessageBucketTest, FromTimePointUTC) {
    // 2026-10-15 12:00:00 UTC
    // 1792065600 seconds since Unix epoch
    auto tp = std::chrono::system_clock::time_point(std::chrono::seconds(1792065600));
    auto b = MessageBucket::from_time_point(tp);
    EXPECT_EQ(b.value(), "202610");
    EXPECT_EQ(b.year(), 2026);
    EXPECT_EQ(b.month(), 10);
}

TEST(MessageBucketTest, NextAndPreviousBucketWithRollover) {
    auto b = MessageBucket::from_year_month(2026, 12);
    auto next = b.next_bucket();
    EXPECT_EQ(next.value(), "202701");
    EXPECT_EQ(next.year(), 2027);
    EXPECT_EQ(next.month(), 1);

    auto prev = next.previous_bucket();
    EXPECT_EQ(prev.value(), "202612");
    EXPECT_EQ(prev.year(), 2026);
    EXPECT_EQ(prev.month(), 12);

    auto jan = MessageBucket::from_year_month(2026, 1);
    auto dec_prev = jan.previous_bucket();
    EXPECT_EQ(dec_prev.value(), "202512");
    EXPECT_EQ(dec_prev.year(), 2025);
    EXPECT_EQ(dec_prev.month(), 12);
}

TEST(MessageBucketTest, ComparisonAndHash) {
    auto b1 = MessageBucket::from_year_month(2026, 9);
    auto b2 = MessageBucket::from_year_month(2026, 10);
    auto b3 = MessageBucket::from_year_month(2026, 10);

    EXPECT_LT(b1, b2);
    EXPECT_EQ(b2, b3);

    std::unordered_set<MessageBucket> bucket_set;
    bucket_set.insert(b1);
    bucket_set.insert(b2);
    bucket_set.insert(b3);
    EXPECT_EQ(bucket_set.size(), 2U);
}

} // namespace securecloud::messaging::domain::test
