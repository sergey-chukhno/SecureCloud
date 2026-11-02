#include "query/audit_page_cursor.hpp"

#include <gtest/gtest.h>

namespace securecloud::audit::query::testing {

class AuditPageCursorTest : public ::testing::Test {
  protected:
    AuditQueryFilter build_sample_filter() {
        AuditQueryFilter filter;
        filter.start_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710000000000LL));
        filter.end_occurred_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(1710086400000LL));
        filter.producer_services = {domain::ProducerService::Auth, domain::ProducerService::Gateway};
        filter.event_types = {"user.login", "user.logout"};
        filter.severities = {domain::Severity::Info, domain::Severity::Security};
        filter.actor_type = domain::ActorType::User;
        filter.actor_id = "user-123";
        filter.sort_order = SortOrder::Descending;
        return filter;
    }
};

TEST_F(AuditPageCursorTest, EncodeAndDecodeValidToken) {
    auto filter = build_sample_filter();
    auto filter_hash = AuditPageCursorCodec::compute_filter_hash(filter);

    AuditPageCursor cursor;
    cursor.last_occurred_at_ms = 1710050000000LL;
    cursor.last_producer_service = "auth";
    cursor.last_event_type = "user.login";
    cursor.last_event_id = domain::EventId::from_string("018f6e4a-7b3c-7000-8000-000000000001").value();
    cursor.sort_order = SortOrder::Descending;
    cursor.filter_hash = filter_hash;

    std::string token = AuditPageCursorCodec::encode(cursor);
    EXPECT_FALSE(token.empty());

    auto decoded_opt = AuditPageCursorCodec::decode(token, filter_hash);
    ASSERT_TRUE(decoded_opt.has_value());

    const auto& decoded = *decoded_opt;
    EXPECT_EQ(decoded.last_occurred_at_ms, cursor.last_occurred_at_ms);
    EXPECT_EQ(decoded.last_producer_service, cursor.last_producer_service);
    EXPECT_EQ(decoded.last_event_type, cursor.last_event_type);
    EXPECT_EQ(decoded.last_event_id, cursor.last_event_id);
    EXPECT_EQ(decoded.sort_order, cursor.sort_order);
    EXPECT_EQ(decoded.filter_hash, filter_hash);
}

TEST_F(AuditPageCursorTest, RejectsTamperedOrMismatchedFilterHash) {
    auto filter1 = build_sample_filter();
    auto filter_hash1 = AuditPageCursorCodec::compute_filter_hash(filter1);

    AuditPageCursor cursor;
    cursor.last_occurred_at_ms = 1710050000000LL;
    cursor.last_producer_service = "auth";
    cursor.last_event_type = "user.login";
    cursor.last_event_id = domain::EventId::from_string("018f6e4a-7b3c-7000-8000-000000000001").value();
    cursor.sort_order = SortOrder::Descending;
    cursor.filter_hash = filter_hash1;

    std::string token = AuditPageCursorCodec::encode(cursor);

    // Modify filter parameter -> produces different filter_hash
    auto filter2 = filter1;
    filter2.event_types = {"user.login"}; // Removed user.logout
    auto filter_hash2 = AuditPageCursorCodec::compute_filter_hash(filter2);

    EXPECT_NE(filter_hash1, filter_hash2);

    // Decode with modified filter_hash fails closed
    auto decoded_opt = AuditPageCursorCodec::decode(token, filter_hash2);
    EXPECT_FALSE(decoded_opt.has_value());
}

} // namespace securecloud::audit::query::testing