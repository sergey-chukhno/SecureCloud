#include <gtest/gtest.h>
#include <pqxx/pqxx>

TEST(PqxxSmokeTest, TypeVisibilityAndLinkage) {
    pqxx::zview view("securecloud_test_string");
    EXPECT_EQ(view.size(), 23);
    EXPECT_STREQ(view.c_str(), "securecloud_test_string");
}
