#include "files/repository/device_revocation_provider.hpp"

#include <gtest/gtest.h>

namespace securecloud::files {
namespace {

TEST(DeviceRevocationProviderTest, ActiveDeviceIsNotRevokedByDefault) {
    DeviceRevocationProvider provider(nullptr);
    EXPECT_FALSE(provider.is_device_revoked("0191ec4d-91b4-7b4d-b6a9-8e41e3d36001"));
}

TEST(DeviceRevocationProviderTest, EmptyDeviceIdIsNotRevoked) {
    DeviceRevocationProvider provider(nullptr);
    EXPECT_FALSE(provider.is_device_revoked(""));
}

TEST(DeviceRevocationProviderTest, MarkDeviceRevokedAndClear) {
    DeviceRevocationProvider provider(nullptr);
    const std::string dev_id = "0191ec4d-91b4-7b4d-b6a9-8e41e3d36002";

    EXPECT_FALSE(provider.is_device_revoked(dev_id));

    provider.mark_device_revoked(dev_id);
    EXPECT_TRUE(provider.is_device_revoked(dev_id));

    // Another device is unaffected
    EXPECT_FALSE(provider.is_device_revoked("0191ec4d-91b4-7b4d-b6a9-8e41e3d36003"));

    provider.clear_revocation(dev_id);
    EXPECT_FALSE(provider.is_device_revoked(dev_id));
}

} // namespace
} // namespace securecloud::files
