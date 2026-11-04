#include "ui/window_state_manager.hpp"

#include <QFile>
#include <QGuiApplication>
#include <QTemporaryDir>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client::ui;

class WindowStateManagerTest : public ::testing::Test {
  protected:
    static void SetUpTestSuite() {
        if (!qobject_cast<QGuiApplication*>(QGuiApplication::instance())) {
            static int argc = 1;
            static char appName[] = "WindowStateManagerTest";
            static char* argv[] = {appName, nullptr};
            [[maybe_unused]] static auto* app = new QGuiApplication(argc, argv);
        }
    }
};

TEST_F(WindowStateManagerTest, DefaultValuesAndConstants) {
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());
    const QString nonExistentFile = tempDir.filePath(QStringLiteral("non_existent_state.json"));

    WindowStateManager manager(nonExistentFile);

    EXPECT_EQ(manager.minWidth(), WindowStateManager::kMinWidth);
    EXPECT_EQ(manager.minHeight(), WindowStateManager::kMinHeight);
    EXPECT_EQ(manager.defaultWidth(), WindowStateManager::kDefaultWidth);
    EXPECT_EQ(manager.defaultHeight(), WindowStateManager::kDefaultHeight);

    EXPECT_GE(manager.width(), WindowStateManager::kMinWidth);
    EXPECT_GE(manager.height(), WindowStateManager::kMinHeight);
    EXPECT_FALSE(manager.isMaximized());
}

TEST_F(WindowStateManagerTest, DimensionClampingAndSetters) {
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());
    const QString tempFile = tempDir.filePath(QStringLiteral("state_clamp.json"));

    WindowStateManager manager(tempFile);

    // Below minimum width
    manager.setWidth(600);
    EXPECT_EQ(manager.width(), WindowStateManager::kMinWidth);

    // Above minimum width
    manager.setWidth(1400);
    EXPECT_EQ(manager.width(), 1400);

    // Below minimum height
    manager.setHeight(400);
    EXPECT_EQ(manager.height(), WindowStateManager::kMinHeight);

    // Above minimum height
    manager.setHeight(900);
    EXPECT_EQ(manager.height(), 900);

    // Position and maximized state
    manager.setX(220);
    EXPECT_EQ(manager.x(), 220);

    manager.setY(180);
    EXPECT_EQ(manager.y(), 180);

    manager.setIsMaximized(true);
    EXPECT_TRUE(manager.isMaximized());
}

TEST_F(WindowStateManagerTest, SanitizeGeometry) {
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());
    const QString tempFile = tempDir.filePath(QStringLiteral("state_sanitize.json"));

    WindowStateManager manager(tempFile);

    // Verify small dimensions are clamped
    const QRect rect = manager.sanitizeGeometry(100, 100, 400, 300);
    EXPECT_GE(rect.width(), WindowStateManager::kMinWidth);
    EXPECT_GE(rect.height(), WindowStateManager::kMinHeight);

    // Verify offscreen coordinates are handled and do not result in negative or inaccessible bounds
    const QRect offscreen = manager.sanitizeGeometry(-10000, -10000, 1200, 800);
    EXPECT_GE(offscreen.width(), WindowStateManager::kMinWidth);
    EXPECT_GE(offscreen.height(), WindowStateManager::kMinHeight);
}

TEST_F(WindowStateManagerTest, PersistenceRoundtrip) {
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());
    const QString tempFile = tempDir.filePath(QStringLiteral("state_roundtrip.json"));

    {
        WindowStateManager manager1(tempFile);
        manager1.saveGeometry(1300, 880, 240, 160, false);
    }

    {
        WindowStateManager manager2(tempFile);
        EXPECT_EQ(manager2.width(), 1300);
        EXPECT_EQ(manager2.height(), 880);
        EXPECT_EQ(manager2.x(), 240);
        EXPECT_EQ(manager2.y(), 160);
        EXPECT_FALSE(manager2.isMaximized());
    }
}

TEST_F(WindowStateManagerTest, MaximizedStatePersistence) {
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());
    const QString tempFile = tempDir.filePath(QStringLiteral("state_maximized.json"));

    {
        WindowStateManager manager1(tempFile);
        manager1.saveGeometry(1200, 800, 100, 100, true);
    }

    {
        WindowStateManager manager2(tempFile);
        EXPECT_TRUE(manager2.isMaximized());
    }
}

TEST_F(WindowStateManagerTest, CorruptJsonFileHandling) {
    QTemporaryDir tempDir;
    ASSERT_TRUE(tempDir.isValid());
    const QString corruptFile = tempDir.filePath(QStringLiteral("corrupt_state.json"));

    // Write malformed JSON
    {
        QFile file(corruptFile);
        ASSERT_TRUE(file.open(QIODevice::WriteOnly));
        file.write("{ invalid json non-closing object");
        file.close();
    }

    WindowStateManager manager(corruptFile);
    EXPECT_GE(manager.width(), WindowStateManager::kMinWidth);
    EXPECT_GE(manager.height(), WindowStateManager::kMinHeight);
    EXPECT_FALSE(manager.isMaximized());
}

} // namespace
