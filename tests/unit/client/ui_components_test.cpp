#include "ui/ui_theme.hpp"

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QUrl>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client::ui;

class UiComponentsTest : public ::testing::Test {
  protected:
    static void SetUpTestSuite() {
        if (!qobject_cast<QGuiApplication*>(QGuiApplication::instance())) {
            static int argc = 1;
            static char appName[] = "UiComponentsTest";
            static char* argv[] = {appName, nullptr};
            // Intentionally allocate on heap to avoid static destruction order issues with gtest_main
            [[maybe_unused]] static auto* app = new QGuiApplication(argc, argv);
        }
    }

    void SetUp() override { engine_.rootContext()->setContextProperty("Theme", &theme_); }

    QQmlApplicationEngine engine_;
    UiTheme theme_;
};

TEST_F(UiComponentsTest, SCButtonInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCButton.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    // Verify default properties
    EXPECT_EQ(obj->property("variant").toString(), "Primary");
    EXPECT_EQ(obj->property("busy").toBool(), false);
    EXPECT_EQ(obj->property("enabled").toBool(), true);
    EXPECT_EQ(obj->property("buttonHeight").toInt(), 38);

    // Mutation of properties
    obj->setProperty("variant", "Danger");
    EXPECT_EQ(obj->property("variant").toString(), "Danger");

    obj->setProperty("text", "Emergency Wipe");
    EXPECT_EQ(obj->property("text").toString(), "Emergency Wipe");

    obj->setProperty("busy", true);
    EXPECT_TRUE(obj->property("busy").toBool());

    delete obj;
}

TEST_F(UiComponentsTest, SCTextFieldInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCTextField.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    // Verify label and placeholder
    obj->setProperty("label", "Master Key");
    EXPECT_EQ(obj->property("label").toString(), "Master Key");

    obj->setProperty("placeholderText", "Enter 32-byte secret");
    EXPECT_EQ(obj->property("placeholderText").toString(), "Enter 32-byte secret");

    obj->setProperty("isPassword", true);
    EXPECT_TRUE(obj->property("isPassword").toBool());

    obj->setProperty("isMonospace", true);
    EXPECT_TRUE(obj->property("isMonospace").toBool());

    obj->setProperty("text", "super_secret_payload");
    EXPECT_EQ(obj->property("text").toString(), "super_secret_payload");

    obj->setProperty("errorMessage", "Key checksum verification failed");
    EXPECT_EQ(obj->property("errorMessage").toString(), "Key checksum verification failed");

    delete obj;
}

TEST_F(UiComponentsTest, SCIconButtonInstantiationAndProperties) {
    QQmlComponent component(&engine_, QUrl("qrc:/qml/controls/SCIconButton.qml"));
    ASSERT_TRUE(component.isReady()) << component.errorString().toStdString();

    auto* obj = component.create();
    ASSERT_NE(obj, nullptr);

    EXPECT_EQ(obj->property("variant").toString(), "Ghost");
    EXPECT_EQ(obj->property("size").toInt(), 34);

    obj->setProperty("iconText", "⚙");
    EXPECT_EQ(obj->property("iconText").toString(), "⚙");

    obj->setProperty("tooltipText", "Application Settings");
    EXPECT_EQ(obj->property("tooltipText").toString(), "Application Settings");

    obj->setProperty("badgeCount", 7);
    EXPECT_EQ(obj->property("badgeCount").toInt(), 7);

    obj->setProperty("active", true);
    EXPECT_TRUE(obj->property("active").toBool());

    delete obj;
}

} // namespace
