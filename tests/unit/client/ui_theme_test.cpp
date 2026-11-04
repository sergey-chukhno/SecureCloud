#include "ui/ui_theme.hpp"

#include <QColor>
#include <QSignalSpy>
#include <gtest/gtest.h>

namespace {

using namespace securecloud::client::ui;

TEST(UiThemeTest, DefaultModeIsDarkAndConsistent) {
    UiTheme theme;

    EXPECT_EQ(theme.themeMode(), ThemeMode::Dark);
    EXPECT_TRUE(theme.isDark());

    // Dark palette baseline assertions
    EXPECT_EQ(theme.backgroundPrimary(), "#0B0F17");
    EXPECT_EQ(theme.backgroundSecondary(), "#151B26");
    EXPECT_EQ(theme.backgroundElevated(), "#1E2638");
    EXPECT_EQ(theme.borderSubtle(), "#263245");
    EXPECT_EQ(theme.borderFocused(), "#3B82F6");
    EXPECT_EQ(theme.textPrimary(), "#F8FAFC");
    EXPECT_EQ(theme.textSecondary(), "#94A3B8");
    EXPECT_EQ(theme.textMuted(), "#64748B");
    EXPECT_EQ(theme.textInverse(), "#0F172A");
    EXPECT_EQ(theme.accentPrimary(), "#3B82F6");

    // Security indicator signals
    EXPECT_EQ(theme.statusSuccess(), "#10B981");
    EXPECT_EQ(theme.statusWarning(), "#F59E0B");
    EXPECT_EQ(theme.statusDanger(), "#EF4444");
    EXPECT_EQ(theme.statusInfo(), "#3B82F6");

    // Chat message bubble colors
    EXPECT_EQ(theme.bubbleSelf(), "#2563EB");
    EXPECT_EQ(theme.bubblePeer(), "#1E2638");
    EXPECT_EQ(theme.bubbleSelfText(), "#FFFFFF");
    EXPECT_EQ(theme.bubblePeerText(), "#F8FAFC");
}

TEST(UiThemeTest, LightModePaletteAndSwitching) {
    UiTheme theme;

    QSignalSpy themeSpy(&theme, &UiTheme::themeChanged);
    QSignalSpy modeSpy(&theme, &UiTheme::themeModeChanged);

    theme.setThemeMode(ThemeMode::Light);

    EXPECT_EQ(themeSpy.count(), 1);
    EXPECT_EQ(modeSpy.count(), 1);
    EXPECT_EQ(theme.themeMode(), ThemeMode::Light);
    EXPECT_FALSE(theme.isDark());

    // Light palette assertions
    EXPECT_EQ(theme.backgroundPrimary(), "#F8FAFC");
    EXPECT_EQ(theme.backgroundSecondary(), "#FFFFFF");
    EXPECT_EQ(theme.backgroundElevated(), "#FFFFFF");
    EXPECT_EQ(theme.borderSubtle(), "#E2E8F0");
    EXPECT_EQ(theme.borderFocused(), "#2563EB");
    EXPECT_EQ(theme.textPrimary(), "#0F172A");
    EXPECT_EQ(theme.textSecondary(), "#475569");
    EXPECT_EQ(theme.textMuted(), "#94A3B8");
    EXPECT_EQ(theme.textInverse(), "#F8FAFC");
    EXPECT_EQ(theme.accentPrimary(), "#2563EB");

    // Light-adapted security status signals
    EXPECT_EQ(theme.statusSuccess(), "#059669");
    EXPECT_EQ(theme.statusWarning(), "#D97706");
    EXPECT_EQ(theme.statusDanger(), "#DC2626");

    // Chat message bubbles
    EXPECT_EQ(theme.bubbleSelf(), "#2563EB");
    EXPECT_EQ(theme.bubblePeer(), "#F1F5F9");
    EXPECT_EQ(theme.bubbleSelfText(), "#FFFFFF");
    EXPECT_EQ(theme.bubblePeerText(), "#0F172A");

    // Setting same mode is idempotent
    theme.setThemeMode(ThemeMode::Light);
    EXPECT_EQ(themeSpy.count(), 1);
    EXPECT_EQ(modeSpy.count(), 1);
}

TEST(UiThemeTest, ToggleThemeFlipsBetweenModes) {
    UiTheme theme;
    EXPECT_TRUE(theme.isDark());

    theme.toggleTheme();
    EXPECT_FALSE(theme.isDark());
    EXPECT_EQ(theme.themeMode(), ThemeMode::Light);

    theme.toggleTheme();
    EXPECT_TRUE(theme.isDark());
    EXPECT_EQ(theme.themeMode(), ThemeMode::Dark);
}

TEST(UiThemeTest, PaletteColorsAreValidQColors) {
    UiTheme theme;

    auto assert_valid_colors = [](const UiTheme& t) {
        EXPECT_TRUE(QColor(t.backgroundPrimary()).isValid());
        EXPECT_TRUE(QColor(t.backgroundSecondary()).isValid());
        EXPECT_TRUE(QColor(t.backgroundElevated()).isValid());
        EXPECT_TRUE(QColor(t.borderSubtle()).isValid());
        EXPECT_TRUE(QColor(t.borderFocused()).isValid());
        EXPECT_TRUE(QColor(t.textPrimary()).isValid());
        EXPECT_TRUE(QColor(t.textSecondary()).isValid());
        EXPECT_TRUE(QColor(t.textMuted()).isValid());
        EXPECT_TRUE(QColor(t.textInverse()).isValid());
        EXPECT_TRUE(QColor(t.accentPrimary()).isValid());
        EXPECT_TRUE(QColor(t.accentHover()).isValid());
        EXPECT_TRUE(QColor(t.accentActive()).isValid());
        EXPECT_TRUE(QColor(t.statusSuccess()).isValid());
        EXPECT_TRUE(QColor(t.statusWarning()).isValid());
        EXPECT_TRUE(QColor(t.statusDanger()).isValid());
        EXPECT_TRUE(QColor(t.statusInfo()).isValid());
        EXPECT_TRUE(QColor(t.bubbleSelf()).isValid());
        EXPECT_TRUE(QColor(t.bubblePeer()).isValid());
        EXPECT_TRUE(QColor(t.bubbleSelfText()).isValid());
        EXPECT_TRUE(QColor(t.bubblePeerText()).isValid());
    };

    // Dark Palette validation
    theme.setThemeMode(ThemeMode::Dark);
    assert_valid_colors(theme);

    // Light Palette validation
    theme.setThemeMode(ThemeMode::Light);
    assert_valid_colors(theme);
}

TEST(UiThemeTest, TypographyAndLayoutMetricsAreMonotonic) {
    UiTheme theme;

    // Typography point size hierarchy
    EXPECT_LT(theme.fontCaption(), theme.fontBody());
    EXPECT_LT(theme.fontBody(), theme.fontSubtitle());
    EXPECT_LT(theme.fontSubtitle(), theme.fontTitle());
    EXPECT_LT(theme.fontTitle(), theme.fontHeadline());

    // Font families
    EXPECT_FALSE(theme.fontFamilyPrimary().isEmpty());
    EXPECT_FALSE(theme.fontFamilyMonospace().isEmpty());
    EXPECT_NE(theme.fontFamilyPrimary(), theme.fontFamilyMonospace());

    // Spacing scale (multiples of 2/4)
    EXPECT_EQ(theme.space2(), 2);
    EXPECT_EQ(theme.space4(), 4);
    EXPECT_EQ(theme.space8(), 8);
    EXPECT_EQ(theme.space12(), 12);
    EXPECT_EQ(theme.space16(), 16);
    EXPECT_EQ(theme.space24(), 24);
    EXPECT_EQ(theme.space32(), 32);

    // Corner radii
    EXPECT_LT(theme.radiusSmall(), theme.radiusMedium());
    EXPECT_LT(theme.radiusMedium(), theme.radiusLarge());
    EXPECT_LT(theme.radiusLarge(), theme.radiusRound());

    // Animation durations
    EXPECT_LT(theme.durationFast(), theme.durationNormal());
    EXPECT_LT(theme.durationNormal(), theme.durationSlow());
}

} // namespace
