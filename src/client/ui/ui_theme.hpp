#pragma once

#include <QObject>
#include <QString>

namespace securecloud::client::ui {

/**
 * @brief Theme mode preference controlling visual presentation.
 */
enum class ThemeMode { System = 0, Dark = 1, Light = 2 };

/**
 * @brief Centralized design tokens and dynamic palette engine for the SecureCloud Client.
 *
 * Exposes color, typography, spacing, radius, and duration tokens to both C++
 * and declarative QML, with automatic dark/light theme switching and OS sync.
 */
class UiTheme : public QObject {
    Q_OBJECT

    Q_PROPERTY(ThemeMode themeMode READ themeMode WRITE setThemeMode NOTIFY themeModeChanged)
    Q_PROPERTY(int themeModeInt READ themeModeInt NOTIFY themeModeChanged)
    Q_PROPERTY(bool isDark READ isDark NOTIFY themeChanged)

    // Surface & Background Colors
    Q_PROPERTY(QString backgroundPrimary READ backgroundPrimary NOTIFY themeChanged)
    Q_PROPERTY(QString backgroundSecondary READ backgroundSecondary NOTIFY themeChanged)
    Q_PROPERTY(QString backgroundElevated READ backgroundElevated NOTIFY themeChanged)

    // Border Colors
    Q_PROPERTY(QString borderSubtle READ borderSubtle NOTIFY themeChanged)
    Q_PROPERTY(QString borderFocused READ borderFocused NOTIFY themeChanged)
    Q_PROPERTY(QString borderFocus READ borderFocused NOTIFY themeChanged)

    // Typography Colors
    Q_PROPERTY(QString textPrimary READ textPrimary NOTIFY themeChanged)
    Q_PROPERTY(QString textSecondary READ textSecondary NOTIFY themeChanged)
    Q_PROPERTY(QString textMuted READ textMuted NOTIFY themeChanged)
    Q_PROPERTY(QString textInverse READ textInverse NOTIFY themeChanged)

    // Accent & Action Colors
    Q_PROPERTY(QString accentPrimary READ accentPrimary NOTIFY themeChanged)
    Q_PROPERTY(QString accentSecondary READ accentSecondary NOTIFY themeChanged)
    Q_PROPERTY(QString accentHover READ accentHover NOTIFY themeChanged)
    Q_PROPERTY(QString accentActive READ accentActive NOTIFY themeChanged)

    // Security & Status Signals
    Q_PROPERTY(QString statusSuccess READ statusSuccess NOTIFY themeChanged)
    Q_PROPERTY(QString statusWarning READ statusWarning NOTIFY themeChanged)
    Q_PROPERTY(QString statusDanger READ statusDanger NOTIFY themeChanged)
    Q_PROPERTY(QString statusInfo READ statusInfo NOTIFY themeChanged)

    // Chat Message Bubbles
    Q_PROPERTY(QString bubbleSelf READ bubbleSelf NOTIFY themeChanged)
    Q_PROPERTY(QString bubblePeer READ bubblePeer NOTIFY themeChanged)
    Q_PROPERTY(QString bubbleSelfText READ bubbleSelfText NOTIFY themeChanged)
    Q_PROPERTY(QString bubblePeerText READ bubblePeerText NOTIFY themeChanged)

    // Shadows & Elevation
    Q_PROPERTY(QString shadowColor READ shadowColor NOTIFY themeChanged)

    // Typography Scales (Point Sizes)
    Q_PROPERTY(int fontMicro READ fontMicro CONSTANT)
    Q_PROPERTY(int fontCaption READ fontCaption CONSTANT)
    Q_PROPERTY(int fontBody READ fontBody CONSTANT)
    Q_PROPERTY(int fontSubtitle READ fontSubtitle CONSTANT)
    Q_PROPERTY(int fontHeader READ fontSubtitle CONSTANT)
    Q_PROPERTY(int fontTitle READ fontTitle CONSTANT)
    Q_PROPERTY(int fontHeadline READ fontHeadline CONSTANT)
    Q_PROPERTY(int fontDisplay READ fontDisplay CONSTANT)

    // Font Families
    Q_PROPERTY(QString fontFamilyPrimary READ fontFamilyPrimary CONSTANT)
    Q_PROPERTY(QString fontFamilyMonospace READ fontFamilyMonospace CONSTANT)

    // Spacing Metrics (Pixels)
    Q_PROPERTY(int space2 READ space2 CONSTANT)
    Q_PROPERTY(int space4 READ space4 CONSTANT)
    Q_PROPERTY(int space8 READ space8 CONSTANT)
    Q_PROPERTY(int space12 READ space12 CONSTANT)
    Q_PROPERTY(int space16 READ space16 CONSTANT)
    Q_PROPERTY(int space24 READ space24 CONSTANT)
    Q_PROPERTY(int space32 READ space32 CONSTANT)

    // Corner Radii (Pixels)
    Q_PROPERTY(int radiusSmall READ radiusSmall CONSTANT)
    Q_PROPERTY(int radiusMedium READ radiusMedium CONSTANT)
    Q_PROPERTY(int radiusLarge READ radiusLarge CONSTANT)
    Q_PROPERTY(int radiusRound READ radiusRound CONSTANT)

    // Animation Durations (Milliseconds)
    Q_PROPERTY(int durationFast READ durationFast CONSTANT)
    Q_PROPERTY(int durationNormal READ durationNormal CONSTANT)
    Q_PROPERTY(int durationSlow READ durationSlow CONSTANT)

  public:
    explicit UiTheme(QObject* parent = nullptr);
    ~UiTheme() override = default;

    // Theme Mode Accessors
    [[nodiscard]] ThemeMode themeMode() const noexcept;
    [[nodiscard]] int themeModeInt() const noexcept { return static_cast<int>(theme_mode_); }
    void setThemeMode(ThemeMode mode);
    Q_INVOKABLE void setThemeMode(int mode);
    [[nodiscard]] bool isDark() const noexcept;

    // Q_INVOKABLE Actions
    Q_INVOKABLE void toggleTheme();

    // Color Accessors
    [[nodiscard]] QString backgroundPrimary() const;
    [[nodiscard]] QString backgroundSecondary() const;
    [[nodiscard]] QString backgroundElevated() const;

    [[nodiscard]] QString borderSubtle() const;
    [[nodiscard]] QString borderFocused() const;

    [[nodiscard]] QString textPrimary() const;
    [[nodiscard]] QString textSecondary() const;
    [[nodiscard]] QString textMuted() const;
    [[nodiscard]] QString textInverse() const;

    [[nodiscard]] QString accentPrimary() const;
    [[nodiscard]] QString accentSecondary() const { return accentHover(); }
    [[nodiscard]] QString accentHover() const;
    [[nodiscard]] QString accentActive() const;

    [[nodiscard]] QString statusSuccess() const;
    [[nodiscard]] QString statusWarning() const;
    [[nodiscard]] QString statusDanger() const;
    [[nodiscard]] QString statusInfo() const;

    [[nodiscard]] QString bubbleSelf() const;
    [[nodiscard]] QString bubblePeer() const;
    [[nodiscard]] QString bubbleSelfText() const;
    [[nodiscard]] QString bubblePeerText() const;

    [[nodiscard]] QString shadowColor() const;

    // Typography Metrics Accessors
    [[nodiscard]] int fontMicro() const noexcept { return 10; }
    [[nodiscard]] int fontCaption() const noexcept { return 11; }
    [[nodiscard]] int fontBody() const noexcept { return 13; }
    [[nodiscard]] int fontSubtitle() const noexcept { return 15; }
    [[nodiscard]] int fontTitle() const noexcept { return 18; }
    [[nodiscard]] int fontHeadline() const noexcept { return 24; }
    [[nodiscard]] int fontDisplay() const noexcept { return 28; }

    [[nodiscard]] QString fontFamilyPrimary() const;
    [[nodiscard]] QString fontFamilyMonospace() const;

    // Spacing Metrics Accessors
    [[nodiscard]] int space2() const noexcept { return 2; }
    [[nodiscard]] int space4() const noexcept { return 4; }
    [[nodiscard]] int space8() const noexcept { return 8; }
    [[nodiscard]] int space12() const noexcept { return 12; }
    [[nodiscard]] int space16() const noexcept { return 16; }
    [[nodiscard]] int space24() const noexcept { return 24; }
    [[nodiscard]] int space32() const noexcept { return 32; }

    // Corner Radii Accessors
    [[nodiscard]] int radiusSmall() const noexcept { return 6; }
    [[nodiscard]] int radiusMedium() const noexcept { return 10; }
    [[nodiscard]] int radiusLarge() const noexcept { return 16; }
    [[nodiscard]] int radiusRound() const noexcept { return 9999; }

    // Duration Accessors
    [[nodiscard]] int durationFast() const noexcept { return 150; }
    [[nodiscard]] int durationNormal() const noexcept { return 250; }
    [[nodiscard]] int durationSlow() const noexcept { return 400; }

  signals:
    void themeChanged();
    void themeModeChanged();

  private:
    struct Palette {
        QString backgroundPrimary;
        QString backgroundSecondary;
        QString backgroundElevated;
        QString borderSubtle;
        QString borderFocused;
        QString textPrimary;
        QString textSecondary;
        QString textMuted;
        QString textInverse;
        QString accentPrimary;
        QString accentHover;
        QString accentActive;
        QString statusSuccess;
        QString statusWarning;
        QString statusDanger;
        QString statusInfo;
        QString bubbleSelf;
        QString bubblePeer;
        QString bubbleSelfText;
        QString bubblePeerText;
        QString shadowColor;
    };

    static const Palette& darkPalette();
    static const Palette& lightPalette();
    [[nodiscard]] const Palette& currentPalette() const;
    [[nodiscard]] bool resolveSystemIsDark() const;

    ThemeMode theme_mode_{ThemeMode::Dark};
};

} // namespace securecloud::client::ui
