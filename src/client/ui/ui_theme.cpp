#include "ui/ui_theme.hpp"

#include <QGuiApplication>
#include <QStyleHints>

namespace securecloud::client::ui {

UiTheme::UiTheme(QObject* parent) : QObject(parent) {
    if (auto* app = qobject_cast<QGuiApplication*>(QGuiApplication::instance())) {
        if (auto* hints = app->styleHints()) {
            connect(hints, &QStyleHints::colorSchemeChanged, this, [this](Qt::ColorScheme) {
                if (theme_mode_ == ThemeMode::System) {
                    emit themeChanged();
                }
            });
        }
    }
}

ThemeMode UiTheme::themeMode() const noexcept {
    return theme_mode_;
}

void UiTheme::setThemeMode(ThemeMode mode) {
    if (theme_mode_ == mode) {
        return;
    }
    theme_mode_ = mode;
    emit themeModeChanged();
    emit themeChanged();
}

bool UiTheme::isDark() const noexcept {
    switch (theme_mode_) {
    case ThemeMode::Dark:
        return true;
    case ThemeMode::Light:
        return false;
    case ThemeMode::System:
        return resolveSystemIsDark();
    }
    return true;
}

void UiTheme::toggleTheme() {
    if (isDark()) {
        setThemeMode(ThemeMode::Light);
    } else {
        setThemeMode(ThemeMode::Dark);
    }
}

bool UiTheme::resolveSystemIsDark() const {
    if (auto* app = qobject_cast<QGuiApplication*>(QGuiApplication::instance())) {
        if (auto* hints = app->styleHints()) {
            return hints->colorScheme() == Qt::ColorScheme::Dark;
        }
    }
    // Default to Dark theme baseline for zero-trust security workstation if system query unavailable
    return true;
}

const UiTheme::Palette& UiTheme::darkPalette() {
    static const Palette palette{
        QStringLiteral("#0B0F17"),            // backgroundPrimary
        QStringLiteral("#151B26"),            // backgroundSecondary
        QStringLiteral("#1E2638"),            // backgroundElevated
        QStringLiteral("#263245"),            // borderSubtle
        QStringLiteral("#3B82F6"),            // borderFocused
        QStringLiteral("#F8FAFC"),            // textPrimary
        QStringLiteral("#94A3B8"),            // textSecondary
        QStringLiteral("#64748B"),            // textMuted
        QStringLiteral("#0F172A"),            // textInverse
        QStringLiteral("#3B82F6"),            // accentPrimary
        QStringLiteral("#2563EB"),            // accentHover
        QStringLiteral("#1D4ED8"),            // accentActive
        QStringLiteral("#10B981"),            // statusSuccess
        QStringLiteral("#F59E0B"),            // statusWarning
        QStringLiteral("#EF4444"),            // statusDanger
        QStringLiteral("#3B82F6"),            // statusInfo
        QStringLiteral("#2563EB"),            // bubbleSelf
        QStringLiteral("#1E2638"),            // bubblePeer
        QStringLiteral("#FFFFFF"),            // bubbleSelfText
        QStringLiteral("#F8FAFC"),            // bubblePeerText
        QStringLiteral("rgba(0, 0, 0, 0.40)") // shadowColor
    };
    return palette;
}

const UiTheme::Palette& UiTheme::lightPalette() {
    static const Palette palette{
        QStringLiteral("#F8FAFC"),               // backgroundPrimary
        QStringLiteral("#FFFFFF"),               // backgroundSecondary
        QStringLiteral("#FFFFFF"),               // backgroundElevated
        QStringLiteral("#E2E8F0"),               // borderSubtle
        QStringLiteral("#2563EB"),               // borderFocused
        QStringLiteral("#0F172A"),               // textPrimary
        QStringLiteral("#475569"),               // textSecondary
        QStringLiteral("#94A3B8"),               // textMuted
        QStringLiteral("#F8FAFC"),               // textInverse
        QStringLiteral("#2563EB"),               // accentPrimary
        QStringLiteral("#1D4ED8"),               // accentHover
        QStringLiteral("#1E40AF"),               // accentActive
        QStringLiteral("#059669"),               // statusSuccess
        QStringLiteral("#D97706"),               // statusWarning
        QStringLiteral("#DC2626"),               // statusDanger
        QStringLiteral("#2563EB"),               // statusInfo
        QStringLiteral("#2563EB"),               // bubbleSelf
        QStringLiteral("#F1F5F9"),               // bubblePeer
        QStringLiteral("#FFFFFF"),               // bubbleSelfText
        QStringLiteral("#0F172A"),               // bubblePeerText
        QStringLiteral("rgba(15, 23, 42, 0.08)") // shadowColor
    };
    return palette;
}

const UiTheme::Palette& UiTheme::currentPalette() const {
    return isDark() ? darkPalette() : lightPalette();
}

QString UiTheme::backgroundPrimary() const {
    return currentPalette().backgroundPrimary;
}

QString UiTheme::backgroundSecondary() const {
    return currentPalette().backgroundSecondary;
}

QString UiTheme::backgroundElevated() const {
    return currentPalette().backgroundElevated;
}

QString UiTheme::borderSubtle() const {
    return currentPalette().borderSubtle;
}

QString UiTheme::borderFocused() const {
    return currentPalette().borderFocused;
}

QString UiTheme::textPrimary() const {
    return currentPalette().textPrimary;
}

QString UiTheme::textSecondary() const {
    return currentPalette().textSecondary;
}

QString UiTheme::textMuted() const {
    return currentPalette().textMuted;
}

QString UiTheme::textInverse() const {
    return currentPalette().textInverse;
}

QString UiTheme::accentPrimary() const {
    return currentPalette().accentPrimary;
}

QString UiTheme::accentHover() const {
    return currentPalette().accentHover;
}

QString UiTheme::accentActive() const {
    return currentPalette().accentActive;
}

QString UiTheme::statusSuccess() const {
    return currentPalette().statusSuccess;
}

QString UiTheme::statusWarning() const {
    return currentPalette().statusWarning;
}

QString UiTheme::statusDanger() const {
    return currentPalette().statusDanger;
}

QString UiTheme::statusInfo() const {
    return currentPalette().statusInfo;
}

QString UiTheme::bubbleSelf() const {
    return currentPalette().bubbleSelf;
}

QString UiTheme::bubblePeer() const {
    return currentPalette().bubblePeer;
}

QString UiTheme::bubbleSelfText() const {
    return currentPalette().bubbleSelfText;
}

QString UiTheme::bubblePeerText() const {
    return currentPalette().bubblePeerText;
}

QString UiTheme::shadowColor() const {
    return currentPalette().shadowColor;
}

QString UiTheme::fontFamilyPrimary() const {
    return QStringLiteral("system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif");
}

QString UiTheme::fontFamilyMonospace() const {
    return QStringLiteral("'SF Mono', 'Cascadia Code', Consolas, 'Courier New', monospace");
}

} // namespace securecloud::client::ui
