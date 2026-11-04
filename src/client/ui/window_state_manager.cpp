#include "ui/window_state_manager.hpp"

#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QScreen>
#include <QStandardPaths>
#include <algorithm>

namespace securecloud::client::ui {

WindowStateManager::WindowStateManager(QString storagePath, QObject* parent)
    : QObject(parent), custom_storage_path_(std::move(storagePath)) {
    loadGeometry();
}

void WindowStateManager::setWidth(int w) {
    const int clamped = std::max(kMinWidth, w);
    if (width_ != clamped) {
        width_ = clamped;
        emit geometryChanged();
    }
}

void WindowStateManager::setHeight(int h) {
    const int clamped = std::max(kMinHeight, h);
    if (height_ != clamped) {
        height_ = clamped;
        emit geometryChanged();
    }
}

void WindowStateManager::setX(int val) {
    if (x_ != val) {
        x_ = val;
        emit geometryChanged();
    }
}

void WindowStateManager::setY(int val) {
    if (y_ != val) {
        y_ = val;
        emit geometryChanged();
    }
}

void WindowStateManager::setIsMaximized(bool maximized) {
    if (is_maximized_ != maximized) {
        is_maximized_ = maximized;
        emit isMaximizedChanged();
    }
}

QString WindowStateManager::effectiveStoragePath() const {
    if (!custom_storage_path_.isEmpty()) {
        return custom_storage_path_;
    }
    const QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    return baseDir + QStringLiteral("/window_state.json");
}

QRect WindowStateManager::sanitizeGeometry(int posX, int posY, int w, int h) const {
    const int clampedW = std::max(kMinWidth, w);
    const int clampedH = std::max(kMinHeight, h);

    if (auto* app = qobject_cast<QGuiApplication*>(QGuiApplication::instance())) {
        const auto screens = app->screens();
        if (!screens.isEmpty()) {
            const QRect candidate(posX, posY, clampedW, clampedH);
            bool intersectsVisibleScreen = false;

            for (const auto* screen : screens) {
                if (screen) {
                    const QRect screenGeo = screen->availableGeometry();
                    const QRect intersection = candidate.intersected(screenGeo);
                    // Ensure at least 120x120 pixels of window is visible
                    if (intersection.width() >= 120 && intersection.height() >= 120) {
                        intersectsVisibleScreen = true;
                        break;
                    }
                }
            }

            if (intersectsVisibleScreen) {
                return candidate;
            }

            // Window was positioned offscreen or on a disconnected monitor; center on primary screen
            const QScreen* primary = app->primaryScreen();
            if (!primary && !screens.isEmpty()) {
                primary = screens.first();
            }

            if (primary) {
                const QRect screenGeo = primary->availableGeometry();
                const int centerX = screenGeo.x() + std::max(0, (screenGeo.width() - clampedW) / 2);
                const int centerY = screenGeo.y() + std::max(0, (screenGeo.height() - clampedH) / 2);
                return QRect(centerX, centerY, clampedW, clampedH);
            }
        }
    }

    return QRect(std::max(0, posX), std::max(0, posY), clampedW, clampedH);
}

void WindowStateManager::loadGeometry() {
    const QString path = effectiveStoragePath();
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        // Fall back to sanitized defaults centered on primary display
        const QRect sanitized = sanitizeGeometry(100, 100, kDefaultWidth, kDefaultHeight);
        width_ = sanitized.width();
        height_ = sanitized.height();
        x_ = sanitized.x();
        y_ = sanitized.y();
        is_maximized_ = false;
        return;
    }

    const QByteArray data = file.readAll();
    file.close();

    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        return;
    }

    const QJsonObject obj = doc.object();
    const int readW = obj.value(QStringLiteral("width")).toInt(kDefaultWidth);
    const int readH = obj.value(QStringLiteral("height")).toInt(kDefaultHeight);
    const int readX = obj.value(QStringLiteral("x")).toInt(100);
    const int readY = obj.value(QStringLiteral("y")).toInt(100);
    const bool readMax = obj.value(QStringLiteral("isMaximized")).toBool(false);

    const QRect sanitized = sanitizeGeometry(readX, readY, readW, readH);
    width_ = sanitized.width();
    height_ = sanitized.height();
    x_ = sanitized.x();
    y_ = sanitized.y();
    is_maximized_ = readMax;

    emit geometryChanged();
    emit isMaximizedChanged();
}

void WindowStateManager::saveGeometry(int w, int h, int posX, int posY, bool maximized) {
    if (!maximized) {
        width_ = std::max(kMinWidth, w);
        height_ = std::max(kMinHeight, h);
        x_ = posX;
        y_ = posY;
    }
    is_maximized_ = maximized;

    const QString path = effectiveStoragePath();
    const QFileInfo fileInfo(path);
    QDir().mkpath(fileInfo.absolutePath());

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return;
    }

    QJsonObject obj;
    obj.insert(QStringLiteral("width"), width_);
    obj.insert(QStringLiteral("height"), height_);
    obj.insert(QStringLiteral("x"), x_);
    obj.insert(QStringLiteral("y"), y_);
    obj.insert(QStringLiteral("isMaximized"), is_maximized_);

    const QJsonDocument doc(obj);
    file.write(doc.toJson(QJsonDocument::Compact));
    file.close();

    emit geometryChanged();
    emit isMaximizedChanged();
}

} // namespace securecloud::client::ui

