#pragma once

#include <QObject>
#include <QRect>
#include <QString>

namespace securecloud::client::ui {

/**
 * @brief Manages desktop window geometry, sizing bounds, responsive breakpoints,
 *        and state persistence across application launches.
 */
class WindowStateManager : public QObject {
    Q_OBJECT

    Q_PROPERTY(int width READ width WRITE setWidth NOTIFY geometryChanged)
    Q_PROPERTY(int height READ height WRITE setHeight NOTIFY geometryChanged)
    Q_PROPERTY(int x READ x WRITE setX NOTIFY geometryChanged)
    Q_PROPERTY(int y READ y WRITE setY NOTIFY geometryChanged)
    Q_PROPERTY(bool isMaximized READ isMaximized WRITE setIsMaximized NOTIFY isMaximizedChanged)

    Q_PROPERTY(int minWidth READ minWidth CONSTANT)
    Q_PROPERTY(int minHeight READ minHeight CONSTANT)
    Q_PROPERTY(int defaultWidth READ defaultWidth CONSTANT)
    Q_PROPERTY(int defaultHeight READ defaultHeight CONSTANT)

  public:
    static constexpr int kMinWidth = 960;
    static constexpr int kMinHeight = 640;
    static constexpr int kDefaultWidth = 1200;
    static constexpr int kDefaultHeight = 800;

    explicit WindowStateManager(QString storagePath = QString(), QObject* parent = nullptr);
    ~WindowStateManager() override = default;

    [[nodiscard]] int width() const noexcept { return width_; }
    void setWidth(int w);

    [[nodiscard]] int height() const noexcept { return height_; }
    void setHeight(int h);

    [[nodiscard]] int x() const noexcept { return x_; }
    void setX(int val);

    [[nodiscard]] int y() const noexcept { return y_; }
    void setY(int val);

    [[nodiscard]] bool isMaximized() const noexcept { return is_maximized_; }
    void setIsMaximized(bool maximized);

    [[nodiscard]] int minWidth() const noexcept { return kMinWidth; }
    [[nodiscard]] int minHeight() const noexcept { return kMinHeight; }
    [[nodiscard]] int defaultWidth() const noexcept { return kDefaultWidth; }
    [[nodiscard]] int defaultHeight() const noexcept { return kDefaultHeight; }

    // Q_INVOKABLE Persistence & Sanitization
    Q_INVOKABLE void loadGeometry();
    Q_INVOKABLE void saveGeometry(int w, int h, int posX, int posY, bool maximized);
    [[nodiscard]] Q_INVOKABLE QRect sanitizeGeometry(int posX, int posY, int w, int h) const;

  signals:
    void geometryChanged();
    void isMaximizedChanged();

  private:
    [[nodiscard]] QString effectiveStoragePath() const;

    QString custom_storage_path_;
    int width_{kDefaultWidth};
    int height_{kDefaultHeight};
    int x_{100};
    int y_{100};
    bool is_maximized_{false};
};

} // namespace securecloud::client::ui
