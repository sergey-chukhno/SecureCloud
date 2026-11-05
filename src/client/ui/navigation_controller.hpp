#pragma once

#include <QObject>
#include <QString>
#include <vector>

namespace securecloud::client::ui {

class NavigationController : public QObject {
    Q_OBJECT
    Q_PROPERTY(NavigationState currentState READ currentState NOTIFY stateChanged)
    Q_PROPERTY(QString currentViewName READ currentViewName NOTIFY stateChanged)
    Q_PROPERTY(QString activeWorkspaceSection READ activeWorkspaceSection NOTIFY workspaceSectionChanged)
    Q_PROPERTY(bool canNavigateBack READ canNavigateBack NOTIFY stateChanged)
    Q_PROPERTY(bool isAuthenticated READ isAuthenticated WRITE setAuthenticated NOTIFY authenticationChanged)

  public:
    enum class NavigationState {
        Unauthenticated = 0,
        MfaVerification,
        MainWorkspace,
        Settings,
        EmergencyMode,
        StyleGuide
    };
    Q_ENUM(NavigationState)

    enum class WorkspaceSection { Messages = 0, Contacts = 1, Files = 2 };
    Q_ENUM(WorkspaceSection)

    explicit NavigationController(QObject* parent = nullptr);
    ~NavigationController() override = default;

    NavigationController(const NavigationController&) = delete;
    NavigationController& operator=(const NavigationController&) = delete;

    [[nodiscard]] NavigationState currentState() const noexcept { return currentState_; }
    [[nodiscard]] QString currentViewName() const;
    [[nodiscard]] WorkspaceSection currentWorkspaceSection() const noexcept { return workspaceSection_; }
    [[nodiscard]] QString activeWorkspaceSection() const;
    [[nodiscard]] bool canNavigateBack() const noexcept { return !history_.empty(); }
    [[nodiscard]] bool isAuthenticated() const noexcept { return isAuthenticated_; }

    Q_INVOKABLE bool navigateTo(NavigationState state);
    Q_INVOKABLE bool navigateToSection(const QString& sectionName);
    Q_INVOKABLE bool navigateBack();
    Q_INVOKABLE void reset(NavigationState initial_state = NavigationState::Unauthenticated);

    void setAuthenticated(bool authenticated);

    static QString to_view_name(NavigationState state);
    static QString to_section_name(WorkspaceSection section);

  signals:
    void stateChanged(NavigationState newState);
    void workspaceSectionChanged(const QString& newSection);
    void authenticationChanged(bool authenticated);
    void navigationDenied(NavigationState requestedState, const QString& reason);

  private:
    [[nodiscard]] bool is_restricted_state(NavigationState state) const noexcept;

    NavigationState currentState_{NavigationState::Unauthenticated};
    WorkspaceSection workspaceSection_{WorkspaceSection::Messages};
    bool isAuthenticated_{false};
    std::vector<NavigationState> history_;
};

} // namespace securecloud::client::ui
