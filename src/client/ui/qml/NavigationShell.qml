import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Item {
    id: navShell

    signal emergencyWipeRequested()

    property bool isSidebarCollapsed: width < 1000
    property string alertMessage: ""
    property bool showAlert: false
    readonly property var wvm: typeof workspaceViewModel !== "undefined" ? workspaceViewModel : null
    readonly property var avm: typeof appViewModel !== "undefined" ? appViewModel : null
    readonly property bool showShellNavigation:
        navigationController.isAuthenticated || navigationController.currentViewName === "StyleGuide"

    Connections {
        target: navigationController
        function onNavigationDenied(requestedState, reason) {
            navShell.alertMessage = reason
            navShell.showAlert = true
            alertTimer.restart()
        }
        function onStateChanged(newState) {
            navShell.showAlert = false
        }
    }

    Timer {
        id: alertTimer
        interval: 4000
        repeat: false
        onTriggered: navShell.showAlert = false
    }

    // Keyboard Navigation Shortcuts
    Shortcut {
        sequence: "Ctrl+1"
        enabled: navigationController.isAuthenticated
        onActivated: navigationController.navigateToSection("Messages")
    }
    Shortcut {
        sequence: "Ctrl+2"
        enabled: navigationController.isAuthenticated
        onActivated: navigationController.navigateToSection("Contacts")
    }
    Shortcut {
        sequence: "Ctrl+3"
        enabled: navigationController.isAuthenticated
        onActivated: navigationController.navigateToSection("Files")
    }
    Shortcut {
        sequence: "Ctrl+4"
        enabled: navigationController.isAuthenticated
        onActivated: navigationController.navigateTo(3) // Settings
    }
    Shortcut {
        sequence: "Ctrl+5"
        onActivated: navigationController.navigateTo(5) // StyleGuide
    }
    Shortcut {
        sequence: "Ctrl+Shift+E"
        enabled: navigationController.isAuthenticated
        onActivated: navShell.emergencyWipeRequested()
    }
    Shortcut {
        sequence: "Alt+Left"
        enabled: navigationController.canNavigateBack
        onActivated: navigationController.navigateBack()
    }
    Shortcut {
        sequence: "Esc"
        enabled: navShell.showAlert
        onActivated: navShell.showAlert = false
    }

    // Reusable Keyboard-Accessible Sidebar Item
    component SidebarNavItem: FocusScope {
        id: navItem
        property string labelText: ""
        property string iconName: ""
        property string shortcutHint: ""
        property string tooltipShortcut: shortcutHint
        property int badgeCount: 0
        property bool isActive: false
        property bool isDanger: false
        signal activated()

        Layout.fillWidth: true
        implicitHeight: 40
        height: 40
        activeFocusOnTab: visible && enabled

        Accessible.role: Accessible.Button
        Accessible.name: navItem.labelText + (navItem.tooltipShortcut !== "" ? " (" + navItem.tooltipShortcut + ")" : "")

        Keys.onReturnPressed: if (enabled) navItem.activated()
        Keys.onEnterPressed: if (enabled) navItem.activated()
        Keys.onSpacePressed: if (enabled) navItem.activated()

        Rectangle {
            anchors.fill: parent
            radius: Theme.radiusSmall
            color: {
                if (navItem.isDanger) {
                    if (navMouse.pressed) return "#991B1B"
                    if (navItem.isActive) return "#DC2626"
                    if (navMouse.containsMouse || navItem.activeFocus) {
                        return Theme.isDark ? "rgba(248, 113, 113, 0.14)" : "rgba(220, 38, 38, 0.08)"
                    }
                    return "transparent"
                }
                if (navItem.isActive) {
                    return Theme.backgroundElevated
                }
                if (navMouse.containsMouse || navItem.activeFocus) {
                    return Theme.isDark ? "#1B2332" : "#E2E8F0"
                }
                return "transparent"
            }
            border.color: {
                if (navItem.activeFocus) return Theme.borderFocused
                if (navItem.isDanger) return Theme.statusDanger
                if (navItem.isActive) return Theme.borderSubtle
                return "transparent"
            }
            border.width: navItem.activeFocus ? 2 : (navItem.isDanger || navItem.isActive ? 1 : 0)
            scale: (navMouse.pressed && navItem.enabled) ? 0.975 : 1.0

            Behavior on color {
                ColorAnimation { duration: Theme.durationFast }
            }
            Behavior on scale {
                NumberAnimation { duration: 110; easing.type: Easing.OutQuad }
            }

            // Active Left Accent Indicator Pill
            Rectangle {
                visible: !navItem.isDanger && height > 0
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                width: 3
                height: navItem.isActive ? 20 : 0
                radius: 1.5
                color: Theme.accentPrimary

                Behavior on height {
                    NumberAnimation { duration: 180; easing.type: Easing.OutCubic }
                }
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space12
                anchors.rightMargin: Theme.space12
                spacing: Theme.space8

                Item {
                    width: 18
                    height: 18
                    Layout.alignment: Qt.AlignVCenter

                    SCIcon {
                        anchors.centerIn: parent
                        name: navItem.iconName
                        size: 18
                        color: {
                            if (navItem.isDanger) {
                                return navItem.isActive ? "#FFFFFF" : Theme.statusDanger
                            }
                            return navItem.isActive ? Theme.accentPrimary : Theme.textSecondary
                        }
                    }

                    Rectangle {
                        visible: navShell.isSidebarCollapsed && navItem.badgeCount > 0
                        anchors.top: parent.top
                        anchors.right: parent.right
                        anchors.topMargin: -2
                        anchors.rightMargin: -3
                        width: 7
                        height: 7
                        radius: 3.5
                        color: Theme.accentPrimary
                    }
                }

                Label {
                    visible: !navShell.isSidebarCollapsed
                    text: navItem.labelText
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontBody
                    font.bold: navItem.isActive || navItem.isDanger
                    elide: Text.ElideRight
                    color: {
                        if (navItem.isDanger) {
                            return navItem.isActive ? "#FFFFFF" : Theme.statusDanger
                        }
                        return navItem.isActive ? Theme.textPrimary : Theme.textSecondary
                    }
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                }

                Rectangle {
                    visible: !navShell.isSidebarCollapsed && navItem.badgeCount > 0
                    height: 18
                    width: Math.max(18, badgeCountLabel.implicitWidth + 10)
                    radius: 9
                    color: Theme.accentPrimary
                    Layout.alignment: Qt.AlignVCenter

                    Label {
                        id: badgeCountLabel
                        anchors.centerIn: parent
                        text: navItem.badgeCount.toString()
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontMicro
                        font.bold: true
                        color: "#FFFFFF"
                    }
                }

                Label {
                    visible: !navShell.isSidebarCollapsed && navItem.badgeCount === 0 && navItem.shortcutHint !== ""
                    text: navItem.shortcutHint
                    font.family: Theme.fontFamilyMonospace
                    font.pixelSize: Theme.fontMicro
                    color: navItem.isDanger ? Theme.statusDanger : Theme.textMuted
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            ToolTip {
                visible: navMouse.containsMouse && (navShell.isSidebarCollapsed || navItem.tooltipShortcut !== navItem.shortcutHint || navItem.badgeCount > 0)
                text: navItem.labelText + (navItem.tooltipShortcut !== "" ? " (" + navItem.tooltipShortcut + ")" : "")
                delay: 300
                timeout: 2500
            }

            MouseArea {
                id: navMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: {
                    navItem.forceActiveFocus()
                    navItem.activated()
                }
            }
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Responsive Collapsible Navigation Rail (visible post-auth or in StyleGuide catalog)
        Rectangle {
            id: sideRail
            visible: navShell.showShellNavigation
            Layout.fillHeight: true
            Layout.preferredWidth: navShell.isSidebarCollapsed ? 64 : 200
            color: Theme.backgroundSecondary

            Rectangle {
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.right: parent.right
                width: 1
                color: Theme.borderSubtle
            }

            Behavior on Layout.preferredWidth {
                NumberAnimation { duration: Theme.durationNormal; easing.type: Easing.OutQuad }
            }

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.space8
                spacing: Theme.space8

                // Top Brand Header + Collapse/Theme Controls
                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space4
                    Layout.bottomMargin: Theme.space4
                    Layout.leftMargin: navShell.isSidebarCollapsed ? 0 : Theme.space4
                    spacing: Theme.space4

                    Rectangle {
                        visible: !navShell.isSidebarCollapsed
                        width: 24
                        height: 24
                        radius: Theme.radiusSmall
                        color: Theme.isDark ? "#13233D" : "#DBEAFE"
                        border.color: Theme.accentPrimary
                        border.width: 1

                        SCIcon {
                            anchors.centerIn: parent
                            name: "shield-check"
                            size: 14
                            color: Theme.accentPrimary
                        }
                    }

                    Label {
                        visible: !navShell.isSidebarCollapsed
                        text: qsTr("SecureCloud")
                        font.pixelSize: Theme.fontBody
                        font.bold: true
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }

                    SCIconButton {
                        visible: !navShell.isSidebarCollapsed
                        iconName: Theme.isDark ? "sun" : "moon"
                        buttonSize: 26
                        tooltipText: Theme.isDark ? qsTr("Switch to Light Theme") : qsTr("Switch to Dark Theme")
                        onClicked: Theme.toggleTheme()
                    }

                    SCIconButton {
                        iconName: navShell.isSidebarCollapsed ? "sidebar-expand" : "sidebar-collapse"
                        buttonSize: 26
                        Layout.alignment: navShell.isSidebarCollapsed ? Qt.AlignHCenter : Qt.AlignVCenter
                        tooltipText: navShell.isSidebarCollapsed ? qsTr("Expand Sidebar") : qsTr("Collapse Sidebar")
                        onClicked: navShell.isSidebarCollapsed = !navShell.isSidebarCollapsed
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: Theme.borderSubtle
                }

                // Messages Section Tab
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Messages")
                    iconName: "workspace"
                    shortcutHint: "Ctrl+1"
                    badgeCount: navShell.wvm ? navShell.wvm.totalUnreadCount : 0
                    isActive: navigationController.currentViewName === "Workspace" &&
                              navigationController.activeWorkspaceSection === "Messages"
                    onActivated: navigationController.navigateToSection("Messages")
                }

                // Contacts Section Tab
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Contacts")
                    iconName: "users"
                    shortcutHint: "Ctrl+2"
                    isActive: navigationController.currentViewName === "Workspace" &&
                              navigationController.activeWorkspaceSection === "Contacts"
                    onActivated: navigationController.navigateToSection("Contacts")
                }

                // Encrypted Files Section Tab
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Files")
                    iconName: "file-lock"
                    shortcutHint: "Ctrl+3"
                    badgeCount: navShell.wvm ? navShell.wvm.activeFileTransferCount : 0
                    isActive: navigationController.currentViewName === "Workspace" &&
                              navigationController.activeWorkspaceSection === "Files"
                    onActivated: navigationController.navigateToSection("Files")
                }

                // Settings Tab
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Settings")
                    iconName: "settings"
                    shortcutHint: "Ctrl+4"
                    isActive: navigationController.currentViewName === "Settings"
                    onActivated: navigationController.navigateTo(3)
                }

                // Style Guide / Design System Catalog Tab
                SidebarNavItem {
                    labelText: qsTr("Style Guide")
                    iconName: "style-guide"
                    shortcutHint: "Ctrl+5"
                    isActive: navigationController.currentViewName === "StyleGuide"
                    onActivated: navigationController.navigateTo(5)
                }

                Item {
                    Layout.fillHeight: true
                }

                Rectangle {
                    visible: navigationController.isAuthenticated
                    Layout.fillWidth: true
                    height: 1
                    color: Theme.borderSubtle
                }

                // Emergency Wipe Action (always routes through confirmation modal)
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Emergency Wipe")
                    iconName: "shield-alert"
                    shortcutHint: "⇧^E"
                    tooltipShortcut: "Ctrl+Shift+E"
                    isDanger: true
                    isActive: navigationController.currentViewName === "Emergency"
                    onActivated: navShell.emergencyWipeRequested()
                }

                Rectangle {
                    visible: navigationController.isAuthenticated
                    Layout.fillWidth: true
                    height: 1
                    color: Theme.borderSubtle
                }

                // Integrated Authenticated User Profile Footer
                RowLayout {
                    visible: navigationController.isAuthenticated
                    Layout.fillWidth: true
                    Layout.topMargin: Theme.space4
                    Layout.bottomMargin: Theme.space4
                    Layout.leftMargin: navShell.isSidebarCollapsed ? 0 : Theme.space4
                    spacing: Theme.space8

                    SCAvatar {
                        userId: (navShell.avm && navShell.avm.currentUser !== "")
                                ? navShell.avm.currentUser
                                : "operator"
                        displayName: (navShell.avm && navShell.avm.currentUser !== "")
                                     ? navShell.avm.currentUser
                                     : "Operator"
                        size: 32
                        presence: "Online"
                        Layout.alignment: navShell.isSidebarCollapsed ? Qt.AlignHCenter : Qt.AlignVCenter
                    }

                    ColumnLayout {
                        visible: !navShell.isSidebarCollapsed
                        spacing: 1
                        Layout.fillWidth: true

                        Label {
                            text: (navShell.avm && navShell.avm.currentUser !== "")
                                  ? navShell.avm.currentUser
                                  : qsTr("Operator")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }

                        Label {
                            text: qsTr("Authenticated")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textMuted
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }

                    SCIconButton {
                        visible: !navShell.isSidebarCollapsed
                        iconName: "logout"
                        buttonSize: 30
                        tooltipText: qsTr("Sign Out")
                        onClicked: if (navShell.avm) navShell.avm.requestLogout()
                    }
                }
            }
        }

        // Central Content Area
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Breadcrumb & Context Header Bar (shown on non-Workspace views such as Settings & StyleGuide)
            Rectangle {
                visible: navShell.showShellNavigation && navigationController.currentViewName !== "Workspace"
                Layout.fillWidth: true
                height: 36
                color: Theme.backgroundPrimary

                Rectangle {
                    anchors.bottom: parent.bottom
                    anchors.left: parent.left
                    anchors.right: parent.right
                    height: 1
                    color: Theme.borderSubtle
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.space16
                    anchors.rightMargin: Theme.space16
                    spacing: Theme.space8

                    Label {
                        text: qsTr("SecureCloud")
                        font.pixelSize: Theme.fontCaption
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textMuted
                    }

                    Label {
                        text: "›"
                        font.pixelSize: Theme.fontCaption
                        color: Theme.textMuted
                    }

                    Label {
                        text: navigationController.currentViewName
                        font.pixelSize: Theme.fontCaption
                        font.bold: true
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                    }

                    Item { Layout.fillWidth: true }

                    SCBadge {
                        visible: navigationController.currentViewName === "StyleGuide"
                        text: qsTr("Design System Catalog")
                        type: "Info"
                        hasDot: false
                    }
                }
            }

            // Navigation Denied Alert Banner
            Rectangle {
                Layout.fillWidth: true
                height: navShell.showAlert ? 36 : 0
                visible: navShell.showAlert
                color: "#DC2626"
                clip: true

                Behavior on height {
                    NumberAnimation { duration: Theme.durationFast }
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.space16
                    anchors.rightMargin: Theme.space16
                    spacing: Theme.space8

                    SCIcon {
                        name: "alert-triangle"
                        size: 15
                        color: "#FFFFFF"
                        Layout.alignment: Qt.AlignVCenter
                    }

                    Label {
                        text: navShell.alertMessage
                        color: "#FFFFFF"
                        font.pixelSize: Theme.fontCaption
                        font.bold: true
                        Layout.fillWidth: true
                    }

                    SCIconButton {
                        iconName: "close"
                        variant: "Danger"
                        buttonSize: 24
                        tooltipText: qsTr("Dismiss (Esc)")
                        onClicked: navShell.showAlert = false
                    }
                }
            }

            // Primary Content View Loader
            Loader {
                id: viewLoader
                Layout.fillWidth: true
                Layout.fillHeight: true

                source: {
                    switch (navigationController.currentViewName) {
                        case "Login":
                            return "LoginPlaceholder.qml"
                        case "MfaVerification":
                            return "LoginPlaceholder.qml"
                        case "Workspace":
                            return "WorkspacePlaceholder.qml"
                        case "Settings":
                            return "SettingsPlaceholder.qml"
                        case "Emergency":
                            return "EmergencyPlaceholder.qml"
                        case "StyleGuide":
                            return "StyleGuideView.qml"
                        default:
                            return "LoginPlaceholder.qml"
                    }
                }
            }
        }
    }
}
