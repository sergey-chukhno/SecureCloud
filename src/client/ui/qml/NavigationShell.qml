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
        onActivated: navigationController.navigateTo(2) // MainWorkspace
    }
    Shortcut {
        sequence: "Ctrl+2"
        enabled: navigationController.isAuthenticated
        onActivated: navigationController.navigateTo(3) // Settings
    }
    Shortcut {
        sequence: "Ctrl+3"
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

            Behavior on color {
                ColorAnimation { duration: Theme.durationFast }
            }

            // Active Left Accent Indicator Pill
            Rectangle {
                visible: navItem.isActive && !navItem.isDanger
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                width: 3
                height: 20
                radius: 1.5
                color: Theme.accentPrimary
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space12
                anchors.rightMargin: Theme.space12
                spacing: Theme.space8

                SCIcon {
                    name: navItem.iconName
                    size: 18
                    color: {
                        if (navItem.isDanger) {
                            return navItem.isActive ? "#FFFFFF" : Theme.statusDanger
                        }
                        return navItem.isActive ? Theme.accentPrimary : Theme.textSecondary
                    }
                    Layout.alignment: Qt.AlignVCenter
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

                Label {
                    visible: !navShell.isSidebarCollapsed && navItem.shortcutHint !== ""
                    text: navItem.shortcutHint
                    font.family: Theme.fontFamilyMonospace
                    font.pixelSize: Theme.fontMicro
                    color: navItem.isDanger ? Theme.statusDanger : Theme.textMuted
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            ToolTip {
                visible: navMouse.containsMouse && (navShell.isSidebarCollapsed || navItem.tooltipShortcut !== navItem.shortcutHint)
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
            Layout.preferredWidth: navShell.isSidebarCollapsed ? 64 : 236
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

                // Sidebar Toggle / Collapse Button
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    SCIconButton {
                        iconName: navShell.isSidebarCollapsed ? "sidebar-expand" : "sidebar-collapse"
                        tooltipText: navShell.isSidebarCollapsed ? qsTr("Expand Sidebar") : qsTr("Collapse Sidebar")
                        onClicked: navShell.isSidebarCollapsed = !navShell.isSidebarCollapsed
                    }

                    Label {
                        visible: !navShell.isSidebarCollapsed
                        text: qsTr("NAVIGATION")
                        font.pixelSize: Theme.fontMicro
                        font.bold: true
                        font.letterSpacing: 0.8
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textMuted
                        Layout.fillWidth: true
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: Theme.borderSubtle
                }

                // Workspace Tab
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Workspace")
                    iconName: "workspace"
                    shortcutHint: "Ctrl+1"
                    isActive: navigationController.currentViewName === "Workspace"
                    onActivated: navigationController.navigateTo(2)
                }

                // Settings Tab
                SidebarNavItem {
                    visible: navigationController.isAuthenticated
                    labelText: qsTr("Settings")
                    iconName: "settings"
                    shortcutHint: "Ctrl+2"
                    isActive: navigationController.currentViewName === "Settings"
                    onActivated: navigationController.navigateTo(3)
                }

                // Style Guide / Design System Catalog Tab
                SidebarNavItem {
                    labelText: qsTr("Style Guide")
                    iconName: "style-guide"
                    shortcutHint: "Ctrl+3"
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
            }
        }

        // Central Content Area
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Breadcrumb & Context Header Bar (shown only when shell navigation is active)
            Rectangle {
                visible: navShell.showShellNavigation
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
