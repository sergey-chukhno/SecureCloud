import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Item {
    id: navShell

    property bool isSidebarCollapsed: width < 1000
    property string alertMessage: ""
    property bool showAlert: false

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
        onActivated: navigationController.navigateTo(2) // MainWorkspace
    }
    Shortcut {
        sequence: "Ctrl+2"
        onActivated: navigationController.navigateTo(3) // Settings
    }
    Shortcut {
        sequence: "Ctrl+3"
        onActivated: navigationController.navigateTo(5) // StyleGuide
    }
    Shortcut {
        sequence: "Ctrl+Shift+E"
        onActivated: navigationController.navigateTo(4) // EmergencyMode
    }
    Shortcut {
        sequence: "Alt+Left"
        enabled: navigationController.canNavigateBack
        onActivated: navigationController.navigateBack()
    }
    Shortcut {
        sequence: "Esc"
        enabled: navigationController.canNavigateBack
        onActivated: navigationController.navigateBack()
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Responsive Collapsible Navigation Rail
        Rectangle {
            id: sideRail
            Layout.fillHeight: true
            Layout.preferredWidth: navShell.isSidebarCollapsed ? 64 : 200
            color: Theme.backgroundSecondary
            border.color: Theme.borderSubtle
            border.width: 1

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
                        iconText: navShell.isSidebarCollapsed ? "☰" : "⮜"
                        tooltipText: navShell.isSidebarCollapsed ? qsTr("Expand Sidebar") : qsTr("Collapse Sidebar")
                        onClicked: navShell.isSidebarCollapsed = !navShell.isSidebarCollapsed
                    }

                    Label {
                        visible: !navShell.isSidebarCollapsed
                        text: qsTr("Navigation")
                        font.pixelSize: Theme.fontCaption
                        font.bold: true
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
                Rectangle {
                    Layout.fillWidth: true
                    height: 40
                    radius: Theme.radiusMedium
                    visible: navigationController.isAuthenticated
                    color: navigationController.currentViewName === "Workspace" ? Theme.backgroundElevated : (wsMouse.containsMouse ? Theme.backgroundPrimary : "transparent")
                    border.color: navigationController.currentViewName === "Workspace" ? Theme.accentPrimary : "transparent"
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space12
                        anchors.rightMargin: Theme.space8
                        spacing: Theme.space12

                        Label {
                            text: "💬"
                            font.pixelSize: 16
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: qsTr("Workspace")
                            font.pixelSize: Theme.fontBody
                            font.bold: navigationController.currentViewName === "Workspace"
                            color: navigationController.currentViewName === "Workspace" ? Theme.textPrimary : Theme.textSecondary
                            Layout.fillWidth: true
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: "Ctrl+1"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textMuted
                        }
                    }

                    MouseArea {
                        id: wsMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: navigationController.navigateTo(2) // MainWorkspace
                    }
                }

                // Settings Tab
                Rectangle {
                    Layout.fillWidth: true
                    height: 40
                    radius: Theme.radiusMedium
                    visible: navigationController.isAuthenticated
                    color: navigationController.currentViewName === "Settings" ? Theme.backgroundElevated : (setMouse.containsMouse ? Theme.backgroundPrimary : "transparent")
                    border.color: navigationController.currentViewName === "Settings" ? Theme.accentPrimary : "transparent"
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space12
                        anchors.rightMargin: Theme.space8
                        spacing: Theme.space12

                        Label {
                            text: "⚙️"
                            font.pixelSize: 16
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: qsTr("Settings")
                            font.pixelSize: Theme.fontBody
                            font.bold: navigationController.currentViewName === "Settings"
                            color: navigationController.currentViewName === "Settings" ? Theme.textPrimary : Theme.textSecondary
                            Layout.fillWidth: true
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: "Ctrl+2"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textMuted
                        }
                    }

                    MouseArea {
                        id: setMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: navigationController.navigateTo(3) // Settings
                    }
                }

                // Style Guide / Design System Catalog Tab
                Rectangle {
                    Layout.fillWidth: true
                    height: 40
                    radius: Theme.radiusMedium
                    color: navigationController.currentViewName === "StyleGuide" ? Theme.backgroundElevated : (sgMouse.containsMouse ? Theme.backgroundPrimary : "transparent")
                    border.color: navigationController.currentViewName === "StyleGuide" ? Theme.accentPrimary : "transparent"
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space12
                        anchors.rightMargin: Theme.space8
                        spacing: Theme.space12

                        Label {
                            text: "🎨"
                            font.pixelSize: 16
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: qsTr("Style Guide")
                            font.pixelSize: Theme.fontBody
                            font.bold: navigationController.currentViewName === "StyleGuide"
                            color: navigationController.currentViewName === "StyleGuide" ? Theme.textPrimary : Theme.textSecondary
                            Layout.fillWidth: true
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: "Ctrl+3"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textMuted
                        }
                    }

                    MouseArea {
                        id: sgMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: navigationController.navigateTo(5) // StyleGuide
                    }
                }

                Item {
                    Layout.fillHeight: true
                }

                // Emergency Wipe Tab
                Rectangle {
                    Layout.fillWidth: true
                    height: 40
                    radius: Theme.radiusMedium
                    visible: navigationController.isAuthenticated
                    color: navigationController.currentViewName === "Emergency" ? Theme.statusDanger : (emMouse.containsMouse ? Theme.backgroundElevated : "transparent")
                    border.color: Theme.statusDanger
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space12
                        anchors.rightMargin: Theme.space8
                        spacing: Theme.space12

                        Label {
                            text: "🚨"
                            font.pixelSize: 16
                        }

                        Label {
                            visible: !navShell.isSidebarCollapsed
                            text: qsTr("Emergency")
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: navigationController.currentViewName === "Emergency" ? "#FFFFFF" : Theme.statusDanger
                            Layout.fillWidth: true
                        }
                    }

                    MouseArea {
                        id: emMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: navigationController.navigateTo(4) // EmergencyMode
                    }
                }
            }
        }

        // Central Content Area
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Breadcrumb & Context Header Bar
            Rectangle {
                Layout.fillWidth: true
                height: 38
                color: Theme.backgroundPrimary
                border.color: Theme.borderSubtle
                border.width: 1

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.space16
                    anchors.rightMargin: Theme.space16
                    spacing: Theme.space8

                    Label {
                        text: "SecureCloud"
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
                        text: qsTr("Catalog Mode")
                        type: "Info"
                    }
                }
            }

            // Navigation Denied Alert Banner
            Rectangle {
                Layout.fillWidth: true
                height: navShell.showAlert ? 36 : 0
                visible: navShell.showAlert
                color: Theme.statusDanger
                clip: true

                Behavior on height {
                    NumberAnimation { duration: Theme.durationFast }
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: Theme.space16
                    anchors.rightMargin: Theme.space16
                    spacing: Theme.space8

                    Label {
                        text: "⚠️"
                        font.pixelSize: 14
                    }

                    Label {
                        text: navShell.alertMessage
                        color: "#FFFFFF"
                        font.pixelSize: Theme.fontCaption
                        font.bold: true
                        Layout.fillWidth: true
                    }

                    SCIconButton {
                        iconText: "✕"
                        buttonSize: 24
                        tooltipText: qsTr("Dismiss")
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
