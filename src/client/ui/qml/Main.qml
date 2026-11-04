import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

ApplicationWindow {
    id: rootWindow
    visible: true
    x: typeof windowStateManager !== "undefined" ? windowStateManager.x : 100
    y: typeof windowStateManager !== "undefined" ? windowStateManager.y : 100
    width: typeof windowStateManager !== "undefined" ? windowStateManager.width : 1200
    height: typeof windowStateManager !== "undefined" ? windowStateManager.height : 800
    minimumWidth: typeof windowStateManager !== "undefined" ? windowStateManager.minWidth : 960
    minimumHeight: typeof windowStateManager !== "undefined" ? windowStateManager.minHeight : 640
    visibility: (typeof windowStateManager !== "undefined" && windowStateManager.isMaximized) ? Window.Maximized : Window.Windowed
    title: qsTr("SecureCloud Desktop")
    color: Theme.backgroundPrimary

    Timer {
        id: saveGeometryTimer
        interval: 500
        repeat: false
        onTriggered: {
            if (typeof windowStateManager !== "undefined" && windowStateManager !== null) {
                windowStateManager.saveGeometry(
                    rootWindow.width,
                    rootWindow.height,
                    rootWindow.x,
                    rootWindow.y,
                    rootWindow.visibility === Window.Maximized
                )
            }
        }
    }

    onWidthChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onHeightChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onXChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onYChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onVisibilityChanged: {
        if (rootWindow.visible && typeof windowStateManager !== "undefined" && windowStateManager !== null) {
            windowStateManager.saveGeometry(
                rootWindow.width,
                rootWindow.height,
                rootWindow.x,
                rootWindow.y,
                rootWindow.visibility === Window.Maximized
            )
        }
    }
    onClosing: {
        if (typeof windowStateManager !== "undefined" && windowStateManager !== null) {
            windowStateManager.saveGeometry(
                rootWindow.width,
                rootWindow.height,
                rootWindow.x,
                rootWindow.y,
                rootWindow.visibility === Window.Maximized
            )
        }
    }

    header: ToolBar {
        background: Rectangle {
            color: Theme.backgroundSecondary
            border.color: Theme.borderSubtle
            border.width: 1
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.space16
            anchors.rightMargin: Theme.space16
            spacing: Theme.space12

            SCIconButton {
                iconText: "←"
                tooltipText: qsTr("Go Back")
                visible: navigationController.canNavigateBack
                onClicked: navigationController.navigateBack()
            }

            Label {
                text: qsTr("SecureCloud")
                font.bold: true
                font.pixelSize: Theme.fontTitle
                font.family: Theme.fontFamilyPrimary
                color: Theme.textPrimary
            }

            SCBadge {
                visible: navigationController.isAuthenticated
                text: qsTr("Verified Identity")
                type: "Verified"
            }

            Item { Layout.fillWidth: true }

            RowLayout {
                visible: navigationController.isAuthenticated
                spacing: Theme.space8

                SCAvatar {
                    userId: appViewModel.currentUser
                    displayName: appViewModel.currentUser
                    size: 30
                    presence: "Online"
                }

                Label {
                    text: appViewModel.currentUser
                    color: Theme.textPrimary
                    font.pixelSize: Theme.fontBody
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                }
            }

            Label {
                visible: !navigationController.isAuthenticated
                text: qsTr("Not Authenticated")
                color: Theme.textMuted
                font.pixelSize: Theme.fontBody
                font.family: Theme.fontFamilyPrimary
            }

            SCIconButton {
                iconText: Theme.isDark ? "☀️" : "🌙"
                tooltipText: Theme.isDark ? qsTr("Switch to Light Mode") : qsTr("Switch to Dark Mode")
                onClicked: Theme.toggleTheme()
            }

            SCButton {
                text: qsTr("Settings")
                variant: "Secondary"
                buttonHeight: 32
                visible: navigationController.isAuthenticated
                onClicked: navigationController.navigateTo(3) // Settings
            }

            SCButton {
                text: qsTr("Emergency Wipe")
                variant: "Danger"
                buttonHeight: 32
                visible: navigationController.isAuthenticated
                onClicked: emergencyConfirmDialog.isOpen = true
            }
        }
    }

    NavigationShell {
        anchors.fill: parent
    }

    footer: ToolBar {
        background: Rectangle {
            color: Theme.backgroundSecondary
            border.color: Theme.borderSubtle
            border.width: 1
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.space16
            anchors.rightMargin: Theme.space16

            Label {
                text: qsTr("Status: %1 | View: %2").arg(appViewModel.connectionStatus).arg(navigationController.currentViewName)
                color: Theme.textMuted
                font.pixelSize: Theme.fontCaption
                font.family: Theme.fontFamilyPrimary
            }

            Item { Layout.fillWidth: true }

            SCBadge {
                text: qsTr("End-to-End Encrypted")
                type: "Verified"
                hasDot: true
            }
        }
    }

    // Modal Confirmation Dialog for High-Risk Emergency Action
    SCDialog {
        id: emergencyConfirmDialog
        title: qsTr("Initiate Emergency Wipe?")
        message: qsTr("Warning: This action will permanently zeroize all cryptographic ratchets, purge session tokens, and scrub local database caches from memory and disk. You will be logged out immediately.")
        confirmText: qsTr("Execute Emergency Wipe")
        cancelText: qsTr("Cancel")
        isDanger: true
        onConfirmed: appViewModel.triggerEmergencyWipe()
    }
}
