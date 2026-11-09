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

    readonly property bool showAuthenticatedChrome:
        navigationController.isAuthenticated &&
        appViewModel.isAuthenticated &&
        navigationController.currentViewName !== "Login" &&
        navigationController.currentViewName !== "MfaVerification" &&
        navigationController.currentViewName !== "Emergency"

    function openEmergencyDialog() {
        if (navigationController.isAuthenticated) {
            emergencyConfirmDialog.isOpen = true
        }
    }

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
        visible: !rootWindow.showAuthenticatedChrome
        height: visible ? implicitHeight : 0
        implicitHeight: 52
        background: Rectangle {
            color: Theme.backgroundSecondary
            Rectangle {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.borderSubtle
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.space16
            anchors.rightMargin: Theme.space16
            spacing: Theme.space12

            SCIconButton {
                iconName: "arrow-left"
                tooltipText: qsTr("Go Back (Alt+Left)")
                visible: navigationController.canNavigateBack
                onClicked: navigationController.navigateBack()
            }

            // Brand Mark + Wordmark
            RowLayout {
                spacing: Theme.space8

                Rectangle {
                    width: 28
                    height: 28
                    radius: Theme.radiusSmall
                    color: Theme.isDark ? "#13233D" : "#DBEAFE"
                    border.color: Theme.accentPrimary
                    border.width: 1

                    SCIcon {
                        anchors.centerIn: parent
                        name: "shield-check"
                        size: 16
                        color: Theme.accentPrimary
                    }
                }

                Label {
                    text: qsTr("SecureCloud")
                    font.bold: true
                    font.pixelSize: Theme.fontTitle
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }
            }

            SCBadge {
                visible: rootWindow.showAuthenticatedChrome
                text: qsTr("Authenticated Session")
                type: "Online"
                hasDot: true
            }

            Item { Layout.fillWidth: true }

            // Authenticated User Identity Chip
            RowLayout {
                visible: rootWindow.showAuthenticatedChrome
                spacing: Theme.space8

                SCAvatar {
                    userId: appViewModel.currentUser
                    displayName: appViewModel.currentUser
                    size: 28
                    presence: "Online"
                }

                Label {
                    text: appViewModel.currentUser
                    color: Theme.textPrimary
                    font.pixelSize: Theme.fontBody
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                }

                SCButton {
                    text: qsTr("Sign Out")
                    iconName: "logout"
                    variant: "Ghost"
                    buttonHeight: 30
                    horizontalPadding: 10
                    onClicked: appViewModel.requestLogout()
                }
            }

            // Unauthenticated Status Badge
            SCBadge {
                visible: !rootWindow.showAuthenticatedChrome
                text: appViewModel.isEmergencyWiped ? qsTr("Emergency Wipe Active") : qsTr("Unauthenticated")
                type: appViewModel.isEmergencyWiped ? "Danger" : "Offline"
                hasDot: true
            }

            Rectangle {
                width: 1
                height: 20
                color: Theme.borderSubtle
            }

            SCIconButton {
                iconName: "style-guide"
                active: navigationController.currentViewName === "StyleGuide"
                tooltipText: navigationController.currentViewName === "StyleGuide"
                             ? qsTr("Exit Style Guide")
                             : qsTr("Design System Style Guide (Ctrl+5)")
                onClicked: {
                    if (navigationController.currentViewName === "StyleGuide" && navigationController.canNavigateBack) {
                        navigationController.navigateBack()
                    } else {
                        navigationController.navigateTo(5)
                    }
                }
            }

            SCIconButton {
                iconName: Theme.isDark ? "sun" : "moon"
                tooltipText: Theme.isDark ? qsTr("Switch to Light Theme") : qsTr("Switch to Dark Theme")
                onClicked: Theme.toggleTheme()
            }
        }
    }

    NavigationShell {
        anchors.fill: parent
        onEmergencyWipeRequested: rootWindow.openEmergencyDialog()
    }

    footer: ToolBar {
        implicitHeight: 34
        background: Rectangle {
            color: Theme.backgroundSecondary
            Rectangle {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.borderSubtle
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.space16
            anchors.rightMargin: Theme.space16
            spacing: Theme.space8

            Rectangle {
                width: 7
                height: 7
                radius: 3.5
                color: appViewModel.isEmergencyWiped
                       ? Theme.statusDanger
                       : (appViewModel.isAuthenticated ? Theme.statusSuccess : Theme.textMuted)
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: appViewModel.sessionStatusText
                color: Theme.textSecondary
                font.pixelSize: Theme.fontCaption
                font.family: Theme.fontFamilyPrimary
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: "·"
                color: Theme.textMuted
                font.pixelSize: Theme.fontCaption
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: qsTr("View: %1").arg(navigationController.currentViewName)
                color: Theme.textMuted
                font.pixelSize: Theme.fontCaption
                font.family: Theme.fontFamilyPrimary
                Layout.alignment: Qt.AlignVCenter
            }

            Item { Layout.fillWidth: true }

            SCBadge {
                text: appViewModel.securityStatusText
                type: appViewModel.securityBadgeType
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
