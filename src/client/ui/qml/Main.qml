import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

ApplicationWindow {
    id: rootWindow
    visible: true
    width: 1200
    height: 800
    minimumWidth: 960
    minimumHeight: 640
    title: qsTr("SecureCloud Desktop")
    color: Theme.backgroundPrimary

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

            Item { Layout.fillWidth: true }

            Label {
                text: appViewModel.currentUser !== "" ? qsTr("Logged in as: %1").arg(appViewModel.currentUser) : qsTr("Not Authenticated")
                color: Theme.textSecondary
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
                text: qsTr("Emergency")
                variant: "Danger"
                buttonHeight: 32
                visible: navigationController.isAuthenticated
                onClicked: appViewModel.triggerEmergencyWipe()
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

            Rectangle {
                width: 8
                height: 8
                radius: 4
                color: Theme.statusSuccess
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: qsTr("End-to-End Encrypted")
                color: Theme.statusSuccess
                font.pixelSize: Theme.fontCaption
                font.family: Theme.fontFamilyPrimary
                font.bold: true
            }
        }
    }
}
