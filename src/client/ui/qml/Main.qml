import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: rootWindow
    visible: true
    width: 1200
    height: 800
    minimumWidth: 960
    minimumHeight: 600
    title: qsTr("SecureCloud Desktop")
    color: "#1e1e24"

    header: ToolBar {
        background: Rectangle {
            color: "#18181c"
            border.color: "#2a2a32"
            border.width: 1
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16
            spacing: 12

            Button {
                text: qsTr("← Back")
                visible: navigationController.canNavigateBack
                onClicked: navigationController.navigateBack()
            }

            Label {
                text: qsTr("SecureCloud")
                font.bold: true
                font.pixelSize: 16
                color: "#f0f0f5"
            }

            Item { Layout.fillWidth: true }

            Label {
                text: appViewModel.currentUser !== "" ? qsTr("Logged in as: %1").arg(appViewModel.currentUser) : qsTr("Not Authenticated")
                color: "#a0a0b0"
                font.pixelSize: 13
            }

            Button {
                text: qsTr("Settings")
                visible: navigationController.isAuthenticated
                onClicked: navigationController.navigateTo(3) // Settings
            }

            Button {
                text: qsTr("Emergency")
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
            color: "#18181c"
            border.color: "#2a2a32"
            border.width: 1
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16

            Label {
                text: qsTr("Status: %1 | View: %2").arg(appViewModel.connectionStatus).arg(navigationController.currentViewName)
                color: "#707080"
                font.pixelSize: 12
            }

            Item { Layout.fillWidth: true }

            Label {
                text: qsTr("End-to-End Encrypted")
                color: "#4e9a06"
                font.pixelSize: 12
            }
        }
    }
}

