import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: workspaceRoot
    color: Theme.backgroundPrimary

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Sidebar Panel
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 280
            color: Theme.backgroundSecondary
            border.color: Theme.borderSubtle
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.space16
                spacing: Theme.space12

                Label {
                    text: qsTr("Conversations")
                    font.bold: true
                    font.pixelSize: Theme.fontSubtitle
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }

                Label {
                    text: qsTr("Encrypted Direct & Group Channels")
                    font.pixelSize: Theme.fontCaption
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textMuted
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 1
                    color: Theme.borderSubtle
                }

                Item { Layout.fillHeight: true }

                SCButton {
                    text: qsTr("Log Out")
                    variant: "Secondary"
                    fullWidth: true
                    onClicked: appViewModel.requestLogout()
                }
            }
        }

        // Main Workspace Area
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.backgroundPrimary

            ColumnLayout {
                anchors.centerIn: parent
                spacing: Theme.space12

                Label {
                    text: qsTr("Welcome, %1!").arg(appViewModel.currentUser)
                    font.pixelSize: Theme.fontHeadline
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                    Layout.alignment: Qt.AlignHCenter
                }

                Label {
                    text: qsTr("Select a conversation from the sidebar to begin encrypted messaging.")
                    font.pixelSize: Theme.fontBody
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textSecondary
                    Layout.alignment: Qt.AlignHCenter
                }
            }
        }
    }
}
