import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: workspaceRoot
    color: "#1e1e24"

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Sidebar Placeholder
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 260
            color: "#141418"
            border.color: "#2a2a32"
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 16
                spacing: 12

                Label {
                    text: qsTr("Conversations")
                    font.bold: true
                    font.pixelSize: 14
                    color: "#f0f0f5"
                }

                Label {
                    text: qsTr("CLIENT-003 Workspace Shell\nExtension Point")
                    font.pixelSize: 12
                    color: "#707080"
                }

                Item { Layout.fillHeight: true }

                Button {
                    text: qsTr("Log Out")
                    Layout.fillWidth: true
                    onClicked: appViewModel.requestLogout()
                }
            }
        }

        // Main Chat Area Placeholder
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: "#1e1e24"

            ColumnLayout {
                anchors.centerIn: parent
                spacing: 12

                Label {
                    text: qsTr("Welcome, %1!").arg(appViewModel.currentUser)
                    font.pixelSize: 20
                    font.bold: true
                    color: "#ffffff"
                    Layout.alignment: Qt.AlignHCenter
                }

                Label {
                    text: qsTr("Select a conversation from the sidebar to begin messaging.")
                    font.pixelSize: 14
                    color: "#a0a0b0"
                    Layout.alignment: Qt.AlignHCenter
                }
            }
        }
    }
}

