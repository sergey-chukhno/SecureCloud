import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: emergencyRoot
    color: "#2a1010"

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 16
        width: 440

        Label {
            text: qsTr("⚠ Emergency Wipe Mode")
            font.pixelSize: 22
            font.bold: true
            color: "#ff5555"
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr("Local cryptographic keys and session tokens have been securely wiped.\nTo regain access, restart the application and log in again.")
            font.pixelSize: 13
            color: "#ffaaaa"
            horizontalAlignment: Text.AlignHCenter
            Layout.alignment: Qt.AlignHCenter
        }

        Button {
            text: qsTr("Return to Login")
            Layout.alignment: Qt.AlignHCenter
            onClicked: navigationController.reset(0) // Unauthenticated
        }
    }
}

