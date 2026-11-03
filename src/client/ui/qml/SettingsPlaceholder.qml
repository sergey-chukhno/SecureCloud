import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: settingsRoot
    color: "#1e1e24"

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 16
        width: 400

        Label {
            text: qsTr("Application Settings")
            font.pixelSize: 20
            font.bold: true
            color: "#ffffff"
        }

        Label {
            text: qsTr("Connection & Cryptography Preferences")
            font.pixelSize: 13
            color: "#808090"
        }

        Button {
            text: qsTr("Back to Workspace")
            onClicked: navigationController.navigateBack()
        }
    }
}

