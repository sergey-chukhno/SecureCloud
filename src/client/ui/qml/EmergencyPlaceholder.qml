import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: emergencyRoot
    color: Theme.backgroundPrimary

    ColumnLayout {
        anchors.centerIn: parent
        spacing: Theme.space16
        width: 480

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 180
            radius: Theme.radiusMedium
            color: Theme.backgroundSecondary
            border.color: Theme.statusDanger
            border.width: 2

            ColumnLayout {
                anchors.centerIn: parent
                spacing: Theme.space12
                width: parent.width - Theme.space32

                Label {
                    text: qsTr("⚠ Emergency Wipe Mode Activated")
                    font.pixelSize: Theme.fontTitle
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.statusDanger
                    Layout.alignment: Qt.AlignHCenter
                }

                Label {
                    text: qsTr("All in-memory cryptographic ratchets, session credentials, and decrypted caches have been wiped from memory.")
                    font.pixelSize: Theme.fontBody
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textSecondary
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }
        }

        SCButton {
            text: qsTr("Return to Login")
            variant: "Danger"
            Layout.alignment: Qt.AlignHCenter
            onClicked: navigationController.reset(0) // Unauthenticated
        }
    }
}
