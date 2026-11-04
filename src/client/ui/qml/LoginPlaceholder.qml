import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: loginRoot
    color: Theme.backgroundPrimary

    ColumnLayout {
        anchors.centerIn: parent
        spacing: Theme.space16
        width: 360

        Label {
            text: qsTr("Sign in to SecureCloud")
            font.pixelSize: Theme.fontHeadline
            font.bold: true
            font.family: Theme.fontFamilyPrimary
            color: Theme.textPrimary
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr("Zero-Knowledge Encrypted Client")
            font.pixelSize: Theme.fontBody
            font.family: Theme.fontFamilyPrimary
            color: Theme.textSecondary
            Layout.alignment: Qt.AlignHCenter
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: Theme.borderSubtle
        }

        SCTextField {
            id: usernameField
            label: qsTr("Username or Email")
            placeholderText: qsTr("Enter your username")
            Layout.fillWidth: true
            text: "alice"
        }

        SCTextField {
            id: passwordField
            label: qsTr("Password")
            placeholderText: qsTr("Enter your password")
            isPassword: true
            Layout.fillWidth: true
            text: "secret"
            onAccepted: loginButton.clicked()
        }

        SCButton {
            id: loginButton
            text: qsTr("Log In")
            variant: "Primary"
            fullWidth: true
            onClicked: {
                appViewModel.requestLogin(usernameField.text, passwordField.text)
            }
        }
    }
}
