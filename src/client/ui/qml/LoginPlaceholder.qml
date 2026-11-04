import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

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

        TextField {
            id: usernameField
            placeholderText: qsTr("Username or Email")
            Layout.fillWidth: true
            text: "alice"
        }

        TextField {
            id: passwordField
            placeholderText: qsTr("Password")
            echoMode: TextInput.Password
            Layout.fillWidth: true
            text: "secret"
        }

        Button {
            text: qsTr("Log In")
            Layout.fillWidth: true
            highlighted: true
            onClicked: {
                appViewModel.requestLogin(usernameField.text, passwordField.text)
            }
        }
    }
}
