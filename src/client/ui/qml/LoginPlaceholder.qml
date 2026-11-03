import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: loginRoot
    color: "#1e1e24"

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 16
        width: 340

        Label {
            text: qsTr("Sign in to SecureCloud")
            font.pixelSize: 22
            font.bold: true
            color: "#ffffff"
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: qsTr("CLIENT-002 Authentication Extension Point")
            font.pixelSize: 12
            color: "#808090"
            Layout.alignment: Qt.AlignHCenter
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

