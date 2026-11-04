import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: settingsRoot
    color: Theme.backgroundPrimary

    ColumnLayout {
        anchors.centerIn: parent
        spacing: Theme.space16
        width: 440

        Label {
            text: qsTr("Application Settings")
            font.pixelSize: Theme.fontHeadline
            font.bold: true
            font.family: Theme.fontFamilyPrimary
            color: Theme.textPrimary
        }

        Label {
            text: qsTr("Appearance & Theme Mode")
            font.pixelSize: Theme.fontSubtitle
            font.bold: true
            font.family: Theme.fontFamilyPrimary
            color: Theme.textSecondary
        }

        RowLayout {
            spacing: Theme.space12

            Button {
                text: qsTr("🌙 Dark Mode")
                highlighted: Theme.isDark
                onClicked: Theme.setThemeMode(1) // Dark
            }

            Button {
                text: qsTr("☀️ Light Mode")
                highlighted: !Theme.isDark
                onClicked: Theme.setThemeMode(2) // Light
            }

            Button {
                text: qsTr("💻 System Sync")
                onClicked: Theme.setThemeMode(0) // System
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: Theme.borderSubtle
        }

        Button {
            text: qsTr("Back to Workspace")
            onClicked: navigationController.navigateBack()
        }
    }
}
