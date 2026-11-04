import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

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

            SCButton {
                text: qsTr("🌙 Dark")
                variant: Theme.isDark ? "Primary" : "Secondary"
                onClicked: Theme.setThemeMode(1) // Dark
            }

            SCButton {
                text: qsTr("☀️ Light")
                variant: !Theme.isDark ? "Primary" : "Secondary"
                onClicked: Theme.setThemeMode(2) // Light
            }

            SCButton {
                text: qsTr("💻 System")
                variant: "Secondary"
                onClicked: Theme.setThemeMode(0) // System
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            color: Theme.borderSubtle
        }

        SCButton {
            text: qsTr("Back to Workspace")
            variant: "Ghost"
            iconText: "←"
            onClicked: navigationController.navigateBack()
        }
    }
}
