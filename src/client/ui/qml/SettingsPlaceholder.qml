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
        width: 520

        Label {
            text: qsTr("Application Settings")
            font.pixelSize: Theme.fontHeadline
            font.bold: true
            font.family: Theme.fontFamilyPrimary
            color: Theme.textPrimary
        }

        SCCard {
            Layout.fillWidth: true
            Layout.preferredHeight: 130
            headerText: qsTr("Appearance & Theme")
            headerIcon: "🎨"
            elevation: "Elevated"

            ColumnLayout {
                anchors.fill: parent
                spacing: Theme.space12

                Label {
                    text: qsTr("Choose your preferred visual presentation:")
                    font.pixelSize: Theme.fontCaption
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
                        text: qsTr("💻 System Sync")
                        variant: "Secondary"
                        onClicked: Theme.setThemeMode(0) // System
                    }
                }
            }
        }

        SCCard {
            Layout.fillWidth: true
            Layout.preferredHeight: 110
            headerText: qsTr("Security & Trust Boundaries")
            headerIcon: "🔒"
            elevation: "Base"

            RowLayout {
                anchors.fill: parent
                spacing: Theme.space12

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    Label {
                        text: qsTr("Transport Encryption")
                        font.bold: true
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontBody
                        color: Theme.textPrimary
                    }

                    Label {
                        text: qsTr("TLS 1.3 mTLS with strict certificate validation")
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontCaption
                        color: Theme.textMuted
                    }
                }

                SCBadge {
                    type: "Verified"
                    text: "Active"
                }
            }
        }

        SCButton {
            text: qsTr("Back to Workspace")
            variant: "Ghost"
            iconText: "←"
            onClicked: navigationController.navigateBack()
        }
    }
}
