import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: dialogRoot

    property string title: ""
    property string message: ""
    property string confirmText: qsTr("Confirm")
    property string cancelText: qsTr("Cancel")
    property bool isDanger: false
    property bool isOpen: false
    property Component customContent: null

    signal confirmed()
    signal cancelled()

    function open() {
        isOpen = true;
    }

    function close() {
        isOpen = false;
    }

    visible: isOpen
    anchors.fill: parent
    z: 999

    Shortcut {
        sequence: "Esc"
        enabled: dialogRoot.isOpen
        onActivated: {
            dialogRoot.isOpen = false
            dialogRoot.cancelled()
        }
    }

    // Dimmed modal backdrop capturing all events
    Rectangle {
        id: backdrop
        anchors.fill: parent
        color: Theme.isDark ? "rgba(0, 0, 0, 0.72)" : "rgba(15, 23, 42, 0.48)"

        MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            preventStealing: true
            onClicked: {
                // Clicking outside does not dismiss if danger dialog to prevent accidental triggers
                if (!dialogRoot.isDanger) {
                    dialogRoot.isOpen = false
                    dialogRoot.cancelled()
                }
            }
        }
    }

    // Centered Dialog Window
    Rectangle {
        id: dialogBox
        width: 440
        implicitHeight: dialogLayout.implicitHeight + (Theme.space24 * 2)
        anchors.centerIn: parent
        radius: Theme.radiusLarge
        color: Theme.backgroundElevated
        border.color: dialogRoot.isDanger ? Theme.statusDanger : Theme.borderSubtle
        border.width: dialogRoot.isDanger ? 2 : 1

        ColumnLayout {
            id: dialogLayout
            anchors.fill: parent
            anchors.margins: Theme.space24
            spacing: Theme.space16

            // Dialog Title Row
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space8

                SCIcon {
                    visible: dialogRoot.isDanger
                    name: "shield-alert"
                    size: 20
                    color: Theme.statusDanger
                    Layout.alignment: Qt.AlignVCenter
                }

                Label {
                    text: dialogRoot.title
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontTitle
                    font.bold: true
                    color: dialogRoot.isDanger ? Theme.statusDanger : Theme.textPrimary
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            // Dialog Message Body
            Label {
                visible: dialogRoot.message.length > 0
                text: dialogRoot.message
                font.family: Theme.fontFamilyPrimary
                font.pixelSize: Theme.fontBody
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            // Optional Custom Content Slot (forms, inputs, list items)
            Loader {
                Layout.fillWidth: true
                visible: dialogRoot.customContent !== null
                sourceComponent: dialogRoot.customContent
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
                color: Theme.borderSubtle
            }

            // Dialog Action Buttons
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space12

                Item { Layout.fillWidth: true }

                SCButton {
                    text: dialogRoot.cancelText
                    variant: "Secondary"
                    onClicked: {
                        dialogRoot.isOpen = false
                        dialogRoot.cancelled()
                    }
                }

                SCButton {
                    text: dialogRoot.confirmText
                    variant: dialogRoot.isDanger ? "Danger" : "Primary"
                    onClicked: {
                        dialogRoot.isOpen = false
                        dialogRoot.confirmed()
                    }
                }
            }
        }
    }
}

