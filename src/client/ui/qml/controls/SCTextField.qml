import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

FocusScope {
    id: control

    property string label: ""
    property string placeholderText: ""
    property alias text: innerInput.text
    property bool isPassword: false
    property bool isMonospace: false
    property string errorMessage: ""
    property bool readOnly: false
    property int inputHeight: 40

    signal accepted()
    signal textEdited()

    property bool showPassword: false

    implicitWidth: 280
    implicitHeight: columnLayout.implicitHeight
    activeFocusOnTab: true

    ColumnLayout {
        id: columnLayout
        anchors.fill: parent
        spacing: Theme.space4

        // Top Label (if present)
        Label {
            visible: control.label !== ""
            text: control.label
            font.family: Theme.fontFamilyPrimary
            font.pixelSize: Theme.fontCaption
            font.bold: true
            color: control.errorMessage !== "" ? Theme.statusDanger : Theme.textSecondary
            Layout.fillWidth: true
        }

        // Input Box Container
        Rectangle {
            id: inputBg
            Layout.fillWidth: true
            Layout.preferredHeight: control.inputHeight
            radius: Theme.radiusMedium
            color: control.readOnly ? (Theme.isDark ? "#121824" : "#F1F5F9") : Theme.backgroundSecondary
            border.color: {
                if (control.errorMessage !== "") {
                    return Theme.statusDanger
                }
                if (innerInput.activeFocus) {
                    return Theme.borderFocused
                }
                return Theme.borderSubtle
            }
            border.width: innerInput.activeFocus || control.errorMessage !== "" ? 2 : 1

            Behavior on border.color {
                ColorAnimation { duration: Theme.durationFast }
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space12
                anchors.rightMargin: Theme.space8
                spacing: Theme.space4

                TextInput {
                    id: innerInput
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    font.family: control.isMonospace ? Theme.fontFamilyMonospace : Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontBody
                    color: Theme.textPrimary
                    echoMode: control.isPassword && !control.showPassword ? TextInput.Password : TextInput.Normal
                    readOnly: control.readOnly
                    selectByMouse: true
                    selectionColor: Theme.accentPrimary
                    selectedTextColor: "#FFFFFF"
                    clip: true

                    onAccepted: control.accepted()
                    onTextEdited: control.textEdited()

                    // Placeholder text overlay
                    Text {
                        anchors.fill: parent
                        text: control.placeholderText
                        font: parent.font
                        color: Theme.textMuted
                        visible: !innerInput.text && !innerInput.activeFocus
                        verticalAlignment: Text.AlignVCenter
                        elide: Text.ElideRight
                    }
                }

                // Clear button (when text is present and not read-only)
                Rectangle {
                    visible: innerInput.text !== "" && !control.readOnly && !control.isPassword
                    width: 20
                    height: 20
                    radius: 10
                    color: clearMouse.containsMouse ? (Theme.isDark ? "#2A364A" : "#CBD5E1") : "transparent"
                    Layout.alignment: Qt.AlignVCenter

                    Text {
                        anchors.centerIn: parent
                        text: "✕"
                        font.pixelSize: 11
                        color: Theme.textMuted
                    }

                    MouseArea {
                        id: clearMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            innerInput.text = ""
                            innerInput.forceActiveFocus()
                            control.textEdited()
                        }
                    }
                }

                // Password Reveal Toggle
                Rectangle {
                    visible: control.isPassword
                    width: 26
                    height: 26
                    radius: 4
                    color: eyeMouse.containsMouse ? (Theme.isDark ? "#2A364A" : "#CBD5E1") : "transparent"
                    Layout.alignment: Qt.AlignVCenter

                    Text {
                        anchors.centerIn: parent
                        text: control.showPassword ? "👁" : "🔒"
                        font.pixelSize: 13
                        color: control.showPassword ? Theme.accentPrimary : Theme.textMuted
                    }

                    MouseArea {
                        id: eyeMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            control.showPassword = !control.showPassword
                        }
                    }
                }
            }
        }

        // Error message (if present)
        Label {
            visible: control.errorMessage !== ""
            text: control.errorMessage
            font.family: Theme.fontFamilyPrimary
            font.pixelSize: Theme.fontCaption
            color: Theme.statusDanger
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
    }
}

