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
    property bool isError: errorMessage !== ""
    property bool readOnly: false
    property int inputHeight: 40
    property string leadingIconName: ""

    Accessible.role: Accessible.EditableText
    Accessible.name: control.label !== "" ? control.label : control.placeholderText
    Accessible.description: control.errorMessage

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
            color: {
                if (!control.enabled) return Theme.isDark ? "#0D111A" : "#E2E8F0"
                if (control.readOnly) return Theme.isDark ? "#121824" : "#F1F5F9"
                return Theme.isDark ? "#0F141E" : Theme.backgroundSecondary
            }
            border.color: {
                if (control.errorMessage !== "") {
                    return Theme.statusDanger
                }
                if (innerInput.activeFocus) {
                    return Theme.borderFocused
                }
                if (inputHoverHandler.hovered && control.enabled && !control.readOnly) {
                    return Theme.isDark ? "#38465E" : "#94A3B8"
                }
                return Theme.borderSubtle
            }
            border.width: innerInput.activeFocus || control.errorMessage !== "" ? 2 : 1

            HoverHandler {
                id: inputHoverHandler
            }

            Behavior on border.color {
                ColorAnimation { duration: Theme.durationFast }
            }

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space12
                anchors.rightMargin: Theme.space8
                spacing: Theme.space8

                SCIcon {
                    visible: control.leadingIconName !== ""
                    name: control.leadingIconName
                    size: 16
                    color: innerInput.activeFocus ? Theme.accentPrimary : Theme.textMuted
                    Layout.alignment: Qt.AlignVCenter
                }

                TextInput {
                    id: innerInput
                    focus: true
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    font.family: control.isMonospace ? Theme.fontFamilyMonospace : Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontBody
                    color: control.enabled ? Theme.textPrimary : Theme.textMuted
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
                        visible: !innerInput.text
                        verticalAlignment: Text.AlignVCenter
                        elide: Text.ElideRight
                    }
                }

                // Clear button (when text is present and not read-only)
                Rectangle {
                    visible: innerInput.text !== "" && !control.readOnly && !control.isPassword && control.enabled
                    width: 22
                    height: 22
                    radius: 11
                    color: clearMouse.containsMouse ? (Theme.isDark ? "#2A364A" : "#CBD5E1") : "transparent"
                    Layout.alignment: Qt.AlignVCenter

                    SCIcon {
                        anchors.centerIn: parent
                        name: "close"
                        size: 12
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
                    width: 28
                    height: 28
                    radius: Theme.radiusSmall
                    color: eyeMouse.containsMouse ? (Theme.isDark ? "#2A364A" : "#CBD5E1") : "transparent"
                    Layout.alignment: Qt.AlignVCenter

                    SCIcon {
                        anchors.centerIn: parent
                        name: control.showPassword ? "eye-off" : "eye"
                        size: 16
                        color: control.showPassword ? Theme.accentPrimary : Theme.textMuted
                    }

                    ToolTip {
                        visible: eyeMouse.containsMouse
                        text: control.showPassword ? qsTr("Hide password") : qsTr("Show password")
                        delay: 400
                        timeout: 2500
                    }

                    MouseArea {
                        id: eyeMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: control.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                        onClicked: {
                            if (control.enabled) {
                                control.showPassword = !control.showPassword
                                innerInput.forceActiveFocus()
                            }
                        }
                    }
                }
            }
        }

        // Error message (if present)
        RowLayout {
            visible: control.errorMessage !== ""
            Layout.fillWidth: true
            spacing: Theme.space4

            SCIcon {
                name: "alert-triangle"
                size: 13
                color: Theme.statusDanger
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: control.errorMessage
                font.family: Theme.fontFamilyPrimary
                font.pixelSize: Theme.fontCaption
                color: Theme.statusDanger
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                Layout.alignment: Qt.AlignVCenter
            }
        }
    }
}

