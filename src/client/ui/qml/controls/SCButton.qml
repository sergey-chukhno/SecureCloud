import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

FocusScope {
    id: control

    property string text: ""
    property string variant: "Primary" // Primary, Secondary, Ghost, Danger
    property bool busy: false
    property int buttonHeight: 38
    property int horizontalPadding: 16
    property string iconText: ""
    property bool fullWidth: false

    signal clicked()

    implicitWidth: fullWidth ? parent.width : Math.max(88, contentRow.implicitWidth + (horizontalPadding * 2))
    implicitHeight: buttonHeight
    activeFocusOnTab: true

    Keys.onReturnPressed: if (enabled && !busy) control.clicked()
    Keys.onEnterPressed: if (enabled && !busy) control.clicked()
    Keys.onSpacePressed: if (enabled && !busy) control.clicked()

    Rectangle {
        id: bg
        anchors.fill: parent
        radius: Theme.radiusMedium
        color: {
            if (!control.enabled) {
                return Theme.isDark ? "#1C2433" : "#E2E8F0"
            }
            if (control.variant === "Primary") {
                if (mouseArea.pressed) return Theme.accentActive
                if (mouseArea.containsMouse || control.activeFocus) return Theme.accentHover
                return Theme.accentPrimary
            }
            if (control.variant === "Secondary") {
                if (mouseArea.pressed) return Theme.isDark ? "#2A364A" : "#CBD5E1"
                if (mouseArea.containsMouse) return Theme.isDark ? "#222D3D" : "#E2E8F0"
                return Theme.backgroundSecondary
            }
            if (control.variant === "Ghost") {
                if (mouseArea.pressed) return Theme.isDark ? "rgba(255, 255, 255, 0.12)" : "rgba(0, 0, 0, 0.08)"
                if (mouseArea.containsMouse) return Theme.isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.04)"
                return "transparent"
            }
            if (control.variant === "Danger") {
                if (mouseArea.pressed) return Theme.isDark ? "#991B1B" : "#B91C1C"
                if (mouseArea.containsMouse || control.activeFocus) return Theme.isDark ? "#DC2626" : "#DC2626"
                return Theme.statusDanger
            }
            return Theme.accentPrimary
        }

        border.color: {
            if (control.activeFocus) {
                return Theme.borderFocused
            }
            if (control.variant === "Secondary") {
                return Theme.borderSubtle
            }
            return "transparent"
        }
        border.width: control.activeFocus ? 2 : (control.variant === "Secondary" ? 1 : 0)

        Behavior on color {
            ColorAnimation { duration: Theme.durationFast }
        }

        RowLayout {
            id: contentRow
            anchors.centerIn: parent
            spacing: Theme.space8

            // Optional Icon Text (e.g. "←", "✓", "⚠")
            Label {
                visible: control.iconText !== "" && !control.busy
                text: control.iconText
                font.pixelSize: Theme.fontSubtitle
                color: labelText.color
                Layout.alignment: Qt.AlignVCenter
            }

            // Spinner animation placeholder when busy
            Rectangle {
                id: spinner
                visible: control.busy
                width: 14
                height: 14
                radius: 7
                color: "transparent"
                border.color: labelText.color
                border.width: 2
                Layout.alignment: Qt.AlignVCenter

                RotationAnimation on rotation {
                    running: control.busy
                    loops: Animation.Infinite
                    from: 0
                    to: 360
                    duration: 800
                }
            }

            Label {
                id: labelText
                text: control.busy ? qsTr("Processing...") : control.text
                font.family: Theme.fontFamilyPrimary
                font.pixelSize: Theme.fontBody
                font.bold: control.variant === "Primary" || control.variant === "Danger"
                color: {
                    if (!control.enabled) {
                        return Theme.textMuted
                    }
                    if (control.variant === "Primary" || control.variant === "Danger") {
                        return "#FFFFFF"
                    }
                    return Theme.textPrimary
                }
                Layout.alignment: Qt.AlignVCenter
            }
        }

        MouseArea {
            id: mouseArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: control.enabled && !control.busy ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: {
                if (control.enabled && !control.busy) {
                    control.forceActiveFocus()
                    control.clicked()
                }
            }
        }
    }
}

