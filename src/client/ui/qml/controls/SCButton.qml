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
    property string iconName: ""
    property string iconText: ""
    property bool fullWidth: false

    Accessible.role: Accessible.Button
    Accessible.name: control.text
    Accessible.description: control.busy ? qsTr("Busy") : ""

    signal clicked()

    implicitWidth: fullWidth && parent ? parent.width : Math.max(88, contentRow.implicitWidth + (horizontalPadding * 2))
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
                if (mouseArea.pressed) return "#1E40AF"
                if (mouseArea.containsMouse || control.activeFocus) return "#1D4ED8"
                return "#2563EB"
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
                if (mouseArea.pressed) return "#991B1B"
                if (mouseArea.containsMouse || control.activeFocus) return "#B91C1C"
                return "#DC2626"
            }
            return "#2563EB"
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
        scale: (mouseArea.pressed && control.enabled && !control.busy) ? 0.97 : 1.0

        Behavior on color {
            ColorAnimation { duration: Theme.durationFast }
        }
        Behavior on scale {
            NumberAnimation { duration: 110; easing.type: Easing.OutQuad }
        }

        RowLayout {
            id: contentRow
            anchors.centerIn: parent
            spacing: Theme.space8

            // Vector Icon
            SCIcon {
                visible: control.iconName !== "" && !control.busy
                name: control.iconName
                size: 16
                color: labelText.color
                Layout.alignment: Qt.AlignVCenter
            }

            // Optional Icon Text fallback
            Label {
                visible: control.iconName === "" && control.iconText !== "" && !control.busy
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

