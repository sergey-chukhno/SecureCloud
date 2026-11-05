import QtQuick
import QtQuick.Controls

FocusScope {
    id: control

    property string iconName: ""
    property string iconText: ""
    property string tooltipText: ""
    property int size: 34
    property alias buttonSize: control.size
    property string variant: "Ghost" // Ghost, Secondary, Danger
    property bool active: false
    property int badgeCount: 0

    Accessible.role: Accessible.Button
    Accessible.name: control.tooltipText !== "" ? control.tooltipText : (control.iconName !== "" ? control.iconName : control.iconText)

    signal clicked()

    implicitWidth: size
    implicitHeight: size
    activeFocusOnTab: true

    Keys.onReturnPressed: if (enabled) control.clicked()
    Keys.onEnterPressed: if (enabled) control.clicked()
    Keys.onSpacePressed: if (enabled) control.clicked()

    Rectangle {
        id: bg
        anchors.fill: parent
        radius: Theme.radiusSmall
        color: {
            if (!control.enabled) {
                return "transparent"
            }
            if (control.active) {
                return Theme.isDark ? "#222D3D" : "#E2E8F0"
            }
            if (control.variant === "Secondary") {
                if (mouseArea.pressed) return Theme.isDark ? "#2A364A" : "#CBD5E1"
                if (mouseArea.containsMouse) return Theme.isDark ? "#222D3D" : "#E2E8F0"
                return Theme.backgroundSecondary
            }
            if (control.variant === "Danger") {
                if (mouseArea.pressed) return "#991B1B"
                if (mouseArea.containsMouse) return "#B91C1C"
                return "#DC2626"
            }
            // Ghost default
            if (mouseArea.pressed) return Theme.isDark ? "rgba(255, 255, 255, 0.12)" : "rgba(0, 0, 0, 0.08)"
            if (mouseArea.containsMouse || control.activeFocus) return Theme.isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.04)"
            return "transparent"
        }

        border.color: control.activeFocus ? Theme.borderFocused : (control.variant === "Secondary" ? Theme.borderSubtle : "transparent")
        border.width: control.activeFocus ? 2 : (control.variant === "Secondary" ? 1 : 0)
        scale: (mouseArea.pressed && control.enabled) ? 0.94 : 1.0

        Behavior on color {
            ColorAnimation { duration: Theme.durationFast }
        }
        Behavior on scale {
            NumberAnimation { duration: 110; easing.type: Easing.OutQuad }
        }

        SCIcon {
            anchors.centerIn: parent
            visible: control.iconName !== ""
            name: control.iconName
            size: Math.round(control.size * 0.5)
            color: {
                if (!control.enabled) return Theme.textMuted
                if (control.variant === "Danger") return "#FFFFFF"
                if (control.active) return Theme.accentPrimary
                return Theme.textPrimary
            }
        }

        Text {
            anchors.centerIn: parent
            visible: control.iconName === ""
            text: control.iconText
            font.family: Theme.fontFamilyPrimary
            font.pixelSize: Math.round(control.size * 0.45)
            color: {
                if (!control.enabled) return Theme.textMuted
                if (control.variant === "Danger") return "#FFFFFF"
                if (control.active) return Theme.accentPrimary
                return Theme.textPrimary
            }
        }

        // Badge indicator (for unread count or alerts)
        Rectangle {
            visible: control.badgeCount > 0
            anchors.top: parent.top
            anchors.right: parent.right
            anchors.margins: -2
            width: Math.max(14, badgeText.implicitWidth + 6)
            height: 14
            radius: 7
            color: Theme.statusDanger

            Text {
                id: badgeText
                anchors.centerIn: parent
                text: control.badgeCount > 99 ? "99+" : control.badgeCount.toString()
                font.pixelSize: 9
                font.bold: true
                color: "#FFFFFF"
            }
        }

        // Tooltip
        ToolTip {
            visible: mouseArea.containsMouse && control.tooltipText !== ""
            text: control.tooltipText
            delay: 400
            timeout: 3000
        }

        MouseArea {
            id: mouseArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: control.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: {
                if (control.enabled) {
                    control.forceActiveFocus()
                    control.clicked()
                }
            }
        }
    }
}

