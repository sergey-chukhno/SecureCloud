import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: badge

    property string text: ""
    property string type: "Info" // Verified, Unverified, Online, Offline, Danger, Info
    property bool hasDot: true
    property int badgeHeight: 22

    implicitWidth: badgeRow.implicitWidth + Theme.space16
    implicitHeight: badgeHeight
    radius: badgeHeight / 2

    readonly property color statusColor: {
        switch (badge.type) {
            case "Verified":
            case "Online":
                return Theme.statusSuccess
            case "Unverified":
                return Theme.statusWarning
            case "Danger":
                return Theme.statusDanger
            case "Offline":
                return Theme.textMuted
            case "Info":
            default:
                return Theme.accentPrimary
        }
    }

    color: {
        switch (badge.type) {
            case "Verified":
            case "Online":
                return Theme.isDark ? "#122A22" : "#ECFDF5"
            case "Unverified":
                return Theme.isDark ? "#2C2011" : "#FFFBEB"
            case "Danger":
                return Theme.isDark ? "#2D1416" : "#FEF2F2"
            case "Offline":
                return Theme.isDark ? "#171D28" : "#F1F5F9"
            case "Info":
            default:
                return Theme.isDark ? "#13233D" : "#EFF6FF"
        }
    }

    border.color: statusColor
    border.width: 1

    RowLayout {
        id: badgeRow
        anchors.centerIn: parent
        spacing: Theme.space4

        // Indicator Dot
        Rectangle {
            visible: badge.hasDot
            width: 6
            height: 6
            radius: 3
            color: badge.statusColor
            Layout.alignment: Qt.AlignVCenter
        }

        Label {
            text: badge.text !== "" ? badge.text : badge.type
            font.family: Theme.fontFamilyPrimary
            font.pixelSize: Theme.fontCaption - 1
            font.bold: true
            color: badge.statusColor
            Layout.alignment: Qt.AlignVCenter
        }
    }
}

