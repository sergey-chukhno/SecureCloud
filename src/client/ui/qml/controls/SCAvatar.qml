import QtQuick
import QtQuick.Controls

Item {
    id: avatar

    property string userId: ""
    property string displayName: ""
    property string imageUrl: ""
    property int size: 40
    property string presence: "None" // None, Online, Offline

    implicitWidth: size
    implicitHeight: size

    function getInitials(name, fallbackId) {
        var str = (name && name.trim().length > 0) ? name.trim() : fallbackId;
        if (!str || str.length === 0) return "?";
        var parts = str.split(" ");
        if (parts.length >= 2 && parts[0].length > 0 && parts[1].length > 0) {
            return (parts[0][0] + parts[1][0]).toUpperCase();
        }
        return str.substring(0, Math.min(2, str.length)).toUpperCase();
    }

    function getHashColor(str) {
        if (!str || str.length === 0) return Theme.accentPrimary;
        var hash = 0;
        for (var i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        var colors = [
            "#2563EB", // Blue
            "#7C3AED", // Purple
            "#DB2777", // Pink
            "#D97706", // Amber
            "#059669", // Emerald
            "#0891B2", // Cyan
            "#4F46E5", // Indigo
            "#0D9488"  // Teal
        ];
        var index = Math.abs(hash) % colors.length;
        return colors[index];
    }

    Rectangle {
        id: circle
        anchors.fill: parent
        radius: avatar.size / 2
        color: avatar.getHashColor(avatar.userId !== "" ? avatar.userId : avatar.displayName)
        border.color: Theme.borderSubtle
        border.width: 1

        Text {
            anchors.centerIn: parent
            text: avatar.getInitials(avatar.displayName, avatar.userId)
            font.family: Theme.fontFamilyPrimary
            font.pixelSize: Math.round(avatar.size * 0.40)
            font.bold: true
            color: "#FFFFFF"
        }
    }

    // Presence indicator dot (bottom-right)
    Rectangle {
        visible: avatar.presence !== "None"
        width: Math.max(8, Math.round(avatar.size * 0.28))
        height: width
        radius: width / 2
        anchors.bottom: parent.bottom
        anchors.right: parent.right
        color: avatar.presence === "Online" ? Theme.statusSuccess : Theme.textMuted
        border.color: Theme.backgroundPrimary
        border.width: 2
    }
}

