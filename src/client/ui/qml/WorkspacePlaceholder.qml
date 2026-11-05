import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: workspaceRoot
    color: Theme.backgroundPrimary

    readonly property var wvm: typeof workspaceViewModel !== "undefined" ? workspaceViewModel : null
    readonly property string activeSection: wvm ? wvm.activeSection : "Messages"

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Zone 2 — Master List Panel (Conversations / Contacts / Encrypted Files)
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 300
            color: Theme.backgroundSecondary

            Rectangle {
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.right: parent.right
                width: 1
                color: Theme.borderSubtle
            }

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.space16
                spacing: Theme.space12

                // Header + Counter Badge
                RowLayout {
                    Layout.fillWidth: true

                    Label {
                        text: {
                            if (workspaceRoot.activeSection === "Contacts") return qsTr("Contacts")
                            if (workspaceRoot.activeSection === "Files") return qsTr("Encrypted Files")
                            return qsTr("Messages")
                        }
                        font.bold: true
                        font.pixelSize: Theme.fontTitle
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                    }

                    Item { Layout.fillWidth: true }

                    SCBadge {
                        text: {
                            if (!workspaceRoot.wvm) return "0"
                            if (workspaceRoot.activeSection === "Contacts") {
                                return qsTr("%1 Peers").arg(workspaceRoot.wvm.contacts.length)
                            }
                            if (workspaceRoot.activeSection === "Files") {
                                return qsTr("%1 Vault Items").arg(workspaceRoot.wvm.activeFileTransferCount)
                            }
                            return qsTr("%1 Unread").arg(workspaceRoot.wvm.totalUnreadCount)
                        }
                        type: {
                            if (workspaceRoot.activeSection === "Contacts") return "Verified"
                            if (workspaceRoot.activeSection === "Messages" && workspaceRoot.wvm && workspaceRoot.wvm.totalUnreadCount === 0) {
                                return "Offline"
                            }
                            return "Info"
                        }
                        hasDot: false
                    }
                }

                // Real-Time Search Filter Input
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    SCTextField {
                        id: masterSearchField
                        Layout.fillWidth: true
                        inputHeight: 36
                        leadingIconName: "search"
                        placeholderText: {
                            if (workspaceRoot.activeSection === "Contacts") return qsTr("Search contacts or roles...")
                            if (workspaceRoot.activeSection === "Files") return qsTr("Search encrypted files...")
                            return qsTr("Search conversations...")
                        }
                        text: workspaceRoot.wvm ? workspaceRoot.wvm.searchQuery : ""
                        onTextEdited: {
                            if (workspaceRoot.wvm) {
                                workspaceRoot.wvm.searchQuery = masterSearchField.text
                            }
                        }
                    }

                    SCIconButton {
                        visible: masterSearchField.text.length > 0
                        iconName: "close"
                        buttonSize: 30
                        tooltipText: qsTr("Clear Search")
                        onClicked: {
                            masterSearchField.text = ""
                            if (workspaceRoot.wvm) {
                                workspaceRoot.wvm.searchQuery = ""
                            }
                        }
                    }
                }

                // Dynamic Master List (Conversations / Contacts / Files)
                Item {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    ListView {
                        id: masterListView
                        anchors.fill: parent
                        spacing: Theme.space8
                        clip: true
                        model: {
                            if (!workspaceRoot.wvm) return []
                            if (workspaceRoot.activeSection === "Contacts") return workspaceRoot.wvm.contacts
                            if (workspaceRoot.activeSection === "Files") return workspaceRoot.wvm.fileTransfers
                            return workspaceRoot.wvm.conversations
                        }

                        delegate: Rectangle {
                            id: cardDelegate
                            width: masterListView.width
                            height: 72
                            radius: 12
                            readonly property int itemPriority: modelData.priority || 1
                            readonly property bool hasUnread: (modelData.unreadCount || 0) > 0

                            color: {
                                if (modelData.isSelected) {
                                    return Theme.backgroundElevated
                                }
                                if (itemMouse.pressed) {
                                    return Theme.isDark ? "#222C3F" : "#CBD5E1"
                                }
                                if (itemMouse.containsMouse) {
                                    return Theme.isDark ? "#192130" : "#E2E8F0"
                                }
                                return "transparent"
                            }
                            border.color: {
                                if (modelData.isSelected && !Theme.isDark) {
                                    return Theme.borderSubtle
                                }
                                return "transparent"
                            }
                            border.width: (modelData.isSelected && !Theme.isDark) ? 1 : 0
                            scale: itemMouse.pressed ? 0.985 : 1.0

                            Behavior on color {
                                ColorAnimation { duration: Theme.durationFast }
                            }
                            Behavior on scale {
                                NumberAnimation { duration: 110; easing.type: Easing.OutQuad }
                            }

                            // Animated Active Left Accent Indicator Pill
                            Rectangle {
                                visible: height > 0
                                anchors.left: parent.left
                                anchors.verticalCenter: parent.verticalCenter
                                width: 3
                                height: modelData.isSelected ? 26 : 0
                                radius: 1.5
                                color: Theme.accentPrimary

                                Behavior on height {
                                    NumberAnimation { duration: 180; easing.type: Easing.OutCubic }
                                }
                            }

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space12
                                anchors.rightMargin: Theme.space12
                                anchors.topMargin: Theme.space10
                                anchors.bottomMargin: Theme.space10
                                spacing: Theme.space12

                                // Avatar for Messages/Contacts OR File-Lock Badge for Files
                                Loader {
                                    Layout.alignment: Qt.AlignVCenter
                                    sourceComponent: workspaceRoot.activeSection === "Files" ? fileVaultIconComp : peerAvatarComp
                                }

                                Component {
                                    id: peerAvatarComp
                                    SCAvatar {
                                        userId: modelData.peerUserId || modelData.userId || "peer"
                                        displayName: modelData.peerDisplayName || modelData.displayName || "Peer"
                                        size: 40
                                        presence: modelData.presence || "Offline"
                                    }
                                }

                                Component {
                                    id: fileVaultIconComp
                                    Rectangle {
                                        width: 40
                                        height: 40
                                        radius: 10
                                        color: Theme.isDark ? "#13233D" : "#DBEAFE"
                                        border.color: Theme.accentPrimary
                                        border.width: 1

                                        SCIcon {
                                            anchors.centerIn: parent
                                            name: "file-lock"
                                            size: 20
                                            color: Theme.accentPrimary
                                        }
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4

                                    // Top Row: Display Name + Verification Icon + Timestamp
                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 5

                                        Label {
                                            text: workspaceRoot.activeSection === "Files"
                                                  ? (modelData.fileName || "")
                                                  : (modelData.peerDisplayName || modelData.displayName || "")
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontBody
                                            font.bold: true
                                            color: Theme.textPrimary
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }

                                        SCIcon {
                                            visible: workspaceRoot.activeSection !== "Files"
                                            name: modelData.isBlocked
                                                  ? "shield-alert"
                                                  : (modelData.isVerified ? "shield-check" : "alert-triangle")
                                            size: 13
                                            color: modelData.isBlocked
                                                   ? Theme.statusDanger
                                                   : (modelData.isVerified ? Theme.accentPrimary : Theme.statusWarning)
                                            Layout.alignment: Qt.AlignVCenter
                                        }

                                        Label {
                                            text: workspaceRoot.activeSection === "Files"
                                                  ? (modelData.fileSizeText || "")
                                                  : (modelData.timestampText || modelData.handle || "")
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontMicro
                                            color: Theme.textMuted
                                            Layout.alignment: Qt.AlignVCenter
                                        }
                                    }

                                    // Bottom Row: Priority Pill + Preview / Role Note / Cipher Info + Unread Badge or Quick Action
                                    RowLayout {
                                        Layout.fillWidth: true
                                        spacing: 6

                                        // ADR-007 Priority Pill Badge (Urgent / Emergency)
                                        Rectangle {
                                            id: priorityPill
                                            visible: workspaceRoot.activeSection === "Messages" && cardDelegate.itemPriority > 1
                                            height: 17
                                            width: priorityRow.implicitWidth + 8
                                            radius: 8.5
                                            color: cardDelegate.itemPriority === 3
                                                   ? (Theme.isDark ? "rgba(239, 68, 68, 0.20)" : "#FEE2E2")
                                                   : (Theme.isDark ? "rgba(245, 158, 11, 0.20)" : "#FEF3C7")
                                            border.color: cardDelegate.itemPriority === 3 ? Theme.statusDanger : Theme.statusWarning
                                            border.width: 1
                                            Layout.alignment: Qt.AlignVCenter

                                            SequentialAnimation on opacity {
                                                running: priorityPill.visible && cardDelegate.itemPriority === 3 && cardDelegate.hasUnread
                                                loops: Animation.Infinite
                                                NumberAnimation { from: 1.0; to: 0.65; duration: 900; easing.type: Easing.InOutSine }
                                                NumberAnimation { from: 0.65; to: 1.0; duration: 900; easing.type: Easing.InOutSine }
                                            }

                                            RowLayout {
                                                id: priorityRow
                                                anchors.centerIn: parent
                                                spacing: 3

                                                SCIcon {
                                                    name: cardDelegate.itemPriority === 3 ? "shield-alert" : "zap"
                                                    size: 10
                                                    color: cardDelegate.itemPriority === 3 ? Theme.statusDanger : Theme.statusWarning
                                                }

                                                Label {
                                                    text: cardDelegate.itemPriority === 3 ? qsTr("EMERGENCY") : qsTr("URGENT")
                                                    font.family: Theme.fontFamilyPrimary
                                                    font.pixelSize: 9
                                                    font.bold: true
                                                    color: cardDelegate.itemPriority === 3 ? Theme.statusDanger : Theme.statusWarning
                                                }
                                            }
                                        }

                                        Label {
                                            text: {
                                                if (workspaceRoot.activeSection === "Files") {
                                                    return (modelData.cipherSuite || "AES-256-GCM") + " · " + (modelData.peerDisplayName || "")
                                                }
                                                if (workspaceRoot.activeSection === "Contacts") {
                                                    return modelData.roleNote || ""
                                                }
                                                return modelData.lastMessagePreview || ""
                                            }
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontCaption
                                            color: cardDelegate.hasUnread ? Theme.textPrimary : Theme.textSecondary
                                            font.bold: cardDelegate.hasUnread
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }

                                        // Unread Counter Pill (Messages section)
                                        Rectangle {
                                            visible: workspaceRoot.activeSection === "Messages" && cardDelegate.hasUnread
                                            width: 20
                                            height: 20
                                            radius: 10
                                            color: cardDelegate.itemPriority === 3
                                                   ? Theme.statusDanger
                                                   : (cardDelegate.itemPriority === 2 ? Theme.statusWarning : Theme.accentPrimary)

                                            Label {
                                                anchors.centerIn: parent
                                                text: (modelData.unreadCount || 0).toString()
                                                font.pixelSize: Theme.fontMicro
                                                font.bold: true
                                                color: "#FFFFFF"
                                            }
                                        }

                                        // Quick Jump to Encrypted Chat Button (Contacts section)
                                        SCIconButton {
                                            visible: workspaceRoot.activeSection === "Contacts"
                                            iconName: "workspace"
                                            buttonSize: 24
                                            z: 2
                                            tooltipText: qsTr("Open Encrypted Chat")
                                            onClicked: {
                                                if (workspaceRoot.wvm) {
                                                    workspaceRoot.wvm.selectConversation(modelData.conversationId)
                                                    workspaceRoot.wvm.activeSection = "Messages"
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            MouseArea {
                                id: itemMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    if (!workspaceRoot.wvm) return
                                    if (workspaceRoot.activeSection === "Files") {
                                        workspaceRoot.wvm.selectTransfer(modelData.transferId)
                                    } else if (workspaceRoot.activeSection === "Contacts") {
                                        workspaceRoot.wvm.selectContact(modelData.userId)
                                    } else {
                                        workspaceRoot.wvm.selectConversation(modelData.conversationId)
                                    }
                                }
                            }
                        }
                    }

                    // Empty Search Filter State
                    ColumnLayout {
                        visible: masterListView.count === 0
                        anchors.centerIn: parent
                        width: parent.width - 32
                        spacing: Theme.space8

                        SCIcon {
                            name: "search"
                            size: 28
                            color: Theme.textMuted
                            Layout.alignment: Qt.AlignHCenter
                        }

                        Label {
                            text: qsTr("No matching items found")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textSecondary
                            horizontalAlignment: Text.AlignHCenter
                            Layout.fillWidth: true
                        }

                        SCButton {
                            text: qsTr("Reset Filter")
                            variant: "Secondary"
                            buttonHeight: 30
                            Layout.alignment: Qt.AlignHCenter
                            onClicked: {
                                masterSearchField.text = ""
                                if (workspaceRoot.wvm) {
                                    workspaceRoot.wvm.searchQuery = ""
                                }
                            }
                        }
                    }
                }
            }
        }

        // Zone 3 — Central Conversation / File Stream Area
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.backgroundPrimary

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                // Contextual Peer Header Bar
                Rectangle {
                    Layout.fillWidth: true
                    height: 60
                    color: Theme.backgroundPrimary

                    Rectangle {
                        anchors.bottom: parent.bottom
                        anchors.left: parent.left
                        anchors.right: parent.right
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space16
                        anchors.rightMargin: Theme.space16
                        spacing: Theme.space12

                        SCAvatar {
                            userId: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerUserId : "peer"
                            displayName: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "Peer"
                            size: 36
                            presence: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerPresence : "Online"
                        }

                        ColumnLayout {
                            spacing: 2
                            Layout.fillWidth: true

                            RowLayout {
                                spacing: Theme.space8
                                Layout.fillWidth: true

                                Label {
                                    text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : ""
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: Theme.fontSubtitle
                                    font.bold: true
                                    color: Theme.textPrimary
                                    elide: Text.ElideRight
                                }

                                SCBadge {
                                    text: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                          ? qsTr("Verified")
                                          : qsTr("Unverified")
                                    type: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                          ? "Verified"
                                          : "Unverified"
                                }

                                Item { Layout.fillWidth: true }
                            }

                            Label {
                                text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerHandle : ""
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        SCIconButton {
                            iconName: "lock"
                            variant: "Secondary"
                            tooltipText: qsTr("Stage Encrypted File Transfer (audit-key-bundle.enc)")
                            onClicked: {
                                if (workspaceRoot.wvm) {
                                    workspaceRoot.wvm.stageEncryptedFileTransfer("audit-key-bundle.enc", 3145728)
                                }
                            }
                        }

                        SCIconButton {
                            iconName: (workspaceRoot.wvm && workspaceRoot.wvm.isInspectorOpen)
                                      ? "sidebar-expand"
                                      : "sidebar-collapse"
                            active: workspaceRoot.wvm ? workspaceRoot.wvm.isInspectorOpen : true
                            tooltipText: (workspaceRoot.wvm && workspaceRoot.wvm.isInspectorOpen)
                                         ? qsTr("Hide Peer Inspector")
                                         : qsTr("Show Peer Inspector")
                            onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.toggleInspector()
                        }
                    }
                }

                // Active Conversation Messages & Inline Encrypted File Cards
                ListView {
                    id: messageListView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: Theme.space12
                    clip: true
                    model: workspaceRoot.wvm ? workspaceRoot.wvm.activeMessages : []

                    header: Item { width: 1; height: Theme.space16 }
                    footer: Item { width: 1; height: Theme.space16 }

                    delegate: Item {
                        id: msgDelegate
                        width: messageListView.width
                        height: delegateCol.implicitHeight

                        readonly property int maxBubbleWidth: Math.max(220, Math.min(360, messageListView.width - 48))

                        ColumnLayout {
                            id: delegateCol
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: Theme.space24
                            anchors.rightMargin: Theme.space24
                            spacing: Theme.space4

                            Label {
                                text: (modelData.senderName || "") + "  " + (modelData.timestampText || "")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontMicro
                                color: Theme.textMuted
                                Layout.alignment: modelData.isSelf ? Qt.AlignRight : Qt.AlignLeft
                            }

                            Rectangle {
                                id: bubbleRect
                                Layout.alignment: modelData.isSelf ? Qt.AlignRight : Qt.AlignLeft
                                Layout.preferredWidth: msgDelegate.maxBubbleWidth
                                implicitHeight: msgColumn.implicitHeight + (Theme.space12 * 2)
                                radius: Theme.radiusLarge
                                color: modelData.isSelf ? Theme.bubbleSelf : Theme.bubblePeer
                                border.color: modelData.isFileTransfer ? Theme.accentPrimary : "transparent"
                                border.width: modelData.isFileTransfer ? 1 : 0

                                ColumnLayout {
                                    id: msgColumn
                                    anchors.fill: parent
                                    anchors.margins: Theme.space12
                                    spacing: Theme.space4

                                    RowLayout {
                                        visible: modelData.isFileTransfer ? true : false
                                        Layout.fillWidth: true
                                        spacing: Theme.space8

                                        SCIcon {
                                            name: "lock"
                                            size: 16
                                            color: modelData.isSelf ? "#FFFFFF" : Theme.accentPrimary
                                        }

                                        Label {
                                            text: (modelData.fileName || "") + " (" + (modelData.fileSizeText || "") + ")"
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontBody
                                            font.bold: true
                                            color: modelData.isSelf ? Theme.bubbleSelfText : Theme.bubblePeerText
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }

                                    Label {
                                        text: modelData.isFileTransfer
                                              ? qsTr("%1 · SHA-256: %2").arg(modelData.cipherSuite || "AES-256-GCM").arg(modelData.sha256Short || "")
                                              : (modelData.text || "")
                                        font.family: modelData.isFileTransfer ? Theme.fontFamilyMonospace : Theme.fontFamilyPrimary
                                        font.pixelSize: modelData.isFileTransfer ? Theme.fontMicro : Theme.fontBody
                                        color: modelData.isSelf ? Theme.bubbleSelfText : Theme.bubblePeerText
                                        wrapMode: Text.WordWrap
                                        Layout.fillWidth: true
                                    }
                                }
                            }
                        }
                    }
                }

                // Floating Pill Composer Bar
                Rectangle {
                    Layout.fillWidth: true
                    Layout.margins: Theme.space16
                    height: 52
                    radius: Theme.radiusLarge
                    color: Theme.backgroundSecondary
                    border.color: Theme.borderSubtle
                    border.width: 1

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space12
                        anchors.rightMargin: Theme.space12
                        spacing: Theme.space8

                        SCTextField {
                            id: composerInput
                            Layout.fillWidth: true
                            inputHeight: 36
                            placeholderText: qsTr("Type an encrypted message...")
                            onAccepted: sendBtn.clicked()
                        }

                        SCButton {
                            id: sendBtn
                            text: qsTr("Send")
                            iconName: "check"
                            variant: "Primary"
                            buttonHeight: 36
                            onClicked: {
                                if (workspaceRoot.wvm && workspaceRoot.wvm.sendMessage(composerInput.text)) {
                                    composerInput.text = ""
                                }
                            }
                        }
                    }
                }
            }
        }

        // Zone 4 — Collapsible Right-Hand Peer Security & Shared Files Inspector
        Rectangle {
            visible: workspaceRoot.wvm ? workspaceRoot.wvm.isInspectorOpen : true
            Layout.fillHeight: true
            Layout.preferredWidth: 280
            color: Theme.backgroundPrimary

            Rectangle {
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                width: 1
                color: Theme.borderSubtle
            }

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.space24
                spacing: Theme.space16

                RowLayout {
                    Layout.fillWidth: true
                    Item { Layout.fillWidth: true }
                    SCIconButton {
                        iconName: "close"
                        tooltipText: qsTr("Close Inspector")
                        onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.setInspectorOpen(false)
                    }
                }

                SCAvatar {
                    userId: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerUserId : "peer"
                    displayName: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "Peer"
                    size: 76
                    presence: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerPresence : "Online"
                    Layout.alignment: Qt.AlignHCenter
                }

                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Theme.space8

                    Label {
                        text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerHandle : ""
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontSubtitle
                        font.bold: true
                        color: Theme.textPrimary
                    }

                    SCIcon {
                        name: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified) ? "shield-check" : "alert-triangle"
                        size: 16
                        color: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified) ? Theme.accentPrimary : Theme.statusWarning
                    }
                }

                Label {
                    text: qsTr("Safety Number:")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    font.bold: true
                    color: Theme.textPrimary
                }

                Label {
                    text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerSafetyNumber : ""
                    font.family: Theme.fontFamilyMonospace
                    font.pixelSize: Theme.fontMicro
                    color: Theme.accentPrimary
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                Label {
                    text: qsTr("Notes:")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    font.bold: true
                    color: Theme.textPrimary
                }

                Label {
                    text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerRoleNote : ""
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    color: Theme.textSecondary
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                Item { Layout.fillHeight: true }

                SCButton {
                    text: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked)
                          ? qsTr("Unblock Peer")
                          : qsTr("Block %1").arg(workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "")
                    iconName: "shield-alert"
                    variant: "Danger"
                    fullWidth: true
                    onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.togglePeerBlocked("")
                }
            }
        }
    }
}
