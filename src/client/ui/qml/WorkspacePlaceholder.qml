import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: workspaceRoot
    color: Theme.backgroundPrimary

    readonly property var wvm: typeof workspaceViewModel !== "undefined" ? workspaceViewModel : null
    readonly property var avm: typeof appViewModel !== "undefined" ? appViewModel : null
    readonly property string activeSection: wvm ? wvm.activeSection : "Messages"
    readonly property int currentPriority: wvm ? wvm.composerPriority : 1
    property bool animateNewMessages: false
    property int stagedFileCounter: 0

    readonly property var sampleAttachmentNames: [
        "audit-key-bundle.enc",
        "incident-forensics-dump.tar.enc",
        "x3dh-prekey-attestation.json.enc",
        "zero-trust-network-policy-v3.pdf"
    ]

    function triggerSampleFileAttachment() {
        if (!workspaceRoot.wvm) return
        workspaceRoot.animateNewMessages = true
        var idx = workspaceRoot.stagedFileCounter % workspaceRoot.sampleAttachmentNames.length
        var fileName = workspaceRoot.sampleAttachmentNames[idx]
        var fileSize = 1572864 + (idx * 943718)
        workspaceRoot.stagedFileCounter += 1
        workspaceRoot.wvm.stageEncryptedFileTransfer(fileName, fileSize)
    }

    Connections {
        target: workspaceRoot.wvm
        function onActiveMessagesChanged() {
            Qt.callLater(function() {
                if (messageListView.count > 0) {
                    messageListView.positionViewAtEnd()
                }
            })
        }
    }

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
                    id: peerHeaderBar
                    Layout.fillWidth: true
                    height: 64
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
                            size: 38
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
                                    Layout.maximumWidth: Math.max(100, peerHeaderBar.width - 230)
                                }

                                SCBadge {
                                    text: {
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked) return qsTr("Blocked")
                                        return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                               ? qsTr("Verified")
                                               : qsTr("Unverified")
                                    }
                                    type: {
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked) return "Danger"
                                        return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                               ? "Verified"
                                               : "Unverified"
                                    }
                                }

                                Rectangle {
                                    visible: peerHeaderBar.width > 540
                                    height: 20
                                    width: cipherHeaderRow.implicitWidth + 12
                                    radius: 10
                                    color: Theme.backgroundSecondary
                                    border.color: Theme.borderSubtle
                                    border.width: 1

                                    RowLayout {
                                        id: cipherHeaderRow
                                        anchors.centerIn: parent
                                        spacing: 4

                                        SCIcon {
                                            name: "lock"
                                            size: 11
                                            color: Theme.accentPrimary
                                        }

                                        Label {
                                            text: qsTr("Double Ratchet · AES-256-GCM")
                                            font.family: Theme.fontFamilyMonospace
                                            font.pixelSize: 10
                                            color: Theme.textSecondary
                                        }
                                    }
                                }

                                Item { Layout.fillWidth: true }
                            }

                            Label {
                                text: {
                                    var handle = workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerHandle : ""
                                    return handle + "  ·  " + qsTr("Double Ratchet E2EE")
                                }
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        SCIconButton {
                            iconName: "paperclip"
                            variant: "Secondary"
                            tooltipText: qsTr("Stage Encrypted File Transfer (AES-256-GCM)")
                            onClicked: workspaceRoot.triggerSampleFileAttachment()
                        }

                        SCIconButton {
                            iconName: "info"
                            variant: "Secondary"
                            active: workspaceRoot.wvm ? workspaceRoot.wvm.isInspectorOpen : true
                            tooltipText: (workspaceRoot.wvm && workspaceRoot.wvm.isInspectorOpen)
                                         ? qsTr("Hide Peer Security Inspector")
                                         : qsTr("Show Peer Security Inspector")
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

                    header: Item { width: 1; height: Theme.space12 }
                    footer: Item { width: 1; height: Theme.space12 }

                    delegate: Item {
                        id: msgDelegate
                        width: messageListView.width
                        height: delegateOuterCol.implicitHeight

                        readonly property int msgPriority: modelData.priority || 1
                        readonly property bool isEmergency: msgPriority === 3
                        readonly property bool isUrgent: msgPriority === 2
                        readonly property int maxBubbleWidth: Math.max(240, Math.min(410, messageListView.width - 96))

                        transform: Translate {
                            id: entryTranslate
                            y: 0
                        }

                        ParallelAnimation {
                            id: entryAnim
                            NumberAnimation {
                                target: msgDelegate
                                property: "opacity"
                                from: 0.0
                                to: 1.0
                                duration: 180
                                easing.type: Easing.OutCubic
                            }
                            NumberAnimation {
                                target: entryTranslate
                                property: "y"
                                from: 10
                                to: 0
                                duration: 180
                                easing.type: Easing.OutCubic
                            }
                        }

                        Component.onCompleted: {
                            if (workspaceRoot.animateNewMessages && index === messageListView.count - 1) {
                                entryAnim.restart()
                            }
                        }

                        ColumnLayout {
                            id: delegateOuterCol
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: Theme.space24
                            anchors.rightMargin: Theme.space24
                            spacing: Theme.space12

                            // Centered Date Group Pill Separator (matching visual reference)
                            Rectangle {
                                visible: modelData.showDateSeparator ? true : false
                                Layout.alignment: Qt.AlignHCenter
                                Layout.topMargin: Theme.space4
                                Layout.bottomMargin: Theme.space4
                                height: 22
                                width: dateGroupLabel.implicitWidth + 20
                                radius: 11
                                color: Theme.backgroundSecondary
                                border.color: Theme.borderSubtle
                                border.width: 1

                                Label {
                                    id: dateGroupLabel
                                    anchors.centerIn: parent
                                    text: modelData.dateGroup || ""
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: 10
                                    font.bold: true
                                    font.letterSpacing: 0.6
                                    color: Theme.textMuted
                                }
                            }

                            // Message Row with Peer/Self Avatar + Bubble Column
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space12

                                // Left Filler for Self Messages
                                Item {
                                    visible: modelData.isSelf ? true : false
                                    Layout.fillWidth: true
                                }

                                // Peer Avatar (Left-aligned for incoming messages)
                                SCAvatar {
                                    visible: !modelData.isSelf
                                    userId: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerUserId : "peer"
                                    displayName: modelData.senderName || "Peer"
                                    size: 28
                                    presence: ""
                                    Layout.alignment: Qt.AlignTop
                                    Layout.topMargin: 18
                                }

                                // Bubble + Metadata Column
                                ColumnLayout {
                                    spacing: 4
                                    Layout.maximumWidth: msgDelegate.maxBubbleWidth

                                    // Sender + Timestamp + Priority Header Row
                                    RowLayout {
                                        Layout.alignment: modelData.isSelf ? Qt.AlignRight : Qt.AlignLeft
                                        spacing: 6

                                        Label {
                                            text: (modelData.senderName || "") + "  " + (modelData.timestampText || "")
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontMicro
                                            color: Theme.textMuted
                                        }

                                        Rectangle {
                                            visible: msgDelegate.msgPriority > 1
                                            height: 16
                                            width: msgPriorityRow.implicitWidth + 8
                                            radius: 8
                                            color: msgDelegate.isEmergency
                                                   ? (Theme.isDark ? "rgba(239, 68, 68, 0.22)" : "#FEE2E2")
                                                   : (Theme.isDark ? "rgba(245, 158, 11, 0.22)" : "#FEF3C7")
                                            border.color: msgDelegate.isEmergency ? Theme.statusDanger : Theme.statusWarning
                                            border.width: 1

                                            RowLayout {
                                                id: msgPriorityRow
                                                anchors.centerIn: parent
                                                spacing: 3

                                                SCIcon {
                                                    name: msgDelegate.isEmergency ? "shield-alert" : "zap"
                                                    size: 10
                                                    color: msgDelegate.isEmergency ? Theme.statusDanger : Theme.statusWarning
                                                }

                                                Label {
                                                    text: msgDelegate.isEmergency ? qsTr("EMERGENCY") : qsTr("URGENT")
                                                    font.family: Theme.fontFamilyPrimary
                                                    font.pixelSize: 9
                                                    font.bold: true
                                                    color: msgDelegate.isEmergency ? Theme.statusDanger : Theme.statusWarning
                                                }
                                            }
                                        }
                                    }

                                    // Message or Encrypted File Bubble
                                    Rectangle {
                                        id: bubbleRect
                                        Layout.alignment: modelData.isSelf ? Qt.AlignRight : Qt.AlignLeft
                                        Layout.preferredWidth: msgDelegate.maxBubbleWidth
                                        implicitHeight: msgColumn.implicitHeight + (Theme.space12 * 2)
                                        radius: 16
                                        color: {
                                            if (msgDelegate.isEmergency && !modelData.isSelf) {
                                                return Theme.isDark ? "#2A161D" : "#FEF2F2"
                                            }
                                            return modelData.isSelf ? Theme.bubbleSelf : Theme.bubblePeer
                                        }
                                        border.color: {
                                            if (msgDelegate.isEmergency) return Theme.statusDanger
                                            if (msgDelegate.isUrgent) return Theme.statusWarning
                                            if (modelData.isFileTransfer) return Theme.accentPrimary
                                            return "transparent"
                                        }
                                        border.width: (msgDelegate.msgPriority > 1) ? 1.5 : (modelData.isFileTransfer ? 1 : 0)

                                        ColumnLayout {
                                            id: msgColumn
                                            anchors.fill: parent
                                            anchors.margins: Theme.space12
                                            spacing: 6

                                            // Inline Encrypted File Attachment Card Header
                                            RowLayout {
                                                visible: modelData.isFileTransfer ? true : false
                                                Layout.fillWidth: true
                                                spacing: Theme.space8

                                                Rectangle {
                                                    width: 34
                                                    height: 34
                                                    radius: 8
                                                    color: modelData.isSelf
                                                           ? "rgba(255, 255, 255, 0.16)"
                                                           : (Theme.isDark ? "#13233D" : "#DBEAFE")
                                                    border.color: modelData.isSelf ? "rgba(255, 255, 255, 0.35)" : Theme.accentPrimary
                                                    border.width: 1

                                                    SCIcon {
                                                        anchors.centerIn: parent
                                                        name: "file-lock"
                                                        size: 18
                                                        color: modelData.isSelf ? "#FFFFFF" : Theme.accentPrimary
                                                    }
                                                }

                                                ColumnLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 2

                                                    Label {
                                                        text: modelData.fileName || ""
                                                        font.family: Theme.fontFamilyPrimary
                                                        font.pixelSize: Theme.fontBody
                                                        font.bold: true
                                                        color: modelData.isSelf ? Theme.bubbleSelfText : Theme.bubblePeerText
                                                        elide: Text.ElideRight
                                                        Layout.fillWidth: true
                                                    }

                                                    Label {
                                                        text: qsTr("%1 · %2 · SHA-256: %3")
                                                              .arg(modelData.fileSizeText || "")
                                                              .arg(modelData.cipherSuite || "AES-256-GCM")
                                                              .arg(modelData.sha256Short || "")
                                                        font.family: Theme.fontFamilyMonospace
                                                        font.pixelSize: 10
                                                        color: modelData.isSelf
                                                               ? "rgba(255, 255, 255, 0.82)"
                                                               : Theme.textSecondary
                                                        elide: Text.ElideRight
                                                        Layout.fillWidth: true
                                                    }
                                                }

                                                SCIconButton {
                                                    iconName: "download"
                                                    buttonSize: 28
                                                    variant: modelData.isSelf ? "Ghost" : "Secondary"
                                                    tooltipText: qsTr("Inspect Encrypted File in Vault")
                                                    onClicked: {
                                                        if (workspaceRoot.wvm) {
                                                            workspaceRoot.wvm.selectTransfer(modelData.transferId)
                                                            workspaceRoot.wvm.activeSection = "Files"
                                                        }
                                                    }
                                                }
                                            }

                                            // Standard Text Message Content
                                            Label {
                                                visible: !modelData.isFileTransfer
                                                text: modelData.text || ""
                                                font.family: Theme.fontFamilyPrimary
                                                font.pixelSize: Theme.fontBody
                                                color: modelData.isSelf ? Theme.bubbleSelfText : Theme.bubblePeerText
                                                wrapMode: Text.WordWrap
                                                Layout.fillWidth: true
                                            }
                                        }
                                    }

                                    // Bottom-Right Cryptographic Delivery Status (Self Messages)
                                    RowLayout {
                                        visible: modelData.isSelf ? true : false
                                        Layout.alignment: Qt.AlignRight
                                        spacing: 4

                                        SCIcon {
                                            name: "lock"
                                            size: 10
                                            color: Theme.textMuted
                                        }

                                        Label {
                                            text: qsTr("E2EE · %1 · %2")
                                                  .arg(modelData.deliveryState || "Encrypted")
                                                  .arg(modelData.timestampText || "")
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: 10
                                            color: Theme.textMuted
                                        }
                                    }
                                }

                                // Self Avatar (Right-aligned for outgoing messages, matching visual reference)
                                SCAvatar {
                                    visible: modelData.isSelf ? true : false
                                    userId: (workspaceRoot.avm && workspaceRoot.avm.currentUser !== "")
                                            ? workspaceRoot.avm.currentUser
                                            : "operator"
                                    displayName: (workspaceRoot.avm && workspaceRoot.avm.currentUser !== "")
                                                 ? workspaceRoot.avm.currentUser
                                                 : "You"
                                    size: 28
                                    presence: ""
                                    Layout.alignment: Qt.AlignTop
                                    Layout.topMargin: 18
                                }

                                // Right Filler for Peer Messages
                                Item {
                                    visible: !modelData.isSelf
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }
                }

                // Floating Pill Composer Bar (Element 4 of Visual Reference Blueprint)
                Rectangle {
                    id: composerPill
                    Layout.fillWidth: true
                    Layout.leftMargin: Theme.space16
                    Layout.rightMargin: Theme.space16
                    Layout.bottomMargin: Theme.space16
                    Layout.topMargin: Theme.space4
                    height: 54
                    radius: 20
                    color: Theme.backgroundSecondary
                    border.color: {
                        if (workspaceRoot.currentPriority === 3) return Theme.statusDanger
                        if (workspaceRoot.currentPriority === 2) return Theme.statusWarning
                        if (composerInput.activeFocus) return Theme.borderFocused
                        return Theme.borderSubtle
                    }
                    border.width: (workspaceRoot.currentPriority > 1 || composerInput.activeFocus) ? 1.5 : 1

                    Behavior on border.color {
                        ColorAnimation { duration: Theme.durationFast }
                    }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: Theme.space12
                        anchors.rightMargin: Theme.space8
                        spacing: Theme.space8

                        // Attach Encrypted File Button (Paperclip)
                        SCIconButton {
                            iconName: "paperclip"
                            buttonSize: 34
                            tooltipText: qsTr("Attach & Encrypt File (AES-256-GCM)")
                            onClicked: workspaceRoot.triggerSampleFileAttachment()
                        }

                        // ADR-007 Interactive Priority Selector Pill (Normal / Urgent / Emergency)
                        Rectangle {
                            id: composerPriorityBtn
                            height: 30
                            width: priorityBtnRow.implicitWidth + 16
                            radius: 15
                            color: {
                                if (workspaceRoot.currentPriority === 3) {
                                    return Theme.isDark ? "rgba(239, 68, 68, 0.20)" : "#FEE2E2"
                                }
                                if (workspaceRoot.currentPriority === 2) {
                                    return Theme.isDark ? "rgba(245, 158, 11, 0.20)" : "#FEF3C7"
                                }
                                return priorityMouse.containsMouse ? Theme.backgroundElevated : Theme.backgroundPrimary
                            }
                            border.color: {
                                if (workspaceRoot.currentPriority === 3) return Theme.statusDanger
                                if (workspaceRoot.currentPriority === 2) return Theme.statusWarning
                                return Theme.borderSubtle
                            }
                            border.width: 1
                            scale: priorityMouse.pressed ? 0.95 : 1.0

                            Behavior on color {
                                ColorAnimation { duration: Theme.durationFast }
                            }
                            Behavior on border.color {
                                ColorAnimation { duration: Theme.durationFast }
                            }
                            Behavior on scale {
                                NumberAnimation { duration: 110; easing.type: Easing.OutQuad }
                            }

                            RowLayout {
                                id: priorityBtnRow
                                anchors.centerIn: parent
                                spacing: 4

                                SCIcon {
                                    name: {
                                        if (workspaceRoot.currentPriority === 3) return "shield-alert"
                                        if (workspaceRoot.currentPriority === 2) return "zap"
                                        return "lock"
                                    }
                                    size: 12
                                    color: {
                                        if (workspaceRoot.currentPriority === 3) return Theme.statusDanger
                                        if (workspaceRoot.currentPriority === 2) return Theme.statusWarning
                                        return Theme.accentPrimary
                                    }
                                }

                                Label {
                                    text: workspaceRoot.wvm ? workspaceRoot.wvm.composerPriorityLabel : qsTr("Normal")
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: Theme.fontMicro
                                    font.bold: true
                                    color: {
                                        if (workspaceRoot.currentPriority === 3) return Theme.statusDanger
                                        if (workspaceRoot.currentPriority === 2) return Theme.statusWarning
                                        return Theme.textSecondary
                                    }
                                }
                            }

                            ToolTip {
                                visible: priorityMouse.containsMouse
                                text: qsTr("Message Priority: %1 (Click to cycle Normal → Urgent → Emergency)")
                                      .arg(workspaceRoot.wvm ? workspaceRoot.wvm.composerPriorityLabel : "Normal")
                                delay: 250
                                timeout: 2500
                            }

                            MouseArea {
                                id: priorityMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    if (workspaceRoot.wvm) {
                                        workspaceRoot.wvm.cycleComposerPriority()
                                    }
                                }
                            }
                        }

                        // Seamless Integrated Text Input inside the Floating Pill
                        Item {
                            Layout.fillWidth: true
                            Layout.fillHeight: true

                            TextInput {
                                id: composerInput
                                anchors.fill: parent
                                anchors.leftMargin: 4
                                anchors.rightMargin: 4
                                verticalAlignment: TextInput.AlignVCenter
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                                selectByMouse: true
                                selectionColor: Theme.accentPrimary
                                selectedTextColor: "#FFFFFF"
                                clip: true
                                onAccepted: sendCircleBtn.triggerSend()

                                Text {
                                    anchors.fill: parent
                                    verticalAlignment: Text.AlignVCenter
                                    visible: !composerInput.text
                                    font: composerInput.font
                                    color: Theme.textMuted
                                    elide: Text.ElideRight
                                    text: {
                                        if (workspaceRoot.currentPriority === 3) {
                                            return qsTr("Type an EMERGENCY priority broadcast...")
                                        }
                                        if (workspaceRoot.currentPriority === 2) {
                                            return qsTr("Type an URGENT encrypted message...")
                                        }
                                        return qsTr("Type an encrypted message...")
                                    }
                                }
                            }
                        }

                        // Circular Encrypted Send Button (matching visual reference)
                        Rectangle {
                            id: sendCircleBtn
                            width: 38
                            height: 38
                            radius: 19
                            readonly property bool canSend: composerInput.text.trim().length > 0

                            function triggerSend() {
                                if (!workspaceRoot.wvm) return
                                var txt = composerInput.text
                                if (txt.trim().length === 0) return
                                workspaceRoot.animateNewMessages = true
                                if (workspaceRoot.wvm.sendMessage(txt)) {
                                    composerInput.text = ""
                                }
                            }

                            color: {
                                if (workspaceRoot.currentPriority === 3) {
                                    return sendMouse.pressed ? "#991B1B" : (sendMouse.containsMouse ? "#B91C1C" : Theme.statusDanger)
                                }
                                if (workspaceRoot.currentPriority === 2) {
                                    return sendMouse.pressed ? "#B45309" : (sendMouse.containsMouse ? "#D97706" : Theme.statusWarning)
                                }
                                return sendMouse.pressed ? "#1E40AF" : (sendMouse.containsMouse ? "#1D4ED8" : Theme.accentPrimary)
                            }
                            opacity: sendCircleBtn.canSend ? 1.0 : 0.78
                            scale: sendMouse.pressed ? 0.92 : (sendMouse.containsMouse ? 1.05 : 1.0)

                            Behavior on color {
                                ColorAnimation { duration: Theme.durationFast }
                            }
                            Behavior on scale {
                                NumberAnimation { duration: 110; easing.type: Easing.OutQuad }
                            }

                            SCIcon {
                                anchors.centerIn: parent
                                name: "send"
                                size: 17
                                color: "#FFFFFF"
                            }

                            ToolTip {
                                visible: sendMouse.containsMouse
                                text: qsTr("Send Encrypted Message (Enter)")
                                delay: 250
                                timeout: 2000
                            }

                            MouseArea {
                                id: sendMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: sendCircleBtn.triggerSend()
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
