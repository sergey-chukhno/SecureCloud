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
            Layout.preferredWidth: 280
            Layout.minimumWidth: 240
            Layout.maximumWidth: 320
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

                    SCIconButton {
                        visible: workspaceRoot.activeSection === "Messages"
                        iconName: "plus"
                        buttonSize: 28
                        tooltipText: qsTr("New Conversation or Group")
                        onClicked: newConversationDialog.open()
                    }

                    SCIconButton {
                        visible: workspaceRoot.activeSection === "Contacts"
                        iconName: "user-plus"
                        buttonSize: 28
                        tooltipText: qsTr("Add New Contact")
                        onClicked: addContactDialog.open()
                    }

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
                                            visible: workspaceRoot.activeSection === "Messages"
                                            name: modelData.isBlocked
                                                  ? "shield-alert"
                                                  : ((modelData.verificationStatus === "KeyChanged")
                                                     ? "shield-alert"
                                                     : (modelData.isVerified ? "shield-check" : "alert-triangle"))
                                            size: 13
                                            color: (modelData.isBlocked || modelData.verificationStatus === "KeyChanged")
                                                   ? Theme.statusDanger
                                                   : (modelData.isVerified ? Theme.accentPrimary : Theme.statusWarning)
                                            Layout.alignment: Qt.AlignVCenter
                                        }

                                        SCBadge {
                                            visible: workspaceRoot.activeSection === "Contacts"
                                            text: {
                                                if (modelData.isBlocked) return qsTr("Blocked")
                                                if (modelData.verificationStatus === "KeyChanged") return qsTr("Key Changed!")
                                                return modelData.isVerified ? qsTr("Verified") : qsTr("Unverified")
                                            }
                                            type: {
                                                if (modelData.isBlocked || modelData.verificationStatus === "KeyChanged") return "Danger"
                                                return modelData.isVerified ? "Verified" : "Unverified"
                                            }
                                            badgeHeight: 18
                                            hasDot: false
                                            Layout.alignment: Qt.AlignVCenter
                                        }

                                        Label {
                                            visible: workspaceRoot.activeSection !== "Contacts"
                                            text: workspaceRoot.activeSection === "Files"
                                                  ? (modelData.fileSizeText || "")
                                                  : (modelData.timestampText || "")
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

                                        SCBadge {
                                            visible: workspaceRoot.activeSection === "Messages" && (modelData.isGroup === true)
                                            text: qsTr("Group")
                                            type: "Info"
                                            badgeHeight: 18
                                            hasDot: false
                                            Layout.alignment: Qt.AlignVCenter
                                        }

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
                                                    var handle = modelData.handle || ""
                                                    var role = modelData.roleNote || ""
                                                    return role.length > 0 ? (handle + " · " + role) : handle
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
                            text: (workspaceRoot.wvm && workspaceRoot.wvm.searchQuery !== "")
                                  ? qsTr("No matching items found for \"%1\"").arg(workspaceRoot.wvm.searchQuery)
                                  : qsTr("No items in this section")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textSecondary
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        SCButton {
                            visible: workspaceRoot.wvm ? (workspaceRoot.wvm.searchQuery !== "") : false
                            text: qsTr("Clear Search")
                            iconName: "close"
                            variant: "Secondary"
                            buttonHeight: 30
                            Layout.alignment: Qt.AlignHCenter
                            onClicked: {
                                masterSearchField.text = ""
                                if (workspaceRoot.wvm) {
                                    workspaceRoot.wvm.clearSearchQuery()
                                }
                            }
                        }
                    }
                }
            }
        }

        // Zone 3 — Central Conversation / File Stream Area
        Rectangle {
            id: zone3Pane
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumWidth: 240
            color: Theme.backgroundPrimary
            clip: true

            readonly property var selectedTx: workspaceRoot.wvm ? workspaceRoot.wvm.selectedTransferDetails : ({})

            // 3A. Conversation Stream & Floating Composer (active when section is Messages or Contacts)
            ColumnLayout {
                visible: (workspaceRoot.activeSection !== "Files") && (workspaceRoot.wvm ? (workspaceRoot.wvm.selectedConversationId !== "") : true)
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
                                    Layout.preferredWidth: implicitWidth
                                    Layout.maximumWidth: Math.max(120, peerHeaderBar.width - 180)
                                }

                                SCBadge {
                                    text: {
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerKeyChanged) return qsTr("Key Changed")
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup) {
                                            return workspaceRoot.wvm.selectedGroupAllVerified
                                                   ? qsTr("All Verified")
                                                   : qsTr("Unverified (%1)").arg(workspaceRoot.wvm.selectedGroupUnverifiedCount)
                                        }
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked) return qsTr("Blocked")
                                        return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                               ? qsTr("Verified")
                                               : qsTr("Unverified")
                                    }
                                    type: {
                                        if (workspaceRoot.wvm && (workspaceRoot.wvm.selectedPeerKeyChanged || workspaceRoot.wvm.selectedPeerBlocked)) return "Danger"
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup) {
                                            return workspaceRoot.wvm.selectedGroupAllVerified ? "Verified" : "Unverified"
                                        }
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
                                    if (workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup) {
                                        return qsTr("Group · %1 Participants · Double Ratchet E2EE")
                                            .arg(workspaceRoot.wvm.selectedConversationParticipantCount)
                                    }
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

                // ADR-008 Non-Bypassable Identity Key Changed Security Alert Banner
                Rectangle {
                    id: keyChangedSecurityBanner
                    objectName: "keyChangedSecurityBanner"
                    visible: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerKeyChanged : false
                    Layout.fillWidth: true
                    implicitHeight: bannerContentColumn.implicitHeight + (Theme.space12 * 2)
                    color: Theme.isDark ? "rgba(239, 68, 68, 0.16)" : "#FEE2E2"
                    border.color: Theme.statusDanger
                    border.width: 1

                    ColumnLayout {
                        id: bannerContentColumn
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.margins: Theme.space12
                        spacing: Theme.space8

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space8

                            SCIcon {
                                name: "shield-alert"
                                size: 18
                                color: Theme.statusDanger
                                Layout.alignment: Qt.AlignVCenter
                            }

                            Label {
                                text: qsTr("CRITICAL: Peer Identity Key Changed (ADR-008)")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.statusDanger
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            text: {
                                var handle = workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerKeyChangedHandle : ""
                                return qsTr("The identity key for %1 has changed unexpectedly. Outbound messaging is strictly suspended to protect against MITM eavesdropping. You must verify the new safety number to resume communication.")
                                    .arg(handle.length > 0 ? handle : "this peer")
                            }
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.isDark ? "#FCA5A5" : "#991B1B"
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        RowLayout {
                            Layout.fillWidth: true

                            Item { Layout.fillWidth: true }

                            SCButton {
                                text: qsTr("Verify Safety Number")
                                iconName: "shield-check"
                                variant: "Danger"
                                buttonHeight: 30
                                horizontalPadding: 12
                                onClicked: {
                                    if (workspaceRoot.wvm) {
                                        workspaceRoot.wvm.acceptAndVerifyPeerKey(workspaceRoot.wvm.selectedPeerUserId)
                                    }
                                }
                            }
                        }
                    }
                }

                // ADR-007 Active Emergency Alert Banner (unacknowledged messages in active conversation)
                Rectangle {
                    id: emergencyAlertBanner
                    objectName: "emergencyAlertBanner"
                    visible: workspaceRoot.wvm ? (workspaceRoot.wvm.unacknowledgedEmergencyCount > 0) : false
                    Layout.fillWidth: true
                    implicitHeight: emergencyBannerCol.implicitHeight + (Theme.space12 * 2)
                    color: Theme.isDark ? "rgba(239, 68, 68, 0.18)" : "#FEE2E2"
                    border.color: Theme.statusDanger
                    border.width: 1

                    ColumnLayout {
                        id: emergencyBannerCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.margins: Theme.space12
                        spacing: Theme.space8

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space8

                            SCIcon {
                                name: "shield-alert"
                                size: 18
                                color: Theme.statusDanger
                                Layout.alignment: Qt.AlignVCenter
                            }

                            Label {
                                text: qsTr("ACTIVE EMERGENCY ALERT: %1 unacknowledged message%2 requiring immediate operator action")
                                      .arg(workspaceRoot.wvm ? workspaceRoot.wvm.unacknowledgedEmergencyCount : 0)
                                      .arg((workspaceRoot.wvm && workspaceRoot.wvm.unacknowledgedEmergencyCount > 1) ? "s" : "")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.statusDanger
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        Label {
                            text: qsTr("One or more high-priority encrypted emergency alerts have been transmitted in this thread. Operating procedures require explicit receipt acknowledgement.")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.isDark ? "#FCA5A5" : "#991B1B"
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
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
                                    userId: modelData.senderName || "peer"
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
                                            visible: !modelData.isSelf && workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup
                                            text: modelData.senderName || ""
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontMicro
                                            font.bold: true
                                            color: Theme.accentPrimary
                                        }

                                        Label {
                                            text: ((modelData.isSelf || !workspaceRoot.wvm || !workspaceRoot.wvm.selectedConversationIsGroup)
                                                   ? ((modelData.senderName || "") + "  ") : "") + (modelData.timestampText || "")
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
                                            if (modelData.deliveryState === "Failed") {
                                                return Theme.isDark ? "#2D1518" : "#FEF2F2"
                                            }
                                            if (msgDelegate.isEmergency && !modelData.isSelf) {
                                                return Theme.isDark ? "#2A161D" : "#FEF2F2"
                                            }
                                            return modelData.isSelf ? Theme.bubbleSelf : Theme.bubblePeer
                                        }
                                        border.color: {
                                            if (modelData.deliveryState === "Failed") return Theme.statusDanger
                                            if (msgDelegate.isEmergency) return Theme.statusDanger
                                            if (msgDelegate.isUrgent) return Theme.statusWarning
                                            if (modelData.isFileTransfer) return Theme.accentPrimary
                                            return "transparent"
                                        }
                                        border.width: (modelData.deliveryState === "Failed" || msgDelegate.msgPriority > 1) ? 1.5 : (modelData.isFileTransfer ? 1 : 0)

                                        ColumnLayout {
                                            id: msgColumn
                                            anchors.fill: parent
                                            anchors.margins: Theme.space12
                                            spacing: 6

                                            // ADR-007 Emergency Acknowledgement Card
                                            Rectangle {
                                                visible: msgDelegate.isEmergency
                                                Layout.fillWidth: true
                                                implicitHeight: emergencyAckCol.implicitHeight + 14
                                                radius: 8
                                                color: modelData.emergencyAcknowledged
                                                       ? (Theme.isDark ? "rgba(16, 185, 129, 0.15)" : "#D1FAE5")
                                                       : (Theme.isDark ? "rgba(239, 68, 68, 0.25)" : "#FEE2E2")
                                                border.color: modelData.emergencyAcknowledged ? Theme.statusSuccess : Theme.statusDanger
                                                border.width: 1

                                                ColumnLayout {
                                                    id: emergencyAckCol
                                                    anchors.fill: parent
                                                    anchors.margins: 8
                                                    spacing: 6

                                                    RowLayout {
                                                        Layout.fillWidth: true
                                                        spacing: 6

                                                        SCIcon {
                                                            name: modelData.emergencyAcknowledged ? "shield-check" : "shield-alert"
                                                            size: 13
                                                            color: modelData.emergencyAcknowledged ? Theme.statusSuccess : Theme.statusDanger
                                                        }

                                                        Label {
                                                            text: modelData.emergencyAcknowledged
                                                                  ? qsTr("✓ Emergency Acknowledged")
                                                                  : qsTr("ACTION REQUIRED: Unacknowledged Emergency Alert")
                                                            font.family: Theme.fontFamilyPrimary
                                                            font.pixelSize: 10
                                                            font.bold: true
                                                            color: modelData.emergencyAcknowledged ? Theme.statusSuccess : Theme.statusDanger
                                                            Layout.fillWidth: true
                                                            wrapMode: Text.WordWrap
                                                        }
                                                    }

                                                    SCButton {
                                                        visible: !modelData.emergencyAcknowledged
                                                        text: qsTr("Acknowledge Receipt")
                                                        iconName: "shield-check"
                                                        variant: "Danger"
                                                        buttonHeight: 26
                                                        horizontalPadding: 10
                                                        onClicked: {
                                                            if (workspaceRoot.wvm) {
                                                                workspaceRoot.wvm.acknowledgeEmergencyMessage(modelData.messageId)
                                                            }
                                                        }
                                                    }
                                                }
                                            }

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

                                            // Failed Delivery Warning & Idempotent Retry Action Bar
                                            Rectangle {
                                                visible: modelData.isSelf && modelData.deliveryState === "Failed"
                                                Layout.fillWidth: true
                                                implicitHeight: failedActionCol.implicitHeight + 14
                                                radius: 8
                                                color: Theme.isDark ? "rgba(239, 68, 68, 0.22)" : "#FEE2E2"
                                                border.color: Theme.statusDanger
                                                border.width: 1

                                                ColumnLayout {
                                                    id: failedActionCol
                                                    anchors.fill: parent
                                                    anchors.margins: 8
                                                    spacing: 6

                                                    RowLayout {
                                                        Layout.fillWidth: true
                                                        spacing: 6

                                                        SCIcon {
                                                            name: "alert-circle"
                                                            size: 13
                                                            color: Theme.statusDanger
                                                        }

                                                        Label {
                                                            text: qsTr("Delivery Failed — network endpoint unreachable")
                                                            font.family: Theme.fontFamilyPrimary
                                                            font.pixelSize: 10
                                                            font.bold: true
                                                            color: Theme.statusDanger
                                                            Layout.fillWidth: true
                                                        }
                                                    }

                                                    RowLayout {
                                                        Layout.fillWidth: true
                                                        spacing: 8

                                                        SCButton {
                                                            text: qsTr("Retry Send (Idempotent)")
                                                            iconName: "refresh-cw"
                                                            variant: "Danger"
                                                            buttonHeight: 26
                                                            horizontalPadding: 10
                                                            onClicked: {
                                                                if (workspaceRoot.wvm) {
                                                                    workspaceRoot.wvm.retryFailedMessage(modelData.messageId)
                                                                }
                                                            }
                                                        }

                                                        SCButton {
                                                            text: qsTr("Discard")
                                                            iconName: "trash"
                                                            variant: "Ghost"
                                                            buttonHeight: 26
                                                            horizontalPadding: 8
                                                            onClicked: {
                                                                if (workspaceRoot.wvm) {
                                                                    workspaceRoot.wvm.discardFailedMessage(modelData.messageId)
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Bottom-Right Cryptographic Delivery Status (Self Messages)
                                    RowLayout {
                                        visible: modelData.isSelf ? true : false
                                        Layout.alignment: Qt.AlignRight
                                        spacing: 4

                                        SCIcon {
                                            name: {
                                                var state = modelData.deliveryState || ""
                                                if (state === "Failed") return "alert-circle"
                                                if (state === "LocalPending") return "clock"
                                                if (state === "Submitting") return "upload-cloud"
                                                if (state === "Accepted") return "check"
                                                if (state === "Delivered") return "check-check"
                                                if (state === "Read") return "shield-check"
                                                return "lock"
                                            }
                                            size: 12
                                            color: {
                                                var state = modelData.deliveryState || ""
                                                if (state === "Failed") return Theme.statusDanger
                                                if (state === "Read") return Theme.statusSuccess
                                                if (state === "Delivered") return Theme.accentPrimary
                                                if (state === "Accepted" || state === "Submitting") return Theme.accentPrimary
                                                return Theme.textMuted
                                            }
                                        }

                                        Label {
                                            text: {
                                                var state = modelData.deliveryState || ""
                                                var ts = modelData.timestampText || ""
                                                if (state === "Failed") return qsTr("Delivery Failed · %1").arg(ts)
                                                if (state === "LocalPending") return qsTr("Pending Local Queue · %1").arg(ts)
                                                if (state === "Submitting") return qsTr("Submitting via mTLS... · %1").arg(ts)
                                                if (state === "Accepted") return qsTr("Accepted by Gateway · %1").arg(ts)
                                                if (state === "Delivered") return qsTr("Delivered · E2EE · %1").arg(ts)
                                                if (state === "Read") return qsTr("Read · Verified · %1").arg(ts)
                                                return qsTr("E2EE · %1 · %2").arg(state).arg(ts)
                                            }
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: 10
                                            font.bold: (modelData.deliveryState === "Failed")
                                            color: {
                                                var state = modelData.deliveryState || ""
                                                if (state === "Failed") return Theme.statusDanger
                                                if (state === "Read") return Theme.isDark ? "#6EE7B7" : "#047857"
                                                if (state === "Delivered") return Theme.accentPrimary
                                                return Theme.textMuted
                                            }
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

                    // Empty Conversation Stream State (Double Ratchet Initialized)
                    ColumnLayout {
                        visible: (messageListView.count === 0) && (workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationId !== "") && !(workspaceRoot.wvm && workspaceRoot.wvm.isLoadingMessages)
                        anchors.centerIn: parent
                        width: Math.min(360, parent.width - 48)
                        spacing: Theme.space12

                        Rectangle {
                            width: 56
                            height: 56
                            radius: 28
                            color: Theme.isDark ? "rgba(37, 99, 235, 0.16)" : "#EFF6FF"
                            border.color: Theme.accentPrimary
                            border.width: 1
                            Layout.alignment: Qt.AlignHCenter

                            SCIcon {
                                anchors.centerIn: parent
                                name: "lock"
                                size: 26
                                color: Theme.accentPrimary
                            }
                        }

                        Label {
                            text: qsTr("End-to-End Encrypted Session Initialized")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            horizontalAlignment: Text.AlignHCenter
                            Layout.fillWidth: true
                        }

                        Label {
                            text: qsTr("Messages and files in this thread are cryptographically secured with the Double Ratchet and X3DH protocols. Send a message to advance the ratchet.")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textMuted
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }

                    // Loading Messages State Overlay
                    ColumnLayout {
                        visible: workspaceRoot.wvm ? workspaceRoot.wvm.isLoadingMessages : false
                        anchors.centerIn: parent
                        spacing: Theme.space12

                        SCIcon {
                            name: "refresh-cw"
                            size: 28
                            color: Theme.accentPrimary
                            Layout.alignment: Qt.AlignHCenter

                            RotationAnimation on rotation {
                                running: workspaceRoot.wvm ? workspaceRoot.wvm.isLoadingMessages : false
                                loops: Animation.Infinite
                                from: 0
                                to: 360
                                duration: 1000
                            }
                        }

                        Label {
                            text: qsTr("Loading encrypted messages...")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            color: Theme.textSecondary
                            Layout.alignment: Qt.AlignHCenter
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
                    clip: true
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
                            buttonSize: 32
                            tooltipText: qsTr("Attach & Encrypt File (AES-256-GCM)")
                            onClicked: workspaceRoot.triggerSampleFileAttachment()
                        }

                        // ADR-007 Interactive Priority Selector Pill (Normal / Urgent / Emergency)
                        Rectangle {
                            id: composerPriorityBtn
                            height: 30
                            width: priorityBtnRow.implicitWidth + 14
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

                        // Network Failure Simulation Toggle Chip (CLIENT-004-T05)
                        Rectangle {
                            id: failSimChip
                            height: 30
                            width: (workspaceRoot.wvm && workspaceRoot.wvm.deliveryFailureSimulated)
                                   ? (failSimRow.implicitWidth + 12)
                                   : 30
                            radius: 15
                            color: (workspaceRoot.wvm && workspaceRoot.wvm.deliveryFailureSimulated)
                                   ? (Theme.isDark ? "rgba(239, 68, 68, 0.28)" : "#FEE2E2")
                                   : (failSimMouse.containsMouse ? Theme.backgroundElevated : Theme.backgroundPrimary)
                            border.color: (workspaceRoot.wvm && workspaceRoot.wvm.deliveryFailureSimulated)
                                          ? Theme.statusDanger
                                          : Theme.borderSubtle
                            border.width: 1

                            RowLayout {
                                id: failSimRow
                                anchors.centerIn: parent
                                spacing: 3

                                SCIcon {
                                    name: "alert-circle"
                                    size: 13
                                    color: (workspaceRoot.wvm && workspaceRoot.wvm.deliveryFailureSimulated)
                                           ? Theme.statusDanger
                                           : Theme.textMuted
                                }

                                Label {
                                    visible: workspaceRoot.wvm && workspaceRoot.wvm.deliveryFailureSimulated
                                    text: qsTr("Fail ON")
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: 10
                                    font.bold: true
                                    color: Theme.statusDanger
                                }
                            }

                            ToolTip {
                                visible: failSimMouse.containsMouse
                                text: (workspaceRoot.wvm && workspaceRoot.wvm.deliveryFailureSimulated)
                                      ? qsTr("Simulate Delivery Failure (Active: outbound sends will fail)")
                                      : qsTr("Simulate Delivery Failure (Click to test packet drop & retry)")
                                delay: 250
                                timeout: 2500
                            }

                            MouseArea {
                                id: failSimMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    if (workspaceRoot.wvm) {
                                        workspaceRoot.wvm.setSimulateDeliveryFailure(!workspaceRoot.wvm.deliveryFailureSimulated)
                                    }
                                }
                            }
                        }

                        // Seamless Integrated Text Input inside the Floating Pill
                        Item {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 60
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
                                enabled: !(workspaceRoot.wvm && (workspaceRoot.wvm.selectedPeerKeyChanged || workspaceRoot.wvm.selectedPeerBlocked))
                                onAccepted: sendCircleBtn.triggerSend()

                                Text {
                                    anchors.fill: parent
                                    verticalAlignment: Text.AlignVCenter
                                    visible: !composerInput.text
                                    font: composerInput.font
                                    color: Theme.textMuted
                                    elide: Text.ElideRight
                                    text: {
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerKeyChanged) {
                                            return qsTr("Outbound messaging suspended until safety number is verified (ADR-008)...")
                                        }
                                        if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked) {
                                            return qsTr("Cannot send message: peer is blocked...")
                                        }
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
                            readonly property bool canSend: composerInput.text.trim().length > 0 &&
                                !(workspaceRoot.wvm && (workspaceRoot.wvm.selectedPeerKeyChanged || workspaceRoot.wvm.selectedPeerBlocked))

                            function triggerSend() {
                                if (!workspaceRoot.wvm || !canSend) return
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

            // 3C. No Conversation Selected State (when selectedConversationId is empty and section !== "Files")
            ColumnLayout {
                visible: (workspaceRoot.activeSection !== "Files") && (workspaceRoot.wvm ? (workspaceRoot.wvm.selectedConversationId === "") : false)
                anchors.centerIn: parent
                width: Math.min(380, parent.width - 48)
                spacing: Theme.space16

                Rectangle {
                    width: 64
                    height: 64
                    radius: 32
                    color: Theme.isDark ? "rgba(255, 255, 255, 0.06)" : "#F3F4F6"
                    border.color: Theme.borderSubtle
                    border.width: 1
                    Layout.alignment: Qt.AlignHCenter

                    SCIcon {
                        anchors.centerIn: parent
                        name: "workspace"
                        size: 30
                        color: Theme.textMuted
                    }
                }

                Label {
                    text: qsTr("No Conversation Selected")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontTitle
                    font.bold: true
                    color: Theme.textPrimary
                    horizontalAlignment: Text.AlignHCenter
                    Layout.fillWidth: true
                }

                Label {
                    text: qsTr("Select a secure thread from the sidebar or initiate a new end-to-end encrypted session.")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontBody
                    color: Theme.textMuted
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    spacing: 12

                    SCButton {
                        text: qsTr("New Conversation")
                        iconName: "plus"
                        variant: "Primary"
                        buttonHeight: 34
                        onClicked: workspaceRoot.isNewConversationModalOpen = true
                    }

                    SCButton {
                        text: qsTr("Browse Contacts")
                        iconName: "contacts"
                        variant: "Secondary"
                        buttonHeight: 34
                        onClicked: {
                            if (workspaceRoot.wvm) workspaceRoot.wvm.activeSection = "Contacts"
                        }
                    }
                }
            }

            // 3B. Dedicated Encrypted Files Vault View (active when section === "Files")
            ColumnLayout {
                visible: workspaceRoot.activeSection === "Files"
                anchors.fill: parent
                spacing: 0

                // Top Vault Header Bar
                Rectangle {
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

                        Rectangle {
                            width: 38
                            height: 38
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

                        ColumnLayout {
                            spacing: 2
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.preferredWidth: 1

                            Label {
                                text: zone3Pane.selectedTx.fileName || qsTr("Encrypted File Vault")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontSubtitle
                                font.bold: true
                                color: Theme.textPrimary
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                Layout.preferredWidth: 1
                            }

                            Label {
                                text: {
                                    var tx = zone3Pane.selectedTx
                                    if (!tx || !tx.fileName) return qsTr("Zero-Knowledge Chunked AEAD File Storage")
                                    return qsTr("%1 · %2 · Peer: %3 · %4")
                                           .arg(tx.direction || "Inbound")
                                           .arg(tx.fileSizeText || "")
                                           .arg(tx.peerDisplayName || "")
                                           .arg(tx.timestampText || "")
                                }
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                Layout.preferredWidth: 1
                            }
                        }

                        SCButton {
                            text: qsTr("Stage File")
                            iconName: "paperclip"
                            variant: "Primary"
                            buttonHeight: 34
                            horizontalPadding: 10
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

                // Selected File Cryptographic Manifest & Vault Ledger
                ScrollView {
                    id: vaultScrollView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    contentWidth: availableWidth
                    ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

                    ScrollBar.vertical: ScrollBar {
                        policy: ScrollBar.AsNeeded
                        width: 6
                        contentItem: Rectangle {
                            implicitWidth: 6
                            radius: 3
                            color: Theme.isDark ? "rgba(255, 255, 255, 0.28)" : "rgba(0, 0, 0, 0.25)"
                        }
                        background: Rectangle {
                            color: "transparent"
                        }
                    }

                    ColumnLayout {
                        width: vaultScrollView.availableWidth
                        spacing: Theme.space16

                        Item { width: 1; height: Theme.space4 }

                        // Cryptographic Manifest Card for Selected Transfer
                        Rectangle {
                            id: manifestCard
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.leftMargin: Theme.space16
                            Layout.rightMargin: Theme.space16
                            implicitHeight: manifestCol.implicitHeight + (Theme.space16 * 2)
                            radius: 16
                            color: Theme.backgroundSecondary
                            border.color: Theme.borderSubtle
                            border.width: 1
                            clip: true

                            readonly property var tx: workspaceRoot.wvm ? workspaceRoot.wvm.selectedTransferDetails : ({})

                            ColumnLayout {
                                id: manifestCol
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.top: parent.top
                                anchors.margins: Theme.space16
                                spacing: Theme.space12

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space8

                                    SCIcon {
                                        name: "shield-check"
                                        size: 18
                                        color: Theme.accentPrimary
                                    }

                                    Label {
                                        text: qsTr("Cryptographic File Manifest")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontBody
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        Layout.preferredWidth: 1
                                    }

                                    SCBadge {
                                        text: manifestCard.tx.statusText || qsTr("Encrypted & Verified")
                                        type: (manifestCard.tx.statusText === "Cancelled")
                                              ? "Danger"
                                              : "Verified"
                                    }
                                }

                                Rectangle {
                                    Layout.fillWidth: true
                                    height: 1
                                    color: Theme.borderSubtle
                                }

                                GridLayout {
                                    Layout.fillWidth: true
                                    columns: 2
                                    rowSpacing: 8
                                    columnSpacing: Theme.space12

                                    Label {
                                        text: qsTr("Artifact Name:")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: Theme.textMuted
                                    }
                                    Label {
                                        text: manifestCard.tx.fileName || "—"
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        Layout.preferredWidth: 1
                                    }

                                    Label {
                                        text: qsTr("AEAD Cipher:")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: Theme.textMuted
                                    }
                                    Label {
                                        text: (manifestCard.tx.cipherSuite || "AES-256-GCM") + " · 256-bit HKDF"
                                        font.family: Theme.fontFamilyMonospace
                                        font.pixelSize: Theme.fontMicro
                                        color: Theme.accentPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        Layout.preferredWidth: 1
                                    }

                                    Label {
                                        text: qsTr("SHA-256 Digest:")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: Theme.textMuted
                                    }
                                    Label {
                                        text: manifestCard.tx.sha256Short || "—"
                                        font.family: Theme.fontFamilyMonospace
                                        font.pixelSize: Theme.fontMicro
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        Layout.preferredWidth: 1
                                    }

                                    Label {
                                        text: qsTr("Peer & Size:")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: Theme.textMuted
                                    }
                                    Label {
                                        text: (manifestCard.tx.peerDisplayName || "—") + " · " + (manifestCard.tx.direction || "Inbound") + " (" + (manifestCard.tx.fileSizeText || "") + ")"
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: Theme.textSecondary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                        Layout.minimumWidth: 0
                                        Layout.preferredWidth: 1
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space8

                                    SCButton {
                                        text: qsTr("Open Thread")
                                        iconName: "workspace"
                                        variant: "Secondary"
                                        buttonHeight: 32
                                        horizontalPadding: 10
                                        onClicked: {
                                            if (workspaceRoot.wvm && manifestCard.tx.conversationId) {
                                                workspaceRoot.wvm.selectConversation(manifestCard.tx.conversationId)
                                                workspaceRoot.wvm.activeSection = "Messages"
                                            }
                                        }
                                    }

                                    Item { Layout.fillWidth: true }

                                    SCButton {
                                        text: (manifestCard.tx.statusText === "Cancelled")
                                              ? qsTr("Revoked")
                                              : qsTr("Revoke Transfer")
                                        iconName: "shield-alert"
                                        variant: "Danger"
                                        buttonHeight: 32
                                        horizontalPadding: 10
                                        enabled: manifestCard.tx.statusText !== "Cancelled"
                                        onClicked: {
                                            if (workspaceRoot.wvm && manifestCard.tx.transferId) {
                                                workspaceRoot.wvm.cancelFileTransfer(manifestCard.tx.transferId)
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Vault Transfer Ledger Header
                        Label {
                            text: qsTr("All Encrypted Vault Transfers")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            Layout.leftMargin: Theme.space16
                        }

                        // All Vault Items Repeater
                        ColumnLayout {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 0
                            Layout.leftMargin: Theme.space16
                            Layout.rightMargin: Theme.space16
                            spacing: Theme.space8

                            Repeater {
                                model: workspaceRoot.wvm ? workspaceRoot.wvm.fileTransfers : []

                                delegate: Rectangle {
                                    Layout.fillWidth: true
                                    Layout.minimumWidth: 0
                                    height: 60
                                    radius: 12
                                    clip: true
                                    color: modelData.isSelected
                                           ? Theme.backgroundElevated
                                           : (vaultRowMouse.containsMouse ? Theme.backgroundSecondary : "transparent")
                                    border.color: modelData.isSelected ? Theme.accentPrimary : Theme.borderSubtle
                                    border.width: 1

                                    Behavior on color {
                                        ColorAnimation { duration: Theme.durationFast }
                                    }

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: Theme.space12
                                        anchors.rightMargin: Theme.space12
                                        spacing: Theme.space12

                                        SCIcon {
                                            name: "file-lock"
                                            size: 18
                                            color: Theme.accentPrimary
                                        }

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            Layout.minimumWidth: 0
                                            Layout.preferredWidth: 1
                                            spacing: 2

                                            Label {
                                                text: modelData.fileName || ""
                                                font.family: Theme.fontFamilyPrimary
                                                font.pixelSize: Theme.fontBody
                                                font.bold: true
                                                color: Theme.textPrimary
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                                Layout.minimumWidth: 0
                                                Layout.preferredWidth: 1
                                            }

                                            Label {
                                                text: (modelData.fileSizeText || "") + " · " + (modelData.cipherSuite || "") + " · " + (modelData.peerDisplayName || "")
                                                font.family: Theme.fontFamilyPrimary
                                                font.pixelSize: Theme.fontMicro
                                                color: Theme.textMuted
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                                Layout.minimumWidth: 0
                                                Layout.preferredWidth: 1
                                            }
                                        }

                                        SCBadge {
                                            text: modelData.statusText || "Encrypted"
                                            type: modelData.statusText === "Cancelled" ? "Danger" : "Verified"
                                        }
                                    }

                                    MouseArea {
                                        id: vaultRowMouse
                                        anchors.fill: parent
                                        hoverEnabled: true
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: {
                                            if (workspaceRoot.wvm) {
                                                workspaceRoot.wvm.selectTransfer(modelData.transferId)
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Item { width: 1; height: Theme.space16 }
                    }
                }
            }
        }

        // Zone 4 — Collapsible Right-Hand Peer Security & Shared Files Inspector
        Rectangle {
            id: inspectorDrawer
            readonly property bool isExpanded: workspaceRoot.wvm ? workspaceRoot.wvm.isInspectorOpen : true
            visible: Layout.preferredWidth > 0
            Layout.fillHeight: true
            Layout.preferredWidth: isExpanded ? Math.min(260, Math.max(210, workspaceRoot.width * 0.28)) : 0
            Layout.minimumWidth: isExpanded ? 200 : 0
            Layout.maximumWidth: 280
            color: Theme.backgroundPrimary
            clip: true

            Behavior on Layout.preferredWidth {
                NumberAnimation { duration: 220; easing.type: Easing.OutCubic }
            }

            Rectangle {
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                width: 1
                color: Theme.borderSubtle
            }

            ColumnLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.space12
                anchors.rightMargin: Theme.space12
                anchors.topMargin: Theme.space12
                anchors.bottomMargin: Theme.space12
                spacing: Theme.space8
                opacity: inspectorDrawer.isExpanded ? 1.0 : 0.0

                Behavior on opacity {
                    NumberAnimation { duration: 160; easing.type: Easing.OutQuad }
                }

                RowLayout {
                    Layout.fillWidth: true

                    Label {
                        text: (workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup)
                              ? qsTr("GROUP ENCRYPTION ROSTER")
                              : qsTr("PEER SECURITY INSPECTOR")
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: 10
                        font.bold: true
                        font.letterSpacing: 0.7
                        color: Theme.textMuted
                    }

                    Item { Layout.fillWidth: true }

                    SCIconButton {
                        iconName: "close"
                        buttonSize: 28
                        tooltipText: qsTr("Close Inspector")
                        onClicked: {
                            if (workspaceRoot.wvm) {
                                workspaceRoot.wvm.isInspectorOpen = false
                            }
                        }
                    }
                }

                // 4A. 1-on-1 Peer Security Inspector Content
                ColumnLayout {
                    id: peerInspectorContent
                    visible: !workspaceRoot.wvm || !workspaceRoot.wvm.selectedConversationIsGroup
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: Theme.space12

                    SCAvatar {
                        userId: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerUserId : "peer"
                        displayName: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "Peer"
                        size: 72
                        presence: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerPresence : "Online"
                        Layout.alignment: Qt.AlignHCenter
                    }

                    RowLayout {
                        Layout.alignment: Qt.AlignHCenter
                        spacing: 6

                        Label {
                            text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerHandle : ""
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontSubtitle
                            font.bold: true
                            color: Theme.textPrimary
                        }

                        SCIcon {
                            name: {
                                if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked) return "shield-alert"
                                if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerKeyChanged) return "shield-alert"
                                return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified) ? "shield-check" : "alert-triangle"
                            }
                            size: 16
                            color: {
                                if (workspaceRoot.wvm && (workspaceRoot.wvm.selectedPeerBlocked || workspaceRoot.wvm.selectedPeerKeyChanged)) return Theme.statusDanger
                                return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified) ? Theme.accentPrimary : Theme.statusWarning
                            }
                        }
                    }

                    SCBadge {
                        Layout.alignment: Qt.AlignHCenter
                        text: {
                            if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerKeyChanged) return qsTr("Key Changed (ADR-008)")
                            if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked) return qsTr("Blocked")
                            return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified) ? qsTr("Verified") : qsTr("Unverified")
                        }
                        type: {
                            if (workspaceRoot.wvm && (workspaceRoot.wvm.selectedPeerKeyChanged || workspaceRoot.wvm.selectedPeerBlocked)) return "Danger"
                            return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified) ? "Verified" : "Unverified"
                        }
                    }

                    // Quick Cryptographic Action Buttons (Verify Safety Number + Edit Profile)
                    SCButton {
                        Layout.fillWidth: true
                        text: {
                            if (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerKeyChanged) return qsTr("Verify Safety Number")
                            return (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                  ? qsTr("Verified Safety Number")
                                  : qsTr("Verify Safety Number")
                        }
                        iconName: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerVerified)
                                  ? "shield-check"
                                  : "alert-triangle"
                        variant: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerKeyChanged) ? "Danger" : "Secondary"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: {
                            if (workspaceRoot.wvm) {
                                if (workspaceRoot.wvm.selectedPeerKeyChanged) {
                                    workspaceRoot.wvm.acceptAndVerifyPeerKey(workspaceRoot.wvm.selectedPeerUserId)
                                } else {
                                    workspaceRoot.wvm.togglePeerVerified("")
                                }
                            }
                        }
                    }

                    SCButton {
                        Layout.fillWidth: true
                        text: qsTr("Edit Profile & Notes")
                        iconName: "edit"
                        variant: "Secondary"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: editContactDialog.openWithCurrentContact()
                    }

                    SCButton {
                        Layout.fillWidth: true
                        text: qsTr("Send Encrypted File")
                        iconName: "paperclip"
                        variant: "Secondary"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: workspaceRoot.triggerSampleFileAttachment()
                    }

                    // Safety Number Monospace Box
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

                        Label {
                            text: qsTr("Safety Number (X3DH):")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            font.bold: true
                            color: Theme.textPrimary
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: safetyNumLabel.implicitHeight + 14
                            radius: 8
                            color: Theme.backgroundSecondary
                            border.color: Theme.borderSubtle
                            border.width: 1

                            Label {
                                id: safetyNumLabel
                                anchors.fill: parent
                                anchors.margins: 7
                                text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerSafetyNumber : ""
                                font.family: Theme.fontFamilyMonospace
                                font.pixelSize: 10
                                color: Theme.accentPrimary
                                wrapMode: Text.WrapAnywhere
                            }
                        }
                    }

                    // Shared Encrypted Files Section
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 6

                        RowLayout {
                            Layout.fillWidth: true

                            Label {
                                text: qsTr("Shared Encrypted Files")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Item { Layout.fillWidth: true }

                            Label {
                                text: workspaceRoot.wvm ? workspaceRoot.wvm.sharedFilesForSelectedPeer.length.toString() : "0"
                                font.family: Theme.fontFamilyMonospace
                                font.pixelSize: Theme.fontMicro
                                font.bold: true
                                color: Theme.accentPrimary
                            }
                        }

                        Repeater {
                            model: workspaceRoot.wvm ? workspaceRoot.wvm.sharedFilesForSelectedPeer : []

                            delegate: Rectangle {
                                Layout.fillWidth: true
                                height: 36
                                radius: 8
                                color: sharedFileMouse.containsMouse ? Theme.backgroundElevated : Theme.backgroundSecondary
                                border.color: Theme.borderSubtle
                                border.width: 1

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 8
                                    anchors.rightMargin: 8
                                    spacing: 6

                                    SCIcon {
                                        name: "file-lock"
                                        size: 14
                                        color: Theme.accentPrimary
                                    }

                                    Label {
                                        text: modelData.fileName || ""
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontMicro
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    Label {
                                        text: modelData.fileSizeText || ""
                                        font.family: Theme.fontFamilyMonospace
                                        font.pixelSize: 10
                                        color: Theme.textMuted
                                    }
                                }

                                MouseArea {
                                    id: sharedFileMouse
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: {
                                        if (workspaceRoot.wvm) {
                                            workspaceRoot.wvm.selectTransfer(modelData.transferId)
                                            workspaceRoot.wvm.activeSection = "Files"
                                        }
                                    }
                                }
                            }
                        }

                        Label {
                            visible: !workspaceRoot.wvm || workspaceRoot.wvm.sharedFilesForSelectedPeer.length === 0
                            text: qsTr("No encrypted files shared in this session yet.")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textMuted
                        }
                    }

                    // Role & Cryptographic Policy Notes
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 4

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
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }

                    Item { Layout.fillHeight: true }

                    // Simulate Key Change (ADR-008 testing) & Remove Contact Buttons
                    SCButton {
                        Layout.fillWidth: true
                        text: qsTr("Simulate Key Change")
                        iconName: "refresh"
                        variant: "Secondary"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: {
                            if (workspaceRoot.wvm) {
                                workspaceRoot.wvm.simulatePeerKeyChange(workspaceRoot.wvm.selectedPeerUserId)
                            }
                        }
                    }

                    SCButton {
                        Layout.fillWidth: true
                        text: qsTr("Remove Contact")
                        iconName: "trash"
                        variant: "Secondary"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: removeContactConfirmDialog.open()
                    }

                    SCButton {
                        Layout.fillWidth: true
                        text: (workspaceRoot.wvm && workspaceRoot.wvm.selectedPeerBlocked)
                              ? qsTr("Unblock Peer")
                              : qsTr("Block %1").arg(workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "")
                        iconName: "shield-alert"
                        variant: "Danger"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.togglePeerBlocked("")
                    }
                }

                // 4B: Group Encryption Roster Content
                ColumnLayout {
                    id: groupRosterContent
                    visible: workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: Theme.space12

                    SCAvatar {
                        displayName: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "Group"
                        userId: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerUserId : "group"
                        size: 64
                        presence: "Online"
                        Layout.alignment: Qt.AlignHCenter
                    }

                    Label {
                        text: workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : ""
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontSubtitle
                        font.bold: true
                        color: Theme.textPrimary
                        horizontalAlignment: Text.AlignHCenter
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }

                    SCBadge {
                        Layout.alignment: Qt.AlignHCenter
                        text: {
                            if (!workspaceRoot.wvm) return ""
                            if (workspaceRoot.wvm.selectedPeerKeyChanged) return qsTr("Key Changed!")
                            return workspaceRoot.wvm.selectedGroupAllVerified
                                   ? qsTr("All Members Verified")
                                   : qsTr("Unverified Members (%1)").arg(workspaceRoot.wvm.selectedGroupUnverifiedCount)
                        }
                        type: {
                            if (!workspaceRoot.wvm) return "Offline"
                            if (workspaceRoot.wvm.selectedPeerKeyChanged) return "Danger"
                            return workspaceRoot.wvm.selectedGroupAllVerified ? "Verified" : "Unverified"
                        }
                    }

                    // Add Participant Action Button
                    SCButton {
                        Layout.fillWidth: true
                        text: qsTr("Add Participant")
                        iconName: "user-plus"
                        variant: "Secondary"
                        buttonHeight: 32
                        horizontalPadding: 8
                        fontSize: Theme.fontCaption
                        onClicked: addParticipantDialog.openWithUnusedContacts()
                    }

                    // Roster Header
                    RowLayout {
                        Layout.fillWidth: true

                        Label {
                            text: qsTr("PARTICIPANTS (%1)").arg(workspaceRoot.wvm ? workspaceRoot.wvm.selectedConversationParticipantCount : 0)
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: 10
                            font.bold: true
                            color: Theme.textMuted
                        }

                        Item { Layout.fillWidth: true }
                    }

                    // Scrollable Participant List
                    ScrollView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true

                        ScrollBar.vertical: ScrollBar {
                            policy: ScrollBar.AsNeeded
                            width: 6
                            contentItem: Rectangle {
                                implicitWidth: 6
                                radius: 3
                                color: Theme.isDark ? "rgba(255, 255, 255, 0.28)" : "rgba(0, 0, 0, 0.25)"
                            }
                            background: Rectangle {
                                color: "transparent"
                            }
                        }

                        ColumnLayout {
                            width: parent.width
                            spacing: Theme.space8

                            Repeater {
                                model: (workspaceRoot.wvm && workspaceRoot.wvm.selectedConversationIsGroup)
                                       ? workspaceRoot.wvm.selectedConversationParticipants
                                       : []

                                delegate: Rectangle {
                                    Layout.fillWidth: true
                                    height: 48
                                    radius: 8
                                    color: Theme.backgroundSecondary
                                    border.color: Theme.borderSubtle
                                    border.width: 1

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: 8
                                        anchors.rightMargin: 8
                                        spacing: 8

                                        SCAvatar {
                                            displayName: modelData.name || "User"
                                            userId: modelData.userId || "user"
                                            size: 28
                                            presence: modelData.presence || ""
                                        }

                                        ColumnLayout {
                                            spacing: 1
                                            Layout.fillWidth: true

                                            RowLayout {
                                                spacing: 4
                                                Layout.fillWidth: true

                                                Label {
                                                    text: modelData.name || ""
                                                    font.family: Theme.fontFamilyPrimary
                                                    font.pixelSize: Theme.fontCaption
                                                    font.bold: true
                                                    color: Theme.textPrimary
                                                    elide: Text.ElideRight
                                                    Layout.fillWidth: true
                                                }

                                                SCBadge {
                                                    text: modelData.isVerified ? qsTr("Verified") : qsTr("Unverified")
                                                    type: modelData.isVerified ? "Verified" : "Unverified"
                                                    badgeHeight: 16
                                                    hasDot: false
                                                }
                                            }

                                            Label {
                                                text: modelData.handle || ""
                                                font.family: Theme.fontFamilyPrimary
                                                font.pixelSize: 10
                                                color: Theme.textMuted
                                                elide: Text.ElideRight
                                                Layout.fillWidth: true
                                            }
                                        }

                                        SCIconButton {
                                            visible: !modelData.isSelf
                                            iconName: "trash"
                                            buttonSize: 22
                                            tooltipText: qsTr("Remove from Group")
                                            onClicked: {
                                                if (workspaceRoot.wvm) {
                                                    workspaceRoot.wvm.removeParticipantFromActiveGroup(modelData.userId)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Leave Group Button
                    SCButton {
                        Layout.fillWidth: true
                        text: qsTr("Leave Encrypted Group")
                        iconName: "shield-alert"
                        variant: "Danger"
                        buttonHeight: 34
                        onClicked: leaveGroupConfirmDialog.open()
                    }
                }
            }
        }
    }

    // Modal Dialogs for Contact Management
    // 1. Add Contact Modal Dialog
    SCDialog {
        id: addContactDialog
        objectName: "addContactDialog"
        title: qsTr("Add New Secure Contact")
        confirmText: qsTr("Add Contact")
        cancelText: qsTr("Cancel")
        property string draftHandle: ""
        property string draftName: ""
        property string draftRole: ""

        onConfirmed: {
            if (workspaceRoot.wvm && draftHandle.trim().length > 0 && draftName.trim().length > 0) {
                workspaceRoot.wvm.addContact(draftHandle.trim(), draftName.trim(), draftRole.trim(), "")
                draftHandle = ""
                draftName = ""
                draftRole = ""
            }
        }

        customContent: Component {
            ColumnLayout {
                spacing: Theme.space12
                width: parent.width

                SCTextField {
                    Layout.fillWidth: true
                    label: qsTr("Peer Handle / Identity")
                    placeholderText: qsTr("@username or username@securecloud.org")
                    text: addContactDialog.draftHandle
                    onTextChanged: addContactDialog.draftHandle = text
                }

                SCTextField {
                    Layout.fillWidth: true
                    label: qsTr("Display Name")
                    placeholderText: qsTr("e.g. Eve Vance")
                    text: addContactDialog.draftName
                    onTextChanged: addContactDialog.draftName = text
                }

                SCTextField {
                    Layout.fillWidth: true
                    label: qsTr("Role / Security Note (Optional)")
                    placeholderText: qsTr("e.g. Senior Security Auditor")
                    text: addContactDialog.draftRole
                    onTextChanged: addContactDialog.draftRole = text
                }
            }
        }
    }

    // 2. Edit Contact Profile Modal Dialog
    SCDialog {
        id: editContactDialog
        objectName: "editContactDialog"
        title: qsTr("Edit Contact Profile")
        confirmText: qsTr("Save Changes")
        cancelText: qsTr("Cancel")
        property string draftName: ""
        property string draftRole: ""

        function openWithCurrentContact() {
            if (!workspaceRoot.wvm) return
            draftName = workspaceRoot.wvm.selectedPeerName
            draftRole = workspaceRoot.wvm.selectedPeerRoleNote
            open()
        }

        onConfirmed: {
            if (workspaceRoot.wvm && draftName.trim().length > 0) {
                workspaceRoot.wvm.updateContactProfile(workspaceRoot.wvm.selectedPeerUserId, draftName.trim(), draftRole.trim())
            }
        }

        customContent: Component {
            ColumnLayout {
                spacing: Theme.space12
                width: parent.width

                SCTextField {
                    Layout.fillWidth: true
                    label: qsTr("Display Name")
                    placeholderText: qsTr("Display alias")
                    text: editContactDialog.draftName
                    onTextChanged: editContactDialog.draftName = text
                }

                SCTextField {
                    Layout.fillWidth: true
                    label: qsTr("Role / Security Note")
                    placeholderText: qsTr("Cryptographic role & security context")
                    text: editContactDialog.draftRole
                    onTextChanged: editContactDialog.draftRole = text
                }
            }
        }
    }

    // 3. Remove Contact Confirmation Dialog
    SCDialog {
        id: removeContactConfirmDialog
        objectName: "removeContactConfirmDialog"
        title: qsTr("Remove Secure Contact")
        message: qsTr("Are you sure you want to remove %1 from your local contacts directory? All cached safety numbers for this peer will be deleted.")
            .arg(workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "this contact")
        confirmText: qsTr("Remove Contact")
        cancelText: qsTr("Keep Contact")
        isDanger: true
        onConfirmed: {
            if (workspaceRoot.wvm) {
                workspaceRoot.wvm.removeContact(workspaceRoot.wvm.selectedPeerUserId)
            }
        }
    }

    // 4. New Direct or Group Conversation Modal Dialog
    SCDialog {
        id: newConversationDialog
        objectName: "newConversationDialog"
        title: isGroupMode ? qsTr("Create Encrypted Group") : qsTr("Start Direct Conversation")
        confirmText: isGroupMode ? qsTr("Create Group") : qsTr("Open Chat")
        cancelText: qsTr("Cancel")

        property bool isGroupMode: false
        property string draftGroupTitle: ""
        property var selectedUserIds: []
        property var unverifiedMembers: []

        function resetAndOpen() {
            isGroupMode = false
            draftGroupTitle = ""
            selectedUserIds = []
            unverifiedMembers = []
            open()
        }

        function toggleUser(userId) {
            var arr = selectedUserIds.slice()
            var idx = arr.indexOf(userId)
            if (idx >= 0) {
                arr.splice(idx, 1)
            } else {
                arr.push(userId)
            }
            selectedUserIds = arr
            recomputeUnverified()
        }

        function selectSingleUser(userId) {
            selectedUserIds = [userId]
            recomputeUnverified()
        }

        function recomputeUnverified() {
            var unverified = []
            if (workspaceRoot.wvm) {
                var cList = workspaceRoot.wvm.contacts
                for (var i = 0; i < cList.length; ++i) {
                    var c = cList[i]
                    if (selectedUserIds.indexOf(c.userId) >= 0 && !c.isVerified) {
                        unverified.push(c.displayName + " (" + c.handle + ")")
                    }
                }
            }
            unverifiedMembers = unverified
        }

        onConfirmed: {
            if (!workspaceRoot.wvm) return
            if (isGroupMode) {
                if (draftGroupTitle.trim().length > 0 && selectedUserIds.length > 0) {
                    workspaceRoot.wvm.createGroupConversation(draftGroupTitle.trim(), selectedUserIds)
                }
            } else {
                if (selectedUserIds.length > 0) {
                    workspaceRoot.wvm.createDirectConversation(selectedUserIds[0])
                }
            }
        }

        customContent: Component {
            ColumnLayout {
                spacing: Theme.space12
                width: parent.width

                // Tab Switcher: Direct Chat vs Encrypted Group
                RowLayout {
                    Layout.fillWidth: true
                    spacing: 0

                    Rectangle {
                        Layout.fillWidth: true
                        height: 32
                        color: !newConversationDialog.isGroupMode ? Theme.accentPrimary : Theme.backgroundSecondary
                        radius: 6

                        Label {
                            anchors.centerIn: parent
                            text: qsTr("Direct Chat")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            font.bold: true
                            color: !newConversationDialog.isGroupMode ? "#FFFFFF" : Theme.textSecondary
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                newConversationDialog.isGroupMode = false
                                newConversationDialog.selectedUserIds = []
                                newConversationDialog.recomputeUnverified()
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 32
                        color: newConversationDialog.isGroupMode ? Theme.accentPrimary : Theme.backgroundSecondary
                        radius: 6

                        Label {
                            anchors.centerIn: parent
                            text: qsTr("Encrypted Group")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            font.bold: true
                            color: newConversationDialog.isGroupMode ? "#FFFFFF" : Theme.textSecondary
                        }

                        MouseArea {
                            anchors.fill: parent
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                newConversationDialog.isGroupMode = true
                                newConversationDialog.selectedUserIds = []
                                newConversationDialog.recomputeUnverified()
                            }
                        }
                    }
                }

                // Group Title Input (Group Mode only)
                SCTextField {
                    visible: newConversationDialog.isGroupMode
                    Layout.fillWidth: true
                    label: qsTr("Group Conversation Title")
                    placeholderText: qsTr("e.g. Incident Response Alpha")
                    text: newConversationDialog.draftGroupTitle
                    onTextChanged: newConversationDialog.draftGroupTitle = text
                }

                Label {
                    text: newConversationDialog.isGroupMode ? qsTr("Select Participants:") : qsTr("Select Contact:")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    font.bold: true
                    color: Theme.textPrimary
                }

                // Contact Selection List
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(180, (workspaceRoot.wvm ? workspaceRoot.wvm.contacts.length : 0) * 44)
                    clip: true

                    ScrollBar.vertical: ScrollBar {
                        policy: ScrollBar.AsNeeded
                        width: 6
                        contentItem: Rectangle {
                            implicitWidth: 6
                            radius: 3
                            color: Theme.isDark ? "rgba(255, 255, 255, 0.28)" : "rgba(0, 0, 0, 0.25)"
                        }
                        background: Rectangle {
                            color: "transparent"
                        }
                    }

                    ColumnLayout {
                        width: parent.width
                        spacing: 4

                        Repeater {
                            model: workspaceRoot.wvm ? workspaceRoot.wvm.contacts : []

                            delegate: Rectangle {
                                Layout.fillWidth: true
                                height: 40
                                radius: 6
                                readonly property bool isSelected: newConversationDialog.selectedUserIds.indexOf(modelData.userId) >= 0
                                color: isSelected
                                       ? (Theme.isDark ? "#1E293B" : "#E2E8F0")
                                       : (contactItemMouse.containsMouse ? Theme.backgroundSecondary : "transparent")
                                border.color: isSelected ? Theme.accentPrimary : Theme.borderSubtle
                                border.width: 1

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 8
                                    anchors.rightMargin: 8
                                    spacing: 8

                                    SCIcon {
                                        name: isSelected ? "shield-check" : "circle"
                                        size: 16
                                        color: isSelected ? Theme.accentPrimary : Theme.textMuted
                                    }

                                    SCAvatar {
                                        displayName: modelData.displayName || "User"
                                        userId: modelData.userId || "user"
                                        size: 24
                                    }

                                    Label {
                                        text: modelData.displayName || ""
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    SCBadge {
                                        text: modelData.isVerified ? qsTr("Verified") : qsTr("Unverified")
                                        type: modelData.isVerified ? "Verified" : "Unverified"
                                        badgeHeight: 16
                                        hasDot: false
                                    }
                                }

                                MouseArea {
                                    id: contactItemMouse
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: {
                                        if (newConversationDialog.isGroupMode) {
                                            newConversationDialog.toggleUser(modelData.userId)
                                        } else {
                                            newConversationDialog.selectSingleUser(modelData.userId)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Security Warning Box for Unverified Selectees
                Rectangle {
                    visible: newConversationDialog.unverifiedMembers.length > 0
                    Layout.fillWidth: true
                    radius: 8
                    color: Theme.isDark ? "rgba(245, 158, 11, 0.15)" : "#FEF3C7"
                    border.color: Theme.statusWarning
                    border.width: 1
                    implicitHeight: unverifiedWarnCol.implicitHeight + 16

                    ColumnLayout {
                        id: unverifiedWarnCol
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 3

                        RowLayout {
                            spacing: 6
                            SCIcon { name: "alert-triangle"; size: 14; color: Theme.statusWarning }
                            Label {
                                text: qsTr("Security Notice: Unverified Members Selected (%1)").arg(newConversationDialog.unverifiedMembers.length)
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontMicro
                                font.bold: true
                                color: Theme.statusWarning
                            }
                        }

                        Label {
                            text: qsTr("The following contacts have unverified safety numbers: %1. Group messages will be encrypted to unverified identities.")
                                .arg(newConversationDialog.unverifiedMembers.join(", "))
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: 10
                            color: Theme.textSecondary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }
    }

    // 5. Add Participant to Active Group Dialog
    SCDialog {
        id: addParticipantDialog
        objectName: "addParticipantDialog"
        title: qsTr("Add Participant to Encrypted Group")
        confirmText: qsTr("Add to Group")
        cancelText: qsTr("Cancel")

        property string selectedUserId: ""
        property bool selectedIsUnverified: false
        property string selectedUserName: ""

        function openWithUnusedContacts() {
            selectedUserId = ""
            selectedIsUnverified = false
            selectedUserName = ""
            open()
        }

        onConfirmed: {
            if (workspaceRoot.wvm && selectedUserId.trim().length > 0) {
                workspaceRoot.wvm.addParticipantToActiveGroup(selectedUserId.trim())
            }
        }

        customContent: Component {
            ColumnLayout {
                spacing: Theme.space12
                width: parent.width

                Label {
                    text: qsTr("Select contact to add:")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    font.bold: true
                    color: Theme.textPrimary
                }

                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: Math.min(180, (workspaceRoot.wvm ? workspaceRoot.wvm.contacts.length : 0) * 44)
                    clip: true

                    ScrollBar.vertical: ScrollBar {
                        policy: ScrollBar.AsNeeded
                        width: 6
                        contentItem: Rectangle {
                            implicitWidth: 6
                            radius: 3
                            color: Theme.isDark ? "rgba(255, 255, 255, 0.28)" : "rgba(0, 0, 0, 0.25)"
                        }
                        background: Rectangle {
                            color: "transparent"
                        }
                    }

                    ColumnLayout {
                        width: parent.width
                        spacing: 4

                        Repeater {
                            model: workspaceRoot.wvm ? workspaceRoot.wvm.contacts : []

                            delegate: Rectangle {
                                Layout.fillWidth: true
                                height: 40
                                radius: 6
                                readonly property bool isSelected: addParticipantDialog.selectedUserId === modelData.userId
                                color: isSelected
                                       ? (Theme.isDark ? "#1E293B" : "#E2E8F0")
                                       : (addPartMouse.containsMouse ? Theme.backgroundSecondary : "transparent")
                                border.color: isSelected ? Theme.accentPrimary : Theme.borderSubtle
                                border.width: 1

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 8
                                    anchors.rightMargin: 8
                                    spacing: 8

                                    SCIcon {
                                        name: isSelected ? "shield-check" : "circle"
                                        size: 16
                                        color: isSelected ? Theme.accentPrimary : Theme.textMuted
                                    }

                                    SCAvatar {
                                        displayName: modelData.displayName || "User"
                                        userId: modelData.userId || "user"
                                        size: 24
                                    }

                                    Label {
                                        text: modelData.displayName || ""
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    SCBadge {
                                        text: modelData.isVerified ? qsTr("Verified") : qsTr("Unverified")
                                        type: modelData.isVerified ? "Verified" : "Unverified"
                                        badgeHeight: 16
                                        hasDot: false
                                    }
                                }

                                MouseArea {
                                    id: addPartMouse
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: {
                                        addParticipantDialog.selectedUserId = modelData.userId
                                        addParticipantDialog.selectedIsUnverified = !modelData.isVerified
                                        addParticipantDialog.selectedUserName = modelData.displayName
                                    }
                                }
                            }
                        }
                    }
                }

                // Security Warning if selected contact is unverified
                Rectangle {
                    visible: addParticipantDialog.selectedIsUnverified && addParticipantDialog.selectedUserId.length > 0
                    Layout.fillWidth: true
                    radius: 8
                    color: Theme.isDark ? "rgba(245, 158, 11, 0.15)" : "#FEF3C7"
                    border.color: Theme.statusWarning
                    border.width: 1
                    implicitHeight: addPartWarnCol.implicitHeight + 16

                    ColumnLayout {
                        id: addPartWarnCol
                        anchors.fill: parent
                        anchors.margins: 8
                        spacing: 3

                        RowLayout {
                            spacing: 6
                            SCIcon { name: "alert-triangle"; size: 14; color: Theme.statusWarning }
                            Label {
                                text: qsTr("Notice: Unverified Identity")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontMicro
                                font.bold: true
                                color: Theme.statusWarning
                            }
                        }

                        Label {
                            text: qsTr("%1's safety number has not been verified yet. Adding this contact will downgrade the group's aggregate trust level.")
                                .arg(addParticipantDialog.selectedUserName)
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: 10
                            color: Theme.textSecondary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }
                }
            }
        }
    }

    // 6. Leave Group Confirmation Dialog
    SCDialog {
        id: leaveGroupConfirmDialog
        objectName: "leaveGroupConfirmDialog"
        title: qsTr("Leave Encrypted Group")
        message: qsTr("Are you sure you want to leave '%1'? Group sender keys will be rotated and you will no longer receive new messages from this group.")
            .arg(workspaceRoot.wvm ? workspaceRoot.wvm.selectedPeerName : "this group")
        confirmText: qsTr("Leave Group")
        cancelText: qsTr("Stay in Group")
        isDanger: true
        onConfirmed: {
            if (workspaceRoot.wvm) {
                workspaceRoot.wvm.leaveActiveGroup()
            }
        }
    }
}
