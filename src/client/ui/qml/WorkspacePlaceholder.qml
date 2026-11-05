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
            Layout.preferredWidth: 284
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

                // Section Switcher Pills (Messages | Contacts | Files)
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    SCButton {
                        text: qsTr("Messages")
                        variant: workspaceRoot.activeSection === "Messages" ? "Primary" : "Secondary"
                        buttonHeight: 30
                        horizontalPadding: 10
                        Layout.fillWidth: true
                        onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.activeSection = "Messages"
                    }

                    SCButton {
                        text: qsTr("Contacts")
                        variant: workspaceRoot.activeSection === "Contacts" ? "Primary" : "Secondary"
                        buttonHeight: 30
                        horizontalPadding: 10
                        Layout.fillWidth: true
                        onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.activeSection = "Contacts"
                    }

                    SCButton {
                        text: qsTr("Files")
                        variant: workspaceRoot.activeSection === "Files" ? "Primary" : "Secondary"
                        buttonHeight: 30
                        horizontalPadding: 10
                        Layout.fillWidth: true
                        onClicked: if (workspaceRoot.wvm) workspaceRoot.wvm.activeSection = "Files"
                    }
                }

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
                            if (workspaceRoot.activeSection === "Files") {
                                return qsTr("%1 Vault Items").arg(workspaceRoot.wvm.activeFileTransferCount)
                            }
                            return qsTr("%1 Unread").arg(workspaceRoot.wvm.totalUnreadCount)
                        }
                        type: "Info"
                        hasDot: false
                    }
                }

                // Real-Time Search Filter Input
                SCTextField {
                    id: masterSearchField
                    Layout.fillWidth: true
                    inputHeight: 36
                    leadingIconName: "search"
                    placeholderText: workspaceRoot.activeSection === "Files"
                                     ? qsTr("Search encrypted files...")
                                     : qsTr("Search conversations...")
                    text: workspaceRoot.wvm ? workspaceRoot.wvm.searchQuery : ""
                    onTextEdited: {
                        if (workspaceRoot.wvm) {
                            workspaceRoot.wvm.searchQuery = masterSearchField.text
                        }
                    }
                }

                // Dynamic Master List (Conversations / Contacts / Files)
                ListView {
                    id: masterListView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: Theme.space8
                    clip: true
                    model: {
                        if (!workspaceRoot.wvm) return []
                        if (workspaceRoot.activeSection === "Contacts") return workspaceRoot.wvm.contacts
                        if (workspaceRoot.activeSection === "Files") return workspaceRoot.wvm.fileTransfers
                        return workspaceRoot.wvm.conversations
                    }

                    delegate: Rectangle {
                        width: masterListView.width
                        height: 68
                        radius: Theme.radiusMedium
                        color: modelData.isSelected
                               ? Theme.backgroundElevated
                               : (itemMouse.containsMouse ? (Theme.isDark ? "#192130" : "#E2E8F0") : "transparent")
                        border.color: modelData.isSelected ? Theme.borderSubtle : "transparent"
                        border.width: modelData.isSelected ? 1 : 0

                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: Theme.space12
                            spacing: Theme.space12

                            SCAvatar {
                                userId: workspaceRoot.activeSection === "Files"
                                        ? (modelData.fileName || "file")
                                        : (modelData.peerUserId || modelData.userId || "peer")
                                displayName: workspaceRoot.activeSection === "Files"
                                             ? (modelData.fileName || "F")
                                             : (modelData.peerDisplayName || modelData.displayName || "Peer")
                                size: 40
                                presence: workspaceRoot.activeSection === "Files" ? "" : (modelData.presence || "Offline")
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 3

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space4

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

                                    Label {
                                        text: modelData.timestampText || modelData.handle || ""
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontMicro
                                        color: Theme.textMuted
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space8

                                    Label {
                                        text: {
                                            if (workspaceRoot.activeSection === "Files") {
                                                return (modelData.fileSizeText || "") + " · " + (modelData.cipherSuite || "") + " · " + (modelData.peerDisplayName || "")
                                            }
                                            if (workspaceRoot.activeSection === "Contacts") {
                                                return modelData.roleNote || ""
                                            }
                                            return modelData.lastMessagePreview || ""
                                        }
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: (modelData.unreadCount && modelData.unreadCount > 0)
                                               ? Theme.textPrimary
                                               : Theme.textSecondary
                                        font.bold: (modelData.unreadCount && modelData.unreadCount > 0) ? true : false
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    Rectangle {
                                        visible: workspaceRoot.activeSection === "Messages" && (modelData.unreadCount || 0) > 0
                                        width: 20
                                        height: 20
                                        radius: 10
                                        color: Theme.accentPrimary

                                        Label {
                                            anchors.centerIn: parent
                                            text: (modelData.unreadCount || 0).toString()
                                            font.pixelSize: Theme.fontMicro
                                            font.bold: true
                                            color: "#FFFFFF"
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
                                } else {
                                    workspaceRoot.wvm.selectConversation(modelData.conversationId)
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
