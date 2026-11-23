import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

ApplicationWindow {
    id: rootWindow
    visible: true
    x: typeof windowStateManager !== "undefined" ? windowStateManager.x : 100
    y: typeof windowStateManager !== "undefined" ? windowStateManager.y : 100
    width: typeof windowStateManager !== "undefined" ? windowStateManager.width : 1200
    height: typeof windowStateManager !== "undefined" ? windowStateManager.height : 800
    minimumWidth: typeof windowStateManager !== "undefined" ? windowStateManager.minWidth : 960
    minimumHeight: typeof windowStateManager !== "undefined" ? windowStateManager.minHeight : 640
    visibility: (typeof windowStateManager !== "undefined" && windowStateManager.isMaximized) ? Window.Maximized : Window.Windowed
    title: qsTr("SecureCloud Desktop")
    color: Theme.backgroundPrimary

    readonly property var wvm: typeof workspaceViewModel !== "undefined" ? workspaceViewModel : null

    readonly property bool showAuthenticatedChrome:
        navigationController.isAuthenticated &&
        appViewModel.isAuthenticated &&
        navigationController.currentViewName !== "Login" &&
        navigationController.currentViewName !== "MfaVerification" &&
        navigationController.currentViewName !== "Emergency"

    function openEmergencyDialog() {
        if (navigationController.isAuthenticated) {
            emergencyConfirmDialog.sendPreWipeBroadcast = false
            emergencyConfirmDialog.waitForBroadcastAck = true
            emergencyConfirmDialog.broadcastAlertText = ""
            var defaultConv = ""
            if (rootWindow.wvm) {
                if (rootWindow.wvm.selectedConversationId && rootWindow.wvm.selectedConversationId !== "") {
                    defaultConv = rootWindow.wvm.selectedConversationId
                } else if (rootWindow.wvm.conversations && rootWindow.wvm.conversations.length > 0) {
                    defaultConv = rootWindow.wvm.conversations[0].conversationId || ""
                }
            }
            emergencyConfirmDialog.broadcastConversationId = defaultConv
            emergencyConfirmDialog.isOpen = true
        }
    }

    Timer {
        id: saveGeometryTimer
        interval: 500
        repeat: false
        onTriggered: {
            if (typeof windowStateManager !== "undefined" && windowStateManager !== null) {
                windowStateManager.saveGeometry(
                    rootWindow.width,
                    rootWindow.height,
                    rootWindow.x,
                    rootWindow.y,
                    rootWindow.visibility === Window.Maximized
                )
            }
        }
    }

    onWidthChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onHeightChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onXChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onYChanged: if (rootWindow.visible && rootWindow.visibility !== Window.Maximized) saveGeometryTimer.restart()
    onVisibilityChanged: {
        if (rootWindow.visible && typeof windowStateManager !== "undefined" && windowStateManager !== null) {
            windowStateManager.saveGeometry(
                rootWindow.width,
                rootWindow.height,
                rootWindow.x,
                rootWindow.y,
                rootWindow.visibility === Window.Maximized
            )
        }
    }
    onClosing: {
        if (typeof windowStateManager !== "undefined" && windowStateManager !== null) {
            windowStateManager.saveGeometry(
                rootWindow.width,
                rootWindow.height,
                rootWindow.x,
                rootWindow.y,
                rootWindow.visibility === Window.Maximized
            )
        }
    }

    header: ToolBar {
        visible: !rootWindow.showAuthenticatedChrome
        height: visible ? implicitHeight : 0
        implicitHeight: 52
        background: Rectangle {
            color: Theme.backgroundSecondary
            Rectangle {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.borderSubtle
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.space16
            anchors.rightMargin: Theme.space16
            spacing: Theme.space12

            SCIconButton {
                iconName: "arrow-left"
                tooltipText: qsTr("Go Back (Alt+Left)")
                visible: navigationController.canNavigateBack
                onClicked: navigationController.navigateBack()
            }

            // Brand Mark + Wordmark
            RowLayout {
                spacing: Theme.space8

                Rectangle {
                    width: 28
                    height: 28
                    radius: Theme.radiusSmall
                    color: Theme.isDark ? "#13233D" : "#DBEAFE"
                    border.color: Theme.accentPrimary
                    border.width: 1

                    SCIcon {
                        anchors.centerIn: parent
                        name: "shield-check"
                        size: 16
                        color: Theme.accentPrimary
                    }
                }

                Label {
                    text: qsTr("SecureCloud")
                    font.bold: true
                    font.pixelSize: Theme.fontTitle
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }
            }

            SCBadge {
                visible: rootWindow.showAuthenticatedChrome
                text: qsTr("Authenticated Session")
                type: "Online"
                hasDot: true
            }

            Item { Layout.fillWidth: true }

            // Authenticated User Identity Chip
            RowLayout {
                visible: rootWindow.showAuthenticatedChrome
                spacing: Theme.space8

                SCAvatar {
                    userId: appViewModel.currentUser
                    displayName: appViewModel.currentUser
                    size: 28
                    presence: "Online"
                }

                Label {
                    text: appViewModel.currentUser
                    color: Theme.textPrimary
                    font.pixelSize: Theme.fontBody
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                }

                SCButton {
                    text: qsTr("Sign Out")
                    iconName: "logout"
                    variant: "Ghost"
                    buttonHeight: 30
                    horizontalPadding: 10
                    onClicked: appViewModel.requestLogout()
                }
            }

            // Unauthenticated Status Badge (strictly suppressed in Decoy sessions)
            SCBadge {
                visible: !rootWindow.showAuthenticatedChrome
                text: (appViewModel.isEmergencyWiped && !appViewModel.isDecoySession)
                      ? qsTr("Emergency Wipe Active")
                      : qsTr("Unauthenticated")
                type: (appViewModel.isEmergencyWiped && !appViewModel.isDecoySession) ? "Danger" : "Offline"
                hasDot: true
            }

            Rectangle {
                width: 1
                height: 20
                color: Theme.borderSubtle
            }

            SCIconButton {
                iconName: "style-guide"
                active: navigationController.currentViewName === "StyleGuide"
                tooltipText: navigationController.currentViewName === "StyleGuide"
                             ? qsTr("Exit Style Guide")
                             : qsTr("Design System Style Guide (Ctrl+5)")
                onClicked: {
                    if (navigationController.currentViewName === "StyleGuide" && navigationController.canNavigateBack) {
                        navigationController.navigateBack()
                    } else {
                        navigationController.navigateTo(5)
                    }
                }
            }

            SCIconButton {
                iconName: Theme.isDark ? "sun" : "moon"
                tooltipText: Theme.isDark ? qsTr("Switch to Light Theme") : qsTr("Switch to Dark Theme")
                onClicked: Theme.toggleTheme()
            }
        }
    }

    NavigationShell {
        anchors.fill: parent
        onEmergencyWipeRequested: rootWindow.openEmergencyDialog()
    }

    footer: ToolBar {
        implicitHeight: 34
        background: Rectangle {
            color: Theme.backgroundSecondary
            Rectangle {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.borderSubtle
            }
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: Theme.space16
            anchors.rightMargin: Theme.space16
            spacing: Theme.space8

            Rectangle {
                width: 7
                height: 7
                radius: 3.5
                color: {
                    if (appViewModel.isEmergencyWiped && !appViewModel.isDecoySession) return Theme.statusDanger
                    if (!appViewModel.isAuthenticated) return Theme.textMuted
                    if (appViewModel.connectivityState === "Offline") return Theme.statusWarning
                    if (appViewModel.connectivityState === "Syncing") return Theme.accentPrimary
                    return Theme.statusSuccess
                }
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: appViewModel.sessionStatusText
                color: Theme.textSecondary
                font.pixelSize: Theme.fontCaption
                font.family: Theme.fontFamilyPrimary
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: "·"
                color: Theme.textMuted
                font.pixelSize: Theme.fontCaption
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: qsTr("View: %1").arg(navigationController.currentViewName)
                color: Theme.textMuted
                font.pixelSize: Theme.fontCaption
                font.family: Theme.fontFamilyPrimary
                Layout.alignment: Qt.AlignVCenter
            }

            Item { Layout.fillWidth: true }

            SCBadge {
                text: appViewModel.securityStatusText
                type: appViewModel.securityBadgeType
                hasDot: true
            }
        }
    }

    // Modal Confirmation Dialog for Instant Forensic Wipe or Optional Pre-Wipe E2EE Broadcast
    SCDialog {
        id: emergencyConfirmDialog
        objectName: "emergencyPanicModal"
        property bool sendPreWipeBroadcast: false
        property string broadcastConversationId: ""
        property string broadcastAlertText: ""
        property bool waitForBroadcastAck: true

        title: qsTr("Initiate Emergency Wipe?")
        message: qsTr("Warning: This action will permanently zeroize all cryptographic ratchets, purge session keys, shred the SQLCipher vault, and clear volatile workspace state from memory and disk.")
        confirmText: emergencyConfirmDialog.sendPreWipeBroadcast
                     ? qsTr("Broadcast & Execute Wipe")
                     : qsTr("Execute Instant Wipe")
        cancelText: qsTr("Cancel")
        isDanger: true

        customContent: Component {
            ColumnLayout {
                width: parent ? parent.width : 0
                spacing: Theme.space12

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2

                        Label {
                            text: qsTr("Send Encrypted Emergency Broadcast Before Wipe")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            font.bold: true
                            color: Theme.textPrimary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        Label {
                            text: qsTr("Dispatches a Priority 3 E2EE distress alert before local destruction.")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textMuted
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }

                    Switch {
                        id: preWipeBroadcastSwitch
                        objectName: "preWipeBroadcastSwitch"
                        checked: emergencyConfirmDialog.sendPreWipeBroadcast
                        onToggled: emergencyConfirmDialog.sendPreWipeBroadcast = checked
                    }
                }

                ColumnLayout {
                    visible: emergencyConfirmDialog.sendPreWipeBroadcast
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    Flow {
                        visible: rootWindow.wvm !== null && rootWindow.wvm.conversations && rootWindow.wvm.conversations.length > 0
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        Repeater {
                            model: rootWindow.wvm ? rootWindow.wvm.conversations.slice(0, 3) : []
                            delegate: SCButton {
                                text: modelData.peerDisplayName || modelData.conversationId || ""
                                variant: emergencyConfirmDialog.broadcastConversationId === (modelData.conversationId || "")
                                         ? "Primary"
                                         : "Secondary"
                                buttonHeight: 28
                                horizontalPadding: 10
                                onClicked: emergencyConfirmDialog.broadcastConversationId = (modelData.conversationId || "")
                            }
                        }
                    }

                    SCTextField {
                        id: broadcastConvField
                        objectName: "emergencyBroadcastConversationField"
                        label: qsTr("Target Conversation ID")
                        placeholderText: qsTr("e.g. conv-secops")
                        Layout.fillWidth: true
                        Component.onCompleted: text = emergencyConfirmDialog.broadcastConversationId
                        onTextEdited: emergencyConfirmDialog.broadcastConversationId = text
                        Connections {
                            target: emergencyConfirmDialog
                            function onBroadcastConversationIdChanged() {
                                if (broadcastConvField.text !== emergencyConfirmDialog.broadcastConversationId) {
                                    broadcastConvField.text = emergencyConfirmDialog.broadcastConversationId
                                }
                            }
                        }
                    }

                    SCTextField {
                        id: broadcastAlertField
                        objectName: "emergencyBroadcastAlertField"
                        label: qsTr("Encrypted Distress Alert (Priority: Emergency)")
                        placeholderText: qsTr("EMERGENCY PANIC WIPE INITIATED")
                        Layout.fillWidth: true
                        Component.onCompleted: text = emergencyConfirmDialog.broadcastAlertText
                        onTextEdited: emergencyConfirmDialog.broadcastAlertText = text
                        Connections {
                            target: emergencyConfirmDialog
                            function onBroadcastAlertTextChanged() {
                                if (broadcastAlertField.text !== emergencyConfirmDialog.broadcastAlertText) {
                                    broadcastAlertField.text = emergencyConfirmDialog.broadcastAlertText
                                }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        Label {
                            text: qsTr("Wait briefly (<=1.5s) for delivery ACK before wiping")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        Switch {
                            checked: emergencyConfirmDialog.waitForBroadcastAck
                            onToggled: emergencyConfirmDialog.waitForBroadcastAck = checked
                        }
                    }

                    Label {
                        text: qsTr("Network failure or ACK timeout will never block or delay local destruction.")
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontMicro
                        color: Theme.textMuted
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }
        }

        onConfirmed: {
            if (emergencyConfirmDialog.sendPreWipeBroadcast &&
                emergencyConfirmDialog.broadcastConversationId.trim() !== "") {
                appViewModel.triggerBroadcastAndPanicWipe(
                    emergencyConfirmDialog.broadcastConversationId,
                    emergencyConfirmDialog.broadcastAlertText,
                    "",
                    emergencyConfirmDialog.waitForBroadcastAck
                )
            } else {
                appViewModel.triggerInstantPanicWipe(0)
            }
        }
    }
}
