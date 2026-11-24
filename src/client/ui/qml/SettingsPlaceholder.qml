import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: settingsRoot
    color: Theme.backgroundPrimary

    readonly property var wvm: typeof workspaceViewModel !== "undefined" ? workspaceViewModel : null
    readonly property var avm: typeof appViewModel !== "undefined" ? appViewModel : null
    readonly property var localIdentity: wvm ? wvm.localDeviceIdentity : ({})

    function syncProfileFieldsFromVm() {
        if (!wvm) {
            return
        }
        profileDisplayNameField.text = wvm.profileDisplayName
        profileHandleField.text = wvm.profileHandle
        profileBioField.text = wvm.profileBio
        profileAllowDiscoverySwitch.checked = wvm.profileAllowDiscovery
    }

    function syncNetworkFieldsFromVm() {
        if (!wvm) {
            return
        }
        liveTransportSwitch.checked = wvm.useLiveGatewayTransport
        gatewayHostField.text = wvm.gatewayHost
        gatewayPortField.text = String(wvm.gatewayPort)
        proxyHostField.text = wvm.proxyHost
        proxyPortField.text = wvm.proxyPort > 0 ? String(wvm.proxyPort) : ""
        proxyUsernameField.text = wvm.proxyUsername
        tlsPinnedSpkiField.text = wvm.tlsPinnedFingerprint
        tlsStrictPinningSwitch.checked = wvm.tlsEnforceStrictPinning
        networkTlsCard.selectedProxyType = wvm.proxyType
    }

    function formatTimerLabel(ttlSeconds) {
        if (ttlSeconds === 3600) {
            return qsTr("1 hour")
        }
        if (ttlSeconds === 86400) {
            return qsTr("24 hours")
        }
        if (ttlSeconds === 604800) {
            return qsTr("7 days")
        }
        return qsTr("Off")
    }

    Connections {
        target: settingsRoot.wvm
        enabled: settingsRoot.wvm !== null

        function onProfileSettingsChanged() {
            settingsRoot.syncProfileFieldsFromVm()
        }

        function onNetworkSettingsChanged() {
            settingsRoot.syncNetworkFieldsFromVm()
        }
    }

    Component.onCompleted: {
        syncProfileFieldsFromVm()
        syncNetworkFieldsFromVm()
    }

    ScrollView {
        id: settingsScrollView
        objectName: "settingsScrollView"
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth

        function scrollToBottom() {
            if (contentItem && contentItem.contentHeight > height) {
                contentItem.contentY = contentItem.contentHeight - height
            }
        }

        ColumnLayout {
            width: Math.min(820, parent.width - (Theme.space32 * 2))
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Theme.space24

            Item { width: 1; height: Theme.space8 }

            // Page Title + Back to Workspace Button
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space12

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    Label {
                        text: qsTr("Security Workstation Settings & Profile Center")
                        font.pixelSize: Theme.fontTitle
                        font.bold: true
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                    }

                    Label {
                        text: qsTr("Manage encrypted profile & avatar, cryptographic device trust, disappearing timers, accessibility scaling, TLS 1.3 pinning & proxy, and endpoint-only BIP-39 recovery.")
                        font.pixelSize: Theme.fontCaption
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textSecondary
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }

                SCButton {
                    text: qsTr("Back to Workspace")
                    variant: "Secondary"
                    iconName: "arrow-left"
                    buttonHeight: 36
                    onClicked: navigationController.navigateToSection("Messages")
                }
            }

            // 1. User Profile & Encrypted Avatar
            SCCard {
                id: profileCard
                objectName: "profileCard"
                Layout.fillWidth: true
                headerText: qsTr("1. User Profile & Encrypted Avatar")
                headerIconName: "users"
                elevation: "Elevated"

                property string profileFeedbackText: ""
                property bool profileFeedbackIsError: false

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCAvatar {
                            userId: (settingsRoot.wvm && settingsRoot.wvm.profileHandle !== "")
                                    ? settingsRoot.wvm.profileHandle
                                    : "operator@securecloud.org"
                            displayName: settingsRoot.wvm ? settingsRoot.wvm.profileDisplayName : qsTr("Operator")
                            size: 48
                            presence: "Online"
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: settingsRoot.wvm ? settingsRoot.wvm.profileDisplayName : qsTr("Operator")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontSubtitle
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: (settingsRoot.wvm && settingsRoot.wvm.profileHandle !== "")
                                      ? ("@" + settingsRoot.wvm.profileHandle)
                                      : qsTr("No public handle configured (private workstation only)")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }
                        }

                        SCBadge {
                            objectName: "profileSyncStatusBadge"
                            text: settingsRoot.wvm ? settingsRoot.wvm.profileSyncStatusText : qsTr("Local Profile")
                            type: {
                                if (!settingsRoot.wvm) return "Info"
                                if (settingsRoot.wvm.profileSyncStatusText.indexOf("Failed") !== -1) return "Danger"
                                if (settingsRoot.wvm.profileSyncStatusText.indexOf("Disabled") !== -1) return "Offline"
                                return "Verified"
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCTextField {
                            id: profileDisplayNameField
                            objectName: "profileDisplayNameField"
                            label: qsTr("Display Name")
                            placeholderText: qsTr("e.g. Alice Vance (SecOps)")
                            Layout.fillWidth: true
                            onTextEdited: profileCard.profileFeedbackText = ""
                        }

                        SCTextField {
                            id: profileHandleField
                            objectName: "profileHandleField"
                            label: qsTr("Public Handle (Optional)")
                            placeholderText: qsTr("alice.secops (lowercase a-z, 0-9, _, ., -)")
                            Layout.fillWidth: true
                            onTextEdited: profileCard.profileFeedbackText = ""
                        }
                    }

                    SCTextField {
                        id: profileBioField
                        objectName: "profileBioField"
                        label: qsTr("Status / Bio")
                        placeholderText: qsTr("Role note or endpoint operational status...")
                        Layout.fillWidth: true
                        onTextEdited: profileCard.profileFeedbackText = ""
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Allow Handle Discovery Sync")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("When disabled, display name, bio, and handle remain strictly encrypted in local SQLCipher.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        Switch {
                            id: profileAllowDiscoverySwitch
                            objectName: "profileAllowDiscoverySwitch"
                            checked: settingsRoot.wvm ? settingsRoot.wvm.profileAllowDiscovery : true
                        }

                        SCButton {
                            objectName: "saveProfileButton"
                            text: qsTr("Save Profile")
                            iconName: "check"
                            variant: "Primary"
                            buttonHeight: 34
                            onClicked: {
                                if (!settingsRoot.wvm) {
                                    return
                                }
                                var ok = settingsRoot.wvm.saveUserProfile(
                                    profileDisplayNameField.text,
                                    profileHandleField.text,
                                    profileBioField.text,
                                    profileAllowDiscoverySwitch.checked,
                                    true)
                                profileCard.profileFeedbackIsError = !ok
                                profileCard.profileFeedbackText = ok
                                    ? qsTr("Encrypted profile updated.")
                                    : qsTr("Profile validation failed — check display name or handle format.")
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        SCTextField {
                            id: profileAvatarPathField
                            objectName: "profileAvatarPathField"
                            label: qsTr("Encrypted E2EE Avatar Image (.png, .jpg, .webp <= 5 MiB)")
                            placeholderText: qsTr("/path/to/avatar.png")
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "uploadAvatarButton"
                            text: qsTr("Encrypt & Upload Avatar")
                            iconName: "upload-cloud"
                            variant: "Secondary"
                            buttonHeight: 36
                            Layout.alignment: Qt.AlignBottom
                            onClicked: {
                                if (!settingsRoot.wvm) {
                                    return
                                }
                                var ok = settingsRoot.wvm.uploadAvatarImage(profileAvatarPathField.text)
                                profileCard.profileFeedbackIsError = !ok
                                profileCard.profileFeedbackText = ok
                                    ? qsTr("Avatar encrypted with client-side E2EE key and uploaded.")
                                    : qsTr("Avatar upload failed — verify local image path and format.")
                                if (ok) {
                                    profileAvatarPathField.text = ""
                                }
                            }
                        }
                    }

                    Label {
                        visible: settingsRoot.wvm ? (settingsRoot.wvm.profileAvatarFileId !== "") : false
                        text: settingsRoot.wvm
                              ? qsTr("Encrypted Avatar Object: %1  ·  SHA-256: %2")
                                    .arg(settingsRoot.wvm.profileAvatarFileId)
                                    .arg(settingsRoot.wvm.profileAvatarSha256)
                              : ""
                        font.family: Theme.fontFamilyMonospace
                        font.pixelSize: Theme.fontMicro
                        color: Theme.textSecondary
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }

                    Label {
                        visible: profileCard.profileFeedbackText !== ""
                        text: profileCard.profileFeedbackText
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontCaption
                        color: profileCard.profileFeedbackIsError ? Theme.statusDanger : Theme.statusSuccess
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            // 2. Local Workstation Cryptographic Identity & Signed Prekey Rotation
            SCCard {
                id: localIdentityCard
                objectName: "localIdentityCard"
                Layout.fillWidth: true
                headerText: qsTr("2. Local Workstation Cryptographic Identity (X3DH / Double Ratchet)")
                headerIconName: "shield-check"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        Rectangle {
                            width: 42
                            height: 42
                            radius: 10
                            color: Theme.isDark ? "#13233D" : "#DBEAFE"
                            border.color: Theme.accentPrimary
                            border.width: 1

                            SCIcon {
                                anchors.centerIn: parent
                                name: "lock"
                                size: 20
                                color: Theme.accentPrimary
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            RowLayout {
                                spacing: Theme.space8

                                Label {
                                    text: settingsRoot.localIdentity.displayName || qsTr("SecOps Workstation · macOS")
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: Theme.fontSubtitle
                                    font.bold: true
                                    color: Theme.textPrimary
                                }

                                SCBadge {
                                    text: (settingsRoot.avm && settingsRoot.avm.isIdentityVerified)
                                          ? qsTr("Identity Verified")
                                          : qsTr("Awaiting Key Attestation")
                                    type: (settingsRoot.avm && settingsRoot.avm.isIdentityVerified)
                                          ? "Verified"
                                          : "Unverified"
                                }
                            }

                            Label {
                                text: (settingsRoot.localIdentity.deviceId || "dev-local-01") + "  ·  " + (settingsRoot.localIdentity.platformInfo || "Apple M-Series Secure Enclave")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }
                        }

                        SCButton {
                            text: qsTr("Rotate Signed Prekey & Verify")
                            iconName: "shield-check"
                            variant: "Primary"
                            buttonHeight: 36
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.rotateSignedPrekey()
                                }
                                if (settingsRoot.avm) {
                                    settingsRoot.avm.setIdentityVerified(true)
                                }
                            }
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
                        rowSpacing: 6
                        columnSpacing: Theme.space16

                        Label {
                            text: qsTr("Ed25519 Identity Key:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textMuted
                        }
                        Label {
                            text: settingsRoot.localIdentity.identityKeyHex || "ED25519-PUB-9F86D081884C7D659A2FEAA0C55AD015"
                            font.family: Theme.fontFamilyMonospace
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textPrimary
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }

                        Label {
                            text: qsTr("Safety Number Fingerprint:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textMuted
                        }
                        Label {
                            text: settingsRoot.localIdentity.fingerprint || "7F8A 9B2C 1E4D 6610 9981 3042 5519 A8C1"
                            font.family: Theme.fontFamilyMonospace
                            font.pixelSize: Theme.fontMicro
                            color: Theme.accentPrimary
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }

                        Label {
                            text: qsTr("Active Signed Prekey:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textMuted
                        }
                        Label {
                            text: (settingsRoot.localIdentity.signedPrekeyId || "SPK-X25519-0014") + "  ·  " + (settingsRoot.localIdentity.prekeySignatureHex || "SIG-ED25519-4419A8B2...C901E24F")
                            font.family: Theme.fontFamilyMonospace
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }
                    }
                }
            }

            // 3. Linked Devices, Activation / Pairing & Revocation
            SCCard {
                id: linkedDevicesCard
                objectName: "linkedDevicesCard"
                Layout.fillWidth: true
                headerText: qsTr("3. Linked Devices, Pairing Activation & Revocation")
                headerIconName: "users"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true

                        Label {
                            text: qsTr("Authorized and pending devices bound to your cryptographic account:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textSecondary
                            Layout.fillWidth: true
                        }

                        SCBadge {
                            visible: settingsRoot.wvm ? (settingsRoot.wvm.pendingDeviceCount > 0) : false
                            text: qsTr("%1 Pending Pairing").arg(settingsRoot.wvm ? settingsRoot.wvm.pendingDeviceCount : 0)
                            type: "Unverified"
                        }
                    }

                    Repeater {
                        model: settingsRoot.wvm ? settingsRoot.wvm.devices : []

                        delegate: Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: devItemCol.implicitHeight + 24
                            radius: 12
                            color: Theme.backgroundPrimary
                            border.color: modelData.status === "Pending"
                                          ? Theme.statusWarning
                                          : (modelData.status === "Revoked" ? Theme.statusDanger : Theme.borderSubtle)
                            border.width: 1

                            ColumnLayout {
                                id: devItemCol
                                anchors.fill: parent
                                anchors.margins: 12
                                spacing: 8

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space8

                                    SCIcon {
                                        name: modelData.status === "Revoked"
                                              ? "shield-alert"
                                              : (modelData.status === "Pending" ? "alert-triangle" : "shield-check")
                                        size: 16
                                        color: modelData.status === "Revoked"
                                               ? Theme.statusDanger
                                               : (modelData.status === "Pending" ? Theme.statusWarning : Theme.accentPrimary)
                                    }

                                    Label {
                                        text: (modelData.displayName || "") + " (" + (modelData.deviceId || "") + ")"
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontBody
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    SCBadge {
                                        text: modelData.status || "Authorized"
                                        type: modelData.status === "Revoked"
                                              ? "Danger"
                                              : (modelData.status === "Pending" ? "Unverified" : "Verified")
                                    }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space12

                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 2

                                        Label {
                                            text: (modelData.platformInfo || "") + "  ·  " + (modelData.lastSeenText || "")
                                            font.family: Theme.fontFamilyPrimary
                                            font.pixelSize: Theme.fontCaption
                                            color: Theme.textSecondary
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }

                                        Label {
                                            text: qsTr("Fingerprint: %1  ·  Prekey: %2")
                                                  .arg(modelData.fingerprint || "")
                                                  .arg(modelData.signedPrekeyId || "")
                                            font.family: Theme.fontFamilyMonospace
                                            font.pixelSize: Theme.fontMicro
                                            color: Theme.textMuted
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }

                                    SCButton {
                                        visible: !modelData.isCurrentDevice && modelData.status !== "Authorized"
                                        text: modelData.status === "Pending" ? qsTr("Approve & Activate") : qsTr("Re-Authorize")
                                        iconName: "check"
                                        variant: "Primary"
                                        buttonHeight: 30
                                        horizontalPadding: 10
                                        onClicked: {
                                            if (settingsRoot.wvm) {
                                                settingsRoot.wvm.approveDevice(modelData.deviceId)
                                            }
                                        }
                                    }

                                    SCButton {
                                        visible: !modelData.isCurrentDevice && modelData.status !== "Revoked"
                                        text: modelData.status === "Pending" ? qsTr("Reject") : qsTr("Revoke Keys")
                                        iconName: "shield-alert"
                                        variant: "Danger"
                                        buttonHeight: 30
                                        horizontalPadding: 10
                                        onClicked: {
                                            if (settingsRoot.wvm) {
                                                settingsRoot.wvm.revokeDevice(modelData.deviceId)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        SCTextField {
                            id: newDeviceInput
                            Layout.fillWidth: true
                            inputHeight: 36
                            placeholderText: qsTr("Enter new device label to initiate X3DH pairing (e.g. Field Tablet Node-05)...")
                            onAccepted: pairDeviceBtn.clicked()
                        }

                        SCButton {
                            id: pairDeviceBtn
                            text: qsTr("Pair New Device")
                            iconName: "lock"
                            variant: "Secondary"
                            buttonHeight: 36
                            onClicked: {
                                var label = newDeviceInput.text.trim()
                                if (label.length === 0) {
                                    label = "SecOps Field Node · Hardware Token"
                                }
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.pairNewDevice(label)
                                    newDeviceInput.text = ""
                                }
                            }
                        }
                    }
                }
            }

            // 4. Security, Privacy, MFA, Disappearing Timers & Duress Policy
            SCCard {
                id: securityPrivacyCard
                objectName: "securityPrivacyCard"
                Layout.fillWidth: true
                headerText: qsTr("4. Security, Privacy, MFA, Disappearing Timers & Duress Policy")
                headerIconName: "lock"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Require TOTP / MFA Challenge on Session Login")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Persisted policy enforcing RFC 6238 6-digit TOTP step-up verification before unsealing local SQLCipher stores.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        SCButton {
                            objectName: "mfaRequiredButton"
                            text: (settingsRoot.wvm && settingsRoot.wvm.mfaRequiredOnLogin)
                                  ? qsTr("MFA Enforced")
                                  : qsTr("MFA Optional")
                            iconName: (settingsRoot.wvm && settingsRoot.wvm.mfaRequiredOnLogin) ? "shield-check" : "alert-triangle"
                            variant: (settingsRoot.wvm && settingsRoot.wvm.mfaRequiredOnLogin) ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.mfaRequiredOnLogin = !settingsRoot.wvm.mfaRequiredOnLogin
                                }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("FIDO2 / Hardware Security Key Attestation")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Binds X3DH identity key signatures to hardware enclave presence.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }
                        }

                        SCButton {
                            objectName: "hardwareKeyButton"
                            text: (settingsRoot.wvm && settingsRoot.wvm.hardwareKeyEnforced)
                                  ? qsTr("Hardware Key Bound")
                                  : qsTr("Software Enclave")
                            iconName: "lock"
                            variant: (settingsRoot.wvm && settingsRoot.wvm.hardwareKeyEnforced) ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.hardwareKeyEnforced = !settingsRoot.wvm.hardwareKeyEnforced
                                }
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Active TOTP Authenticator Seed:")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }

                            Label {
                                text: settingsRoot.wvm ? settingsRoot.wvm.totpEnrollmentSecret : "JBSWY3DPEHPK3PXP · SHA-256 (6-digit / 30s)"
                                font.family: Theme.fontFamilyMonospace
                                font.pixelSize: Theme.fontCaption
                                color: Theme.accentPrimary
                            }
                        }

                        SCButton {
                            text: qsTr("Rotate TOTP Seed")
                            variant: "Secondary"
                            buttonHeight: 32
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.regenerateTotpSecret()
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    // Preserved Read Receipts Privacy Toggle
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Send Read Receipts")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("When disabled, other participants will not see when you have read their messages.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        Switch {
                            id: readReceiptsSwitch
                            objectName: "readReceiptsSwitch"
                            checked: settingsRoot.wvm ? settingsRoot.wvm.readReceiptsEnabled : true
                            onToggled: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.readReceiptsEnabled = checked
                                }
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    // Disappearing Message Timers (Workspace Default & Active Conversation)
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Default Disappearing Message Timer")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Automatically stamps expires_at_ms on newly sent and received messages (current: %1).")
                                      .arg(settingsRoot.formatTimerLabel(settingsRoot.wvm ? settingsRoot.wvm.defaultDisappearingTtlSeconds : 0))
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        SCButton {
                            objectName: "defaultTimerOffButton"
                            text: qsTr("Off")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.defaultDisappearingTtlSeconds === 0) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setDefaultDisappearingTimer(0)
                        }

                        SCButton {
                            objectName: "defaultTimer1hButton"
                            text: qsTr("1h")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.defaultDisappearingTtlSeconds === 3600) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setDefaultDisappearingTimer(3600)
                        }

                        SCButton {
                            objectName: "defaultTimer24hButton"
                            text: qsTr("24h")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.defaultDisappearingTtlSeconds === 86400) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setDefaultDisappearingTimer(86400)
                        }

                        SCButton {
                            objectName: "defaultTimer7dButton"
                            text: qsTr("7d")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.defaultDisappearingTtlSeconds === 604800) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setDefaultDisappearingTimer(604800)
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8
                        visible: settingsRoot.wvm ? (settingsRoot.wvm.selectedConversationId !== "") : false

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Active Conversation Timer (%1)").arg(settingsRoot.wvm ? settingsRoot.wvm.selectedPeerName : "")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Per-conversation override applied locally without revealing timer policy to relays (current: %1).")
                                      .arg(settingsRoot.formatTimerLabel(settingsRoot.wvm ? settingsRoot.wvm.activeConversationDisappearingTtlSeconds : 0))
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        SCButton {
                            objectName: "convTimerOffButton"
                            text: qsTr("Off")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.activeConversationDisappearingTtlSeconds === 0) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setConversationDisappearingTimer(settingsRoot.wvm.selectedConversationId, 0)
                        }

                        SCButton {
                            objectName: "convTimer1hButton"
                            text: qsTr("1h")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.activeConversationDisappearingTtlSeconds === 3600) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setConversationDisappearingTimer(settingsRoot.wvm.selectedConversationId, 3600)
                        }

                        SCButton {
                            objectName: "convTimer24hButton"
                            text: qsTr("24h")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.activeConversationDisappearingTtlSeconds === 86400) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setConversationDisappearingTimer(settingsRoot.wvm.selectedConversationId, 86400)
                        }

                        SCButton {
                            objectName: "convTimer7dButton"
                            text: qsTr("7d")
                            variant: (settingsRoot.wvm && settingsRoot.wvm.activeConversationDisappearingTtlSeconds === 604800) ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 12
                            onClicked: if (settingsRoot.wvm) settingsRoot.wvm.setConversationDisappearingTimer(settingsRoot.wvm.selectedConversationId, 604800)
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    // Preserved Emergency Defense & Login Duress Policy Subsection (CLIENT-013)
                    Rectangle {
                        id: duressPolicyCard
                        objectName: "duressPolicyCard"
                        Layout.fillWidth: true
                        implicitHeight: duressCol.implicitHeight + (Theme.space16 * 2)
                        radius: Theme.radiusMedium
                        color: Theme.backgroundPrimary
                        border.color: Theme.borderSubtle
                        border.width: 1

                        property int selectedDuressMode: settingsRoot.avm ? settingsRoot.avm.configuredDuressPostWipeMode : 2
                        property string duressFeedbackText: ""
                        property bool duressFeedbackIsError: false

                        Connections {
                            target: settingsRoot.avm
                            enabled: settingsRoot.avm !== null
                            function onDuressPolicyChanged() {
                                if (settingsRoot.avm) {
                                    duressPolicyCard.selectedDuressMode = settingsRoot.avm.configuredDuressPostWipeMode
                                }
                            }
                        }

                        ColumnLayout {
                            id: duressCol
                            anchors.fill: parent
                            anchors.margins: Theme.space16
                            spacing: Theme.space12

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space12

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2

                                    Label {
                                        text: qsTr("Login Duress PIN / Passphrase")
                                        font.bold: true
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontBody
                                        color: Theme.textPrimary
                                    }

                                    Label {
                                        text: qsTr("Entering this credential instead of your real password at login immediately triggers an offline, zero-network forensic wipe (one-shot fuse). Minimum 6 characters (up to 1024 bytes, exact match with no trimming). Tip: choose a 12+ character password-style passphrase matching your real password's length for stronger shoulder-surfing deniability.")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        color: Theme.textSecondary
                                        wrapMode: Text.WordWrap
                                        Layout.fillWidth: true
                                    }
                                }

                                SCBadge {
                                    objectName: "duressStatusBadge"
                                    text: (settingsRoot.avm && settingsRoot.avm.hasDuressPinConfigured)
                                          ? qsTr("Duress PIN Active")
                                          : qsTr("Not Configured")
                                    type: (settingsRoot.avm && settingsRoot.avm.hasDuressPinConfigured) ? "Verified" : "Offline"
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space12

                                SCTextField {
                                    id: duressPinField
                                    objectName: "duressPinField"
                                    label: qsTr("Duress PIN / Passphrase")
                                    placeholderText: qsTr("Minimum 6 chars (12+ recommended)")
                                    isPassword: true
                                    Layout.fillWidth: true
                                    onTextEdited: duressPolicyCard.duressFeedbackText = ""
                                }

                                SCTextField {
                                    id: duressPinConfirmField
                                    objectName: "duressPinConfirmField"
                                    label: qsTr("Confirm Duress PIN / Passphrase")
                                    placeholderText: qsTr("Re-enter duress credential")
                                    isPassword: true
                                    Layout.fillWidth: true
                                    onTextEdited: duressPolicyCard.duressFeedbackText = ""
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space8

                                Label {
                                    text: qsTr("Post-Wipe Action:")
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: Theme.fontBody
                                    font.bold: true
                                    color: Theme.textPrimary
                                    Layout.fillWidth: true
                                }

                                SCButton {
                                    text: qsTr("Decoy Workspace")
                                    variant: duressPolicyCard.selectedDuressMode === 2 ? "Primary" : "Secondary"
                                    buttonHeight: 32
                                    onClicked: duressPolicyCard.selectedDuressMode = 2
                                }

                                SCButton {
                                    text: qsTr("Emergency Locked")
                                    variant: duressPolicyCard.selectedDuressMode === 0 ? "Primary" : "Secondary"
                                    buttonHeight: 32
                                    onClicked: duressPolicyCard.selectedDuressMode = 0
                                }

                                SCButton {
                                    text: qsTr("Unconfigured Reset")
                                    variant: duressPolicyCard.selectedDuressMode === 1 ? "Primary" : "Secondary"
                                    buttonHeight: 32
                                    onClicked: duressPolicyCard.selectedDuressMode = 1
                                }
                            }

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: Theme.space12

                                SCButton {
                                    objectName: "saveDuressPinButton"
                                    text: qsTr("Save Duress Policy")
                                    iconName: "shield-check"
                                    variant: "Primary"
                                    buttonHeight: 34
                                    onClicked: {
                                        if (!settingsRoot.avm) {
                                            duressPolicyCard.duressFeedbackIsError = true
                                            duressPolicyCard.duressFeedbackText = qsTr("Application controller unavailable.")
                                            return
                                        }
                                        if (duressPinField.text.length < 6) {
                                            duressPolicyCard.duressFeedbackIsError = true
                                            duressPolicyCard.duressFeedbackText = qsTr("Duress PIN / passphrase must be at least 6 characters (12+ recommended).")
                                            return
                                        }
                                        if (duressPinField.text !== duressPinConfirmField.text) {
                                            duressPolicyCard.duressFeedbackIsError = true
                                            duressPolicyCard.duressFeedbackText = qsTr("Entries do not match. Re-enter both fields identically.")
                                            return
                                        }
                                        if (settingsRoot.avm.configureDuressPin(duressPinField.text, duressPolicyCard.selectedDuressMode)) {
                                            duressPinField.text = ""
                                            duressPinConfirmField.text = ""
                                            duressPolicyCard.duressFeedbackIsError = false
                                            duressPolicyCard.duressFeedbackText = qsTr("Duress policy saved locally as a salted PBKDF2-HMAC-SHA256 verifier.")
                                        } else {
                                            duressPolicyCard.duressFeedbackIsError = true
                                            duressPolicyCard.duressFeedbackText = settingsRoot.avm.lastErrorMessage !== ""
                                                                                  ? settingsRoot.avm.lastErrorMessage
                                                                                  : qsTr("Failed to save duress policy.")
                                        }
                                    }
                                }

                                SCButton {
                                    objectName: "clearDuressPinButton"
                                    text: qsTr("Remove Duress PIN")
                                    variant: "Danger"
                                    buttonHeight: 34
                                    enabled: settingsRoot.avm ? settingsRoot.avm.hasDuressPinConfigured : false
                                    onClicked: {
                                        if (settingsRoot.avm && settingsRoot.avm.clearDuressPin()) {
                                            duressPinField.text = ""
                                            duressPinConfirmField.text = ""
                                            duressPolicyCard.duressFeedbackIsError = false
                                            duressPolicyCard.duressFeedbackText = qsTr("Duress PIN removed from local secure storage.")
                                        }
                                    }
                                }

                                Item { Layout.fillWidth: true }
                            }

                            Label {
                                visible: duressPolicyCard.duressFeedbackText !== ""
                                text: duressPolicyCard.duressFeedbackText
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: duressPolicyCard.duressFeedbackIsError ? Theme.statusDanger : Theme.statusSuccess
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            // 5. Appearance & Accessibility (Theme, Dynamic Font Scale, WCAG AAA High-Contrast)
            SCCard {
                id: appearanceCard
                objectName: "appearanceCard"
                Layout.fillWidth: true
                headerText: qsTr("5. Appearance & Accessibility")
                headerIconName: "style-guide"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        Label {
                            text: qsTr("Color Theme Mode:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "themeDarkButton"
                            text: qsTr("Dark")
                            iconName: "moon"
                            variant: Theme.themeModeInt === 1 ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(1, Theme.fontScale, Theme.highContrastEnabled)
                                } else {
                                    Theme.setThemeMode(1)
                                }
                            }
                        }

                        SCButton {
                            objectName: "themeLightButton"
                            text: qsTr("Light")
                            iconName: "sun"
                            variant: Theme.themeModeInt === 2 ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(2, Theme.fontScale, Theme.highContrastEnabled)
                                } else {
                                    Theme.setThemeMode(2)
                                }
                            }
                        }

                        SCButton {
                            objectName: "themeSystemButton"
                            text: qsTr("System Sync")
                            iconName: "monitor"
                            variant: Theme.themeModeInt === 0 ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(0, Theme.fontScale, Theme.highContrastEnabled)
                                } else {
                                    Theme.setThemeMode(0)
                                }
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Dynamic Accessibility Font Scale (%1%)").arg(Math.round(Theme.fontScale * 100))
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Rescales typography live across all panels without restart (0.85x to 1.40x).")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }
                        }

                        SCButton {
                            objectName: "fontScale85Button"
                            text: qsTr("85%")
                            variant: Math.abs(Theme.fontScale - 0.85) < 0.03 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 10
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(Theme.themeModeInt, 0.85, Theme.highContrastEnabled)
                                } else {
                                    Theme.setFontScale(0.85)
                                }
                            }
                        }

                        SCButton {
                            objectName: "fontScale100Button"
                            text: qsTr("100%")
                            variant: Math.abs(Theme.fontScale - 1.0) < 0.03 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 10
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(Theme.themeModeInt, 1.0, Theme.highContrastEnabled)
                                } else {
                                    Theme.setFontScale(1.0)
                                }
                            }
                        }

                        SCButton {
                            objectName: "fontScale120Button"
                            text: qsTr("120%")
                            variant: Math.abs(Theme.fontScale - 1.20) < 0.03 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 10
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(Theme.themeModeInt, 1.20, Theme.highContrastEnabled)
                                } else {
                                    Theme.setFontScale(1.20)
                                }
                            }
                        }

                        SCButton {
                            objectName: "fontScale140Button"
                            text: qsTr("140%")
                            variant: Math.abs(Theme.fontScale - 1.40) < 0.03 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            horizontalPadding: 10
                            onClicked: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(Theme.themeModeInt, 1.40, Theme.highContrastEnabled)
                                } else {
                                    Theme.setFontScale(1.40)
                                }
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("WCAG AAA High-Contrast Palette")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Activates >= 7:1 contrast foregrounds, high-visibility borders, and zero-restart Dark/Light AAA palettes.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        Switch {
                            id: highContrastSwitch
                            objectName: "highContrastSwitch"
                            checked: Theme.highContrastEnabled
                            onToggled: {
                                if (settingsRoot.wvm) {
                                    settingsRoot.wvm.applyAndSaveAppearance(Theme.themeModeInt, Theme.fontScale, checked)
                                } else {
                                    Theme.setHighContrastEnabled(checked)
                                }
                            }
                        }
                    }
                }
            }

            // 6. Network, Live TLS 1.3 Gateway, Proxy & Certificate Pinning
            SCCard {
                id: networkTlsCard
                objectName: "networkTlsCard"
                Layout.fillWidth: true
                headerText: qsTr("6. Network, Live TLS 1.3 Gateway, Proxy & Certificate Pinning")
                headerIconName: "shield-check"
                elevation: "Base"

                property int selectedProxyType: settingsRoot.wvm ? settingsRoot.wvm.proxyType : 0
                property string networkFeedbackText: ""
                property bool networkFeedbackIsError: false

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Gateway Transport Mode (Live TLS 1.3 vs. Local Simulator)")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Switch between live TLS 1.3 HTTPS Gateway transport and deterministic offline simulation at runtime.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        SCBadge {
                            type: (settingsRoot.wvm && settingsRoot.wvm.useLiveGatewayTransport) ? "Verified" : "Info"
                            text: (settingsRoot.wvm && settingsRoot.wvm.useLiveGatewayTransport) ? qsTr("Live TLS 1.3") : qsTr("Simulator")
                        }

                        Switch {
                            id: liveTransportSwitch
                            objectName: "liveTransportSwitch"
                            checked: settingsRoot.wvm ? settingsRoot.wvm.useLiveGatewayTransport : false
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCTextField {
                            id: gatewayHostField
                            objectName: "gatewayHostField"
                            label: qsTr("Gateway Host")
                            placeholderText: qsTr("127.0.0.1")
                            Layout.fillWidth: true
                        }

                        SCTextField {
                            id: gatewayPortField
                            objectName: "gatewayPortField"
                            label: qsTr("Gateway Port")
                            placeholderText: qsTr("8443")
                            Layout.preferredWidth: 140
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        Label {
                            text: qsTr("Endpoint Proxy Type:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "proxyTypeNoneButton"
                            text: qsTr("None")
                            variant: networkTlsCard.selectedProxyType === 0 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            onClicked: networkTlsCard.selectedProxyType = 0
                        }

                        SCButton {
                            objectName: "proxyTypeHttpButton"
                            text: qsTr("HTTP")
                            variant: networkTlsCard.selectedProxyType === 1 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            onClicked: networkTlsCard.selectedProxyType = 1
                        }

                        SCButton {
                            objectName: "proxyTypeSocks5Button"
                            text: qsTr("SOCKS5")
                            variant: networkTlsCard.selectedProxyType === 2 ? "Primary" : "Secondary"
                            buttonHeight: 30
                            onClicked: networkTlsCard.selectedProxyType = 2
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12
                        visible: networkTlsCard.selectedProxyType !== 0

                        SCTextField {
                            id: proxyHostField
                            objectName: "proxyHostField"
                            label: qsTr("Proxy Host")
                            placeholderText: qsTr("proxy.internal.local")
                            Layout.fillWidth: true
                        }

                        SCTextField {
                            id: proxyPortField
                            objectName: "proxyPortField"
                            label: qsTr("Proxy Port")
                            placeholderText: qsTr("8080")
                            Layout.preferredWidth: 140
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12
                        visible: networkTlsCard.selectedProxyType !== 0

                        SCTextField {
                            id: proxyUsernameField
                            objectName: "proxyUsernameField"
                            label: qsTr("Proxy Username (Optional)")
                            placeholderText: qsTr("proxy-user")
                            Layout.fillWidth: true
                        }

                        SCTextField {
                            id: proxyPasswordField
                            objectName: "proxyPasswordField"
                            label: qsTr("Proxy Password (Stored Only in ISecureStorage)")
                            placeholderText: (settingsRoot.wvm && settingsRoot.wvm.hasProxyPassword)
                                             ? qsTr("Saved in ISecureStorage — leave blank to keep")
                                             : qsTr("Enter new proxy password")
                            isPassword: true
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "clearProxyPasswordButton"
                            text: qsTr("Clear Password")
                            variant: "Danger"
                            buttonHeight: 36
                            Layout.alignment: Qt.AlignBottom
                            enabled: settingsRoot.wvm ? settingsRoot.wvm.hasProxyPassword : false
                            onClicked: {
                                if (!settingsRoot.wvm) return
                                var gPort = parseInt(gatewayPortField.text, 10)
                                var pPort = parseInt(proxyPortField.text, 10)
                                var ok = settingsRoot.wvm.saveNetworkAndProxyConfig(
                                    liveTransportSwitch.checked,
                                    gatewayHostField.text,
                                    isNaN(gPort) ? 8443 : gPort,
                                    networkTlsCard.selectedProxyType,
                                    proxyHostField.text,
                                    isNaN(pPort) ? 0 : pPort,
                                    proxyUsernameField.text,
                                    "",
                                    true,
                                    tlsPinnedSpkiField.text,
                                    tlsStrictPinningSwitch.checked)
                                proxyPasswordField.text = ""
                                networkTlsCard.networkFeedbackIsError = !ok
                                networkTlsCard.networkFeedbackText = ok
                                    ? qsTr("Proxy password purged from local ISecureStorage.")
                                    : qsTr("Failed to clear proxy password.")
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCTextField {
                            id: tlsPinnedSpkiField
                            objectName: "tlsPinnedSpkiField"
                            label: qsTr("Pinned Server SPKI SHA-256 Fingerprint (64-char hex, empty disables pinning)")
                            placeholderText: qsTr("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                            isMonospace: true
                            Layout.fillWidth: true
                        }

                        SCBadge {
                            objectName: "tlsPinStatusBadge"
                            Layout.alignment: Qt.AlignBottom
                            text: {
                                if (!settingsRoot.wvm || settingsRoot.wvm.tlsPinnedFingerprint === "") return qsTr("No SPKI Pin")
                                return settingsRoot.wvm.tlsPinMatches ? qsTr("SPKI Pin Verified") : qsTr("SPKI Pin Mismatch")
                            }
                            type: {
                                if (!settingsRoot.wvm || settingsRoot.wvm.tlsPinnedFingerprint === "") return "Info"
                                return settingsRoot.wvm.tlsPinMatches ? "Verified" : "Danger"
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: qsTr("Enforce Strict Fail-Closed SPKI Verification")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("Aborts TLS 1.3 handshake before Bearer token transmission when observed SPKI differs from saved pin.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        Switch {
                            id: tlsStrictPinningSwitch
                            objectName: "tlsStrictPinningSwitch"
                            checked: settingsRoot.wvm ? settingsRoot.wvm.tlsEnforceStrictPinning : true
                        }
                    }

                    Label {
                        visible: settingsRoot.wvm && settingsRoot.wvm.tlsLastInspectedInfo && settingsRoot.wvm.tlsLastInspectedInfo.spkiSha256 !== undefined
                        text: (settingsRoot.wvm && settingsRoot.wvm.tlsLastInspectedInfo && settingsRoot.wvm.tlsLastInspectedInfo.spkiSha256 !== undefined)
                              ? qsTr("Last Inspected: %1 (%2:%3) · Issuer: %4 · SPKI SHA-256: %5")
                                    .arg(settingsRoot.wvm.tlsLastInspectedInfo.subjectCn || "gateway")
                                    .arg(settingsRoot.wvm.tlsLastInspectedInfo.host || "")
                                    .arg(settingsRoot.wvm.tlsLastInspectedInfo.port || 8443)
                                    .arg(settingsRoot.wvm.tlsLastInspectedInfo.issuerCn || "")
                                    .arg(settingsRoot.wvm.tlsLastInspectedInfo.spkiSha256 || "")
                              : ""
                        font.family: Theme.fontFamilyMonospace
                        font.pixelSize: Theme.fontMicro
                        color: Theme.textSecondary
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        SCButton {
                            objectName: "inspectTlsButton"
                            text: qsTr("Inspect Gateway TLS")
                            iconName: "refresh"
                            variant: "Secondary"
                            buttonHeight: 34
                            onClicked: {
                                if (!settingsRoot.wvm) return
                                var gPort = parseInt(gatewayPortField.text, 10)
                                var info = settingsRoot.wvm.inspectGatewayTlsFingerprint(
                                    gatewayHostField.text,
                                    isNaN(gPort) ? 8443 : gPort,
                                    false)
                                networkTlsCard.networkFeedbackIsError = (info.spkiSha256 === undefined)
                                networkTlsCard.networkFeedbackText = (info.spkiSha256 !== undefined)
                                    ? qsTr("Inspected Gateway leaf SPKI SHA-256 fingerprint.")
                                    : qsTr("Failed to inspect Gateway TLS certificate.")
                            }
                        }

                        SCButton {
                            objectName: "pinObservedTlsButton"
                            text: qsTr("Inspect & Pin SPKI")
                            iconName: "shield-check"
                            variant: "Secondary"
                            buttonHeight: 34
                            onClicked: {
                                if (!settingsRoot.wvm) return
                                var gPort = parseInt(gatewayPortField.text, 10)
                                var info = settingsRoot.wvm.inspectGatewayTlsFingerprint(
                                    gatewayHostField.text,
                                    isNaN(gPort) ? 8443 : gPort,
                                    true)
                                networkTlsCard.networkFeedbackIsError = (info.spkiSha256 === undefined)
                                networkTlsCard.networkFeedbackText = (info.spkiSha256 !== undefined)
                                    ? qsTr("Observed SPKI SHA-256 fingerprint saved to encrypted settings.")
                                    : qsTr("Failed to inspect and pin Gateway TLS certificate.")
                            }
                        }

                        Item { Layout.fillWidth: true }

                        SCButton {
                            objectName: "saveNetworkConfigButton"
                            text: qsTr("Save Network & TLS Config")
                            iconName: "check"
                            variant: "Primary"
                            buttonHeight: 34
                            onClicked: {
                                if (!settingsRoot.wvm) return
                                var gPort = parseInt(gatewayPortField.text, 10)
                                var pPort = parseInt(proxyPortField.text, 10)
                                var ok = settingsRoot.wvm.saveNetworkAndProxyConfig(
                                    liveTransportSwitch.checked,
                                    gatewayHostField.text,
                                    isNaN(gPort) ? 8443 : gPort,
                                    networkTlsCard.selectedProxyType,
                                    proxyHostField.text,
                                    isNaN(pPort) ? 0 : pPort,
                                    proxyUsernameField.text,
                                    proxyPasswordField.text,
                                    false,
                                    tlsPinnedSpkiField.text,
                                    tlsStrictPinningSwitch.checked)
                                if (ok) {
                                    proxyPasswordField.text = ""
                                }
                                networkTlsCard.networkFeedbackIsError = !ok
                                networkTlsCard.networkFeedbackText = ok
                                    ? qsTr("Network, proxy & TLS pinning settings applied cleanly.")
                                    : qsTr("Invalid network/proxy/SPKI input — verify host, ports, or 64-char hex pin.")
                            }
                        }
                    }

                    Label {
                        visible: networkTlsCard.networkFeedbackText !== ""
                        text: networkTlsCard.networkFeedbackText
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontCaption
                        color: networkTlsCard.networkFeedbackIsError ? Theme.statusDanger : Theme.statusSuccess
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            // 7. Cryptographic Identity Recovery Phrase (Local / Offline BIP-39)
            SCCard {
                id: recoveryPhraseCard
                objectName: "recoveryPhraseCard"
                Layout.fillWidth: true
                headerText: qsTr("7. Cryptographic Identity Recovery Phrase (Local / Offline BIP-39)")
                headerIconName: "key"
                elevation: "Base"

                property bool use24Words: false
                property string verifyFeedbackText: ""
                property bool verifyFeedbackIsError: false

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 4

                            Label {
                                text: qsTr("Endpoint-Only Cryptographic Recovery Phrase (Separate from Auth MFA Backup Codes)")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }

                            Label {
                                text: qsTr("Protects your local endpoint identity and E2EE key recovery seed offline. Never transmitted to servers (0 network calls); server login Auth MFA backup codes remain independent.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textSecondary
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }

                        SCBadge {
                            objectName: "recoveryStatusBadge"
                            text: settingsRoot.wvm ? settingsRoot.wvm.recoveryPhraseStatusText : qsTr("Not Backed Up")
                            type: (settingsRoot.wvm && settingsRoot.wvm.recoveryPhraseVerified) ? "Verified" : "Unverified"
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: warningBannerRow.implicitHeight + Theme.space16
                        radius: Theme.radiusSmall
                        color: Theme.isDark ? "#2C2011" : "#FFFBEB"
                        border.color: Theme.statusWarning
                        border.width: 1

                        RowLayout {
                            id: warningBannerRow
                            anchors.fill: parent
                            anchors.margins: Theme.space8
                            spacing: Theme.space8

                            SCIcon {
                                name: "info"
                                size: 16
                                color: Theme.statusWarning
                            }

                            Label {
                                text: qsTr("Never transmitted to servers — write down all words offline and complete the 3-word verification spot-check. Only a salted local PBKDF2-HMAC-SHA256 verifier digest is retained in ISecureStorage.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textPrimary
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        Label {
                            text: qsTr("Phrase Length:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "recoveryLength12Button"
                            text: qsTr("12 Words (Default)")
                            variant: !recoveryPhraseCard.use24Words ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: recoveryPhraseCard.use24Words = false
                        }

                        SCButton {
                            objectName: "recoveryLength24Button"
                            text: qsTr("24 Words (Extended)")
                            variant: recoveryPhraseCard.use24Words ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: recoveryPhraseCard.use24Words = true
                        }

                        SCButton {
                            objectName: "generateRecoveryPhraseButton"
                            text: qsTr("Generate Recovery Phrase")
                            iconName: "key"
                            variant: "Primary"
                            buttonHeight: 34
                            onClicked: {
                                if (!settingsRoot.wvm) return
                                var payload = settingsRoot.wvm.generateRecoveryPhraseWords(recoveryPhraseCard.use24Words)
                                if (payload && payload.words && payload.words.length > 0) {
                                    recoveryPhraseModal.openWithPayload(payload)
                                }
                            }
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        height: 1
                        color: Theme.borderSubtle
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        SCTextField {
                            id: verifyExistingRecoveryField
                            objectName: "verifyExistingRecoveryField"
                            label: qsTr("Verify Saved Recovery Phrase Offline")
                            placeholderText: qsTr("Enter 12 or 24 space-separated BIP-39 words...")
                            isPassword: true
                            Layout.fillWidth: true
                            onTextEdited: recoveryPhraseCard.verifyFeedbackText = ""
                        }

                        SCButton {
                            objectName: "verifyExistingRecoveryButton"
                            text: qsTr("Verify Phrase")
                            iconName: "shield-check"
                            variant: "Secondary"
                            buttonHeight: 36
                            Layout.alignment: Qt.AlignBottom
                            onClicked: {
                                if (!settingsRoot.wvm) return
                                var ok = settingsRoot.wvm.verifyRecoveryPhraseInput(verifyExistingRecoveryField.text)
                                recoveryPhraseCard.verifyFeedbackIsError = !ok
                                recoveryPhraseCard.verifyFeedbackText = ok
                                    ? qsTr("BIP-39 phrase matches your local cryptographic verifier.")
                                    : qsTr("Phrase did not match the saved local verifier.")
                                verifyExistingRecoveryField.text = ""
                            }
                        }
                    }

                    Label {
                        visible: recoveryPhraseCard.verifyFeedbackText !== ""
                        text: recoveryPhraseCard.verifyFeedbackText
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontCaption
                        color: recoveryPhraseCard.verifyFeedbackIsError ? Theme.statusDanger : Theme.statusSuccess
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }
            }

            Item { width: 1; height: Theme.space16 }
        }
    }

    // Modal Overlay: Endpoint-Only BIP-39 Recovery Phrase Generator & 3-Word Spot-Check
    Item {
        id: recoveryPhraseModal
        objectName: "recoveryPhraseModal"
        anchors.fill: parent
        visible: isOpen
        z: 999

        property bool isOpen: false
        property bool showWords: false
        property var generatedWords: []
        property var challengeIndices: []
        property var challengePositions: []
        property string modalErrorText: ""

        function openWithPayload(payload) {
            generatedWords = payload.words || []
            challengeIndices = payload.challengeIndices || []
            challengePositions = payload.challengePositions || []
            showWords = false
            modalErrorText = ""
            recoveryChallengeInput0.text = ""
            recoveryChallengeInput1.text = ""
            recoveryChallengeInput2.text = ""
            isOpen = true
        }

        function closeModal() {
            isOpen = false
            showWords = false
            generatedWords = []
            challengeIndices = []
            challengePositions = []
            modalErrorText = ""
            recoveryChallengeInput0.text = ""
            recoveryChallengeInput1.text = ""
            recoveryChallengeInput2.text = ""
            if (settingsRoot.wvm) {
                settingsRoot.wvm.clearPendingRecoveryPhrase()
            }
        }

        function challengePosLabel(slotIndex) {
            if (challengePositions && slotIndex < challengePositions.length) {
                return qsTr("Word #%1").arg(challengePositions[slotIndex])
            }
            return qsTr("Word #%1").arg(slotIndex + 1)
        }

        Shortcut {
            sequence: "Esc"
            enabled: recoveryPhraseModal.isOpen
            onActivated: recoveryPhraseModal.closeModal()
        }

        Rectangle {
            anchors.fill: parent
            color: Theme.isDark ? "rgba(0, 0, 0, 0.72)" : "rgba(15, 23, 42, 0.48)"

            MouseArea {
                anchors.fill: parent
                hoverEnabled: true
                preventStealing: true
            }
        }

        Rectangle {
            width: Math.min(620, parent.width - Theme.space32)
            implicitHeight: modalLayout.implicitHeight + (Theme.space24 * 2)
            anchors.centerIn: parent
            radius: Theme.radiusLarge
            color: Theme.backgroundElevated
            border.color: Theme.borderSubtle
            border.width: 1

            ColumnLayout {
                id: modalLayout
                anchors.fill: parent
                anchors.margins: Theme.space24
                spacing: Theme.space12

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    SCIcon {
                        name: "key"
                        size: 20
                        color: Theme.accentPrimary
                    }

                    Label {
                        text: qsTr("Write Down Your Cryptographic Recovery Phrase (%1 Words)").arg(recoveryPhraseModal.generatedWords.length)
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontTitle
                        font.bold: true
                        color: Theme.textPrimary
                        Layout.fillWidth: true
                    }

                    SCButton {
                        objectName: "toggleRecoveryWordsVisibilityButton"
                        text: recoveryPhraseModal.showWords ? qsTr("Hide Words") : qsTr("Show Words")
                        iconName: recoveryPhraseModal.showWords ? "eye-off" : "eye"
                        variant: "Secondary"
                        buttonHeight: 30
                        onClicked: recoveryPhraseModal.showWords = !recoveryPhraseModal.showWords
                    }
                }

                Label {
                    text: qsTr("Never transmitted to servers — keep this offline. Complete the 3-word spot-check below to verify your written backup.")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    color: Theme.textSecondary
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                GridLayout {
                    id: recoveryWordsGrid
                    objectName: "recoveryWordsGrid"
                    Layout.fillWidth: true
                    columns: 3
                    rowSpacing: 6
                    columnSpacing: 8

                    Repeater {
                        model: recoveryPhraseModal.generatedWords.length

                        delegate: Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: 32
                            radius: Theme.radiusSmall
                            color: Theme.backgroundSecondary
                            border.color: Theme.borderSubtle
                            border.width: 1

                            Label {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.space8
                                anchors.rightMargin: Theme.space8
                                verticalAlignment: Text.AlignVCenter
                                font.family: Theme.fontFamilyMonospace
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textPrimary
                                elide: Text.ElideRight
                                text: {
                                    var wordVal = (index < recoveryPhraseModal.generatedWords.length)
                                                  ? recoveryPhraseModal.generatedWords[index]
                                                  : ""
                                    return (index + 1) + ". " + (recoveryPhraseModal.showWords ? wordVal : "••••••")
                                }
                            }
                        }
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: Theme.borderSubtle
                }

                Label {
                    text: qsTr("3-Word Confirmation Spot-Check")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontBody
                    font.bold: true
                    color: Theme.textPrimary
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space8

                    SCTextField {
                        id: recoveryChallengeInput0
                        objectName: "recoveryChallengeInput0"
                        label: recoveryPhraseModal.challengePosLabel(0)
                        placeholderText: qsTr("Enter word")
                        Layout.fillWidth: true
                        onTextEdited: recoveryPhraseModal.modalErrorText = ""
                    }

                    SCTextField {
                        id: recoveryChallengeInput1
                        objectName: "recoveryChallengeInput1"
                        label: recoveryPhraseModal.challengePosLabel(1)
                        placeholderText: qsTr("Enter word")
                        Layout.fillWidth: true
                        onTextEdited: recoveryPhraseModal.modalErrorText = ""
                    }

                    SCTextField {
                        id: recoveryChallengeInput2
                        objectName: "recoveryChallengeInput2"
                        label: recoveryPhraseModal.challengePosLabel(2)
                        placeholderText: qsTr("Enter word")
                        Layout.fillWidth: true
                        onTextEdited: recoveryPhraseModal.modalErrorText = ""
                    }
                }

                Label {
                    visible: recoveryPhraseModal.modalErrorText !== ""
                    text: recoveryPhraseModal.modalErrorText
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    color: Theme.statusDanger
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space12

                    Item { Layout.fillWidth: true }

                    SCButton {
                        objectName: "cancelRecoveryModalButton"
                        text: qsTr("Cancel")
                        variant: "Secondary"
                        buttonHeight: 34
                        onClicked: recoveryPhraseModal.closeModal()
                    }

                    SCButton {
                        objectName: "confirmRecoveryChallengeButton"
                        text: qsTr("Confirm & Save Local Verifier")
                        iconName: "shield-check"
                        variant: "Primary"
                        buttonHeight: 34
                        onClicked: {
                            if (!settingsRoot.wvm) return
                            var answers = [
                                recoveryChallengeInput0.text,
                                recoveryChallengeInput1.text,
                                recoveryChallengeInput2.text
                            ]
                            var ok = settingsRoot.wvm.confirmRecoveryPhraseChallenge(
                                recoveryPhraseModal.challengeIndices,
                                answers)
                            if (ok) {
                                recoveryPhraseModal.closeModal()
                            } else {
                                recoveryPhraseModal.modalErrorText = qsTr("Spot-check words did not match. Verify each word position and try again.")
                            }
                        }
                    }
                }
            }
        }
    }
}
