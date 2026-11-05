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

    ScrollView {
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth

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
                        text: qsTr("Security Workstation Settings & Device Trust Center")
                        font.pixelSize: Theme.fontTitle
                        font.bold: true
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                    }

                    Label {
                        text: qsTr("Manage local Ed25519/X25519 cryptographic identity, linked device authorizations, MFA hardware policies, and theme preferences.")
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

            // 1. Local Workstation Cryptographic Identity & Signed Prekey Rotation
            SCCard {
                Layout.fillWidth: true
                headerText: qsTr("1. Local Workstation Cryptographic Identity (X3DH / Double Ratchet)")
                headerIconName: "shield-check"
                elevation: "Elevated"

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

            // 2. Linked Devices, Activation / Pairing & Revocation
            SCCard {
                Layout.fillWidth: true
                headerText: qsTr("2. Linked Devices, Pairing Activation & Revocation")
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

                    // Device List Repeater
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
                                            font.pixelSize: 10
                                            color: Theme.textMuted
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }

                                    // Activate / Approve Button (for Pending or Revoked devices)
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

                                    // Revoke Device Button (for non-current Authorized or Pending devices)
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

                    // Pair New Device Row
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

            // 3. Multi-Factor Authentication (MFA) & Hardware Key Policy
            SCCard {
                Layout.fillWidth: true
                headerText: qsTr("3. Multi-Factor Authentication (MFA) & Hardware Token Policy")
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
                                text: qsTr("Enforces RFC 6238 6-digit TOTP step-up verification before unsealing local SQLCipher stores.")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }
                        }

                        SCButton {
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
                }
            }

            // 4. Appearance, Theme & Transport Security
            SCCard {
                Layout.fillWidth: true
                headerText: qsTr("4. Appearance & Transport Security")
                headerIconName: "style-guide"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        Label {
                            text: qsTr("Color Theme Mode:")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontBody
                            font.bold: true
                            color: Theme.textPrimary
                            Layout.fillWidth: true
                        }

                        SCButton {
                            text: qsTr("Dark")
                            iconName: "moon"
                            variant: Theme.themeModeInt === 1 ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: Theme.setThemeMode(1)
                        }

                        SCButton {
                            text: qsTr("Light")
                            iconName: "sun"
                            variant: Theme.themeModeInt === 2 ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: Theme.setThemeMode(2)
                        }

                        SCButton {
                            text: qsTr("System Sync")
                            iconName: "monitor"
                            variant: Theme.themeModeInt === 0 ? "Primary" : "Secondary"
                            buttonHeight: 32
                            onClicked: Theme.setThemeMode(0)
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
                                text: qsTr("Gateway Transport Encryption")
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                color: Theme.textPrimary
                            }

                            Label {
                                text: qsTr("TLS 1.3 mTLS with strict SPKI certificate pinning & zero-knowledge relay framing")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                            }
                        }

                        SCBadge {
                            type: "Verified"
                            text: qsTr("mTLS Active")
                        }
                    }
                }
            }

            Item { width: 1; height: Theme.space16 }
        }
    }
}
