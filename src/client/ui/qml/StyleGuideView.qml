import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

ScrollView {
    id: styleGuideRoot
    contentWidth: contentLayout.width
    contentHeight: contentLayout.height
    clip: true

    ColumnLayout {
        id: contentLayout
        width: 860
        spacing: Theme.space24

        // Top Header & Introduction
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.space16

            ColumnLayout {
                spacing: Theme.space4
                Layout.fillWidth: true

                Label {
                    text: qsTr("Design System & Style Guide Catalog")
                    font.pixelSize: Theme.fontDisplay
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }

                Label {
                    text: qsTr("Live interactive component sandbox and semantic token inspector.")
                    font.pixelSize: Theme.fontBody
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textSecondary
                }
            }

            SCButton {
                text: Theme.isDark ? qsTr("Switch to Light Mode") : qsTr("Switch to Dark Mode")
                iconName: Theme.isDark ? "sun" : "moon"
                variant: "Secondary"
                onClicked: Theme.toggleTheme()
            }
        }

        // Section 1: Color Tokens & Theme Palette
        SCCard {
            Layout.fillWidth: true
            headerTitle: qsTr("1. Semantic Palette Tokens")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space12

                Label {
                    text: qsTr("Current Active Theme: %1").arg(Theme.isDark ? qsTr("Dark Theme") : qsTr("Light Theme"))
                    font.pixelSize: Theme.fontCaption
                    font.bold: true
                    color: Theme.accentPrimary
                }

                Flow {
                    width: parent.width
                    spacing: Theme.space12

                    // Helper component for color token chip
                    Component {
                        id: tokenChip
                        Rectangle {
                            property string tokenName: ""
                            property color tokenColor: "transparent"
                            property string hexValue: ""

                            width: 170
                            height: 60
                            radius: Theme.radiusMedium
                            color: Theme.backgroundSecondary
                            border.color: Theme.borderSubtle
                            border.width: 1

                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: Theme.space8
                                spacing: Theme.space8

                                Rectangle {
                                    width: 32
                                    height: 32
                                    radius: Theme.radiusSmall
                                    color: tokenColor
                                    border.color: Theme.borderSubtle
                                    border.width: 1
                                }

                                ColumnLayout {
                                    spacing: 2
                                    Layout.fillWidth: true

                                    Label {
                                        text: tokenName
                                        font.pixelSize: Theme.fontMicro
                                        font.bold: true
                                        font.family: Theme.fontFamilyPrimary
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    Label {
                                        text: hexValue
                                        font.pixelSize: Theme.fontMicro
                                        font.family: Theme.fontFamilyMonospace
                                        color: Theme.textMuted
                                    }
                                }
                            }
                        }
                    }

                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "bgPrimary"
                            item.tokenColor = Theme.backgroundPrimary
                            item.hexValue = Theme.backgroundPrimary.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "bgSecondary"
                            item.tokenColor = Theme.backgroundSecondary
                            item.hexValue = Theme.backgroundSecondary.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "bgElevated"
                            item.tokenColor = Theme.backgroundElevated
                            item.hexValue = Theme.backgroundElevated.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "accentPrimary"
                            item.tokenColor = Theme.accentPrimary
                            item.hexValue = Theme.accentPrimary.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "accentSecondary"
                            item.tokenColor = Theme.accentSecondary
                            item.hexValue = Theme.accentSecondary.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "textPrimary"
                            item.tokenColor = Theme.textPrimary
                            item.hexValue = Theme.textPrimary.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "borderSubtle"
                            item.tokenColor = Theme.borderSubtle
                            item.hexValue = Theme.borderSubtle.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "borderFocus"
                            item.tokenColor = Theme.borderFocus
                            item.hexValue = Theme.borderFocus.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "statusSuccess"
                            item.tokenColor = Theme.statusSuccess
                            item.hexValue = Theme.statusSuccess.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "statusWarning"
                            item.tokenColor = Theme.statusWarning
                            item.hexValue = Theme.statusWarning.toString()
                        }
                    }
                    Loader {
                        sourceComponent: tokenChip
                        onLoaded: {
                            item.tokenName = "statusDanger"
                            item.tokenColor = Theme.statusDanger
                            item.hexValue = Theme.statusDanger.toString()
                        }
                    }
                }
            }
        }

        // Section 2: Typography Hierarchy
        SCCard {
            Layout.fillWidth: true
            headerTitle: qsTr("2. Typography Scale")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space8

                Label {
                    text: qsTr("Display (28px Bold) — The quick brown fox jumps over the lazy dog")
                    font.pixelSize: Theme.fontDisplay
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }

                Label {
                    text: qsTr("Title (20px Bold) — Cryptographic Identity & Zero-Trust Messaging")
                    font.pixelSize: Theme.fontTitle
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }

                Label {
                    text: qsTr("Header (16px SemiBold) — Double Ratchet Encryption Session Active")
                    font.pixelSize: Theme.fontHeader
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                }

                Label {
                    text: qsTr("Body (14px Regular) — Standard communicative copy for conversation threads, system notifications, and metadata.")
                    font.pixelSize: Theme.fontBody
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textSecondary
                }

                Label {
                    text: qsTr("Caption (12px Regular) — Secondary timestamps, protocol state summaries, and fingerprint indicators.")
                    font.pixelSize: Theme.fontCaption
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textMuted
                }

                Label {
                    text: qsTr("Monospace (13px) — SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
                    font.pixelSize: 13
                    font.family: Theme.fontFamilyMonospace
                    color: Theme.accentPrimary
                }
            }
        }

        // Section 3: Interactive Buttons (SCButton & SCIconButton)
        SCCard {
            Layout.fillWidth: true
            headerTitle: qsTr("3. Interactive Buttons (SCButton & SCIconButton)")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space16

                Label {
                    text: qsTr("Standard Variants")
                    font.pixelSize: Theme.fontHeader
                    font.bold: true
                    color: Theme.textPrimary
                }

                RowLayout {
                    spacing: Theme.space12

                    SCButton {
                        text: qsTr("Primary Action")
                        variant: "Primary"
                    }

                    SCButton {
                        text: qsTr("Secondary Action")
                        variant: "Secondary"
                    }

                    SCButton {
                        text: qsTr("Ghost Button")
                        variant: "Ghost"
                    }

                    SCButton {
                        text: qsTr("Danger Action")
                        variant: "Danger"
                    }
                }

                Label {
                    text: qsTr("States: Busy Spinner & Disabled")
                    font.pixelSize: Theme.fontHeader
                    font.bold: true
                    color: Theme.textPrimary
                }

                RowLayout {
                    spacing: Theme.space12

                    SCButton {
                        text: qsTr("Synchronizing...")
                        variant: "Primary"
                        busy: true
                    }

                    SCButton {
                        text: qsTr("Disabled Button")
                        variant: "Secondary"
                        enabled: false
                    }

                    SCIconButton {
                        iconName: "bell"
                        tooltipText: qsTr("Notifications")
                        badgeCount: 3
                    }

                    SCIconButton {
                        iconName: "lock"
                        tooltipText: qsTr("Security Settings")
                    }

                    SCIconButton {
                        iconName: "search"
                        tooltipText: qsTr("Search Contacts")
                    }
                }
            }
        }

        // Section 4: Form Input Controls (SCTextField)
        SCCard {
            Layout.fillWidth: true
            headerTitle: qsTr("4. Atomic Text Inputs (SCTextField)")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space16

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space16

                    SCTextField {
                        Layout.fillWidth: true
                        label: qsTr("Username or Handle")
                        placeholderText: qsTr("e.g. alice@securecloud.internal")
                        text: "alice.cooper"
                    }

                    SCTextField {
                        Layout.fillWidth: true
                        label: qsTr("Passphrase")
                        placeholderText: qsTr("Enter cryptographic passphrase")
                        isPassword: true
                        text: "SuperSecretPassphrase123!"
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.space16

                    SCTextField {
                        Layout.fillWidth: true
                        label: qsTr("Invalid Input with Error State")
                        placeholderText: qsTr("Input requiring validation")
                        text: "malformed-gateway-uri"
                        isError: true
                        errorMessage: qsTr("Invalid gateway URI format: must start with https:// or wss://")
                    }

                    SCTextField {
                        Layout.fillWidth: true
                        label: qsTr("Monospace Key / Fingerprint Input")
                        placeholderText: qsTr("Public key hash")
                        text: "SC-ED25519-7F8A-9B2C-1E4D"
                        isMonospace: true
                    }
                }
            }
        }

        // Section 5: Structural & Identity Primitives (Badges, Avatars, Cards)
        SCCard {
            Layout.fillWidth: true
            headerTitle: qsTr("5. Badges & Identity Avatars")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space16

                Label {
                    text: qsTr("Status & Verification Badges")
                    font.pixelSize: Theme.fontHeader
                    font.bold: true
                    color: Theme.textPrimary
                }

                RowLayout {
                    spacing: Theme.space12

                    SCBadge {
                        text: qsTr("Verified Identity")
                        type: "Verified"
                    }

                    SCBadge {
                        text: qsTr("Unverified Contact")
                        type: "Unverified"
                    }

                    SCBadge {
                        text: qsTr("Online")
                        type: "Online"
                        hasDot: true
                    }

                    SCBadge {
                        text: qsTr("Offline")
                        type: "Offline"
                        hasDot: true
                    }

                    SCBadge {
                        text: qsTr("Threat Detected")
                        type: "Danger"
                    }

                    SCBadge {
                        text: qsTr("Double Ratchet v2")
                        type: "Info"
                    }
                }

                Label {
                    text: qsTr("Cryptographic Avatars (Deterministic Hashing & Status)")
                    font.pixelSize: Theme.fontHeader
                    font.bold: true
                    color: Theme.textPrimary
                }

                RowLayout {
                    spacing: Theme.space24

                    ColumnLayout {
                        spacing: Theme.space4
                        SCAvatar {
                            userId: "alice@securecloud.internal"
                            displayName: "Alice Cooper"
                            size: 48
                            presence: "Online"
                        }
                        Label {
                            text: "Alice (Online)"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                        }
                    }

                    ColumnLayout {
                        spacing: Theme.space4
                        SCAvatar {
                            userId: "bob.ross@securecloud.org"
                            displayName: "Bob Ross"
                            size: 48
                            presence: "Busy"
                        }
                        Label {
                            text: "Bob (Busy)"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                        }
                    }

                    ColumnLayout {
                        spacing: Theme.space4
                        SCAvatar {
                            userId: "charlie.security@securecloud.dev"
                            displayName: "Charlie"
                            size: 48
                            presence: "Offline"
                        }
                        Label {
                            text: "Charlie (Offline)"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                        }
                    }

                    ColumnLayout {
                        spacing: Theme.space4
                        SCAvatar {
                            userId: "system.audit"
                            displayName: "System Admin"
                            size: 48
                        }
                        Label {
                            text: "Admin (No presence)"
                            font.pixelSize: Theme.fontMicro
                            color: Theme.textSecondary
                        }
                    }
                }
            }
        }

        // Section 6: Modal Dialogs Demo
        SCCard {
            Layout.fillWidth: true
            headerTitle: qsTr("6. Modal Confirmation Dialogs")

            ColumnLayout {
                width: parent.width
                spacing: Theme.space12

                Label {
                    text: qsTr("Click to preview accessible modal dialogs with event shielding:")
                    font.pixelSize: Theme.fontBody
                    color: Theme.textSecondary
                }

                RowLayout {
                    spacing: Theme.space12

                    SCButton {
                        text: qsTr("Open Standard Dialog")
                        variant: "Secondary"
                        onClicked: standardDemoDialog.isOpen = true
                    }

                    SCButton {
                        text: qsTr("Open Destructive Danger Dialog")
                        variant: "Danger"
                        onClicked: dangerDemoDialog.isOpen = true
                    }
                }
            }
        }

        Item {
            height: Theme.space32
        }
    }

    // Modal Test Dialogs
    SCDialog {
        id: standardDemoDialog
        title: qsTr("Regenerate Prekey Bundle?")
        message: qsTr("This will publish 100 new one-time cryptographic prekeys to the SecureCloud Gateway. Existing conversation ratchets will continue uninterrupted.")
        confirmText: qsTr("Publish Prekeys")
        cancelText: qsTr("Dismiss")
        onConfirmed: console.log("[StyleGuide] Standard dialog confirmed")
    }

    SCDialog {
        id: dangerDemoDialog
        title: qsTr("Purge Device Identity?")
        message: qsTr("Warning: This will permanently delete your identity keys and ratchets on this device. You will be unable to decrypt any past or inbound messages until re-enrolled.")
        confirmText: qsTr("Purge Identity Keys")
        cancelText: qsTr("Cancel")
        isDanger: true
        onConfirmed: console.log("[StyleGuide] Danger dialog confirmed")
    }
}
