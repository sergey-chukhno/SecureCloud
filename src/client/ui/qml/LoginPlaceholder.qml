import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: loginRoot
    color: Theme.backgroundPrimary

    readonly property var vm: typeof appViewModel !== "undefined" ? appViewModel : null
    readonly property string errorText: vm ? vm.lastErrorMessage : ""
    readonly property string errorCategory: vm ? vm.lastErrorCategory : ""
    readonly property bool isBusy: vm ? vm.isAuthenticating : false
    readonly property bool isMfaStep:
        typeof navigationController !== "undefined" && navigationController !== null
        ? navigationController.currentViewName === "MfaVerification"
        : false
    property bool submittedAttempt: false

    Component.onCompleted: {
        if (vm) vm.clearError()
        if (loginRoot.isMfaStep) {
            mfaCodeField.forceActiveFocus()
        } else {
            usernameField.forceActiveFocus()
        }
    }

    onIsMfaStepChanged: {
        loginRoot.submittedAttempt = false
        if (loginRoot.isMfaStep) {
            mfaCodeField.text = ""
            mfaCodeField.forceActiveFocus()
        } else {
            usernameField.forceActiveFocus()
        }
    }

    // Elevated Authentication Card
    Rectangle {
        id: authCard
        width: 420
        implicitHeight: cardColumn.implicitHeight + (Theme.space32 * 2)
        anchors.centerIn: parent
        radius: Theme.radiusLarge
        color: Theme.backgroundElevated
        border.color: Theme.borderSubtle
        border.width: 1

        ColumnLayout {
            id: cardColumn
            anchors.fill: parent
            anchors.margins: Theme.space32
            spacing: Theme.space16

            // Top Security Emblem
            Rectangle {
                width: 48
                height: 48
                radius: Theme.radiusMedium
                color: Theme.isDark ? "#13233D" : "#DBEAFE"
                border.color: Theme.accentPrimary
                border.width: 1
                Layout.alignment: Qt.AlignHCenter

                SCIcon {
                    anchors.centerIn: parent
                    name: loginRoot.isMfaStep ? "key" : "lock"
                    size: 22
                    color: Theme.accentPrimary
                }
            }

            // Title & Subtitle Hierarchy
            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.space4

                Label {
                    text: loginRoot.isMfaStep
                          ? qsTr("Two-Factor Verification")
                          : qsTr("Sign in to SecureCloud")
                    font.pixelSize: Theme.fontHeadline
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                    horizontalAlignment: Text.AlignHCenter
                    Layout.fillWidth: true
                }

                Label {
                    text: loginRoot.isMfaStep
                          ? qsTr("Enter the 6-digit verification code from your hardware security token or authenticator.")
                          : qsTr("Authenticate with your workstation credentials to establish a secure session.")
                    font.pixelSize: Theme.fontBody
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textSecondary
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
                color: Theme.borderSubtle
            }

            // Structured Error / Network / Auth Failure Alert Banner
            Rectangle {
                visible: loginRoot.errorText !== ""
                Layout.fillWidth: true
                implicitHeight: errorBannerRow.implicitHeight + (Theme.space12 * 2)
                radius: Theme.radiusMedium
                color: Theme.isDark ? "#2D1416" : "#FEF2F2"
                border.color: Theme.statusDanger
                border.width: 1

                RowLayout {
                    id: errorBannerRow
                    anchors.fill: parent
                    anchors.margins: Theme.space12
                    spacing: Theme.space12

                    SCIcon {
                        name: "alert-triangle"
                        size: 18
                        color: Theme.statusDanger
                        Layout.alignment: Qt.AlignTop
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2

                        Label {
                            text: {
                                if (loginRoot.errorCategory === "Network") {
                                    return qsTr("Gateway Connection Failure")
                                }
                                if (loginRoot.errorCategory === "Authentication") {
                                    return qsTr("Authentication Failed")
                                }
                                if (loginRoot.errorCategory === "Validation") {
                                    return qsTr("Invalid Credentials")
                                }
                                return qsTr("Authentication Error")
                            }
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            font.bold: true
                            color: Theme.statusDanger
                            Layout.fillWidth: true
                        }

                        Label {
                            text: loginRoot.errorText
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textPrimary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }
                }
            }

            // Primary Credentials Form (Unauthenticated Step)
            ColumnLayout {
                visible: !loginRoot.isMfaStep
                Layout.fillWidth: true
                spacing: Theme.space16

                SCTextField {
                    id: usernameField
                    label: qsTr("Username or Identity Handle")
                    placeholderText: qsTr("username@organization.org")
                    leadingIconName: "workspace"
                    enabled: !loginRoot.isBusy
                    Layout.fillWidth: true
                    errorMessage: ((loginRoot.submittedAttempt || loginRoot.errorCategory === "Validation") && usernameField.text.trim() === "")
                                  ? qsTr("Enter your username or identity handle")
                                  : ""
                    KeyNavigation.tab: passwordField
                    onTextEdited: {
                        if (loginRoot.vm && loginRoot.errorText !== "") {
                            loginRoot.vm.clearError()
                        }
                    }
                    onAccepted: passwordField.forceActiveFocus()
                }

                SCTextField {
                    id: passwordField
                    label: qsTr("Password")
                    placeholderText: qsTr("Enter your password")
                    leadingIconName: "lock"
                    isPassword: true
                    enabled: !loginRoot.isBusy
                    Layout.fillWidth: true
                    errorMessage: ((loginRoot.submittedAttempt || loginRoot.errorCategory === "Validation") && passwordField.text === "")
                                  ? qsTr("Enter your password")
                                  : ""
                    KeyNavigation.tab: loginButton
                    KeyNavigation.backtab: usernameField
                    onTextEdited: {
                        if (loginRoot.vm && loginRoot.errorText !== "") {
                            loginRoot.vm.clearError()
                        }
                    }
                    onAccepted: loginButton.clicked()
                }

                SCButton {
                    id: loginButton
                    text: qsTr("Sign In")
                    iconName: "shield-check"
                    variant: "Primary"
                    buttonHeight: 42
                    fullWidth: true
                    busy: loginRoot.isBusy
                    KeyNavigation.tab: mfaChallengeButton
                    KeyNavigation.backtab: passwordField
                    onClicked: {
                        loginRoot.submittedAttempt = true
                        if (loginRoot.vm) {
                            loginRoot.vm.requestLogin(usernameField.text, passwordField.text)
                        }
                    }
                }

                SCButton {
                    id: mfaChallengeButton
                    text: qsTr("Sign In with Hardware / MFA Token")
                    iconName: "key"
                    variant: "Secondary"
                    buttonHeight: 36
                    fullWidth: true
                    enabled: !loginRoot.isBusy
                    KeyNavigation.tab: usernameField
                    KeyNavigation.backtab: loginButton
                    onClicked: {
                        loginRoot.submittedAttempt = true
                        if (loginRoot.vm) {
                            loginRoot.vm.beginMfaChallenge(usernameField.text, passwordField.text)
                        }
                    }
                }
            }

            // Multi-Factor Authentication Challenge Form (MfaVerification Step)
            ColumnLayout {
                visible: loginRoot.isMfaStep
                Layout.fillWidth: true
                spacing: Theme.space16

                SCTextField {
                    id: mfaCodeField
                    label: qsTr("6-Digit Verification Code")
                    placeholderText: qsTr("000000")
                    leadingIconName: "key"
                    isMonospace: true
                    enabled: !loginRoot.isBusy
                    Layout.fillWidth: true
                    errorMessage: (loginRoot.submittedAttempt && mfaCodeField.text.trim().length !== 6)
                                  ? qsTr("Enter a 6-digit numeric verification code")
                                  : ""
                    KeyNavigation.tab: verifyMfaButton
                    onTextEdited: {
                        if (loginRoot.vm && loginRoot.errorText !== "") {
                            loginRoot.vm.clearError()
                        }
                    }
                    onAccepted: verifyMfaButton.clicked()
                }

                SCButton {
                    id: verifyMfaButton
                    text: qsTr("Verify & Sign In")
                    iconName: "check"
                    variant: "Primary"
                    buttonHeight: 42
                    fullWidth: true
                    busy: loginRoot.isBusy
                    KeyNavigation.tab: cancelMfaButton
                    KeyNavigation.backtab: mfaCodeField
                    onClicked: {
                        loginRoot.submittedAttempt = true
                        if (loginRoot.vm) {
                            loginRoot.vm.submitMfaCode(mfaCodeField.text)
                        }
                    }
                }

                SCButton {
                    id: cancelMfaButton
                    text: qsTr("Back to Credentials")
                    iconName: "arrow-left"
                    variant: "Ghost"
                    buttonHeight: 36
                    fullWidth: true
                    enabled: !loginRoot.isBusy
                    KeyNavigation.tab: mfaCodeField
                    KeyNavigation.backtab: verifyMfaButton
                    onClicked: {
                        if (loginRoot.vm) {
                            loginRoot.vm.cancelMfaChallenge()
                        }
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
                color: Theme.borderSubtle
            }

            // Truthful Pre-Authentication Security Footnote
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space8

                SCIcon {
                    name: "lock"
                    size: 14
                    color: Theme.textMuted
                    Layout.alignment: Qt.AlignVCenter
                }

                Label {
                    text: qsTr("Transport protected via TLS 1.3. End-to-end session keys are derived locally after authentication.")
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontCaption
                    color: Theme.textMuted
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }
        }
    }
}
