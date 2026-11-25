import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: diagnosticsRoot
    color: Theme.backgroundPrimary

    readonly property var dvm: typeof diagnosticsViewModel !== "undefined" ? diagnosticsViewModel : null

    // Reusable KPI Metric Tile for Live Resource & Transport Telemetry
    component MetricTile: Rectangle {
        id: tileRoot
        property string metricLabel: ""
        property string metricValue: ""
        property string valueObjectName: ""
        property color valueColor: Theme.textPrimary

        Layout.fillWidth: true
        implicitHeight: tileColumn.implicitHeight + (Theme.space12 * 2)
        radius: Theme.radiusSmall
        color: Theme.backgroundPrimary
        border.color: Theme.borderSubtle
        border.width: 1

        ColumnLayout {
            id: tileColumn
            anchors.fill: parent
            anchors.margins: Theme.space12
            spacing: Theme.space4

            Label {
                text: tileRoot.metricLabel
                font.family: Theme.fontFamilyPrimary
                font.pixelSize: Theme.fontCaption
                color: Theme.textMuted
                elide: Text.ElideRight
                Layout.fillWidth: true
            }

            Label {
                objectName: tileRoot.valueObjectName
                text: tileRoot.metricValue
                font.family: Theme.fontFamilyMonospace
                font.pixelSize: Theme.fontSubtitle
                font.bold: true
                color: tileRoot.valueColor
                elide: Text.ElideRight
                Layout.fillWidth: true
            }
        }
    }

    ScrollView {
        id: diagnosticsScrollView
        objectName: "diagnosticsScrollView"
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth

        function scrollToTop() {
            if (contentItem) {
                contentItem.contentY = 0
            }
        }

        ColumnLayout {
            id: diagnosticsColumn
            width: Math.min(860, parent.width - (Theme.space32 * 2))
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: Theme.space24

            Item { width: 1; height: Theme.space8 }

            // Header Row: Title, Context Subtitle, Refresh All, Back to Settings
            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.space12

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    Label {
                        text: qsTr("Diagnostics & Security Health Console")
                        font.pixelSize: Theme.fontTitle
                        font.bold: true
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    Label {
                        text: qsTr("Inspect OpenSSL 3.x boot self-tests, live resource/network telemetry, tamper-evident hash-chained audit logs, and export encrypted zero-leak .scdiag bundles.")
                        font.pixelSize: Theme.fontCaption
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textSecondary
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }
                }

                SCButton {
                    objectName: "refreshAllDiagnosticsButton"
                    text: qsTr("Refresh All")
                    variant: "Secondary"
                    iconName: "refresh"
                    buttonHeight: 36
                    onClicked: {
                        if (diagnosticsRoot.dvm) {
                            diagnosticsRoot.dvm.refreshDiagnostics()
                        }
                    }
                }

                SCButton {
                    objectName: "backToSettingsButton"
                    text: qsTr("Back to Settings")
                    variant: "Secondary"
                    iconName: "arrow-left"
                    buttonHeight: 36
                    onClicked: navigationController.navigateTo(3)
                }
            }

            // 1. Cryptographic Boot & Manual Self-Test Suite (OpenSSL 3.x KATs)
            SCCard {
                id: diagnosticsSelfTestCard
                objectName: "diagnosticsSelfTestCard"
                Layout.fillWidth: true
                headerText: qsTr("1. OpenSSL Cryptographic Self-Test Verification")
                headerIconName: "shield-check"
                elevation: "Elevated"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCBadge {
                            objectName: "selfTestStatusBadge"
                            text: (diagnosticsRoot.dvm && diagnosticsRoot.dvm.selfTestPassed)
                                  ? qsTr("All Self-Tests Passed")
                                  : qsTr("Self-Test Failed")
                            type: (diagnosticsRoot.dvm && diagnosticsRoot.dvm.selfTestPassed)
                                  ? "Verified"
                                  : "Danger"
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: diagnosticsRoot.dvm ? diagnosticsRoot.dvm.selfTestSummary : qsTr("Unavailable")
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }

                            Label {
                                text: diagnosticsRoot.dvm
                                      ? qsTr("Backend: %1").arg(diagnosticsRoot.dvm.selfTestBackend)
                                      : ""
                                font.family: Theme.fontFamilyMonospace
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }

                        SCButton {
                            objectName: "runSelfTestButton"
                            text: qsTr("Run Self-Test Now")
                            variant: "Primary"
                            iconName: "shield-check"
                            buttonHeight: 34
                            onClicked: {
                                if (diagnosticsRoot.dvm) {
                                    diagnosticsRoot.dvm.runCryptoSelfTestNow()
                                }
                            }
                        }
                    }

                    Repeater {
                        model: diagnosticsRoot.dvm ? diagnosticsRoot.dvm.selfTestChecks : []

                        delegate: Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: checkRow.implicitHeight + (Theme.space8 * 2)
                            radius: Theme.radiusSmall
                            color: Theme.backgroundPrimary
                            border.color: Theme.borderSubtle
                            border.width: 1

                            RowLayout {
                                id: checkRow
                                anchors.fill: parent
                                anchors.margins: Theme.space8
                                spacing: Theme.space8

                                SCIcon {
                                    name: modelData.passed ? "check" : "alert-triangle"
                                    size: 16
                                    color: modelData.passed ? Theme.statusSuccess : Theme.statusDanger
                                    Layout.alignment: Qt.AlignVCenter
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2

                                    Label {
                                        text: modelData.checkName || ""
                                        font.family: Theme.fontFamilyMonospace
                                        font.pixelSize: Theme.fontCaption
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    Label {
                                        text: modelData.detail || ""
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontMicro
                                        color: Theme.textSecondary
                                        wrapMode: Text.WordWrap
                                        Layout.fillWidth: true
                                    }
                                }

                                Label {
                                    text: qsTr("%1 us").arg(modelData.durationUs !== undefined ? modelData.durationUs : 0)
                                    font.family: Theme.fontFamilyMonospace
                                    font.pixelSize: Theme.fontCaption
                                    color: Theme.textMuted
                                    Layout.alignment: Qt.AlignVCenter
                                }

                                SCBadge {
                                    text: modelData.passed ? qsTr("PASS") : qsTr("FAIL")
                                    type: modelData.passed ? "Verified" : "Danger"
                                    hasDot: false
                                }
                            }
                        }
                    }
                }
            }

            // 2. Live Resource & Transport Telemetry
            SCCard {
                id: diagnosticsTelemetryCard
                objectName: "diagnosticsTelemetryCard"
                Layout.fillWidth: true
                headerText: qsTr("2. Live Process, E2EE Session & Gateway Telemetry")
                headerIconName: "monitor"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space8

                        SCBadge {
                            text: diagnosticsRoot.dvm ? diagnosticsRoot.dvm.connectivityState : qsTr("Online")
                            type: {
                                if (!diagnosticsRoot.dvm) return "Info"
                                if (diagnosticsRoot.dvm.connectivityState === "Offline") return "Offline"
                                if (diagnosticsRoot.dvm.connectivityState === "Syncing") return "Info"
                                return "Online"
                            }
                        }

                        SCBadge {
                            text: diagnosticsRoot.dvm ? diagnosticsRoot.dvm.gatewayTransportMode : qsTr("Simulated Offline")
                            type: "Info"
                            hasDot: false
                        }

                        Label {
                            text: diagnosticsRoot.dvm
                                  ? qsTr("Last sampled: %1  ·  Requests: %2 (%3 failed)")
                                        .arg(diagnosticsRoot.dvm.lastSampledAtText)
                                        .arg(diagnosticsRoot.dvm.gatewayRequestsTotal)
                                        .arg(diagnosticsRoot.dvm.gatewayRequestsFailed)
                                  : ""
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textMuted
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "refreshTelemetryButton"
                            text: qsTr("Refresh Telemetry")
                            variant: "Secondary"
                            iconName: "refresh"
                            buttonHeight: 32
                            onClicked: {
                                if (diagnosticsRoot.dvm) {
                                    diagnosticsRoot.dvm.refreshTelemetry()
                                }
                            }
                        }
                    }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 3
                        rowSpacing: Theme.space8
                        columnSpacing: Theme.space8

                        MetricTile {
                            metricLabel: qsTr("Resident Memory (RSS)")
                            valueObjectName: "telemetryRssValue"
                            metricValue: diagnosticsRoot.dvm
                                         ? qsTr("%1 MB").arg(Number(diagnosticsRoot.dvm.rssMegabytes).toFixed(1))
                                         : qsTr("0.0 MB")
                            valueColor: Theme.accentPrimary
                        }

                        MetricTile {
                            metricLabel: qsTr("Process CPU Usage")
                            valueObjectName: "telemetryCpuValue"
                            metricValue: diagnosticsRoot.dvm
                                         ? qsTr("%1 %").arg(Number(diagnosticsRoot.dvm.cpuPercent).toFixed(1))
                                         : qsTr("0.0 %")
                        }

                        MetricTile {
                            metricLabel: qsTr("Active Ratchet Sessions")
                            valueObjectName: "telemetrySessionsValue"
                            metricValue: diagnosticsRoot.dvm
                                         ? String(diagnosticsRoot.dvm.activeRatchetSessions)
                                         : "0"
                        }

                        MetricTile {
                            metricLabel: qsTr("Pending Outbox / Retries")
                            valueObjectName: "telemetryOutboxValue"
                            metricValue: diagnosticsRoot.dvm
                                         ? qsTr("%1 / %2").arg(diagnosticsRoot.dvm.pendingOutboxCount).arg(diagnosticsRoot.dvm.pendingRetryCount)
                                         : qsTr("0 / 0")
                        }

                        MetricTile {
                            metricLabel: qsTr("Active File Transfers")
                            valueObjectName: "telemetryTransfersValue"
                            metricValue: diagnosticsRoot.dvm
                                         ? String(diagnosticsRoot.dvm.activeFileTransfers)
                                         : "0"
                        }

                        MetricTile {
                            metricLabel: qsTr("Gateway RTT (Last / Avg)")
                            valueObjectName: "telemetryRttValue"
                            metricValue: diagnosticsRoot.dvm
                                         ? qsTr("%1 ms / %2 ms").arg(diagnosticsRoot.dvm.gatewayRttMs).arg(diagnosticsRoot.dvm.gatewayAvgRttMs)
                                         : qsTr("0 ms / 0 ms")
                        }
                    }
                }
            }

            // 3. Tamper-Evident Local Audit Trail (Sanitized, Zero-Secret Inspection)
            SCCard {
                id: diagnosticsAuditCard
                objectName: "diagnosticsAuditCard"
                Layout.fillWidth: true
                headerText: qsTr("3. Tamper-Evident Local Security Audit Trail")
                headerIconName: "lock"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCBadge {
                            objectName: "auditChainStatusBadge"
                            text: (diagnosticsRoot.dvm && diagnosticsRoot.dvm.auditChainValid)
                                  ? qsTr("Hash Chain Verified")
                                  : qsTr("Tamper Detected")
                            type: (diagnosticsRoot.dvm && diagnosticsRoot.dvm.auditChainValid)
                                  ? "Verified"
                                  : "Danger"
                        }

                        Label {
                            text: diagnosticsRoot.dvm
                                  ? diagnosticsRoot.dvm.auditIntegrityStatusText
                                  : qsTr("Pending verification")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.textSecondary
                            elide: Text.ElideRight
                            Layout.fillWidth: true
                        }

                        SCButton {
                            objectName: "verifyAuditChainButton"
                            text: qsTr("Verify Chain Integrity")
                            variant: "Secondary"
                            iconName: "shield-check"
                            buttonHeight: 32
                            onClicked: {
                                if (diagnosticsRoot.dvm) {
                                    diagnosticsRoot.dvm.verifyAuditChainNow()
                                }
                            }
                        }
                    }

                    ListView {
                        id: auditEventsListView
                        objectName: "auditEventsListView"
                        Layout.fillWidth: true
                        Layout.preferredHeight: 220
                        clip: true
                        spacing: Theme.space8
                        model: diagnosticsRoot.dvm ? diagnosticsRoot.dvm.auditEvents : []
                        ScrollBar.vertical: ScrollBar {
                            id: auditScrollBar
                            policy: ScrollBar.AsNeeded
                        }

                        delegate: Rectangle {
                            width: auditEventsListView.width - (auditScrollBar.visible ? 12 : 0)
                            implicitHeight: auditRowCol.implicitHeight + (Theme.space8 * 2)
                            radius: Theme.radiusSmall
                            color: Theme.backgroundPrimary
                            border.color: Theme.borderSubtle
                            border.width: 1

                            ColumnLayout {
                                id: auditRowCol
                                anchors.fill: parent
                                anchors.margins: Theme.space8
                                spacing: 4

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space8

                                    Label {
                                        text: "#" + (modelData.sequenceId !== undefined ? modelData.sequenceId : 0)
                                        font.family: Theme.fontFamilyMonospace
                                        font.pixelSize: Theme.fontCaption
                                        font.bold: true
                                        color: Theme.accentPrimary
                                    }

                                    Label {
                                        text: (modelData.category || "") + " · " + (modelData.eventType || "")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontCaption
                                        font.bold: true
                                        color: Theme.textPrimary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    SCBadge {
                                        text: modelData.outcome || "Success"
                                        type: {
                                            if (modelData.outcome === "Success") return "Verified"
                                            if (modelData.outcome === "Triggered") return "Unverified"
                                            return "Danger"
                                        }
                                        hasDot: false
                                        badgeHeight: 20
                                    }
                                }

                                Label {
                                    text: modelData.summary || ""
                                    font.family: Theme.fontFamilyPrimary
                                    font.pixelSize: Theme.fontMicro
                                    color: Theme.textSecondary
                                    wrapMode: Text.WordWrap
                                    Layout.fillWidth: true
                                }

                                Label {
                                    text: qsTr("%1  ·  SHA-256: %2...")
                                          .arg(modelData.occurredAtText || "")
                                          .arg(modelData.entryHashPrefix || "")
                                    font.family: Theme.fontFamilyMonospace
                                    font.pixelSize: Theme.fontMicro
                                    color: Theme.textMuted
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                            }
                        }
                    }
                }
            }

            // 4. Encrypted Zero-Leak .scdiag Support Bundle Exporter
            SCCard {
                id: diagnosticsExportCard
                objectName: "diagnosticsExportCard"
                Layout.fillWidth: true
                headerText: qsTr("4. Sanitized Encrypted Diagnostic Archive (.scdiag)")
                headerIconName: "download"
                elevation: "Base"

                ColumnLayout {
                    width: parent.width
                    spacing: Theme.space12

                    Label {
                        text: qsTr("Scrubs credentials, keys, recovery seeds, message plaintexts, handles, and local home paths before sealing the report with OpenSSL AES-256-GCM authentication.")
                        font.family: Theme.fontFamilyPrimary
                        font.pixelSize: Theme.fontCaption
                        color: Theme.textSecondary
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        SCTextField {
                            id: exportBundlePathField
                            objectName: "exportBundlePathField"
                            label: qsTr("Destination Bundle Path (.scdiag)")
                            placeholderText: qsTr("/tmp/securecloud-support.scdiag")
                            isMonospace: true
                            Layout.fillWidth: true
                        }

                        SCTextField {
                            id: exportPassphraseField
                            objectName: "exportPassphraseField"
                            label: qsTr("Encryption Passphrase (Optional)")
                            placeholderText: qsTr("Leave blank for random 256-bit export key")
                            isPassword: true
                            Layout.fillWidth: true
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.space12

                        Item { Layout.fillWidth: true }

                        SCButton {
                            objectName: "exportBundleButton"
                            text: qsTr("Export Encrypted .scdiag Bundle")
                            variant: "Primary"
                            iconName: "download"
                            buttonHeight: 36
                            onClicked: {
                                if (!diagnosticsRoot.dvm) {
                                    return
                                }
                                diagnosticsRoot.dvm.exportSanitizedBundle(
                                    exportBundlePathField.text,
                                    exportPassphraseField.text)
                                exportPassphraseField.text = ""
                            }
                        }
                    }

                    Rectangle {
                        id: exportStatusBanner
                        objectName: "exportStatusBanner"
                        visible: diagnosticsRoot.dvm ? (diagnosticsRoot.dvm.lastExportStatusText !== "") : false
                        Layout.fillWidth: true
                        implicitHeight: exportStatusCol.implicitHeight + (Theme.space8 * 2)
                        radius: Theme.radiusSmall
                        color: {
                            if (diagnosticsRoot.dvm && diagnosticsRoot.dvm.lastExportSucceeded) {
                                return Theme.isDark ? "#122A22" : "#ECFDF5"
                            }
                            return Theme.isDark ? "#2D1416" : "#FEF2F2"
                        }
                        border.color: (diagnosticsRoot.dvm && diagnosticsRoot.dvm.lastExportSucceeded)
                                      ? Theme.statusSuccess
                                      : Theme.statusDanger
                        border.width: 1

                        ColumnLayout {
                            id: exportStatusCol
                            anchors.fill: parent
                            anchors.margins: Theme.space8
                            spacing: 4

                            Label {
                                text: diagnosticsRoot.dvm ? diagnosticsRoot.dvm.lastExportStatusText : ""
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                font.bold: true
                                color: (diagnosticsRoot.dvm && diagnosticsRoot.dvm.lastExportSucceeded)
                                       ? Theme.statusSuccess
                                       : Theme.statusDanger
                                wrapMode: Text.WordWrap
                                Layout.fillWidth: true
                            }

                            Label {
                                visible: diagnosticsRoot.dvm
                                         ? (diagnosticsRoot.dvm.lastExportSucceeded && diagnosticsRoot.dvm.lastExportPath !== "")
                                         : false
                                text: diagnosticsRoot.dvm
                                      ? qsTr("Saved to: %1").arg(diagnosticsRoot.dvm.lastExportPath)
                                      : ""
                                font.family: Theme.fontFamilyMonospace
                                font.pixelSize: Theme.fontMicro
                                color: Theme.textSecondary
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            Item { width: 1; height: Theme.space16 }
        }
    }
}
