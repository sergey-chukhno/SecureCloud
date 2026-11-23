import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: emergencyRoot
    color: Theme.backgroundPrimary

    readonly property var avm: typeof appViewModel !== "undefined" ? appViewModel : null
    readonly property var nav: typeof navigationController !== "undefined" ? navigationController : null
    readonly property var report: (avm && avm.lastWipeReportSummary) ? avm.lastWipeReportSummary : ({})
    readonly property bool hasReport: report.hasReport === true
    readonly property var stepsModel: (hasReport && report.stepResults) ? report.stepResults : []

    ScrollView {
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth

        Item {
            width: Math.max(emergencyRoot.width, 520)
            implicitHeight: Math.max(emergencyRoot.height, emergencyColumn.implicitHeight + (Theme.space32 * 2))

            ColumnLayout {
                id: emergencyColumn
                anchors.centerIn: parent
                spacing: Theme.space16
                width: Math.max(320, Math.min(580, emergencyRoot.width - (Theme.space32 * 2)))

                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: cardBody.implicitHeight + (Theme.space24 * 2)
                    radius: Theme.radiusMedium
                    color: Theme.backgroundSecondary
                    border.color: Theme.statusDanger
                    border.width: 2

                    ColumnLayout {
                        id: cardBody
                        anchors.fill: parent
                        anchors.margins: Theme.space24
                        spacing: Theme.space12

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: Theme.space8

                            SCIcon {
                                name: "shield-alert"
                                size: 22
                                color: Theme.statusDanger
                                Layout.alignment: Qt.AlignVCenter
                            }

                            Label {
                                text: qsTr("Emergency Wipe Mode Activated")
                                font.pixelSize: Theme.fontTitle
                                font.bold: true
                                font.family: Theme.fontFamilyPrimary
                                color: Theme.statusDanger
                                Layout.fillWidth: true
                                Layout.alignment: Qt.AlignVCenter
                            }

                            SCBadge {
                                visible: emergencyRoot.hasReport
                                text: emergencyRoot.report.allCriticalStepsSucceeded === true
                                      ? qsTr("Verified")
                                      : qsTr("Partial")
                                type: emergencyRoot.report.allCriticalStepsSucceeded === true ? "Verified" : "Unverified"
                            }
                        }

                        Label {
                            text: qsTr("All in-memory cryptographic ratchets, endpoint secrets, local SQLCipher vault files, and temporary caches have been destroyed.")
                            font.pixelSize: Theme.fontBody
                            font.family: Theme.fontFamilyPrimary
                            color: Theme.textSecondary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        // Strictly non-secret forensic verification metrics
                        Rectangle {
                            visible: emergencyRoot.hasReport
                            Layout.fillWidth: true
                            implicitHeight: metricsGrid.implicitHeight + (Theme.space12 * 2)
                            radius: Theme.radiusSmall
                            color: Theme.backgroundPrimary
                            border.color: Theme.borderSubtle
                            border.width: 1

                            GridLayout {
                                id: metricsGrid
                                anchors.fill: parent
                                anchors.margins: Theme.space12
                                columns: 2
                                columnSpacing: Theme.space16
                                rowSpacing: Theme.space8

                                Label {
                                    text: qsTr("Elapsed Destruction Time: %1 ms")
                                          .arg(emergencyRoot.report.durationMs !== undefined ? emergencyRoot.report.durationMs : 0)
                                    font.family: Theme.fontFamilyMonospace
                                    font.pixelSize: Theme.fontCaption
                                    color: Theme.textPrimary
                                    Layout.fillWidth: true
                                }

                                Label {
                                    text: qsTr("Secrets Purged: %1")
                                          .arg(emergencyRoot.report.secretsPurgedCount !== undefined ? emergencyRoot.report.secretsPurgedCount : 0)
                                    font.family: Theme.fontFamilyMonospace
                                    font.pixelSize: Theme.fontCaption
                                    color: Theme.textPrimary
                                    Layout.fillWidth: true
                                }

                                Label {
                                    text: qsTr("Files Shredded: %1")
                                          .arg(emergencyRoot.report.filesShreddedCount !== undefined ? emergencyRoot.report.filesShreddedCount : 0)
                                    font.family: Theme.fontFamilyMonospace
                                    font.pixelSize: Theme.fontCaption
                                    color: Theme.textPrimary
                                    Layout.fillWidth: true
                                }

                                Label {
                                    text: qsTr("Volatile Caches Cleared: %1")
                                          .arg(emergencyRoot.report.volatileCachesCleared !== undefined ? emergencyRoot.report.volatileCachesCleared : 0)
                                    font.family: Theme.fontFamilyMonospace
                                    font.pixelSize: Theme.fontCaption
                                    color: Theme.textPrimary
                                    Layout.fillWidth: true
                                }
                            }
                        }

                        Label {
                            visible: emergencyRoot.hasReport && emergencyRoot.report.broadcastAttempted === true
                            text: emergencyRoot.report.broadcastAcknowledged === true
                                  ? qsTr("Pre-Wipe E2EE Broadcast: Delivered and acknowledged prior to destruction.")
                                  : qsTr("Pre-Wipe E2EE Broadcast: Attempted (local wipe proceeded unconditionally).")
                            font.family: Theme.fontFamilyPrimary
                            font.pixelSize: Theme.fontCaption
                            color: Theme.accentPrimary
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }

                        ColumnLayout {
                            visible: emergencyRoot.stepsModel.length > 0
                            Layout.fillWidth: true
                            spacing: Theme.space4

                            Repeater {
                                model: emergencyRoot.stepsModel
                                delegate: RowLayout {
                                    Layout.fillWidth: true
                                    spacing: Theme.space8

                                    Label {
                                        text: (modelData.category || "") + " — " + (modelData.detail || "")
                                        font.family: Theme.fontFamilyPrimary
                                        font.pixelSize: Theme.fontMicro
                                        color: Theme.textSecondary
                                        elide: Text.ElideRight
                                        Layout.fillWidth: true
                                    }

                                    SCBadge {
                                        text: modelData.status || "Succeeded"
                                        type: modelData.status === "Failed"
                                              ? "Danger"
                                              : (modelData.status === "Skipped" ? "Unverified" : "Verified")
                                        hasDot: false
                                    }
                                }
                            }
                        }
                    }
                }

                SCButton {
                    objectName: "resetAfterWipeButton"
                    text: qsTr("Reset to Clean Unconfigured State")
                    variant: "Danger"
                    Layout.alignment: Qt.AlignHCenter
                    onClicked: {
                        if (emergencyRoot.avm) {
                            emergencyRoot.avm.resetClientAfterWipe()
                        } else if (emergencyRoot.nav) {
                            emergencyRoot.nav.reset(0)
                        }
                    }
                }
            }
        }
    }
}
