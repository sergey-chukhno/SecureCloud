import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "controls"

Rectangle {
    id: workspaceRoot
    color: Theme.backgroundPrimary

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // Sidebar Panel
        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 300
            color: Theme.backgroundSecondary
            border.color: Theme.borderSubtle
            border.width: 1

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: Theme.space16
                spacing: Theme.space12

                RowLayout {
                    Layout.fillWidth: true

                    Label {
                        text: qsTr("Conversations")
                        font.bold: true
                        font.pixelSize: Theme.fontSubtitle
                        font.family: Theme.fontFamilyPrimary
                        color: Theme.textPrimary
                    }

                    Item { Layout.fillWidth: true }

                    SCBadge {
                        text: "Direct & Group"
                        type: "Info"
                        hasDot: false
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 1
                    color: Theme.borderSubtle
                }

                // Sample conversation items utilizing SCAvatar, SCBadge, and SCCard
                SCCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 64
                    cardPadding: Theme.space8
                    elevation: "Elevated"

                    RowLayout {
                        anchors.fill: parent
                        spacing: Theme.space8

                        SCAvatar {
                            userId: "bob@securecloud.org"
                            displayName: "Bob Stone"
                            size: 38
                            presence: "Online"
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: "Bob Stone"
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: "Safety Number verified ✓"
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.statusSuccess
                                elide: Text.ElideRight
                            }
                        }

                        SCBadge {
                            type: "Verified"
                            text: "E2EE"
                            hasDot: false
                        }
                    }
                }

                SCCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 64
                    cardPadding: Theme.space8
                    elevation: "Base"

                    RowLayout {
                        anchors.fill: parent
                        spacing: Theme.space8

                        SCAvatar {
                            userId: "charlie@securecloud.org"
                            displayName: "Charlie Davis"
                            size: 38
                            presence: "Offline"
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 2

                            Label {
                                text: "Charlie Davis"
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontBody
                                font.bold: true
                                color: Theme.textPrimary
                            }

                            Label {
                                text: "Key exchange pending..."
                                font.family: Theme.fontFamilyPrimary
                                font.pixelSize: Theme.fontCaption
                                color: Theme.textMuted
                                elide: Text.ElideRight
                            }
                        }

                        SCBadge {
                            type: "Unverified"
                            text: "New"
                            hasDot: false
                        }
                    }
                }

                Item { Layout.fillHeight: true }

                SCButton {
                    text: qsTr("Sign Out")
                    iconName: "logout"
                    variant: "Secondary"
                    fullWidth: true
                    onClicked: appViewModel.requestLogout()
                }
            }
        }

        // Main Workspace Area
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: Theme.backgroundPrimary

            ColumnLayout {
                anchors.centerIn: parent
                spacing: Theme.space16
                width: 480

                SCAvatar {
                    userId: appViewModel.currentUser
                    displayName: appViewModel.currentUser
                    size: 72
                    presence: "Online"
                    Layout.alignment: Qt.AlignHCenter
                }

                Label {
                    text: qsTr("Welcome, %1!").arg(appViewModel.currentUser)
                    font.pixelSize: Theme.fontHeadline
                    font.bold: true
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textPrimary
                    Layout.alignment: Qt.AlignHCenter
                }

                Label {
                    text: qsTr("Your authenticated workstation session is active.\nSelect a contact from the sidebar to verify safety numbers or establish an end-to-end encrypted conversation.")
                    font.pixelSize: Theme.fontBody
                    font.family: Theme.fontFamilyPrimary
                    color: Theme.textSecondary
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }

                RowLayout {
                    Layout.alignment: Qt.AlignHCenter
                    spacing: Theme.space8

                    SCBadge {
                        type: "Info"
                        text: qsTr("Session Token Active")
                    }

                    SCBadge {
                        type: "Online"
                        text: qsTr("Gateway Connected")
                    }
                }
            }
        }
    }
}
