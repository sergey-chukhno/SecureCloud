import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: card

    property string headerText: ""
    property alias headerTitle: card.headerText
    property string headerIcon: ""
    property string elevation: "Base" // Base, Elevated
    property bool hasBorder: true
    property int cardPadding: Theme.space16
    property int cardRadius: Theme.radiusMedium

    default property alias content: contentLayout.data

    implicitWidth: 300
    implicitHeight: (card.headerText !== "" ? 44 : 0) + Math.max(40, contentLayout.childrenRect.height + (card.cardPadding * 2))

    radius: cardRadius
    color: elevation === "Elevated" ? Theme.backgroundElevated : Theme.backgroundSecondary
    border.color: hasBorder ? Theme.borderSubtle : "transparent"
    border.width: hasBorder ? 1 : 0

    Behavior on color {
        ColorAnimation { duration: Theme.durationFast }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Optional Header
        Rectangle {
            visible: card.headerText !== ""
            Layout.fillWidth: true
            Layout.preferredHeight: 44
            color: "transparent"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: card.cardPadding
                anchors.rightMargin: card.cardPadding
                spacing: Theme.space8

                Label {
                    visible: card.headerIcon !== ""
                    text: card.headerIcon
                    font.pixelSize: Theme.fontSubtitle
                    color: Theme.textPrimary
                    Layout.alignment: Qt.AlignVCenter
                }

                Label {
                    text: card.headerText
                    font.family: Theme.fontFamilyPrimary
                    font.pixelSize: Theme.fontSubtitle
                    font.bold: true
                    color: Theme.textPrimary
                    Layout.alignment: Qt.AlignVCenter
                }

                Item { Layout.fillWidth: true }
            }

            Rectangle {
                anchors.bottom: parent.bottom
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.borderSubtle
            }
        }

        // Body Content Container
        Item {
            id: contentContainer
            Layout.fillWidth: true
            Layout.fillHeight: true

            Item {
                id: contentLayout
                anchors.fill: parent
                anchors.margins: card.cardPadding
            }
        }
    }
}

