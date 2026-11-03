import QtQuick
import QtQuick.Controls

Item {
    id: navShell

    Loader {
        id: viewLoader
        anchors.fill: parent

        source: {
            switch (navigationController.currentViewName) {
                case "Login":
                    return "LoginPlaceholder.qml"
                case "MfaVerification":
                    return "LoginPlaceholder.qml"
                case "Workspace":
                    return "WorkspacePlaceholder.qml"
                case "Settings":
                    return "SettingsPlaceholder.qml"
                case "Emergency":
                    return "EmergencyPlaceholder.qml"
                default:
                    return "LoginPlaceholder.qml"
            }
        }
    }
}

