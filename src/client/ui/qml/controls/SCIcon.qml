import QtQuick

Item {
    id: iconRoot

    property string name: ""
    property color color: Theme.textPrimary
    property int size: 18
    property real strokeWidth: 1.8

    implicitWidth: size
    implicitHeight: size
    width: size
    height: size

    onNameChanged: canvas.requestPaint()
    onColorChanged: canvas.requestPaint()
    onSizeChanged: canvas.requestPaint()
    onStrokeWidthChanged: canvas.requestPaint()

    Canvas {
        id: canvas
        anchors.fill: parent
        antialiasing: true
        renderTarget: Canvas.Image

        onPaint: {
            var ctx = getContext("2d");
            ctx.reset();
            if (!iconRoot.name || iconRoot.width <= 0 || iconRoot.height <= 0) {
                return;
            }

            var scaleX = iconRoot.width / 24.0;
            var scaleY = iconRoot.height / 24.0;
            ctx.scale(scaleX, scaleY);

            ctx.strokeStyle = iconRoot.color.toString();
            ctx.fillStyle = iconRoot.color.toString();
            ctx.lineWidth = iconRoot.strokeWidth;
            ctx.lineCap = "round";
            ctx.lineJoin = "round";

            var n = iconRoot.name;

            if (n === "workspace" || n === "message") {
                // Message square outline
                ctx.beginPath();
                ctx.moveTo(21, 15);
                ctx.arcTo(21, 17, 19, 17, 2);
                ctx.lineTo(7, 17);
                ctx.lineTo(3, 21);
                ctx.lineTo(3, 5);
                ctx.arcTo(3, 3, 5, 3, 2);
                ctx.lineTo(19, 3);
                ctx.arcTo(21, 3, 21, 5, 2);
                ctx.closePath();
                ctx.stroke();

                // Inner message lines
                ctx.beginPath();
                ctx.moveTo(7, 8.5);
                ctx.lineTo(17, 8.5);
                ctx.moveTo(7, 12.5);
                ctx.lineTo(13.5, 12.5);
                ctx.stroke();
            } else if (n === "settings") {
                // Three precision horizontal tuning sliders
                ctx.beginPath();
                ctx.moveTo(4, 6);
                ctx.lineTo(10, 6);
                ctx.moveTo(14, 6);
                ctx.lineTo(20, 6);

                ctx.moveTo(4, 12);
                ctx.lineTo(14, 12);
                ctx.moveTo(18, 12);
                ctx.lineTo(20, 12);

                ctx.moveTo(4, 18);
                ctx.lineTo(6, 18);
                ctx.moveTo(10, 18);
                ctx.lineTo(20, 18);
                ctx.stroke();

                // Knobs
                ctx.beginPath();
                ctx.arc(12, 6, 2.2, 0, Math.PI * 2);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(16, 12, 2.2, 0, Math.PI * 2);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(8, 18, 2.2, 0, Math.PI * 2);
                ctx.stroke();
            } else if (n === "style-guide" || n === "grid") {
                // 2x2 rounded design system grid
                ctx.beginPath();
                ctx.roundedRect(3, 3, 7.5, 7.5, 1.5, 1.5);
                ctx.roundedRect(13.5, 3, 7.5, 7.5, 1.5, 1.5);
                ctx.roundedRect(13.5, 13.5, 7.5, 7.5, 1.5, 1.5);
                ctx.roundedRect(3, 13.5, 7.5, 7.5, 1.5, 1.5);
                ctx.stroke();
            } else if (n === "sun") {
                // Sun core
                ctx.beginPath();
                ctx.arc(12, 12, 4.2, 0, Math.PI * 2);
                ctx.stroke();
                // 8 rays
                ctx.beginPath();
                ctx.moveTo(12, 2); ctx.lineTo(12, 4.2);
                ctx.moveTo(12, 19.8); ctx.lineTo(12, 22);
                ctx.moveTo(4.93, 4.93); ctx.lineTo(6.48, 6.48);
                ctx.moveTo(17.52, 17.52); ctx.lineTo(19.07, 19.07);
                ctx.moveTo(2, 12); ctx.lineTo(4.2, 12);
                ctx.moveTo(19.8, 12); ctx.lineTo(22, 12);
                ctx.moveTo(4.93, 19.07); ctx.lineTo(6.48, 17.52);
                ctx.moveTo(17.52, 6.48); ctx.lineTo(19.07, 4.93);
                ctx.stroke();
            } else if (n === "moon") {
                // Crescent moon
                ctx.beginPath();
                ctx.arc(12.5, 12, 7.5, 0.22 * Math.PI, 1.28 * Math.PI, false);
                ctx.arc(16.2, 8.8, 6.2, 1.18 * Math.PI, 0.32 * Math.PI, true);
                ctx.closePath();
                ctx.stroke();
            } else if (n === "eye") {
                // Eye contour
                ctx.beginPath();
                ctx.moveTo(2, 12);
                ctx.quadraticCurveTo(12, 4, 22, 12);
                ctx.quadraticCurveTo(12, 20, 2, 12);
                ctx.closePath();
                ctx.stroke();
                // Pupil
                ctx.beginPath();
                ctx.arc(12, 12, 3, 0, Math.PI * 2);
                ctx.stroke();
            } else if (n === "eye-off") {
                // Eye contour
                ctx.beginPath();
                ctx.moveTo(2, 12);
                ctx.quadraticCurveTo(12, 4, 22, 12);
                ctx.quadraticCurveTo(12, 20, 2, 12);
                ctx.closePath();
                ctx.stroke();
                // Diagonal slash
                ctx.beginPath();
                ctx.moveTo(3.5, 3.5);
                ctx.lineTo(20.5, 20.5);
                ctx.stroke();
            } else if (n === "lock") {
                // Lock body
                ctx.beginPath();
                ctx.roundedRect(4.5, 11, 15, 10, 2, 2);
                ctx.stroke();
                // Shackle
                ctx.beginPath();
                ctx.moveTo(7.5, 11);
                ctx.lineTo(7.5, 7.5);
                ctx.arc(12, 7.5, 4.5, Math.PI, 0, false);
                ctx.lineTo(16.5, 11);
                ctx.stroke();
                // Keyhole dot
                ctx.beginPath();
                ctx.arc(12, 16, 1.2, 0, Math.PI * 2);
                ctx.fill();
            } else if (n === "shield-check" || n === "shield") {
                // Shield path
                ctx.beginPath();
                ctx.moveTo(12, 2.5);
                ctx.lineTo(19.5, 5.8);
                ctx.lineTo(19.5, 11.5);
                ctx.quadraticCurveTo(19.5, 18.2, 12, 21.5);
                ctx.quadraticCurveTo(4.5, 18.2, 4.5, 11.5);
                ctx.lineTo(4.5, 5.8);
                ctx.closePath();
                ctx.stroke();
                if (n === "shield-check") {
                    ctx.beginPath();
                    ctx.moveTo(8.8, 12.2);
                    ctx.lineTo(11.1, 14.5);
                    ctx.lineTo(15.5, 9.8);
                    ctx.stroke();
                }
            } else if (n === "shield-alert" || n === "emergency") {
                // Shield path
                ctx.beginPath();
                ctx.moveTo(12, 2.5);
                ctx.lineTo(19.5, 5.8);
                ctx.lineTo(19.5, 11.5);
                ctx.quadraticCurveTo(19.5, 18.2, 12, 21.5);
                ctx.quadraticCurveTo(4.5, 18.2, 4.5, 11.5);
                ctx.lineTo(4.5, 5.8);
                ctx.closePath();
                ctx.stroke();
                // Exclamation
                ctx.beginPath();
                ctx.moveTo(12, 8);
                ctx.lineTo(12, 13);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(12, 16.5, 1.1, 0, Math.PI * 2);
                ctx.fill();
            } else if (n === "alert-triangle" || n === "warning") {
                // Rounded warning triangle
                ctx.beginPath();
                ctx.moveTo(12, 3.5);
                ctx.lineTo(21, 19.5);
                ctx.lineTo(3, 19.5);
                ctx.closePath();
                ctx.stroke();
                // Exclamation
                ctx.beginPath();
                ctx.moveTo(12, 9.5);
                ctx.lineTo(12, 13.8);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(12, 16.8, 1.0, 0, Math.PI * 2);
                ctx.fill();
            } else if (n === "arrow-left") {
                ctx.beginPath();
                ctx.moveTo(19, 12);
                ctx.lineTo(5, 12);
                ctx.moveTo(11, 6);
                ctx.lineTo(5, 12);
                ctx.lineTo(11, 18);
                ctx.stroke();
            } else if (n === "sidebar" || n === "sidebar-collapse" || n === "sidebar-expand") {
                // App frame
                ctx.beginPath();
                ctx.roundedRect(3, 4, 18, 16, 2, 2);
                ctx.moveTo(9, 4);
                ctx.lineTo(9, 20);
                ctx.stroke();
                // Direction chevron
                ctx.beginPath();
                if (n === "sidebar-collapse") {
                    ctx.moveTo(15.5, 9.5);
                    ctx.lineTo(13, 12);
                    ctx.lineTo(15.5, 14.5);
                } else if (n === "sidebar-expand") {
                    ctx.moveTo(13, 9.5);
                    ctx.lineTo(15.5, 12);
                    ctx.lineTo(13, 14.5);
                }
                ctx.stroke();
            } else if (n === "close") {
                ctx.beginPath();
                ctx.moveTo(6, 6);
                ctx.lineTo(18, 18);
                ctx.moveTo(18, 6);
                ctx.lineTo(6, 18);
                ctx.stroke();
            } else if (n === "check") {
                ctx.beginPath();
                ctx.moveTo(5, 12.5);
                ctx.lineTo(10, 17.5);
                ctx.lineTo(19, 6.5);
                ctx.stroke();
            } else if (n === "bell") {
                ctx.beginPath();
                ctx.moveTo(18, 8);
                ctx.arc(12, 8, 6, 0, Math.PI, true);
                ctx.lineTo(6, 15);
                ctx.lineTo(4, 17);
                ctx.lineTo(20, 17);
                ctx.lineTo(18, 15);
                ctx.closePath();
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(12, 19.5, 2, 0, Math.PI, false);
                ctx.stroke();
            } else if (n === "search") {
                ctx.beginPath();
                ctx.arc(10.5, 10.5, 6.5, 0, Math.PI * 2);
                ctx.moveTo(15.2, 15.2);
                ctx.lineTo(20, 20);
                ctx.stroke();
            } else if (n === "monitor" || n === "system") {
                ctx.beginPath();
                ctx.roundedRect(3, 4, 18, 12, 2, 2);
                ctx.moveTo(8, 20);
                ctx.lineTo(16, 20);
                ctx.moveTo(12, 16);
                ctx.lineTo(12, 20);
                ctx.stroke();
            } else if (n === "key" || n === "mfa") {
                ctx.beginPath();
                ctx.arc(8, 15, 4.5, 0, Math.PI * 2);
                ctx.moveTo(11.2, 11.8);
                ctx.lineTo(20, 3);
                ctx.moveTo(16, 7);
                ctx.lineTo(18.5, 9.5);
                ctx.moveTo(18.5, 4.5);
                ctx.lineTo(21, 7);
                ctx.stroke();
            } else if (n === "logout") {
                ctx.beginPath();
                ctx.moveTo(9, 21);
                ctx.lineTo(5, 21);
                ctx.arcTo(3, 21, 3, 19, 2);
                ctx.lineTo(3, 5);
                ctx.arcTo(3, 3, 5, 3, 2);
                ctx.lineTo(9, 3);
                ctx.moveTo(16, 17);
                ctx.lineTo(21, 12);
                ctx.lineTo(16, 7);
                ctx.moveTo(21, 12);
                ctx.lineTo(9, 12);
                ctx.stroke();
            } else if (n === "users" || n === "contacts") {
                // Primary contact head & shoulders
                ctx.beginPath();
                ctx.arc(9, 8.5, 3.5, 0, Math.PI * 2);
                ctx.stroke();
                ctx.beginPath();
                ctx.moveTo(2.5, 19.5);
                ctx.quadraticCurveTo(2.5, 14.5, 9, 14.5);
                ctx.quadraticCurveTo(15.5, 14.5, 15.5, 19.5);
                ctx.stroke();
                // Secondary peer head & shoulder arc
                ctx.beginPath();
                ctx.arc(16.5, 9, 2.8, -0.4 * Math.PI, 0.6 * Math.PI);
                ctx.stroke();
                ctx.beginPath();
                ctx.moveTo(17, 14.8);
                ctx.quadraticCurveTo(21.5, 15.2, 21.5, 19.5);
                ctx.stroke();
            } else if (n === "file-lock" || n === "folder" || n === "files") {
                // Folder / document outline with encrypted lock
                ctx.beginPath();
                ctx.moveTo(3, 6);
                ctx.arcTo(3, 4, 5, 4, 2);
                ctx.lineTo(9.5, 4);
                ctx.lineTo(11.5, 6.5);
                ctx.lineTo(19, 6.5);
                ctx.arcTo(21, 6.5, 21, 8.5, 2);
                ctx.lineTo(21, 18);
                ctx.arcTo(21, 20, 19, 20, 2);
                ctx.lineTo(5, 20);
                ctx.arcTo(3, 20, 3, 18, 2);
                ctx.closePath();
                ctx.stroke();
                // Mini inner lock shackle & body
                ctx.beginPath();
                ctx.roundedRect(9.2, 12.5, 5.6, 4.5, 1, 1);
                ctx.moveTo(10.5, 12.5);
                ctx.lineTo(10.5, 11);
                ctx.arc(12, 11, 1.5, Math.PI, 0, false);
                ctx.lineTo(13.5, 12.5);
                ctx.stroke();
            } else if (n === "paperclip") {
                ctx.beginPath();
                ctx.moveTo(21.4, 11.1);
                ctx.lineTo(12.2, 20.3);
                ctx.arc(8.7, 16.8, 4.9, 0.25 * Math.PI, 1.25 * Math.PI, false);
                ctx.lineTo(14.4, 5.6);
                ctx.arc(16.8, 8.0, 3.2, 1.25 * Math.PI, 0.25 * Math.PI, false);
                ctx.lineTo(9.8, 17.4);
                ctx.arc(8.6, 16.2, 1.6, 0.25 * Math.PI, 1.25 * Math.PI, false);
                ctx.lineTo(15.2, 9.6);
                ctx.stroke();
            } else if (n === "send") {
                ctx.beginPath();
                ctx.moveTo(21, 3);
                ctx.lineTo(10, 14);
                ctx.moveTo(21, 3);
                ctx.lineTo(14.5, 21);
                ctx.lineTo(10, 14);
                ctx.lineTo(3, 9.5);
                ctx.closePath();
                ctx.stroke();
            } else if (n === "download") {
                ctx.beginPath();
                ctx.moveTo(12, 3.5);
                ctx.lineTo(12, 15.5);
                ctx.moveTo(7.5, 11.5);
                ctx.lineTo(12, 16);
                ctx.lineTo(16.5, 11.5);
                ctx.moveTo(4, 17.5);
                ctx.lineTo(4, 19.5);
                ctx.arcTo(4, 20.5, 5, 20.5, 1);
                ctx.lineTo(19, 20.5);
                ctx.arcTo(20, 20.5, 20, 19.5, 1);
                ctx.lineTo(20, 17.5);
                ctx.stroke();
            } else if (n === "info") {
                ctx.beginPath();
                ctx.arc(12, 12, 9, 0, Math.PI * 2);
                ctx.moveTo(12, 11.5);
                ctx.lineTo(12, 16.5);
                ctx.stroke();
                ctx.beginPath();
                ctx.arc(12, 8, 1.0, 0, Math.PI * 2);
                ctx.fill();
            } else if (n === "zap" || n === "bolt" || n === "urgent") {
                ctx.beginPath();
                ctx.moveTo(13, 2.5);
                ctx.lineTo(4.5, 13.5);
                ctx.lineTo(11.5, 13.5);
                ctx.lineTo(10.5, 21.5);
                ctx.lineTo(19.5, 10.5);
                ctx.lineTo(12.5, 10.5);
                ctx.closePath();
                ctx.stroke();
            }
        }
    }
}

