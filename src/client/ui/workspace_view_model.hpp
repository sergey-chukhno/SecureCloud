#pragma once

#include "application/client_application.hpp"
#include "ui/navigation_controller.hpp"

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <cstdint>
#include <vector>

namespace securecloud::client::ui {

/**
 * @brief Authoritative C++ presentation coordinator for the 4-zone authenticated Workspace.
 *
 * Coordinates between the declarative QML workspace (Zone 1 Navigation, Zone 2 Master List & Search,
 * Zone 3 Conversation/File Stream & Composer, Zone 4 Peer Security & Shared Files Inspector)
 * and the underlying Application Managers (MessagingManager, ContactManager, FileManager, DeviceManager).
 */
class WorkspaceViewModel : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString activeSection READ activeSection WRITE setActiveSection NOTIFY activeSectionChanged)
    Q_PROPERTY(QString searchQuery READ searchQuery WRITE setSearchQuery NOTIFY searchQueryChanged)
    Q_PROPERTY(QVariantList conversations READ conversations NOTIFY conversationsChanged)
    Q_PROPERTY(QVariantList contacts READ contacts NOTIFY contactsChanged)
    Q_PROPERTY(QVariantList fileTransfers READ fileTransfers NOTIFY fileTransfersChanged)
    Q_PROPERTY(int totalUnreadCount READ totalUnreadCount NOTIFY conversationsChanged)
    Q_PROPERTY(int activeFileTransferCount READ activeFileTransferCount NOTIFY fileTransfersChanged)

    // Selected Conversation & Peer Properties (Zone 3 & Zone 4)
    Q_PROPERTY(QString selectedConversationId READ selectedConversationId NOTIFY selectedConversationChanged)
    Q_PROPERTY(QString selectedPeerUserId READ selectedPeerUserId NOTIFY selectedConversationChanged)
    Q_PROPERTY(QString selectedPeerName READ selectedPeerName NOTIFY selectedConversationChanged)
    Q_PROPERTY(QString selectedPeerHandle READ selectedPeerHandle NOTIFY selectedConversationChanged)
    Q_PROPERTY(QString selectedPeerPresence READ selectedPeerPresence NOTIFY selectedConversationChanged)
    Q_PROPERTY(bool selectedPeerVerified READ selectedPeerVerified NOTIFY selectedConversationChanged)
    Q_PROPERTY(bool selectedPeerBlocked READ selectedPeerBlocked NOTIFY selectedConversationChanged)
    Q_PROPERTY(QString selectedPeerSafetyNumber READ selectedPeerSafetyNumber NOTIFY selectedConversationChanged)
    Q_PROPERTY(QString selectedPeerRoleNote READ selectedPeerRoleNote NOTIFY selectedConversationChanged)
    Q_PROPERTY(QVariantList activeMessages READ activeMessages NOTIFY activeMessagesChanged)
    Q_PROPERTY(QVariantList sharedFilesForSelectedPeer READ sharedFilesForSelectedPeer NOTIFY fileTransfersChanged)

    // Selected File Transfer Properties (when activeSection == "Files")
    Q_PROPERTY(QString selectedTransferId READ selectedTransferId NOTIFY selectedTransferChanged)
    Q_PROPERTY(QVariantMap selectedTransferDetails READ selectedTransferDetails NOTIFY selectedTransferChanged)

    // Right-Hand Inspector Drawer State (Zone 4)
    Q_PROPERTY(bool isInspectorOpen READ isInspectorOpen WRITE setInspectorOpen NOTIFY inspectorOpenChanged)

  public:
    WorkspaceViewModel(application::ClientApplication& app, NavigationController& nav_controller,
                       QObject* parent = nullptr);
    ~WorkspaceViewModel() override = default;

    WorkspaceViewModel(const WorkspaceViewModel&) = delete;
    WorkspaceViewModel& operator=(const WorkspaceViewModel&) = delete;

    [[nodiscard]] QString activeSection() const;
    void setActiveSection(const QString& section);

    [[nodiscard]] QString searchQuery() const { return search_query_; }
    void setSearchQuery(const QString& query);

    [[nodiscard]] QVariantList conversations() const;
    [[nodiscard]] QVariantList contacts() const;
    [[nodiscard]] QVariantList fileTransfers() const;
    [[nodiscard]] int totalUnreadCount() const noexcept;
    [[nodiscard]] int activeFileTransferCount() const noexcept;

    [[nodiscard]] QString selectedConversationId() const { return selected_conversation_id_; }
    [[nodiscard]] QString selectedPeerUserId() const;
    [[nodiscard]] QString selectedPeerName() const;
    [[nodiscard]] QString selectedPeerHandle() const;
    [[nodiscard]] QString selectedPeerPresence() const;
    [[nodiscard]] bool selectedPeerVerified() const;
    [[nodiscard]] bool selectedPeerBlocked() const;
    [[nodiscard]] QString selectedPeerSafetyNumber() const;
    [[nodiscard]] QString selectedPeerRoleNote() const;
    [[nodiscard]] QVariantList activeMessages() const;
    [[nodiscard]] QVariantList sharedFilesForSelectedPeer() const;

    [[nodiscard]] QString selectedTransferId() const { return selected_transfer_id_; }
    [[nodiscard]] QVariantMap selectedTransferDetails() const;

    [[nodiscard]] bool isInspectorOpen() const noexcept { return is_inspector_open_; }
    void setInspectorOpen(bool open);

    Q_INVOKABLE void selectConversation(const QString& conversationId);
    Q_INVOKABLE void selectContact(const QString& peerUserId);
    Q_INVOKABLE void selectTransfer(const QString& transferId);
    Q_INVOKABLE void toggleInspector();
    Q_INVOKABLE bool sendMessage(const QString& plaintext);
    Q_INVOKABLE QString stageEncryptedFileTransfer(const QString& fileName, qint64 fileSizeBytes = 2457600);
    Q_INVOKABLE bool cancelFileTransfer(const QString& transferId);
    Q_INVOKABLE void togglePeerVerified(const QString& peerUserId);
    Q_INVOKABLE void togglePeerBlocked(const QString& peerUserId);
    Q_INVOKABLE void resetForEmergencyWipe();

  signals:
    void activeSectionChanged();
    void searchQueryChanged();
    void conversationsChanged();
    void contactsChanged();
    void fileTransfersChanged();
    void selectedConversationChanged();
    void activeMessagesChanged();
    void selectedTransferChanged();
    void inspectorOpenChanged();
    void workspaceError(const QString& message);

  private:
    struct ConversationEntry {
        QString conversationId;
        QString peerUserId;
        QString peerDisplayName;
        QString peerHandle;
        QString presence;
        bool isVerified{false};
        bool isBlocked{false};
        QString safetyNumber;
        QString roleNote;
        QString lastMessagePreview;
        QString timestampText;
        int unreadCount{0};
    };

    struct MessageEntry {
        QString messageId;
        QString conversationId;
        QString senderName;
        bool isSelf{false};
        QString text;
        QString timestampText;
        QString dateGroup;
        QString deliveryState;
        bool isFileTransfer{false};
        QString transferId;
        QString fileName;
        QString fileSizeText;
        QString cipherSuite;
        QString sha256Short;
    };

    struct FileTransferEntry {
        QString transferId;
        QString conversationId;
        QString peerUserId;
        QString peerDisplayName;
        QString fileName;
        qint64 fileSizeBytes{0};
        QString fileSizeText;
        QString cipherSuite;
        QString sha256Short;
        QString direction;  // "Outbound" or "Inbound"
        QString statusText; // "Encrypted & Verified", "Streaming Chunks", "Cancelled"
        QString timestampText;
    };

    void seedDefaultWorkspaceData();
    [[nodiscard]] const ConversationEntry* findConversation(const QString& conversationId) const;
    [[nodiscard]] ConversationEntry* findConversationMutable(const QString& conversationId);
    [[nodiscard]] bool matchesQuery(const QString& candidate) const;
    static QString formatFileSize(qint64 bytes);

    application::ClientApplication& app_;
    NavigationController& nav_controller_;
    QString search_query_;
    QString selected_conversation_id_;
    QString selected_transfer_id_;
    bool is_inspector_open_{true};
    int next_msg_seq_{100};
    int next_file_seq_{10};

    std::vector<ConversationEntry> conversations_;
    std::vector<MessageEntry> messages_;
    std::vector<FileTransferEntry> file_transfers_;
};

} // namespace securecloud::client::ui
