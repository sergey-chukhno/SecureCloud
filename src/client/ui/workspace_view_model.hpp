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

    // Group & Multi-Party Conversation Bindings (CLIENT-004-T02 / CLIENT-004-T04)
    Q_PROPERTY(bool selectedConversationIsGroup READ selectedConversationIsGroup NOTIFY selectedConversationChanged)
    Q_PROPERTY(int selectedConversationParticipantCount READ selectedConversationParticipantCount NOTIFY
                   selectedConversationChanged)
    Q_PROPERTY(int selectedConversationDeviceFanoutCount READ selectedConversationDeviceFanoutCount NOTIFY
                   selectedConversationChanged)
    Q_PROPERTY(QVariantList selectedConversationParticipants READ selectedConversationParticipants NOTIFY
                   selectedConversationChanged)
    Q_PROPERTY(bool selectedGroupAllVerified READ selectedGroupAllVerified NOTIFY selectedConversationChanged)
    Q_PROPERTY(int selectedGroupUnverifiedCount READ selectedGroupUnverifiedCount NOTIFY selectedConversationChanged)

    // ADR-008 Identity Key Change State & Warning Banner (CLIENT-004-T02)
    Q_PROPERTY(bool selectedPeerKeyChanged READ selectedPeerKeyChanged NOTIFY selectedConversationChanged)
    Q_PROPERTY(
        QString selectedPeerKeyChangedHandle READ selectedPeerKeyChangedHandle NOTIFY selectedConversationChanged)

    // ADR-007 Emergency Acknowledgement & Status (CLIENT-004-T02)
    Q_PROPERTY(int unacknowledgedEmergencyCount READ unacknowledgedEmergencyCount NOTIFY selectedConversationChanged)
    Q_PROPERTY(bool isLoadingMessages READ isLoadingMessages NOTIFY loadingMessagesChanged)
    Q_PROPERTY(bool deliveryFailureSimulated READ deliveryFailureSimulated WRITE setDeliveryFailureSimulated NOTIFY
                   deliveryFailureSimulatedChanged)

    // Selected File Transfer Properties (when activeSection == "Files")
    Q_PROPERTY(QString selectedTransferId READ selectedTransferId NOTIFY selectedTransferChanged)
    Q_PROPERTY(QVariantMap selectedTransferDetails READ selectedTransferDetails NOTIFY selectedTransferChanged)

    // Right-Hand Inspector Drawer State (Zone 4)
    Q_PROPERTY(bool isInspectorOpen READ isInspectorOpen WRITE setInspectorOpen NOTIFY inspectorOpenChanged)

    // Outbound Composer Priority State (ADR-007: 1 = Normal, 2 = Urgent, 3 = Emergency)
    Q_PROPERTY(int composerPriority READ composerPriority WRITE setComposerPriority NOTIFY composerPriorityChanged)
    Q_PROPERTY(QString composerPriorityLabel READ composerPriorityLabel NOTIFY composerPriorityChanged)

    // Device Trust, Crypto Identity & MFA Policy State (Settings View)
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    Q_PROPERTY(int pendingDeviceCount READ pendingDeviceCount NOTIFY devicesChanged)
    Q_PROPERTY(QVariantMap localDeviceIdentity READ localDeviceIdentity NOTIFY localDeviceIdentityChanged)
    Q_PROPERTY(int prekeyCount READ prekeyCount NOTIFY localDeviceIdentityChanged)
    Q_PROPERTY(QString prekeyHealthStatus READ prekeyHealthStatus NOTIFY localDeviceIdentityChanged)
    Q_PROPERTY(bool mfaRequiredOnLogin READ mfaRequiredOnLogin WRITE setMfaRequiredOnLogin NOTIFY mfaPolicyChanged)
    Q_PROPERTY(bool hardwareKeyEnforced READ hardwareKeyEnforced WRITE setHardwareKeyEnforced NOTIFY mfaPolicyChanged)
    Q_PROPERTY(QString totpEnrollmentSecret READ totpEnrollmentSecret NOTIFY mfaPolicyChanged)

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

    // Group & Multi-Party Conversation Getters (CLIENT-004-T02)
    [[nodiscard]] bool selectedConversationIsGroup() const;
    [[nodiscard]] int selectedConversationParticipantCount() const;
    [[nodiscard]] int selectedConversationDeviceFanoutCount() const;
    [[nodiscard]] QVariantList selectedConversationParticipants() const;
    [[nodiscard]] bool selectedGroupAllVerified() const;
    [[nodiscard]] int selectedGroupUnverifiedCount() const;

    // ADR-008 Key Changed & Emergency State Getters
    [[nodiscard]] bool selectedPeerKeyChanged() const;
    [[nodiscard]] QString selectedPeerKeyChangedHandle() const;
    [[nodiscard]] int unacknowledgedEmergencyCount() const;
    [[nodiscard]] bool isLoadingMessages() const noexcept { return is_loading_messages_; }
    [[nodiscard]] bool deliveryFailureSimulated() const noexcept { return delivery_failure_simulated_; }
    void setDeliveryFailureSimulated(bool simulated);

    [[nodiscard]] QString selectedTransferId() const { return selected_transfer_id_; }
    [[nodiscard]] QVariantMap selectedTransferDetails() const;

    [[nodiscard]] bool isInspectorOpen() const noexcept { return is_inspector_open_; }
    Q_INVOKABLE void setInspectorOpen(bool open);

    [[nodiscard]] int composerPriority() const noexcept { return composer_priority_; }
    void setComposerPriority(int priority);
    [[nodiscard]] QString composerPriorityLabel() const;
    Q_INVOKABLE void cycleComposerPriority();

    [[nodiscard]] QVariantList devices() const;
    [[nodiscard]] int pendingDeviceCount() const noexcept;
    [[nodiscard]] QVariantMap localDeviceIdentity() const;
    [[nodiscard]] int prekeyCount() const noexcept { return local_prekey_count_; }
    [[nodiscard]] QString prekeyHealthStatus() const { return local_prekey_health_; }
    [[nodiscard]] bool mfaRequiredOnLogin() const noexcept { return mfa_required_on_login_; }
    void setMfaRequiredOnLogin(bool required);
    [[nodiscard]] bool hardwareKeyEnforced() const noexcept { return hardware_key_enforced_; }
    void setHardwareKeyEnforced(bool enforced);
    [[nodiscard]] QString totpEnrollmentSecret() const { return totp_enrollment_secret_; }

    // Existing Invokables
    Q_INVOKABLE void selectConversation(const QString& conversationId);
    Q_INVOKABLE void selectContact(const QString& peerUserId);
    Q_INVOKABLE void selectTransfer(const QString& transferId);
    Q_INVOKABLE void toggleInspector();
    Q_INVOKABLE bool sendMessage(const QString& plaintext, int priority = 0);
    Q_INVOKABLE QString stageEncryptedFileTransfer(const QString& fileName, qint64 fileSizeBytes = 2457600);
    Q_INVOKABLE bool cancelFileTransfer(const QString& transferId);
    Q_INVOKABLE void togglePeerVerified(const QString& peerUserId);
    Q_INVOKABLE void togglePeerBlocked(const QString& peerUserId);
    Q_INVOKABLE bool approveDevice(const QString& deviceId);
    Q_INVOKABLE bool revokeDevice(const QString& deviceId);
    Q_INVOKABLE QString pairNewDevice(const QString& displayName);
    Q_INVOKABLE void rotateSignedPrekey();
    Q_INVOKABLE void refreshPrekeyInventory();
    Q_INVOKABLE bool replenishPrekeys(int batchSize = 50);
    Q_INVOKABLE void regenerateTotpSecret();
    Q_INVOKABLE void resetForEmergencyWipe();

    // New Invokables for CLIENT-004-T02
    // Contacts Directory Management
    Q_INVOKABLE bool addContact(const QString& handle, const QString& displayName, const QString& roleNote,
                                const QString& safetyNumber = QString());
    Q_INVOKABLE bool updateContactProfile(const QString& userId, const QString& displayName, const QString& roleNote);
    Q_INVOKABLE bool removeContact(const QString& userId);
    Q_INVOKABLE void simulatePeerKeyChange(const QString& userId);
    Q_INVOKABLE void acceptAndVerifyPeerKey(const QString& userId);

    // Group Conversations Management
    Q_INVOKABLE QString createDirectConversation(const QString& peerUserId);
    Q_INVOKABLE QString createGroupConversation(const QString& groupTitle, const QVariantList& participantUserIds);
    Q_INVOKABLE bool addParticipantToActiveGroup(const QString& userId);
    Q_INVOKABLE bool removeParticipantFromActiveGroup(const QString& userId);
    Q_INVOKABLE bool leaveActiveGroup();

    // Message Retry & Emergency Acknowledgement
    Q_INVOKABLE bool retryFailedMessage(const QString& messageId);
    Q_INVOKABLE bool discardFailedMessage(const QString& messageId);
    Q_INVOKABLE void setSimulateDeliveryFailure(bool enabled);
    Q_INVOKABLE bool acknowledgeEmergencyMessage(const QString& messageId);
    Q_INVOKABLE void clearSearchQuery();

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
    void composerPriorityChanged();
    void devicesChanged();
    void localDeviceIdentityChanged();
    void mfaPolicyChanged();
    void loadingMessagesChanged();
    void deliveryFailureSimulatedChanged();
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
        int lastMessagePriority{1}; // 1 = Normal, 2 = Urgent, 3 = Emergency
        bool isGroup{false};
        std::vector<QString> participantUserIds;
        int authorizedDeviceCount{1};
        QString verificationStatus{QStringLiteral("Verified")};
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
        int priority{1}; // 1 = Normal, 2 = Urgent, 3 = Emergency
        QString idempotencyKey;
        bool emergencyAcknowledged{false};
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

    struct DeviceEntry {
        QString deviceId;
        QString displayName;
        QString platformInfo;
        QString identityKeyHex;
        QString fingerprint;
        QString signedPrekeyId;
        QString prekeySignatureHex;
        QString status; // "Authorized", "Pending", "Revoked"
        QString lastSeenText;
        bool isCurrentDevice{false};
        bool isVerified{false};
    };

    void seedDefaultWorkspaceData();
    [[nodiscard]] const ConversationEntry* findConversation(const QString& conversationId) const;
    [[nodiscard]] ConversationEntry* findConversationMutable(const QString& conversationId);
    [[nodiscard]] bool matchesQuery(const QString& candidate) const;
    static QString formatFileSize(qint64 bytes);
    static QString priorityToLabel(int priority);

    application::ClientApplication& app_;
    NavigationController& nav_controller_;
    QString search_query_;
    QString selected_conversation_id_;
    QString selected_transfer_id_;
    bool is_inspector_open_{true};
    int composer_priority_{1};
    int next_msg_seq_{100};
    int next_file_seq_{10};
    int next_device_seq_{4};
    int prekey_epoch_{14};
    int local_prekey_count_{100};
    QString local_prekey_health_{QStringLiteral("Healthy")};
    bool mfa_required_on_login_{true};
    bool hardware_key_enforced_{true};
    bool is_loading_messages_{false};
    bool delivery_failure_simulated_{false};
    QString totp_enrollment_secret_{QStringLiteral("JBSWY3DPEHPK3PXP · SHA-256 (6-digit / 30s)")};

    std::vector<ConversationEntry> conversations_;
    std::vector<MessageEntry> messages_;
    std::vector<FileTransferEntry> file_transfers_;
    std::vector<DeviceEntry> devices_;
};

} // namespace securecloud::client::ui
