#include "ui/workspace_view_model.hpp"

#include "domain/contact.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

namespace securecloud::client::ui {

WorkspaceViewModel::WorkspaceViewModel(application::ClientApplication& app, NavigationController& nav_controller,
                                       QObject* parent)
    : QObject(parent), app_(app), nav_controller_(nav_controller) {
    connect(&nav_controller_, &NavigationController::workspaceSectionChanged, this,
            [this](const QString&) { emit activeSectionChanged(); });
    seedDefaultWorkspaceData();
}

void WorkspaceViewModel::seedDefaultWorkspaceData() {
    conversations_.clear();
    messages_.clear();
    file_transfers_.clear();
    devices_.clear();

    // Seed realistic security workstation contacts & conversations
    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-frances"), QStringLiteral("frances.swann@securecloud.org"),
        QStringLiteral("Frances Swann"), QStringLiteral("@frances.swann"), QStringLiteral("Online"), true, false,
        QStringLiteral("49281 04829 88310 77241 66109 31204"),
        QStringLiteral("Principal Cryptographic Architect · Key rotation policy enforced (Double Ratchet v2)."),
        QStringLiteral("YOU: Architecture blueprint & key schedule approved."), QStringLiteral("Yesterday"), 0, 1});

    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-angelina"), QStringLiteral("angelina.froster@securecloud.org"),
        QStringLiteral("Angelina Froster"), QStringLiteral("@angelina.froster"), QStringLiteral("Online"), true, false,
        QStringLiteral("81726 39104 55291 00918 44127 98312"),
        QStringLiteral("Incident Response Lead · Hardware security key verified via out-of-band fingerprint."),
        QStringLiteral("Uploaded threats-q4-report.pdf (AES-256-GCM)"), QStringLiteral("1 min ago"), 2, 3});

    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-ricky"), QStringLiteral("ricky.smith@securecloud.org"), QStringLiteral("Ricky Smith"),
        QStringLiteral("@ricky.smith"), QStringLiteral("Busy"), true, false,
        QStringLiteral("72019 48201 99182 33410 11294 65018"),
        QStringLiteral("Security Operations Engineer · Gateway TLS 1.3 mTLS certificate custodian."),
        QStringLiteral("Prekey bundle refreshed for workstation node-04."), QStringLiteral("Jan 02"), 0, 1});

    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-corina"), QStringLiteral("corina.mccoy@securecloud.org"), QStringLiteral("Corina McCoy"),
        QStringLiteral("@corina.mccoy"), QStringLiteral("Offline"), false, false,
        QStringLiteral("10928 38471 66251 89201 44712 09182"),
        QStringLiteral("External Security Auditor · Safety number pending out-of-band verification."),
        QStringLiteral("Key exchange pending safety number check..."), QStringLiteral("Jan 01"), 1, 2});

    conversations_.push_back(
        ConversationEntry{QStringLiteral("conv-daniel"), QStringLiteral("daniel.hamilton@securecloud.org"),
                          QStringLiteral("Daniel Hamilton"), QStringLiteral("@daniel.hamilton"),
                          QStringLiteral("Offline"), true, false, QStringLiteral("55412 90812 31459 77812 00192 84711"),
                          QStringLiteral("Distributed Storage Engineer · Chunked AEAD file vault maintainer."),
                          QStringLiteral("YOU: All 64 encrypted chunks verified."), QStringLiteral("Dec 23"), 0, 1});

    // Persist contacts into ContactManager
    for (const auto& conv : conversations_) {
        const domain::Contact contact(domain::UserId(conv.peerUserId.toStdString()), conv.peerDisplayName.toStdString(),
                                      conv.isVerified ? domain::KeyVerificationStatus::Verified
                                                      : domain::KeyVerificationStatus::Unverified,
                                      conv.safetyNumber.toStdString(), conv.isBlocked);
        (void)app_.bootstrap().contact_manager().add_or_update_contact(contact);
    }

    // Seed messages for Frances Swann (default selected conversation)
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-1"), QStringLiteral("conv-frances"), QStringLiteral("Frances Swann"), false,
        QStringLiteral("Hi! Have you reviewed the Double Ratchet session key schedule for the desktop workspace?"),
        QStringLiteral("11:00 AM"), QStringLiteral("YESTERDAY"), QStringLiteral("Delivered"), false, QString(),
        QString(), QString(), QString(), QString(), 2});

    messages_.push_back(MessageEntry{
        QStringLiteral("msg-2"), QStringLiteral("conv-frances"), QStringLiteral("You"), true,
        QStringLiteral("Yes — verified the X3DH prekey signatures and chunked file encryption parameters."),
        QStringLiteral("11:02 AM"), QStringLiteral("YESTERDAY"), QStringLiteral("Read"), false, QString(), QString(),
        QString(), QString(), QString(), 1});

    messages_.push_back(MessageEntry{
        QStringLiteral("msg-3"), QStringLiteral("conv-frances"), QStringLiteral("Frances Swann"), false,
        QStringLiteral("Encrypted File Attachment"), QStringLiteral("11:05 AM"), QStringLiteral("YESTERDAY"),
        QStringLiteral("Verified"), true, QStringLiteral("tx-001"), QStringLiteral("zero-trust-key-schedule-v2.pdf"),
        QStringLiteral("2.4 MB"), QStringLiteral("AES-256-GCM"), QStringLiteral("9f86d081...b0f00a08"), 1});

    messages_.push_back(MessageEntry{QStringLiteral("msg-4"), QStringLiteral("conv-frances"), QStringLiteral("You"),
                                     true, QStringLiteral("Architecture blueprint & key schedule approved."),
                                     QStringLiteral("11:08 AM"), QStringLiteral("TODAY"), QStringLiteral("Read"), false,
                                     QString(), QString(), QString(), QString(), QString(), 1});

    // Seed messages for Angelina Froster (Emergency Priority)
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-5"), QStringLiteral("conv-angelina"), QStringLiteral("Angelina Froster"), false,
        QStringLiteral(
            "Compromised edge relay certificate detected on node-eu-west-2 — rotate ephemeral ratchets immediately."),
        QStringLiteral("12:40 PM"), QStringLiteral("TODAY"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 3});

    messages_.push_back(MessageEntry{
        QStringLiteral("msg-6"), QStringLiteral("conv-angelina"), QStringLiteral("Angelina Froster"), false,
        QStringLiteral("Encrypted File Attachment"), QStringLiteral("12:41 PM"), QStringLiteral("TODAY"),
        QStringLiteral("Verified"), true, QStringLiteral("tx-002"), QStringLiteral("threats-q4-report.pdf"),
        QStringLiteral("4.8 MB"), QStringLiteral("AES-256-GCM"), QStringLiteral("4a7d1ed4...91e83b2c"), 3});

    // Seed messages for Ricky Smith
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-7"), QStringLiteral("conv-ricky"), QStringLiteral("Ricky Smith"), false,
        QStringLiteral("Prekey bundle refreshed for workstation node-04. mTLS pinning fingerprint matches enclave."),
        QStringLiteral("09:15 AM"), QStringLiteral("JAN 02"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 1});

    // Seed messages for Corina McCoy (Urgent Priority)
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-8"), QStringLiteral("conv-corina"), QStringLiteral("Corina McCoy"), false,
        QStringLiteral(
            "Key exchange pending out-of-band safety number verification before we sign off on the Q1 audit."),
        QStringLiteral("04:30 PM"), QStringLiteral("JAN 01"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 2});

    // Seed messages for Daniel Hamilton
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-9"), QStringLiteral("conv-daniel"), QStringLiteral("You"), true,
        QStringLiteral("All 64 encrypted chunks verified against SHA-256 manifest in the distributed storage vault."),
        QStringLiteral("06:12 PM"), QStringLiteral("DEC 23"), QStringLiteral("Read"), false, QString(), QString(),
        QString(), QString(), QString(), 1});

    // Seed encrypted file transfers
    file_transfers_.push_back(FileTransferEntry{
        QStringLiteral("tx-001"), QStringLiteral("conv-frances"), QStringLiteral("frances.swann@securecloud.org"),
        QStringLiteral("Frances Swann"), QStringLiteral("zero-trust-key-schedule-v2.pdf"), 2516582,
        QStringLiteral("2.4 MB"), QStringLiteral("AES-256-GCM"), QStringLiteral("9f86d081...b0f00a08"),
        QStringLiteral("Inbound"), QStringLiteral("Encrypted & Verified"), QStringLiteral("Yesterday · 11:05 AM")});

    file_transfers_.push_back(FileTransferEntry{
        QStringLiteral("tx-002"), QStringLiteral("conv-angelina"), QStringLiteral("angelina.froster@securecloud.org"),
        QStringLiteral("Angelina Froster"), QStringLiteral("threats-q4-report.pdf"), 5033164, QStringLiteral("4.8 MB"),
        QStringLiteral("AES-256-GCM"), QStringLiteral("4a7d1ed4...91e83b2c"), QStringLiteral("Inbound"),
        QStringLiteral("Encrypted & Verified"), QStringLiteral("Today · 12:41 PM")});

    file_transfers_.push_back(FileTransferEntry{
        QStringLiteral("tx-003"), QStringLiteral("conv-frances"), QStringLiteral("frances.swann@securecloud.org"),
        QStringLiteral("Frances Swann"), QStringLiteral("enclave-attestation-bundle.tar.enc"), 1468006,
        QStringLiteral("1.4 MB"), QStringLiteral("AES-256-GCM"), QStringLiteral("7c211433...f89a1c44"),
        QStringLiteral("Outbound"), QStringLiteral("Encrypted & Verified"), QStringLiteral("Today · 09:15 AM")});

    // Seed operator devices & cryptographic identities
    devices_.push_back(DeviceEntry{QStringLiteral("dev-local-01"), QStringLiteral("SecOps Workstation · macOS"),
                                   QStringLiteral("Apple M-Series Secure Enclave · TLS 1.3 mTLS"),
                                   QStringLiteral("ED25519-PUB-9F86D081884C7D659A2FEAA0C55AD015"),
                                   QStringLiteral("7F8A 9B2C 1E4D 6610 9981 3042 5519 A8C1"),
                                   QStringLiteral("SPK-X25519-0014"), QStringLiteral("SIG-ED25519-4419A8B2...C901E24F"),
                                   QStringLiteral("Authorized"), QStringLiteral("Active now (Current Device)"), true,
                                   false});

    devices_.push_back(DeviceEntry{QStringLiteral("dev-mobile-02"), QStringLiteral("Field Enclave Handset · iOS 18"),
                                   QStringLiteral("Hardware Key Attested · X3DH Prekey v2"),
                                   QStringLiteral("ED25519-PUB-4A7D1ED414474E4033AC29CCB8653D9B"),
                                   QStringLiteral("3C11 89A0 4421 7B1E 0092 8411 6E20 F112"),
                                   QStringLiteral("SPK-X25519-0009"), QStringLiteral("SIG-ED25519-8812F004...11B9A231"),
                                   QStringLiteral("Authorized"), QStringLiteral("Today · 10:14 AM"), false, true});

    devices_.push_back(DeviceEntry{QStringLiteral("dev-audit-03"), QStringLiteral("Air-Gapped Audit Terminal · Linux"),
                                   QStringLiteral("Awaiting Out-of-Band Safety Number Approval"),
                                   QStringLiteral("ED25519-PUB-7C211433F02071597741E6FF5A8EA347"),
                                   QStringLiteral("9012 44A1 77C3 109B 55D2 88E1 0491 C77A"),
                                   QStringLiteral("SPK-X25519-0001"), QStringLiteral("SIG-ED25519-1904C221...77E8A012"),
                                   QStringLiteral("Pending"), QStringLiteral("Requested 4 mins ago"), false, false});

    selected_conversation_id_ = QStringLiteral("conv-frances");
    selected_transfer_id_ = QStringLiteral("tx-001");
}

QString WorkspaceViewModel::activeSection() const {
    return nav_controller_.activeWorkspaceSection();
}

void WorkspaceViewModel::setActiveSection(const QString& section) {
    (void)nav_controller_.navigateToSection(section);
}

void WorkspaceViewModel::setSearchQuery(const QString& query) {
    if (search_query_ == query) {
        return;
    }
    search_query_ = query;
    emit searchQueryChanged();
    emit conversationsChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
}

bool WorkspaceViewModel::matchesQuery(const QString& candidate) const {
    const QString trimmed = search_query_.trimmed();
    if (trimmed.isEmpty()) {
        return true;
    }
    return candidate.contains(trimmed, Qt::CaseInsensitive);
}

QString WorkspaceViewModel::priorityToLabel(int priority) {
    if (priority == 3) {
        return QStringLiteral("Emergency");
    }
    if (priority == 2) {
        return QStringLiteral("Urgent");
    }
    return QStringLiteral("Normal");
}

QVariantList WorkspaceViewModel::conversations() const {
    QVariantList result;
    for (const auto& conv : conversations_) {
        const QString priorityStr = priorityToLabel(conv.lastMessagePriority);
        if (!matchesQuery(conv.peerDisplayName) && !matchesQuery(conv.peerHandle) &&
            !matchesQuery(conv.lastMessagePreview) && !matchesQuery(priorityStr)) {
            continue;
        }
        QVariantMap item;
        item.insert(QStringLiteral("conversationId"), conv.conversationId);
        item.insert(QStringLiteral("peerUserId"), conv.peerUserId);
        item.insert(QStringLiteral("peerDisplayName"), conv.peerDisplayName);
        item.insert(QStringLiteral("peerHandle"), conv.peerHandle);
        item.insert(QStringLiteral("presence"), conv.presence);
        item.insert(QStringLiteral("isVerified"), conv.isVerified);
        item.insert(QStringLiteral("isBlocked"), conv.isBlocked);
        item.insert(QStringLiteral("safetyNumber"), conv.safetyNumber);
        item.insert(QStringLiteral("lastMessagePreview"), conv.lastMessagePreview);
        item.insert(QStringLiteral("timestampText"), conv.timestampText);
        item.insert(QStringLiteral("unreadCount"), conv.unreadCount);
        item.insert(QStringLiteral("priority"), conv.lastMessagePriority);
        item.insert(QStringLiteral("priorityLabel"), priorityStr);
        item.insert(QStringLiteral("isSelected"), conv.conversationId == selected_conversation_id_);
        result.append(item);
    }
    return result;
}

QVariantList WorkspaceViewModel::contacts() const {
    QVariantList result;
    for (const auto& conv : conversations_) {
        if (!matchesQuery(conv.peerDisplayName) && !matchesQuery(conv.peerHandle) && !matchesQuery(conv.roleNote)) {
            continue;
        }
        QVariantMap item;
        item.insert(QStringLiteral("userId"), conv.peerUserId);
        item.insert(QStringLiteral("displayName"), conv.peerDisplayName);
        item.insert(QStringLiteral("handle"), conv.peerHandle);
        item.insert(QStringLiteral("presence"), conv.presence);
        item.insert(QStringLiteral("isVerified"), conv.isVerified);
        item.insert(QStringLiteral("isBlocked"), conv.isBlocked);
        item.insert(QStringLiteral("safetyNumber"), conv.safetyNumber);
        item.insert(QStringLiteral("roleNote"), conv.roleNote);
        item.insert(QStringLiteral("conversationId"), conv.conversationId);
        item.insert(QStringLiteral("isSelected"), conv.conversationId == selected_conversation_id_);
        result.append(item);
    }
    return result;
}

QVariantList WorkspaceViewModel::fileTransfers() const {
    QVariantList result;
    for (const auto& tx : file_transfers_) {
        if (!matchesQuery(tx.fileName) && !matchesQuery(tx.peerDisplayName) && !matchesQuery(tx.cipherSuite) &&
            !matchesQuery(tx.statusText)) {
            continue;
        }
        QVariantMap item;
        item.insert(QStringLiteral("transferId"), tx.transferId);
        item.insert(QStringLiteral("conversationId"), tx.conversationId);
        item.insert(QStringLiteral("peerUserId"), tx.peerUserId);
        item.insert(QStringLiteral("peerDisplayName"), tx.peerDisplayName);
        item.insert(QStringLiteral("fileName"), tx.fileName);
        item.insert(QStringLiteral("fileSizeBytes"), tx.fileSizeBytes);
        item.insert(QStringLiteral("fileSizeText"), tx.fileSizeText);
        item.insert(QStringLiteral("cipherSuite"), tx.cipherSuite);
        item.insert(QStringLiteral("sha256Short"), tx.sha256Short);
        item.insert(QStringLiteral("direction"), tx.direction);
        item.insert(QStringLiteral("statusText"), tx.statusText);
        item.insert(QStringLiteral("timestampText"), tx.timestampText);
        item.insert(QStringLiteral("isSelected"), tx.transferId == selected_transfer_id_);
        result.append(item);
    }
    return result;
}

int WorkspaceViewModel::totalUnreadCount() const noexcept {
    int total = 0;
    for (const auto& conv : conversations_) {
        total += conv.unreadCount;
    }
    return total;
}

int WorkspaceViewModel::activeFileTransferCount() const noexcept {
    return static_cast<int>(file_transfers_.size());
}

const WorkspaceViewModel::ConversationEntry* WorkspaceViewModel::findConversation(const QString& conversationId) const {
    for (const auto& conv : conversations_) {
        if (conv.conversationId == conversationId) {
            return &conv;
        }
    }
    return conversations_.empty() ? nullptr : &conversations_.front();
}

WorkspaceViewModel::ConversationEntry* WorkspaceViewModel::findConversationMutable(const QString& conversationId) {
    for (auto& conv : conversations_) {
        if (conv.conversationId == conversationId) {
            return &conv;
        }
    }
    return conversations_.empty() ? nullptr : &conversations_.front();
}

QString WorkspaceViewModel::selectedPeerUserId() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->peerUserId : QString();
}

QString WorkspaceViewModel::selectedPeerName() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->peerDisplayName : QStringLiteral("No Contact Selected");
}

QString WorkspaceViewModel::selectedPeerHandle() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->peerHandle : QString();
}

QString WorkspaceViewModel::selectedPeerPresence() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->presence : QStringLiteral("Offline");
}

bool WorkspaceViewModel::selectedPeerVerified() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->isVerified : false;
}

bool WorkspaceViewModel::selectedPeerBlocked() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->isBlocked : false;
}

QString WorkspaceViewModel::selectedPeerSafetyNumber() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->safetyNumber : QString();
}

QString WorkspaceViewModel::selectedPeerRoleNote() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->roleNote : QString();
}

QVariantList WorkspaceViewModel::activeMessages() const {
    QVariantList result;
    QString lastDateGroup;
    for (const auto& msg : messages_) {
        if (msg.conversationId != selected_conversation_id_) {
            continue;
        }
        const bool showDateSep = !msg.dateGroup.isEmpty() && (msg.dateGroup != lastDateGroup);
        lastDateGroup = msg.dateGroup;

        QVariantMap item;
        item.insert(QStringLiteral("messageId"), msg.messageId);
        item.insert(QStringLiteral("conversationId"), msg.conversationId);
        item.insert(QStringLiteral("senderName"), msg.senderName);
        item.insert(QStringLiteral("isSelf"), msg.isSelf);
        item.insert(QStringLiteral("text"), msg.text);
        item.insert(QStringLiteral("timestampText"), msg.timestampText);
        item.insert(QStringLiteral("dateGroup"), msg.dateGroup);
        item.insert(QStringLiteral("showDateSeparator"), showDateSep);
        item.insert(QStringLiteral("deliveryState"), msg.deliveryState);
        item.insert(QStringLiteral("isFileTransfer"), msg.isFileTransfer);
        item.insert(QStringLiteral("transferId"), msg.transferId);
        item.insert(QStringLiteral("fileName"), msg.fileName);
        item.insert(QStringLiteral("fileSizeText"), msg.fileSizeText);
        item.insert(QStringLiteral("cipherSuite"), msg.cipherSuite);
        item.insert(QStringLiteral("sha256Short"), msg.sha256Short);
        item.insert(QStringLiteral("priority"), msg.priority);
        item.insert(QStringLiteral("priorityLabel"), priorityToLabel(msg.priority));
        result.append(item);
    }
    return result;
}

QVariantList WorkspaceViewModel::sharedFilesForSelectedPeer() const {
    QVariantList result;
    for (const auto& tx : file_transfers_) {
        if (tx.conversationId != selected_conversation_id_) {
            continue;
        }
        QVariantMap item;
        item.insert(QStringLiteral("transferId"), tx.transferId);
        item.insert(QStringLiteral("fileName"), tx.fileName);
        item.insert(QStringLiteral("fileSizeText"), tx.fileSizeText);
        item.insert(QStringLiteral("cipherSuite"), tx.cipherSuite);
        item.insert(QStringLiteral("sha256Short"), tx.sha256Short);
        item.insert(QStringLiteral("direction"), tx.direction);
        item.insert(QStringLiteral("statusText"), tx.statusText);
        item.insert(QStringLiteral("timestampText"), tx.timestampText);
        result.append(item);
    }
    return result;
}

QVariantMap WorkspaceViewModel::selectedTransferDetails() const {
    QVariantMap item;
    for (const auto& tx : file_transfers_) {
        if (tx.transferId == selected_transfer_id_) {
            item.insert(QStringLiteral("transferId"), tx.transferId);
            item.insert(QStringLiteral("conversationId"), tx.conversationId);
            item.insert(QStringLiteral("peerUserId"), tx.peerUserId);
            item.insert(QStringLiteral("peerDisplayName"), tx.peerDisplayName);
            item.insert(QStringLiteral("fileName"), tx.fileName);
            item.insert(QStringLiteral("fileSizeBytes"), tx.fileSizeBytes);
            item.insert(QStringLiteral("fileSizeText"), tx.fileSizeText);
            item.insert(QStringLiteral("cipherSuite"), tx.cipherSuite);
            item.insert(QStringLiteral("sha256Short"), tx.sha256Short);
            item.insert(QStringLiteral("direction"), tx.direction);
            item.insert(QStringLiteral("statusText"), tx.statusText);
            item.insert(QStringLiteral("timestampText"), tx.timestampText);
            return item;
        }
    }
    return item;
}

void WorkspaceViewModel::setInspectorOpen(bool open) {
    if (is_inspector_open_ == open) {
        return;
    }
    is_inspector_open_ = open;
    emit inspectorOpenChanged();
}

void WorkspaceViewModel::toggleInspector() {
    setInspectorOpen(!is_inspector_open_);
}

void WorkspaceViewModel::setComposerPriority(int priority) {
    const int clamped = (priority < 1 || priority > 3) ? 1 : priority;
    if (composer_priority_ == clamped) {
        return;
    }
    composer_priority_ = clamped;
    emit composerPriorityChanged();
}

QString WorkspaceViewModel::composerPriorityLabel() const {
    return priorityToLabel(composer_priority_);
}

void WorkspaceViewModel::cycleComposerPriority() {
    const int next = (composer_priority_ % 3) + 1;
    setComposerPriority(next);
}

QVariantList WorkspaceViewModel::devices() const {
    QVariantList result;
    for (const auto& dev : devices_) {
        QVariantMap item;
        item.insert(QStringLiteral("deviceId"), dev.deviceId);
        item.insert(QStringLiteral("displayName"), dev.displayName);
        item.insert(QStringLiteral("platformInfo"), dev.platformInfo);
        item.insert(QStringLiteral("identityKeyHex"), dev.identityKeyHex);
        item.insert(QStringLiteral("fingerprint"), dev.fingerprint);
        item.insert(QStringLiteral("signedPrekeyId"), dev.signedPrekeyId);
        item.insert(QStringLiteral("prekeySignatureHex"), dev.prekeySignatureHex);
        item.insert(QStringLiteral("status"), dev.status);
        item.insert(QStringLiteral("lastSeenText"), dev.lastSeenText);
        item.insert(QStringLiteral("isCurrentDevice"), dev.isCurrentDevice);
        item.insert(QStringLiteral("isVerified"), dev.isVerified);
        result.append(item);
    }
    return result;
}

int WorkspaceViewModel::pendingDeviceCount() const noexcept {
    int count = 0;
    for (const auto& dev : devices_) {
        if (dev.status == QStringLiteral("Pending")) {
            ++count;
        }
    }
    return count;
}

QVariantMap WorkspaceViewModel::localDeviceIdentity() const {
    QVariantMap item;
    for (const auto& dev : devices_) {
        if (dev.isCurrentDevice) {
            item.insert(QStringLiteral("deviceId"), dev.deviceId);
            item.insert(QStringLiteral("displayName"), dev.displayName);
            item.insert(QStringLiteral("platformInfo"), dev.platformInfo);
            item.insert(QStringLiteral("identityKeyHex"), dev.identityKeyHex);
            item.insert(QStringLiteral("fingerprint"), dev.fingerprint);
            item.insert(QStringLiteral("signedPrekeyId"), dev.signedPrekeyId);
            item.insert(QStringLiteral("prekeySignatureHex"), dev.prekeySignatureHex);
            item.insert(QStringLiteral("status"), dev.status);
            item.insert(QStringLiteral("isVerified"), dev.isVerified);
            return item;
        }
    }
    return item;
}

void WorkspaceViewModel::setMfaRequiredOnLogin(bool required) {
    if (mfa_required_on_login_ == required) {
        return;
    }
    mfa_required_on_login_ = required;
    emit mfaPolicyChanged();
}

void WorkspaceViewModel::setHardwareKeyEnforced(bool enforced) {
    if (hardware_key_enforced_ == enforced) {
        return;
    }
    hardware_key_enforced_ = enforced;
    emit mfaPolicyChanged();
}

void WorkspaceViewModel::selectConversation(const QString& conversationId) {
    auto* conv = findConversationMutable(conversationId);
    if (!conv) {
        return;
    }
    selected_conversation_id_ = conv->conversationId;
    if (conv->unreadCount > 0) {
        conv->unreadCount = 0;
    }
    emit selectedConversationChanged();
    emit activeMessagesChanged();
    emit conversationsChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
}

void WorkspaceViewModel::selectContact(const QString& peerUserId) {
    for (const auto& conv : conversations_) {
        if (conv.peerUserId == peerUserId) {
            selectConversation(conv.conversationId);
            return;
        }
    }
}

void WorkspaceViewModel::selectTransfer(const QString& transferId) {
    if (selected_transfer_id_ == transferId) {
        return;
    }
    for (const auto& tx : file_transfers_) {
        if (tx.transferId == transferId) {
            selected_transfer_id_ = transferId;
            emit selectedTransferChanged();
            emit fileTransfersChanged();
            return;
        }
    }
}

bool WorkspaceViewModel::sendMessage(const QString& plaintext, int priority) {
    const QString trimmed = plaintext.trimmed();
    if (trimmed.isEmpty()) {
        return false;
    }

    auto* conv = findConversationMutable(selected_conversation_id_);
    if (!conv) {
        return false;
    }
    if (conv->isBlocked) {
        emit workspaceError(QStringLiteral("Cannot send message: peer keys are blocked."));
        return false;
    }

    const int effectivePriority = (priority >= 1 && priority <= 3) ? priority : composer_priority_;

    const auto& currentUserId = app_.bootstrap().auth_manager().current_user();
    const domain::UserId senderId =
        currentUserId.value().empty() ? domain::UserId("operator@securecloud.org") : currentUserId;

    const auto sendRes = app_.bootstrap().messaging_manager().send_message(
        domain::ConversationId(conv->conversationId.toStdString()), senderId, domain::DeviceId("dev-local-01"),
        domain::DeviceId("dev-peer-01"), trimmed.toStdString());

    if (sendRes.is_error()) {
        emit workspaceError(QString::fromStdString(sendRes.error().user_message()));
        return false;
    }

    const QString msgId = QStringLiteral("msg-%1").arg(++next_msg_seq_);
    messages_.push_back(MessageEntry{msgId, conv->conversationId, QStringLiteral("You"), true, trimmed,
                                     QStringLiteral("Just now"), QStringLiteral("TODAY"), QStringLiteral("Encrypted"),
                                     false, QString(), QString(), QString(), QString(), QString(), effectivePriority});

    conv->lastMessagePreview = QStringLiteral("YOU: %1").arg(trimmed);
    conv->timestampText = QStringLiteral("Just now");
    conv->lastMessagePriority = effectivePriority;

    if (composer_priority_ != 1) {
        composer_priority_ = 1;
        emit composerPriorityChanged();
    }

    emit activeMessagesChanged();
    emit conversationsChanged();
    return true;
}

QString WorkspaceViewModel::formatFileSize(qint64 bytes) {
    if (bytes >= 1024 * 1024) {
        const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
        return QStringLiteral("%1 MB").arg(mb, 0, 'f', 1);
    }
    if (bytes >= 1024) {
        const double kb = static_cast<double>(bytes) / 1024.0;
        return QStringLiteral("%1 KB").arg(kb, 0, 'f', 1);
    }
    return QStringLiteral("%1 B").arg(bytes);
}

QString WorkspaceViewModel::stageEncryptedFileTransfer(const QString& fileName, qint64 fileSizeBytes) {
    const QString cleanedName = fileName.trimmed();
    if (cleanedName.isEmpty()) {
        return QString();
    }

    auto* conv = findConversationMutable(selected_conversation_id_);
    if (!conv) {
        return QString();
    }

    const auto prepRes = app_.bootstrap().file_manager().prepare_encrypted_upload(cleanedName.toStdString());
    if (prepRes.is_error()) {
        emit workspaceError(QString::fromStdString(prepRes.error().user_message()));
        return QString();
    }

    const QString transferId = QStringLiteral("tx-0%1").arg(++next_file_seq_);
    const QString sizeStr = formatFileSize(fileSizeBytes > 0 ? fileSizeBytes : 1048576);
    const QString hashShort = QStringLiteral("e3b0c442...98fc1c14");

    file_transfers_.insert(file_transfers_.begin(),
                           FileTransferEntry{transferId, conv->conversationId, conv->peerUserId, conv->peerDisplayName,
                                             cleanedName, fileSizeBytes, sizeStr, QStringLiteral("AES-256-GCM"),
                                             hashShort, QStringLiteral("Outbound"),
                                             QStringLiteral("Encrypted & Verified"), QStringLiteral("Just now")});

    messages_.push_back(MessageEntry{QStringLiteral("msg-%1").arg(++next_msg_seq_), conv->conversationId,
                                     QStringLiteral("You"), true, QStringLiteral("Encrypted File Attachment"),
                                     QStringLiteral("Just now"), QStringLiteral("TODAY"), QStringLiteral("Verified"),
                                     true, transferId, cleanedName, sizeStr, QStringLiteral("AES-256-GCM"), hashShort,
                                     composer_priority_});

    conv->lastMessagePreview = QStringLiteral("YOU: Uploaded %1 (AES-256-GCM)").arg(cleanedName);
    conv->timestampText = QStringLiteral("Just now");
    conv->lastMessagePriority = composer_priority_;
    selected_transfer_id_ = transferId;

    if (composer_priority_ != 1) {
        composer_priority_ = 1;
        emit composerPriorityChanged();
    }

    emit fileTransfersChanged();
    emit selectedTransferChanged();
    emit activeMessagesChanged();
    emit conversationsChanged();
    return transferId;
}

bool WorkspaceViewModel::cancelFileTransfer(const QString& transferId) {
    if (transferId.trimmed().isEmpty()) {
        return false;
    }
    const auto cancelRes = app_.bootstrap().file_manager().cancel_transfer(transferId.toStdString());
    if (cancelRes.is_error()) {
        return false;
    }
    for (auto& tx : file_transfers_) {
        if (tx.transferId == transferId) {
            tx.statusText = QStringLiteral("Cancelled");
            emit fileTransfersChanged();
            emit selectedTransferChanged();
            return true;
        }
    }
    return false;
}

void WorkspaceViewModel::togglePeerVerified(const QString& peerUserId) {
    for (auto& conv : conversations_) {
        if (conv.peerUserId == peerUserId ||
            (peerUserId.isEmpty() && conv.conversationId == selected_conversation_id_)) {
            conv.isVerified = !conv.isVerified;
            const domain::Contact updated(
                domain::UserId(conv.peerUserId.toStdString()), conv.peerDisplayName.toStdString(),
                conv.isVerified ? domain::KeyVerificationStatus::Verified : domain::KeyVerificationStatus::Unverified,
                conv.safetyNumber.toStdString(), conv.isBlocked);
            (void)app_.bootstrap().contact_manager().add_or_update_contact(updated);
            emit selectedConversationChanged();
            emit conversationsChanged();
            emit contactsChanged();
            return;
        }
    }
}

void WorkspaceViewModel::togglePeerBlocked(const QString& peerUserId) {
    for (auto& conv : conversations_) {
        if (conv.peerUserId == peerUserId ||
            (peerUserId.isEmpty() && conv.conversationId == selected_conversation_id_)) {
            conv.isBlocked = !conv.isBlocked;
            (void)app_.bootstrap().contact_manager().set_blocked(domain::UserId(conv.peerUserId.toStdString()),
                                                                 conv.isBlocked);
            emit selectedConversationChanged();
            emit conversationsChanged();
            emit contactsChanged();
            return;
        }
    }
}

bool WorkspaceViewModel::approveDevice(const QString& deviceId) {
    if (deviceId.trimmed().isEmpty()) {
        return false;
    }
    for (auto& dev : devices_) {
        if (dev.deviceId == deviceId) {
            dev.status = QStringLiteral("Authorized");
            dev.isVerified = true;
            dev.lastSeenText = QStringLiteral("Approved just now");
            emit devicesChanged();
            return true;
        }
    }
    return false;
}

bool WorkspaceViewModel::revokeDevice(const QString& deviceId) {
    const QString cleaned = deviceId.trimmed();
    if (cleaned.isEmpty()) {
        return false;
    }
    for (auto& dev : devices_) {
        if (dev.deviceId == cleaned) {
            if (dev.isCurrentDevice) {
                emit workspaceError(QStringLiteral("Cannot revoke the active workstation device from itself."));
                return false;
            }
            const auto revRes =
                app_.bootstrap().device_manager().revoke_device(domain::DeviceId(cleaned.toStdString()));
            if (revRes.is_error()) {
                emit workspaceError(QString::fromStdString(revRes.error().user_message()));
                return false;
            }
            dev.status = QStringLiteral("Revoked");
            dev.isVerified = false;
            dev.lastSeenText = QStringLiteral("Revoked · Keys Zeroized");
            emit devicesChanged();
            return true;
        }
    }
    return false;
}

QString WorkspaceViewModel::pairNewDevice(const QString& displayName) {
    const QString cleaned = displayName.trimmed();
    if (cleaned.isEmpty()) {
        return QString();
    }
    const QString newId = QStringLiteral("dev-node-0%1").arg(next_device_seq_++);
    devices_.push_back(DeviceEntry{
        newId, cleaned, QStringLiteral("Pending X3DH Key Bundle Handshake"),
        QStringLiteral("ED25519-PUB-A910F442...8812C09E"), QStringLiteral("6612 90B4 3319 88A1 4402 19C4 7721 E009"),
        QStringLiteral("SPK-X25519-0001"), QStringLiteral("SIG-ED25519-5501E88A...9920B11C"), QStringLiteral("Pending"),
        QStringLiteral("Pairing requested just now"), false, false});
    emit devicesChanged();
    return newId;
}

void WorkspaceViewModel::rotateSignedPrekey() {
    ++prekey_epoch_;
    for (auto& dev : devices_) {
        if (dev.isCurrentDevice) {
            dev.signedPrekeyId = QStringLiteral("SPK-X25519-00%1").arg(prekey_epoch_);
            dev.prekeySignatureHex =
                QStringLiteral("SIG-ED25519-%1F8...A20%2").arg(prekey_epoch_ * 73).arg(prekey_epoch_);
            dev.isVerified = true;
            dev.lastSeenText = QStringLiteral("Prekey rotated & attested just now");
            break;
        }
    }
    emit localDeviceIdentityChanged();
    emit devicesChanged();
}

void WorkspaceViewModel::regenerateTotpSecret() {
    ++prekey_epoch_;
    totp_enrollment_secret_ =
        QStringLiteral("SC2FA-%1K9-X3DH-%2P · SHA-256 (6-digit / 30s)").arg(prekey_epoch_ * 17).arg(prekey_epoch_ + 40);
    emit mfaPolicyChanged();
}

void WorkspaceViewModel::resetForEmergencyWipe() {
    search_query_.clear();
    conversations_.clear();
    messages_.clear();
    file_transfers_.clear();
    devices_.clear();
    selected_conversation_id_.clear();
    selected_transfer_id_.clear();
    emit searchQueryChanged();
    emit conversationsChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
    emit devicesChanged();
    emit localDeviceIdentityChanged();
    emit selectedConversationChanged();
    emit activeMessagesChanged();
    emit selectedTransferChanged();
}

} // namespace securecloud::client::ui
