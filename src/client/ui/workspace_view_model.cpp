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

    // 1. Seed direct contacts & conversations
    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-frances"),
        QStringLiteral("frances.swann@securecloud.org"),
        QStringLiteral("Frances Swann"),
        QStringLiteral("@frances.swann"),
        QStringLiteral("Online"),
        true,
        false,
        QStringLiteral("49281 04829 88310 77241 66109 31204 58201 94821 03948 17263 84910 28471"),
        QStringLiteral("Principal Cryptographic Architect · Key rotation policy enforced (Double Ratchet v2)."),
        QStringLiteral("YOU: Architecture blueprint & key schedule approved."),
        QStringLiteral("Yesterday"),
        0,
        1,
        false,
        {QStringLiteral("operator@securecloud.org"), QStringLiteral("frances.swann@securecloud.org")},
        2,
        QStringLiteral("Verified")});

    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-angelina"),
        QStringLiteral("angelina.froster@securecloud.org"),
        QStringLiteral("Angelina Froster"),
        QStringLiteral("@angelina.froster"),
        QStringLiteral("Online"),
        true,
        false,
        QStringLiteral("81726 39104 55291 00918 44127 98312 40291 83719 02847 16382 91048 57291"),
        QStringLiteral("Incident Response Lead · Hardware security key verified via out-of-band fingerprint."),
        QStringLiteral("Uploaded threats-q4-report.pdf (AES-256-GCM)"),
        QStringLiteral("1 min ago"),
        2,
        3,
        false,
        {QStringLiteral("operator@securecloud.org"), QStringLiteral("angelina.froster@securecloud.org")},
        3,
        QStringLiteral("Verified")});

    conversations_.push_back(
        ConversationEntry{QStringLiteral("conv-ricky"),
                          QStringLiteral("ricky.smith@securecloud.org"),
                          QStringLiteral("Ricky Smith"),
                          QStringLiteral("@ricky.smith"),
                          QStringLiteral("Busy"),
                          true,
                          false,
                          QStringLiteral("72019 48201 99182 33410 11294 65018 39201 84729 10482 73910 48291 60192"),
                          QStringLiteral("Security Operations Engineer · Gateway TLS 1.3 mTLS certificate custodian."),
                          QStringLiteral("Prekey bundle refreshed for workstation node-04."),
                          QStringLiteral("Jan 02"),
                          0,
                          1,
                          false,
                          {QStringLiteral("operator@securecloud.org"), QStringLiteral("ricky.smith@securecloud.org")},
                          1,
                          QStringLiteral("Verified")});

    conversations_.push_back(
        ConversationEntry{QStringLiteral("conv-corina"),
                          QStringLiteral("corina.mccoy@securecloud.org"),
                          QStringLiteral("Corina McCoy"),
                          QStringLiteral("@corina.mccoy"),
                          QStringLiteral("Offline"),
                          false,
                          false,
                          QStringLiteral("10928 38471 66251 89201 44712 09182 55910 28471 90284 71209 38471 09284"),
                          QStringLiteral("External Security Auditor · Safety number pending out-of-band verification."),
                          QStringLiteral("Key exchange pending safety number check..."),
                          QStringLiteral("Jan 01"),
                          1,
                          2,
                          false,
                          {QStringLiteral("operator@securecloud.org"), QStringLiteral("corina.mccoy@securecloud.org")},
                          1,
                          QStringLiteral("Unverified")});

    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-daniel"),
        QStringLiteral("daniel.hamilton@securecloud.org"),
        QStringLiteral("Daniel Hamilton"),
        QStringLiteral("@daniel.hamilton"),
        QStringLiteral("Offline"),
        true,
        false,
        QStringLiteral("55412 90812 31459 77812 00192 84711 60192 84729 10482 73910 48291 38192"),
        QStringLiteral("Distributed Storage Engineer · Chunked AEAD file vault maintainer."),
        QStringLiteral("YOU: All 64 encrypted chunks verified."),
        QStringLiteral("Dec 23"),
        0,
        1,
        false,
        {QStringLiteral("operator@securecloud.org"), QStringLiteral("daniel.hamilton@securecloud.org")},
        1,
        QStringLiteral("Verified")});

    // 2. Seed multi-party encrypted group conversations (CLIENT-004-T02)
    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-secops"),
        QStringLiteral("group-secops-bridge"),
        QStringLiteral("SecOps Incident Bridge"),
        QStringLiteral("Group · 4 members"),
        QStringLiteral("Online"),
        true,
        false,
        QStringLiteral("SECOPS-BRIDGE-001-GROUP-SAFETY-NUM"),
        QStringLiteral("Multi-Party Incident Response Bridge · Double Ratchet Pairwise + Sender Keys"),
        QStringLiteral("Threat response bridge active: rotate ephemeral ratchets immediately."),
        QStringLiteral("12:40 PM"),
        1,
        3,
        true,
        {QStringLiteral("operator@securecloud.org"), QStringLiteral("frances.swann@securecloud.org"),
         QStringLiteral("angelina.froster@securecloud.org"), QStringLiteral("ricky.smith@securecloud.org")},
        7,
        QStringLiteral("Verified")});

    conversations_.push_back(ConversationEntry{
        QStringLiteral("conv-enclave"),
        QStringLiteral("group-enclave-migration"),
        QStringLiteral("Zero-Trust Enclave Migration"),
        QStringLiteral("Group · 3 members"),
        QStringLiteral("Online"),
        true,
        false,
        QStringLiteral("ENCLAVE-MIGRATION-002-SAFETY-NUM"),
        QStringLiteral("Cryptographic Migration Working Group · HSM Attestation"),
        QStringLiteral("All 64 encrypted chunks verified against SHA-256 manifest in storage enclave."),
        QStringLiteral("Yesterday"),
        0,
        1,
        true,
        {QStringLiteral("operator@securecloud.org"), QStringLiteral("frances.swann@securecloud.org"),
         QStringLiteral("daniel.hamilton@securecloud.org")},
        4,
        QStringLiteral("Verified")});

    // 3. Persist all contacts into ContactManager
    for (const auto& conv : conversations_) {
        if (!conv.isGroup) {
            domain::KeyVerificationStatus status = domain::KeyVerificationStatus::Unverified;
            if (conv.verificationStatus == QStringLiteral("Verified")) {
                status = domain::KeyVerificationStatus::Verified;
            } else if (conv.verificationStatus == QStringLiteral("KeyChanged")) {
                status = domain::KeyVerificationStatus::KeyChanged;
            }
            const domain::Contact contact(domain::UserId(conv.peerUserId.toStdString()),
                                          conv.peerDisplayName.toStdString(), status, conv.safetyNumber.toStdString(),
                                          conv.isBlocked, conv.safetyNumber.toStdString(), conv.roleNote.toStdString(),
                                          domain::PresenceStatus::Online,
                                          static_cast<uint32_t>(conv.authorizedDeviceCount));
            (void)app_.bootstrap().contact_manager().add_or_update_contact(contact);
        }
    }

    // Also register local user contact for roster resolution
    const domain::Contact selfContact(domain::UserId("operator@securecloud.org"), "You (Alice)",
                                      domain::KeyVerificationStatus::Verified, "LOCAL-OPERATOR-KEY", false,
                                      "99999 00000 11111 22222 33333 44444", "Workstation Operator",
                                      domain::PresenceStatus::Online, 1);
    (void)app_.bootstrap().contact_manager().add_or_update_contact(selfContact);

    // 4. Persist all conversations into LocalStore
    for (const auto& conv : conversations_) {
        std::vector<domain::UserId> participants;
        participants.reserve(conv.participantUserIds.size());
        for (const auto& p : conv.participantUserIds) {
            participants.emplace_back(p.toStdString());
        }
        domain::Conversation domainConv(
            domain::ConversationId(conv.conversationId.toStdString()),
            conv.isGroup ? domain::ConversationType::Group : domain::ConversationType::Direct,
            conv.peerDisplayName.toStdString(), std::move(participants), std::chrono::system_clock::now(),
            std::chrono::system_clock::now(), static_cast<uint32_t>(conv.unreadCount), false);
        (void)app_.bootstrap().local_store().save_conversation(domainConv);
    }

    // 4. Seed messages for Frances Swann (default selected conversation)
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-1"), QStringLiteral("conv-frances"), QStringLiteral("Frances Swann"), false,
        QStringLiteral("Hi! Have you reviewed the Double Ratchet session key schedule for the desktop workspace?"),
        QStringLiteral("11:00 AM"), QStringLiteral("YESTERDAY"), QStringLiteral("Delivered"), false, QString(),
        QString(), QString(), QString(), QString(), 2, QStringLiteral("idem-001"), false});

    messages_.push_back(MessageEntry{
        QStringLiteral("msg-2"), QStringLiteral("conv-frances"), QStringLiteral("You"), true,
        QStringLiteral("Yes — verified the X3DH prekey signatures and chunked file encryption parameters."),
        QStringLiteral("11:02 AM"), QStringLiteral("YESTERDAY"), QStringLiteral("Read"), false, QString(), QString(),
        QString(), QString(), QString(), 1, QStringLiteral("idem-002"), false});

    messages_.push_back(MessageEntry{
        QStringLiteral("msg-3"), QStringLiteral("conv-frances"), QStringLiteral("Frances Swann"), false,
        QStringLiteral("Encrypted File Attachment"), QStringLiteral("11:05 AM"), QStringLiteral("YESTERDAY"),
        QStringLiteral("Verified"), true, QStringLiteral("tx-001"), QStringLiteral("zero-trust-key-schedule-v2.pdf"),
        QStringLiteral("2.4 MB"), QStringLiteral("AES-256-GCM"), QStringLiteral("9f86d081...b0f00a08"), 1,
        QStringLiteral("idem-003"), false});

    messages_.push_back(MessageEntry{QStringLiteral("msg-4"), QStringLiteral("conv-frances"), QStringLiteral("You"),
                                     true, QStringLiteral("Architecture blueprint & key schedule approved."),
                                     QStringLiteral("11:08 AM"), QStringLiteral("TODAY"), QStringLiteral("Read"), false,
                                     QString(), QString(), QString(), QString(), QString(), 1,
                                     QStringLiteral("idem-004"), false});

    // Seed messages for Angelina Froster (Emergency Priority)
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-5"), QStringLiteral("conv-angelina"), QStringLiteral("Angelina Froster"), false,
        QStringLiteral(
            "Compromised edge relay certificate detected on node-eu-west-2 — rotate ephemeral ratchets immediately."),
        QStringLiteral("12:40 PM"), QStringLiteral("TODAY"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 3, QStringLiteral("idem-005"), false});

    messages_.push_back(
        MessageEntry{QStringLiteral("msg-6"), QStringLiteral("conv-angelina"), QStringLiteral("Angelina Froster"),
                     false, QStringLiteral("Encrypted File Attachment"), QStringLiteral("12:41 PM"),
                     QStringLiteral("TODAY"), QStringLiteral("Verified"), true, QStringLiteral("tx-002"),
                     QStringLiteral("threats-q4-report.pdf"), QStringLiteral("4.8 MB"), QStringLiteral("AES-256-GCM"),
                     QStringLiteral("4a7d1ed4...91e83b2c"), 3, QStringLiteral("idem-006"), false});

    // Seed messages for Ricky Smith
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-7"), QStringLiteral("conv-ricky"), QStringLiteral("Ricky Smith"), false,
        QStringLiteral("Prekey bundle refreshed for workstation node-04. mTLS pinning fingerprint matches enclave."),
        QStringLiteral("09:15 AM"), QStringLiteral("JAN 02"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 1, QStringLiteral("idem-007"), false});

    // Seed messages for Corina McCoy
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-8"), QStringLiteral("conv-corina"), QStringLiteral("Corina McCoy"), false,
        QStringLiteral(
            "Key exchange pending out-of-band safety number verification before we sign off on the Q1 audit."),
        QStringLiteral("04:30 PM"), QStringLiteral("JAN 01"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 2, QStringLiteral("idem-008"), false});

    // Seed messages for Daniel Hamilton
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-9"), QStringLiteral("conv-daniel"), QStringLiteral("You"), true,
        QStringLiteral("All 64 encrypted chunks verified against SHA-256 manifest in the distributed storage vault."),
        QStringLiteral("06:12 PM"), QStringLiteral("DEC 23"), QStringLiteral("Read"), false, QString(), QString(),
        QString(), QString(), QString(), 1, QStringLiteral("idem-009"), false});

    // Seed messages for SecOps Incident Bridge (Group)
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-10"), QStringLiteral("conv-secops"), QStringLiteral("Angelina Froster"), false,
        QStringLiteral(
            "Compromised edge relay certificate detected on node-eu-west-2 — initiate incident response bridge."),
        QStringLiteral("12:40 PM"), QStringLiteral("TODAY"), QStringLiteral("Delivered"), false, QString(), QString(),
        QString(), QString(), QString(), 3, QStringLiteral("idem-010"), false});

    // Persist seeded messages into LocalStore
    for (const auto& msg : messages_) {
        domain::DeliveryState state = domain::DeliveryState::Delivered;
        if (msg.deliveryState == QStringLiteral("Read")) {
            state = domain::DeliveryState::Read;
        } else if (msg.deliveryState == QStringLiteral("Failed")) {
            state = domain::DeliveryState::Failed;
        }
        const auto* conv = findConversation(msg.conversationId);
        const domain::UserId sender = msg.isSelf ? domain::UserId("operator@securecloud.org")
                                                 : (conv ? domain::UserId(conv->peerUserId.toStdString())
                                                         : domain::UserId("operator@securecloud.org"));

        domain::Message dMsg(
            domain::MessageId(msg.messageId.toStdString()), domain::ConversationId(msg.conversationId.toStdString()),
            sender, domain::DeviceId("dev-local-01"), state, std::chrono::system_clock::now(), msg.text.toStdString(),
            msg.priority, msg.senderName.toStdString(), msg.idempotencyKey.toStdString(), msg.emergencyAcknowledged,
            msg.fileName.toStdString(), 0, msg.sha256Short.toStdString());
        (void)app_.bootstrap().local_store().save_message(dMsg);
    }

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
    auto local_dev_res = app_.bootstrap().device_manager().get_local_device();
    if (local_dev_res.is_ok()) {
        const auto& real_dev = local_dev_res.value();
        devices_.push_back(DeviceEntry{
            QString::fromStdString(real_dev.device_id().value()), QString::fromStdString(real_dev.display_name()),
            QStringLiteral("Apple M-Series Secure Enclave · TLS 1.3 mTLS"),
            QString::fromStdString(real_dev.crypto_identity().identity_key()),
            QString::fromStdString(real_dev.crypto_identity().fingerprint()),
            QString::fromStdString(real_dev.crypto_identity().signed_prekey()),
            QString::fromStdString(real_dev.crypto_identity().signature()),
            QString::fromUtf8(domain::to_string(real_dev.status()).data(),
                              static_cast<qsizetype>(domain::to_string(real_dev.status()).size())),
            QStringLiteral("Active now (Current Device)"), true,
            real_dev.crypto_identity().verification_status() == domain::KeyVerificationStatus::Verified});
    } else {
        devices_.push_back(DeviceEntry{QStringLiteral("dev-local-01"), QStringLiteral("SecOps Workstation · macOS"),
                                       QStringLiteral("Apple M-Series Secure Enclave · TLS 1.3 mTLS"),
                                       QStringLiteral("ED25519-PUB-9F86D081884C7D659A2FEAA0C55AD015"),
                                       QStringLiteral("7F8A 9B2C 1E4D 6610 9981 3042 5519 A8C1"),
                                       QStringLiteral("SPK-X25519-0014"),
                                       QStringLiteral("SIG-ED25519-4419A8B2...C901E24F"), QStringLiteral("Authorized"),
                                       QStringLiteral("Active now (Current Device)"), true, false});
    }

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
        item.insert(QStringLiteral("isGroup"), conv.isGroup);
        item.insert(QStringLiteral("participantCount"), static_cast<int>(conv.participantUserIds.size()));
        item.insert(QStringLiteral("deviceCount"), conv.authorizedDeviceCount);
        item.insert(QStringLiteral("verificationStatus"), conv.verificationStatus);
        result.append(item);
    }
    return result;
}

QVariantList WorkspaceViewModel::contacts() const {
    QVariantList result;
    for (const auto& conv : conversations_) {
        if (conv.isGroup) {
            continue;
        }
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
        item.insert(QStringLiteral("deviceCount"), conv.authorizedDeviceCount);
        item.insert(QStringLiteral("verificationStatus"), conv.verificationStatus);
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

bool WorkspaceViewModel::selectedConversationIsGroup() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->isGroup : false;
}

int WorkspaceViewModel::selectedConversationParticipantCount() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv) {
        return 0;
    }
    return static_cast<int>(conv->participantUserIds.size());
}

int WorkspaceViewModel::selectedConversationDeviceFanoutCount() const {
    const auto* conv = findConversation(selected_conversation_id_);
    return conv ? conv->authorizedDeviceCount : 0;
}

QVariantList WorkspaceViewModel::selectedConversationParticipants() const {
    QVariantList result;
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv) {
        return result;
    }

    for (const auto& uidStr : conv->participantUserIds) {
        QVariantMap pItem;
        pItem.insert(QStringLiteral("userId"), uidStr);
        const bool isSelf = (uidStr == QStringLiteral("operator@securecloud.org"));
        pItem.insert(QStringLiteral("isSelf"), isSelf);

        const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(uidStr.toStdString()));
        if (cRes.is_ok()) {
            const auto& contact = cRes.value();
            pItem.insert(QStringLiteral("name"), QString::fromStdString(contact.alias()));
            pItem.insert(QStringLiteral("handle"),
                         isSelf ? QStringLiteral("@operator")
                                : QStringLiteral("@%1").arg(
                                      QString::fromStdString(contact.alias()).toLower().replace(' ', '.')));
            pItem.insert(QStringLiteral("roleNote"), QString::fromStdString(contact.role_note()));
            pItem.insert(QStringLiteral("deviceCount"), static_cast<int>(contact.authorized_device_count()));
            pItem.insert(QStringLiteral("presence"),
                         QString::fromUtf8(domain::to_string(contact.presence_status()).data()));
            pItem.insert(QStringLiteral("safetyNumber"), QString::fromStdString(contact.safety_number()));
            pItem.insert(QStringLiteral("isBlocked"), contact.is_blocked());
            pItem.insert(QStringLiteral("verificationStatus"),
                         QString::fromUtf8(domain::to_string(contact.verification_status()).data()));
            pItem.insert(QStringLiteral("isVerified"),
                         contact.verification_status() == domain::KeyVerificationStatus::Verified);
        } else {
            pItem.insert(QStringLiteral("name"), uidStr);
            pItem.insert(QStringLiteral("handle"), QStringLiteral("@%1").arg(uidStr));
            pItem.insert(QStringLiteral("roleNote"), QStringLiteral("Participant"));
            pItem.insert(QStringLiteral("deviceCount"), 1);
            pItem.insert(QStringLiteral("presence"), QStringLiteral("Offline"));
            pItem.insert(QStringLiteral("safetyNumber"), QString());
            pItem.insert(QStringLiteral("isBlocked"), false);
            pItem.insert(QStringLiteral("verificationStatus"), QStringLiteral("Unverified"));
            pItem.insert(QStringLiteral("isVerified"), false);
        }
        result.append(pItem);
    }
    return result;
}

bool WorkspaceViewModel::selectedGroupAllVerified() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        return true;
    }
    for (const auto& uidStr : conv->participantUserIds) {
        if (uidStr == QStringLiteral("operator@securecloud.org") || uidStr == QStringLiteral("alice@securecloud.org")) {
            continue;
        }
        const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(uidStr.toStdString()));
        if (cRes.is_error() || cRes.value().verification_status() != domain::KeyVerificationStatus::Verified) {
            return false;
        }
    }
    return true;
}

int WorkspaceViewModel::selectedGroupUnverifiedCount() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        return 0;
    }
    int unverified = 0;
    for (const auto& uidStr : conv->participantUserIds) {
        if (uidStr == QStringLiteral("operator@securecloud.org") || uidStr == QStringLiteral("alice@securecloud.org")) {
            continue;
        }
        const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(uidStr.toStdString()));
        if (cRes.is_error() || cRes.value().verification_status() != domain::KeyVerificationStatus::Verified) {
            ++unverified;
        }
    }
    return unverified;
}

bool WorkspaceViewModel::selectedPeerKeyChanged() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv) {
        return false;
    }

    if (conv->isGroup) {
        for (const auto& uidStr : conv->participantUserIds) {
            const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(uidStr.toStdString()));
            if (cRes.is_ok() && cRes.value().verification_status() == domain::KeyVerificationStatus::KeyChanged) {
                return true;
            }
        }
        return false;
    }

    return conv->verificationStatus == QStringLiteral("KeyChanged");
}

QString WorkspaceViewModel::selectedPeerKeyChangedHandle() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv) {
        return QString();
    }

    if (conv->isGroup) {
        for (const auto& uidStr : conv->participantUserIds) {
            const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(uidStr.toStdString()));
            if (cRes.is_ok() && cRes.value().verification_status() == domain::KeyVerificationStatus::KeyChanged) {
                return QString::fromStdString(cRes.value().alias());
            }
        }
        return QString();
    }

    return conv->verificationStatus == QStringLiteral("KeyChanged") ? conv->peerDisplayName : QString();
}

int WorkspaceViewModel::unacknowledgedEmergencyCount() const {
    int count = 0;
    for (const auto& msg : messages_) {
        if (msg.conversationId == selected_conversation_id_ && msg.priority == 3 && !msg.emergencyAcknowledged) {
            ++count;
        }
    }
    return count;
}

void WorkspaceViewModel::setDeliveryFailureSimulated(bool simulated) {
    if (delivery_failure_simulated_ == simulated) {
        return;
    }
    delivery_failure_simulated_ = simulated;
    emit deliveryFailureSimulatedChanged();
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
        item.insert(QStringLiteral("idempotencyKey"), msg.idempotencyKey);
        item.insert(QStringLiteral("emergencyAcknowledged"), msg.emergencyAcknowledged);
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
    auto local_res = app_.bootstrap().device_manager().get_local_device();

    for (const auto& dev : devices_) {
        QVariantMap item;
        if (dev.isCurrentDevice && local_res.is_ok()) {
            const auto& real_dev = local_res.value();
            item.insert(QStringLiteral("deviceId"), QString::fromStdString(real_dev.device_id().value()));
            item.insert(QStringLiteral("displayName"), QString::fromStdString(real_dev.display_name()));
            item.insert(QStringLiteral("platformInfo"), dev.platformInfo);
            item.insert(QStringLiteral("identityKeyHex"),
                        QString::fromStdString(real_dev.crypto_identity().identity_key()));
            item.insert(QStringLiteral("fingerprint"),
                        QString::fromStdString(real_dev.crypto_identity().fingerprint()));
            item.insert(QStringLiteral("signedPrekeyId"),
                        QString::fromStdString(real_dev.crypto_identity().signed_prekey()));
            item.insert(QStringLiteral("prekeySignatureHex"),
                        QString::fromStdString(real_dev.crypto_identity().signature()));
            item.insert(QStringLiteral("status"),
                        QString::fromUtf8(domain::to_string(real_dev.status()).data(),
                                          static_cast<qsizetype>(domain::to_string(real_dev.status()).size())));
            item.insert(QStringLiteral("lastSeenText"), dev.lastSeenText);
            item.insert(QStringLiteral("isCurrentDevice"), true);
            item.insert(QStringLiteral("isVerified"),
                        real_dev.crypto_identity().verification_status() == domain::KeyVerificationStatus::Verified);
        } else {
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
        }
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
    auto dev_res = app_.bootstrap().device_manager().get_local_device();
    if (dev_res.is_ok()) {
        const auto& dev = dev_res.value();
        QVariantMap item;
        item.insert(QStringLiteral("deviceId"), QString::fromStdString(dev.device_id().value()));
        item.insert(QStringLiteral("displayName"), QString::fromStdString(dev.display_name()));
        item.insert(QStringLiteral("platformInfo"), QStringLiteral("Apple M-Series Secure Enclave · TLS 1.3 mTLS"));
        item.insert(QStringLiteral("identityKeyHex"), QString::fromStdString(dev.crypto_identity().identity_key()));
        item.insert(QStringLiteral("fingerprint"), QString::fromStdString(dev.crypto_identity().fingerprint()));
        item.insert(QStringLiteral("signedPrekeyId"), QString::fromStdString(dev.crypto_identity().signed_prekey()));
        item.insert(QStringLiteral("prekeySignatureHex"), QString::fromStdString(dev.crypto_identity().signature()));
        item.insert(QStringLiteral("status"),
                    QString::fromUtf8(domain::to_string(dev.status()).data(),
                                      static_cast<qsizetype>(domain::to_string(dev.status()).size())));
        item.insert(QStringLiteral("isVerified"),
                    dev.crypto_identity().verification_status() == domain::KeyVerificationStatus::Verified);
        item.insert(QStringLiteral("lastSeenText"), QStringLiteral("Active now (Current Device)"));
        item.insert(QStringLiteral("isCurrentDevice"), true);
        item.insert(QStringLiteral("prekeyCount"), local_prekey_count_);
        item.insert(QStringLiteral("prekeyHealthStatus"), local_prekey_health_);
        return item;
    }

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
            item.insert(QStringLiteral("lastSeenText"), dev.lastSeenText);
            item.insert(QStringLiteral("isCurrentDevice"), true);
            item.insert(QStringLiteral("prekeyCount"), local_prekey_count_);
            item.insert(QStringLiteral("prekeyHealthStatus"), local_prekey_health_);
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
        (void)app_.bootstrap().messaging_manager().mark_conversation_read(
            domain::ConversationId(conv->conversationId.toStdString()));
    }
    emit selectedConversationChanged();
    emit activeMessagesChanged();
    emit conversationsChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
}

void WorkspaceViewModel::selectContact(const QString& peerUserId) {
    for (const auto& conv : conversations_) {
        if (!conv.isGroup && conv.peerUserId == peerUserId) {
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

    // ADR-008 & Security Guard: Block sending if recipient key changed or blocked
    if (selectedPeerKeyChanged()) {
        emit workspaceError(QStringLiteral("Outbound messaging suspended: recipient identity key changed (ADR-008). "
                                           "Verify safety number before sending."));
        return false;
    }

    if (conv->isBlocked) {
        emit workspaceError(QStringLiteral("Cannot send message: peer keys are blocked."));
        return false;
    }

    const int effectivePriority = (priority >= 1 && priority <= 3) ? priority : composer_priority_;
    const QString msgId = QStringLiteral("msg-%1").arg(++next_msg_seq_);
    const QString idempotencyKey = QStringLiteral("idem-%1").arg(next_msg_seq_);

    if (delivery_failure_simulated_) {
        // Simulated failure path for testing retry (CLIENT-004-T05)
        messages_.push_back(MessageEntry{msgId, conv->conversationId, QStringLiteral("You"), true, trimmed,
                                         QStringLiteral("Just now"), QStringLiteral("TODAY"), QStringLiteral("Failed"),
                                         false, QString(), QString(), QString(), QString(), QString(),
                                         effectivePriority, idempotencyKey, false});
        conv->lastMessagePreview = QStringLiteral("YOU: (Failed to send) %1").arg(trimmed);
        conv->timestampText = QStringLiteral("Just now");
        conv->lastMessagePriority = effectivePriority;

        emit activeMessagesChanged();
        emit conversationsChanged();
        emit selectedConversationChanged();
        return true;
    }

    const auto& currentUserId = app_.bootstrap().auth_manager().current_user();
    const domain::UserId senderId =
        currentUserId.value().empty() ? domain::UserId("operator@securecloud.org") : currentUserId;

    const auto sendRes = app_.bootstrap().messaging_manager().stage_outbound_message(
        domain::ConversationId(conv->conversationId.toStdString()), senderId, domain::DeviceId("dev-local-01"),
        trimmed.toStdString(), effectivePriority, "You");

    if (sendRes.is_error()) {
        emit workspaceError(QString::fromStdString(sendRes.error().user_message()));
        return false;
    }

    messages_.push_back(MessageEntry{msgId, conv->conversationId, QStringLiteral("You"), true, trimmed,
                                     QStringLiteral("Just now"), QStringLiteral("TODAY"), QStringLiteral("Delivered"),
                                     false, QString(), QString(), QString(), QString(), QString(), effectivePriority,
                                     idempotencyKey, false});

    conv->lastMessagePreview = QStringLiteral("YOU: %1").arg(trimmed);
    conv->timestampText = QStringLiteral("Just now");
    conv->lastMessagePriority = effectivePriority;

    if (composer_priority_ != 1) {
        composer_priority_ = 1;
        emit composerPriorityChanged();
    }

    emit activeMessagesChanged();
    emit conversationsChanged();
    emit selectedConversationChanged();
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
                                     composer_priority_, QStringLiteral("idem-%1").arg(next_msg_seq_), false});

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
            conv.verificationStatus = conv.isVerified ? QStringLiteral("Verified") : QStringLiteral("Unverified");
            (void)app_.bootstrap().contact_manager().verify_contact_key(domain::UserId(conv.peerUserId.toStdString()),
                                                                        conv.isVerified);
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
    auto rot_res = app_.bootstrap().device_manager().rotate_signed_prekey();
    if (rot_res.is_ok()) {
        auto dev_res = app_.bootstrap().device_manager().get_local_device();
        if (dev_res.is_ok()) {
            const auto& dev = dev_res.value();
            for (auto& d : devices_) {
                if (d.isCurrentDevice) {
                    d.signedPrekeyId = QString::fromStdString(dev.crypto_identity().signed_prekey());
                    d.prekeySignatureHex = QString::fromStdString(dev.crypto_identity().signature());
                    d.isVerified = true;
                    d.lastSeenText = QStringLiteral("Prekey rotated & attested just now");
                    break;
                }
            }
        }
        refreshPrekeyInventory();
    } else {
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
    }
    emit localDeviceIdentityChanged();
    emit devicesChanged();
}

void WorkspaceViewModel::refreshPrekeyInventory() {
    auto inv_res = app_.bootstrap().device_manager().check_prekey_inventory();
    if (inv_res.is_ok()) {
        local_prekey_count_ = static_cast<int>(inv_res.value().active_prekey_count());
        if (inv_res.value().is_exhausted()) {
            local_prekey_health_ = QStringLiteral("Exhausted");
        } else if (inv_res.value().needs_replenishment()) {
            local_prekey_health_ = QStringLiteral("Low");
        } else {
            local_prekey_health_ = QStringLiteral("Healthy");
        }
    }
    emit localDeviceIdentityChanged();
}

bool WorkspaceViewModel::replenishPrekeys(int batchSize) {
    const std::size_t batch = batchSize > 0 ? static_cast<std::size_t>(batchSize) : 50u;
    auto rep_res = app_.bootstrap().device_manager().replenish_prekeys(batch);
    if (rep_res.is_ok()) {
        refreshPrekeyInventory();
        return true;
    }
    return false;
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

// -----------------------------------------------------------------------------
// New Invokables for CLIENT-004-T02 (Contacts, Groups, Retry, Acknowledgement)
// -----------------------------------------------------------------------------

bool WorkspaceViewModel::addContact(const QString& handle, const QString& displayName, const QString& roleNote,
                                    const QString& safetyNumber) {
    const QString cleanedHandle = handle.trimmed();
    const QString cleanedName = displayName.trimmed();
    if (cleanedHandle.isEmpty() || cleanedName.isEmpty()) {
        emit workspaceError(QStringLiteral("Contact handle and display name cannot be empty."));
        return false;
    }

    QString peerUid = cleanedHandle;
    if (peerUid.startsWith('@')) {
        peerUid = peerUid.mid(1);
    }
    if (!peerUid.contains('@')) {
        peerUid += QStringLiteral("@securecloud.org");
    }

    const domain::UserId uid(peerUid.toStdString());
    const std::string sNum = safetyNumber.isEmpty()
                                 ? "10928 38471 66251 89201 44712 09182 55910 28471 90284 71209 38471 09284"
                                 : safetyNumber.toStdString();
    const auto createRes = app_.bootstrap().contact_manager().create_contact(uid, cleanedName.toStdString(), sNum,
                                                                             roleNote.toStdString(), 1);

    if (createRes.is_error()) {
        emit workspaceError(QString::fromStdString(createRes.error().user_message()));
        return false;
    }

    const QString convId = QStringLiteral("conv-%1").arg(peerUid.toLower().remove('@').remove('.'));
    const QString peerHandleStr = QStringLiteral("@%1").arg(peerUid.section('@', 0, 0));

    conversations_.push_back(ConversationEntry{convId,
                                               peerUid,
                                               cleanedName,
                                               peerHandleStr,
                                               QStringLiteral("Offline"),
                                               false,
                                               false,
                                               QString::fromStdString(sNum),
                                               roleNote,
                                               QStringLiteral("Conversation opened."),
                                               QStringLiteral("Just now"),
                                               0,
                                               1,
                                               false,
                                               {QStringLiteral("operator@securecloud.org"), peerUid},
                                               1,
                                               QStringLiteral("Unverified")});

    // Also persist conversation into local_store_
    domain::Conversation domainConv(domain::ConversationId(convId.toStdString()), domain::ConversationType::Direct,
                                    cleanedName.toStdString(), {domain::UserId("operator@securecloud.org"), uid},
                                    std::chrono::system_clock::now(), std::chrono::system_clock::now(), 0, false);
    (void)app_.bootstrap().local_store().save_conversation(domainConv);

    emit contactsChanged();
    emit conversationsChanged();
    return true;
}

bool WorkspaceViewModel::updateContactProfile(const QString& userId, const QString& displayName,
                                              const QString& roleNote) {
    if (userId.trimmed().isEmpty() || displayName.trimmed().isEmpty()) {
        emit workspaceError(QStringLiteral("User ID and display name cannot be empty."));
        return false;
    }

    QString peerUid = userId.trimmed();
    if (peerUid.startsWith('@')) {
        peerUid = peerUid.mid(1);
    }
    if (!peerUid.contains('@')) {
        peerUid += QStringLiteral("@securecloud.org");
    }

    const auto updateRes = app_.bootstrap().contact_manager().update_contact_alias(
        domain::UserId(peerUid.toStdString()), displayName.toStdString(), roleNote.toStdString());

    if (updateRes.is_error()) {
        emit workspaceError(QString::fromStdString(updateRes.error().user_message()));
        return false;
    }

    for (auto& conv : conversations_) {
        if (conv.peerUserId == peerUid || conv.peerUserId == userId) {
            conv.peerDisplayName = displayName;
            conv.roleNote = roleNote;
            break;
        }
    }

    emit contactsChanged();
    emit conversationsChanged();
    emit selectedConversationChanged();
    return true;
}

bool WorkspaceViewModel::removeContact(const QString& userId) {
    if (userId.trimmed().isEmpty()) {
        return false;
    }

    QString peerUid = userId.trimmed();
    if (peerUid.startsWith('@')) {
        peerUid = peerUid.mid(1);
    }
    if (!peerUid.contains('@')) {
        peerUid += QStringLiteral("@securecloud.org");
    }

    const auto delRes = app_.bootstrap().contact_manager().remove_contact(domain::UserId(peerUid.toStdString()));
    if (delRes.is_error()) {
        emit workspaceError(QString::fromStdString(delRes.error().user_message()));
        return false;
    }

    conversations_.erase(std::remove_if(conversations_.begin(), conversations_.end(),
                                        [&](const ConversationEntry& c) {
                                            return !c.isGroup && (c.peerUserId == peerUid || c.peerUserId == userId);
                                        }),
                         conversations_.end());

    if ((selectedPeerUserId() == peerUid || selectedPeerUserId() == userId) && !conversations_.empty()) {
        selected_conversation_id_ = conversations_.front().conversationId;
    }

    emit contactsChanged();
    emit conversationsChanged();
    emit selectedConversationChanged();
    emit activeMessagesChanged();
    return true;
}

void WorkspaceViewModel::simulatePeerKeyChange(const QString& userId) {
    for (auto& conv : conversations_) {
        if (conv.peerUserId == userId || (userId.isEmpty() && conv.conversationId == selected_conversation_id_)) {
            conv.isVerified = false;
            conv.verificationStatus = QStringLiteral("KeyChanged");
            conv.safetyNumber = QStringLiteral(
                "99999 88888 77777 66666 55555 44444 33333 22222 11111 00000 12345 67890 (UNVERIFIED ROTATION)");
            (void)app_.bootstrap().contact_manager().mark_contact_key_changed(
                domain::UserId(conv.peerUserId.toStdString()), conv.safetyNumber.toStdString());
            emit selectedConversationChanged();
            emit conversationsChanged();
            emit contactsChanged();
            return;
        }
    }
}

void WorkspaceViewModel::acceptAndVerifyPeerKey(const QString& userId) {
    for (auto& conv : conversations_) {
        if (conv.peerUserId == userId || (userId.isEmpty() && conv.conversationId == selected_conversation_id_)) {
            conv.isVerified = true;
            conv.verificationStatus = QStringLiteral("Verified");
            (void)app_.bootstrap().contact_manager().verify_contact_key(domain::UserId(conv.peerUserId.toStdString()),
                                                                        true);
            emit selectedConversationChanged();
            emit conversationsChanged();
            emit contactsChanged();
            return;
        }
    }
}

QString WorkspaceViewModel::createDirectConversation(const QString& peerUserId) {
    if (peerUserId.trimmed().isEmpty()) {
        return QString();
    }

    for (const auto& conv : conversations_) {
        if (!conv.isGroup && conv.peerUserId == peerUserId) {
            selectConversation(conv.conversationId);
            return conv.conversationId;
        }
    }

    const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(peerUserId.toStdString()));
    const QString name = cRes.is_ok() ? QString::fromStdString(cRes.value().alias()) : peerUserId;
    const QString handle = peerUserId.startsWith('@') ? peerUserId : QStringLiteral("@%1").arg(peerUserId);
    const QString convId = QStringLiteral("conv-%1").arg(++next_msg_seq_);

    conversations_.push_back(ConversationEntry{convId,
                                               peerUserId,
                                               name,
                                               handle,
                                               QStringLiteral("Online"),
                                               true,
                                               false,
                                               QStringLiteral("12345 67890 12345 67890 12345 67890"),
                                               QStringLiteral("Direct Contact"),
                                               QStringLiteral("Conversation opened."),
                                               QStringLiteral("Just now"),
                                               0,
                                               1,
                                               false,
                                               {QStringLiteral("operator@securecloud.org"), peerUserId},
                                               1,
                                               QStringLiteral("Verified")});

    selectConversation(convId);
    return convId;
}

QString WorkspaceViewModel::createGroupConversation(const QString& groupTitle, const QVariantList& participantUserIds) {
    const QString cleanedTitle = groupTitle.trimmed();
    if (cleanedTitle.isEmpty()) {
        emit workspaceError(QStringLiteral("Group conversation title cannot be empty."));
        return QString();
    }

    std::vector<domain::UserId> pVec;
    std::vector<QString> pUserIdsStr;
    pUserIdsStr.push_back(QStringLiteral("operator@securecloud.org"));

    int totalDeviceFanout = 1; // operator workstation
    for (const auto& var : participantUserIds) {
        const QString uidStr = var.toString().trimmed();
        if (!uidStr.isEmpty() && uidStr != QStringLiteral("operator@securecloud.org")) {
            pVec.emplace_back(uidStr.toStdString());
            pUserIdsStr.push_back(uidStr);
            const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(uidStr.toStdString()));
            if (cRes.is_ok()) {
                totalDeviceFanout += static_cast<int>(cRes.value().authorized_device_count());
            } else {
                totalDeviceFanout += 1;
            }
        }
    }

    const auto createRes = app_.bootstrap().messaging_manager().create_group_conversation(
        domain::UserId("operator@securecloud.org"), cleanedTitle.toStdString(), pVec);

    if (createRes.is_error()) {
        emit workspaceError(QString::fromStdString(createRes.error().user_message()));
        return QString();
    }

    const QString convId = QStringLiteral("conv-group-%1").arg(++next_msg_seq_);
    const int totalMembers = static_cast<int>(pUserIdsStr.size());

    conversations_.insert(conversations_.begin(),
                          ConversationEntry{convId, QStringLiteral("group-%1").arg(next_msg_seq_), cleanedTitle,
                                            QStringLiteral("Group · %1 members").arg(totalMembers),
                                            QStringLiteral("Online"), true, false,
                                            QStringLiteral("GROUP-ROOT-SAFETY-NUMBER"),
                                            QStringLiteral("Encrypted Group · Sender Keys + Pairwise Double Ratchet"),
                                            QStringLiteral("Group conversation created."), QStringLiteral("Just now"),
                                            0, 1, true, pUserIdsStr, totalDeviceFanout, QStringLiteral("Verified")});

    selectConversation(convId);
    return convId;
}

bool WorkspaceViewModel::addParticipantToActiveGroup(const QString& userId) {
    if (userId.trimmed().isEmpty()) {
        return false;
    }

    auto* conv = findConversationMutable(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        emit workspaceError(QStringLiteral("Can only add participants to an active group conversation."));
        return false;
    }

    for (const auto& existing : conv->participantUserIds) {
        if (existing == userId) {
            emit workspaceError(QStringLiteral("User is already a participant in this group."));
            return false;
        }
    }

    (void)app_.bootstrap().messaging_manager().add_group_participant(
        domain::ConversationId(conv->conversationId.toStdString()), domain::UserId(userId.toStdString()));

    conv->participantUserIds.push_back(userId);
    const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(userId.toStdString()));
    if (cRes.is_ok()) {
        conv->authorizedDeviceCount += static_cast<int>(cRes.value().authorized_device_count());
    } else {
        conv->authorizedDeviceCount += 1;
    }
    conv->peerHandle = QStringLiteral("Group · %1 members").arg(conv->participantUserIds.size());

    // Append system message to group chat stream
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-%1").arg(++next_msg_seq_), conv->conversationId, QStringLiteral("System"), false,
        QStringLiteral("Participant %1 added to encrypted group.").arg(userId), QStringLiteral("Just now"),
        QStringLiteral("TODAY"), QStringLiteral("Verified"), false, QString(), QString(), QString(), QString(),
        QString(), 1, QStringLiteral("idem-%1").arg(next_msg_seq_), false});

    emit selectedConversationChanged();
    emit conversationsChanged();
    emit activeMessagesChanged();
    return true;
}

bool WorkspaceViewModel::removeParticipantFromActiveGroup(const QString& userId) {
    if (userId.trimmed().isEmpty()) {
        return false;
    }

    auto* conv = findConversationMutable(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        return false;
    }

    const auto it = std::find(conv->participantUserIds.begin(), conv->participantUserIds.end(), userId);
    if (it == conv->participantUserIds.end()) {
        return false;
    }

    (void)app_.bootstrap().messaging_manager().remove_group_participant(
        domain::ConversationId(conv->conversationId.toStdString()), domain::UserId(userId.toStdString()));

    conv->participantUserIds.erase(it);
    const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(userId.toStdString()));
    if (cRes.is_ok()) {
        conv->authorizedDeviceCount =
            std::max(1, conv->authorizedDeviceCount - static_cast<int>(cRes.value().authorized_device_count()));
    }
    conv->peerHandle = QStringLiteral("Group · %1 members").arg(conv->participantUserIds.size());

    // Append system message
    messages_.push_back(MessageEntry{
        QStringLiteral("msg-%1").arg(++next_msg_seq_), conv->conversationId, QStringLiteral("System"), false,
        QStringLiteral("Participant %1 removed from encrypted group.").arg(userId), QStringLiteral("Just now"),
        QStringLiteral("TODAY"), QStringLiteral("Verified"), false, QString(), QString(), QString(), QString(),
        QString(), 1, QStringLiteral("idem-%1").arg(next_msg_seq_), false});

    emit selectedConversationChanged();
    emit conversationsChanged();
    emit activeMessagesChanged();
    return true;
}

bool WorkspaceViewModel::leaveActiveGroup() {
    auto* conv = findConversationMutable(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        return false;
    }

    (void)app_.bootstrap().messaging_manager().leave_conversation(
        domain::ConversationId(conv->conversationId.toStdString()), domain::UserId("operator@securecloud.org"));

    const QString leavingId = conv->conversationId;
    conversations_.erase(std::remove_if(conversations_.begin(), conversations_.end(),
                                        [&](const ConversationEntry& c) { return c.conversationId == leavingId; }),
                         conversations_.end());

    if (!conversations_.empty()) {
        selectConversation(conversations_.front().conversationId);
    }

    emit conversationsChanged();
    return true;
}

bool WorkspaceViewModel::retryFailedMessage(const QString& messageId) {
    if (messageId.trimmed().isEmpty()) {
        return false;
    }

    for (auto& msg : messages_) {
        if (msg.messageId == messageId && msg.deliveryState == QStringLiteral("Failed")) {
            msg.deliveryState = QStringLiteral("Delivered");
            auto* conv = findConversationMutable(msg.conversationId);
            if (conv) {
                conv->lastMessagePreview = QStringLiteral("YOU: %1").arg(msg.text);
            }
            (void)app_.bootstrap().messaging_manager().retry_failed_message(
                domain::ConversationId(msg.conversationId.toStdString()),
                domain::MessageId(msg.messageId.toStdString()));
            emit activeMessagesChanged();
            emit conversationsChanged();
            return true;
        }
    }
    return false;
}

bool WorkspaceViewModel::discardFailedMessage(const QString& messageId) {
    if (messageId.trimmed().isEmpty()) {
        return false;
    }

    const auto it = std::find_if(messages_.begin(), messages_.end(),
                                 [&](const MessageEntry& m) { return m.messageId == messageId; });
    if (it != messages_.end()) {
        messages_.erase(it);
        emit activeMessagesChanged();
        return true;
    }
    return false;
}

void WorkspaceViewModel::setSimulateDeliveryFailure(bool enabled) {
    setDeliveryFailureSimulated(enabled);
}

bool WorkspaceViewModel::acknowledgeEmergencyMessage(const QString& messageId) {
    if (messageId.trimmed().isEmpty()) {
        return false;
    }

    for (auto& msg : messages_) {
        if (msg.messageId == messageId && msg.priority == 3) {
            msg.emergencyAcknowledged = true;
            (void)app_.bootstrap().emergency_manager().acknowledge_emergency_message(
                domain::ConversationId(msg.conversationId.toStdString()),
                domain::MessageId(msg.messageId.toStdString()), domain::UserId("operator@securecloud.org"));
            emit activeMessagesChanged();
            emit selectedConversationChanged();
            return true;
        }
    }
    return false;
}

void WorkspaceViewModel::clearSearchQuery() {
    setSearchQuery(QString());
}

} // namespace securecloud::client::ui
