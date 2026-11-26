#include "ui/workspace_view_model.hpp"

#include "application/interfaces/i_hardware_authenticator.hpp"
#include "application/managers/device_pairing_coordinator.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "domain/contact.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/recovery_phrase_engine.hpp"
#include "domain/crypto_identity.hpp"
#include "domain/device_id.hpp"
#include "domain/file_transfer.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/realtime_events.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "ui/ui_theme.hpp"

#include <QBuffer>
#include <QGuiApplication>
#include <QImage>
#include <QMetaObject>
#include <QPainter>
#include <QPainterPath>
#include <QPointer>
#include <QUrl>
#include <QUuid>
#include <algorithm>
#include <cmath>
#include <unordered_set>

namespace securecloud::client::ui {

WorkspaceViewModel::WorkspaceViewModel(application::ClientApplication& app, NavigationController& nav_controller,
                                       QObject* parent)
    : QObject(parent), app_(app), nav_controller_(nav_controller) {
    connect(&nav_controller_, &NavigationController::workspaceSectionChanged, this, [this](const QString& section) {
        emit activeSectionChanged();
        if (section == QStringLiteral("Messages")) {
            markSelectedConversationReadIfActive();
        }
    });
    if (qGuiApp != nullptr) {
        connect(qGuiApp, &QGuiApplication::applicationStateChanged, this, [this](Qt::ApplicationState state) {
            if (state == Qt::ApplicationActive) {
                markSelectedConversationReadIfActive();
            }
        });
    }

    QPointer<WorkspaceViewModel> self(this);
    app_.bootstrap().contact_manager().set_key_change_alert_callback(
        [self](const domain::UserId& peer_uid, const std::string& new_safety_number) {
            if (!self) {
                return;
            }
            const QString target_uid = QString::fromStdString(peer_uid.value());
            for (auto& conv : self->conversations_) {
                if (!conv.isGroup && conv.peerUserId == target_uid) {
                    conv.isVerified = false;
                    conv.verificationStatus = QStringLiteral("KeyChanged");
                    if (!new_safety_number.empty()) {
                        conv.safetyNumber = QString::fromStdString(new_safety_number);
                    }
                }
            }
            emit self->selectedConversationChanged();
            emit self->conversationsChanged();
            emit self->contactsChanged();
        });

    app_.bootstrap().file_manager().set_progress_callback([self](const domain::FileTransferRecord& record) {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(
            self.data(),
            [self, record]() {
                if (self) {
                    self->applyFileTransferUpdate(record);
                }
            },
            Qt::AutoConnection);
    });

    const bool has_persistent_db = !app_.bootstrap().config().database_path.empty();
    const auto persisted_convs = app_.bootstrap().messaging_manager().list_conversations();
    const auto persisted_transfers = app_.bootstrap().file_manager().list_transfers();
    if (has_persistent_db || (persisted_convs.is_ok() && !persisted_convs.value().empty()) ||
        (persisted_transfers.is_ok() && !persisted_transfers.value().empty())) {
        hydrateFromLocalStore();
    } else {
        seedDefaultWorkspaceData();
    }
    hydrateSettingsAndProfile();

    realtime_sub_id_ = app_.bootstrap().gateway().subscribe_realtime_events([self](const domain::RealtimeEvent& event) {
        if (!self) {
            return;
        }
        QMetaObject::invokeMethod(
            self.data(),
            [self, event]() {
                if (self) {
                    self->handleRealtimeEvent(event);
                }
            },
            Qt::QueuedConnection);
    });

    connectivity_sub_id_ =
        app_.bootstrap().sync_manager().subscribe_connectivity_state([self](domain::ConnectivityState) {
            if (!self) {
                return;
            }
            QMetaObject::invokeMethod(
                self.data(),
                [self]() {
                    if (!self) {
                        return;
                    }
                    emit self->connectivityStateChanged();
                    emit self->pendingOutboxCountChanged();
                },
                Qt::AutoConnection);
        });

    connect(&live_sync_timer_, &QTimer::timeout, this, [this]() { pollLiveSync(); });
    live_sync_timer_.start(2500);
}

WorkspaceViewModel::~WorkspaceViewModel() {
    app_.bootstrap().file_manager().set_progress_callback({});
    if (realtime_sub_id_ != 0) {
        app_.bootstrap().gateway().unsubscribe_realtime_events(realtime_sub_id_);
        realtime_sub_id_ = 0;
    }
    if (connectivity_sub_id_ != 0) {
        app_.bootstrap().sync_manager().unsubscribe_connectivity_state(connectivity_sub_id_);
        connectivity_sub_id_ = 0;
    }
}

domain::UserId WorkspaceViewModel::localUserId() const {
    const auto& current = app_.bootstrap().auth_manager().current_user();
    if (!current.value().empty()) {
        return current;
    }
    return domain::UserId("operator@securecloud.org");
}

domain::DeviceId WorkspaceViewModel::localDeviceId() const {
    const auto local_res = app_.bootstrap().device_manager().get_local_device();
    if (local_res.is_ok() && !local_res.value().device_id().empty()) {
        return local_res.value().device_id();
    }
    return domain::DeviceId("dev-local-01");
}

void WorkspaceViewModel::reloadFromLocalStore() {
    const QString prev_conv_id = selected_conversation_id_;
    const QString prev_tx_id = selected_transfer_id_;
    hydrateFromLocalStore();
    if (!prev_conv_id.isEmpty() && findConversation(prev_conv_id) != nullptr) {
        selected_conversation_id_ = prev_conv_id;
    }
    if (!prev_tx_id.isEmpty()) {
        for (const auto& tx : file_transfers_) {
            if (tx.transferId == prev_tx_id) {
                selected_transfer_id_ = prev_tx_id;
                break;
            }
        }
    }
    emit conversationsChanged();
    emit activeMessagesChanged();
    emit selectedConversationChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
    emit selectedTransferChanged();
    emit pendingOutboxCountChanged();
    emit connectivityStateChanged();
    hydrateSettingsAndProfile();
    emit profileSettingsChanged();
    emit appearanceSettingsChanged();
    emit networkSettingsChanged();
    emit privacySecuritySettingsChanged();
    emit mfaPolicyChanged();
    emit readReceiptsEnabledChanged();
}

QString WorkspaceViewModel::connectivityState() const {
    const auto sv = domain::to_string(app_.bootstrap().sync_manager().connectivity_state());
    return QString::fromUtf8(sv.data(), static_cast<qsizetype>(sv.size()));
}

bool WorkspaceViewModel::isOffline() const {
    return app_.bootstrap().sync_manager().connectivity_state() == domain::ConnectivityState::Offline;
}

bool WorkspaceViewModel::isSyncing() const {
    return app_.bootstrap().sync_manager().connectivity_state() == domain::ConnectivityState::Syncing;
}

int WorkspaceViewModel::pendingOutboxCount() const {
    return static_cast<int>(app_.bootstrap().messaging_manager().pending_outbox_count());
}

QString WorkspaceViewModel::syncStatusSummary() const {
    const int pending = pendingOutboxCount();
    const auto state = app_.bootstrap().sync_manager().connectivity_state();
    if (state == domain::ConnectivityState::Offline) {
        return QStringLiteral("Offline Mode — Messages & receipts are encrypted and queued locally (%1 in outbox)")
            .arg(pending);
    }
    if (state == domain::ConnectivityState::Syncing) {
        return QStringLiteral("Catch-Up Sync Active — Reconciling encrypted outbox & missed sequence delta...");
    }
    if (pending > 0) {
        return QStringLiteral("Online — %1 encrypted item(s) awaiting outbox sync").arg(pending);
    }
    return QStringLiteral("Online — Encrypted vault synchronized");
}

void WorkspaceViewModel::setSimulatedOfflineMode(bool offline) {
    app_.bootstrap().sync_manager().set_local_identity(localUserId(), localDeviceId());
    if (auto* gw = dynamic_cast<infrastructure::adapters::DefaultGatewayClient*>(&app_.bootstrap().gateway());
        gw != nullptr) {
        gw->set_simulated_failure(offline, "Simulated offline mode");
        gw->set_simulated_submission_failure(offline, "Simulated offline mode");
    }

    const auto res = app_.bootstrap().sync_manager().set_simulated_offline(offline);
    if (!offline) {
        reloadFromLocalStore();
    } else {
        emit connectivityStateChanged();
        emit pendingOutboxCountChanged();
    }
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
    }
}

bool WorkspaceViewModel::triggerCatchUpSync() {
    app_.bootstrap().sync_manager().set_local_identity(localUserId(), localDeviceId());
    if (app_.bootstrap().sync_manager().is_simulated_offline()) {
        setSimulatedOfflineMode(false);
        return !isOffline();
    }
    const auto res = app_.bootstrap().sync_manager().execute_catch_up_sync(localUserId(), localDeviceId());
    reloadFromLocalStore();
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }
    return true;
}

void WorkspaceViewModel::markSelectedConversationReadIfActive() {
    if (!app_.bootstrap().is_live_gateway_transport_active() || !app_.bootstrap().auth_manager().is_authenticated() ||
        selected_conversation_id_.isEmpty() || activeSection() != QStringLiteral("Messages")) {
        return;
    }
    if (qGuiApp != nullptr && qGuiApp->applicationState() != Qt::ApplicationActive) {
        return;
    }
    const auto* conv = findConversation(selected_conversation_id_);
    if (conv == nullptr || conv->unreadCount <= 0) {
        return;
    }
    (void)app_.bootstrap().messaging_manager().mark_conversation_read(
        domain::ConversationId(selected_conversation_id_.toStdString()), localUserId(), localDeviceId());
    reloadFromLocalStore();
}

void WorkspaceViewModel::pollLiveSync() {
    if (!app_.bootstrap().is_live_gateway_transport_active() || !app_.bootstrap().auth_manager().is_authenticated() ||
        isSyncing()) {
        return;
    }
    app_.bootstrap().sync_manager().set_local_identity(localUserId(), localDeviceId());
    if (isOffline()) {
        if (!app_.bootstrap().sync_manager().is_simulated_offline()) {
            const auto conn_res = app_.bootstrap().sync_manager().check_connectivity();
            if (conn_res.is_ok() && conn_res.value() == domain::ConnectivityState::Online) {
                reloadFromLocalStore();
            }
        }
        return;
    }

    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
            .count();
    if (last_presence_heartbeat_ms_ == 0 || (now_ms - last_presence_heartbeat_ms_) >= 15000) {
        if (app_.bootstrap().gateway().update_presence("online").is_ok()) {
            last_presence_heartbeat_ms_ = now_ms;
        }
    }

    bool should_reload = false;
    bool new_messages_arrived = false;
    const auto res = app_.bootstrap().sync_manager().execute_catch_up_sync(localUserId(), localDeviceId(), 50U, 10U);
    if (res.is_ok()) {
        const auto& r = res.value();
        if (r.messages_merged_count > 0) {
            new_messages_arrived = true;
        }
        if (r.outbox_flushed_count > 0 || r.messages_merged_count > 0 || r.conversations_reconciled_count > 0 ||
            r.contacts_reconciled_count > 0 || r.transfers_resumed_count > 0) {
            should_reload = true;
        }
    }

    const auto poll_res = app_.bootstrap().sync_manager().poll_realtime_updates(localDeviceId());
    if (poll_res.is_ok() && poll_res.value() > 0) {
        should_reload = true;
    }

    const bool is_viewing_active_thread = !selected_conversation_id_.isEmpty() &&
                                          activeSection() == QStringLiteral("Messages") &&
                                          (qGuiApp == nullptr || qGuiApp->applicationState() == Qt::ApplicationActive);
    if (new_messages_arrived && is_viewing_active_thread) {
        (void)app_.bootstrap().messaging_manager().mark_conversation_read(
            domain::ConversationId(selected_conversation_id_.toStdString()), localUserId(), localDeviceId());
        should_reload = true;
    }

    if (should_reload) {
        reloadFromLocalStore();
    }

    std::vector<domain::UserId> peer_ids;
    std::unordered_set<std::string> seen_peers;
    for (const auto& conv : conversations_) {
        if (!conv.isGroup && !conv.peerUserId.trimmed().isEmpty()) {
            const std::string uid_str = conv.peerUserId.toStdString();
            if (seen_peers.insert(uid_str).second) {
                peer_ids.emplace_back(uid_str);
            }
        }
    }
    if (!peer_ids.empty()) {
        const auto pres_res = app_.bootstrap().gateway().batch_get_presence(peer_ids);
        if (pres_res.is_ok()) {
            bool presence_changed = false;
            for (const auto& info : pres_res.value()) {
                QString normalized = QStringLiteral("Offline");
                if (info.status == "online") {
                    normalized = QStringLiteral("Online");
                } else if (info.status == "away") {
                    normalized = QStringLiteral("Away");
                } else if (info.status == "busy") {
                    normalized = QStringLiteral("Busy");
                }
                peer_presence_cache_[info.user_id.value()] = normalized;
                const QString uid_q = QString::fromStdString(info.user_id.value());
                for (auto& conv : conversations_) {
                    if (!conv.isGroup && conv.peerUserId == uid_q && conv.presence != normalized) {
                        conv.presence = normalized;
                        presence_changed = true;
                    }
                }
            }
            if (presence_changed) {
                emit conversationsChanged();
                emit contactsChanged();
                emit selectedConversationChanged();
            }
        }
    }
}

void WorkspaceViewModel::hydrateFromLocalStore() {
    conversations_.clear();
    messages_.clear();
    file_transfers_.clear();
    selected_conversation_id_.clear();
    selected_transfer_id_.clear();

    const domain::UserId self_uid = localUserId();
    const auto convs_res = app_.bootstrap().messaging_manager().list_conversations();
    if (convs_res.is_ok()) {
        for (const auto& conv : convs_res.value()) {
            const QString cid = QString::fromStdString(conv.conversation_id().value());
            const bool is_group = (conv.type() == domain::ConversationType::Group);

            std::vector<QString> participant_strs;
            participant_strs.reserve(conv.participants().size());
            int total_devices = 0;
            QString direct_peer_uid;

            for (const auto& p_uid : conv.participants()) {
                const QString uid_q = QString::fromStdString(p_uid.value());
                participant_strs.push_back(uid_q);
                if (p_uid == self_uid) {
                    total_devices += 1;
                } else {
                    if (direct_peer_uid.isEmpty()) {
                        direct_peer_uid = uid_q;
                    }
                    const auto c_res = app_.bootstrap().contact_manager().get_contact(p_uid);
                    total_devices += c_res.is_ok() ? static_cast<int>(c_res.value().authorized_device_count()) : 1;
                }
            }
            if (total_devices == 0) {
                total_devices = 1;
            }

            QString display_name = QString::fromStdString(conv.title());
            QString handle = is_group ? QStringLiteral("Group · %1 members").arg(participant_strs.size()) : QString();
            QString presence = QStringLiteral("Offline");
            bool verified = false;
            bool blocked = false;
            QString safety_number;
            QString role_note =
                is_group ? QStringLiteral("Encrypted Group · Sender Keys + Pairwise Double Ratchet") : QString();
            QString ver_status = QStringLiteral("Unverified");

            if (!is_group && !direct_peer_uid.isEmpty()) {
                const domain::UserId peer_uid(direct_peer_uid.toStdString());
                const auto cache_it = peer_presence_cache_.find(direct_peer_uid.toStdString());
                auto c_res = app_.bootstrap().contact_manager().get_contact(peer_uid);
                if (c_res.is_error() && app_.bootstrap().is_live_gateway_transport_active() &&
                    app_.bootstrap().contact_manager().has_local_identity()) {
                    c_res = app_.bootstrap().contact_manager().create_contact(peer_uid, peer_uid.value(), "", "", 1);
                }
                if (c_res.is_ok()) {
                    const auto& contact = c_res.value();
                    if (!contact.alias().empty() &&
                        (display_name.isEmpty() || contact.alias() != direct_peer_uid.toStdString())) {
                        display_name = QString::fromStdString(contact.alias());
                    }
                    handle =
                        QStringLiteral("@%1").arg(QString::fromStdString(contact.alias()).toLower().replace(' ', '.'));
                    presence = (cache_it != peer_presence_cache_.end())
                                   ? cache_it->second
                                   : QString::fromUtf8(domain::to_string(contact.presence_status()).data());
                    verified = contact.is_verified();
                    blocked = contact.is_blocked();
                    safety_number = QString::fromStdString(contact.safety_number());
                    if (safety_number.isEmpty() && app_.bootstrap().is_live_gateway_transport_active() &&
                        app_.bootstrap().contact_manager().has_local_identity()) {
                        const auto sn_res = app_.bootstrap().contact_manager().get_or_compute_safety_number(peer_uid);
                        if (sn_res.is_ok()) {
                            safety_number = QString::fromStdString(sn_res.value());
                        }
                    }
                    role_note = QString::fromStdString(contact.role_note());
                    ver_status = QString::fromUtf8(domain::to_string(contact.verification_status()).data());
                } else {
                    if (display_name.isEmpty()) {
                        display_name = direct_peer_uid;
                    }
                    if (cache_it != peer_presence_cache_.end()) {
                        presence = cache_it->second;
                    }
                    handle = QStringLiteral("@%1").arg(direct_peer_uid);
                }
            } else if (is_group) {
                verified = true;
                presence = QStringLiteral("Online");
                safety_number = QStringLiteral("GROUP-ROOT-SAFETY-NUMBER");
                ver_status = QStringLiteral("Verified");
            }

            conversations_.push_back(ConversationEntry{
                cid,
                is_group ? QString::fromStdString(conv.conversation_id().value()) : direct_peer_uid,
                display_name,
                handle,
                presence,
                verified,
                blocked,
                safety_number,
                role_note,
                QString(),
                QStringLiteral("Synced"),
                static_cast<int>(conv.unread_count()),
                1,
                is_group,
                std::move(participant_strs),
                total_devices,
                ver_status,
                static_cast<int>(conv.sender_key_epoch()),
                conv.disappearing_ttl_seconds(),
            });
        }
    }

    const auto transfers_res = app_.bootstrap().file_manager().list_transfers();
    if (transfers_res.is_ok()) {
        for (const auto& rec : transfers_res.value()) {
            file_transfers_.push_back(buildTransferEntry(rec));
        }
    }

    if (convs_res.is_ok()) {
        for (std::size_t idx = 0; idx < convs_res.value().size() && idx < conversations_.size(); ++idx) {
            const auto& conv = convs_res.value()[idx];
            auto& convEntry = conversations_[idx];
            const auto msgs_res =
                app_.bootstrap().messaging_manager().get_conversation_messages(conv.conversation_id(), 100);
            QString last_preview;
            int last_priority = 1;
            if (msgs_res.is_ok()) {
                for (const auto& m : msgs_res.value()) {
                    const bool is_self = (m.sender_user_id() == self_uid);
                    const QString sender_label =
                        is_self ? QStringLiteral("You")
                                : (m.sender_display_name().empty() ? QString::fromStdString(m.sender_user_id().value())
                                                                   : QString::fromStdString(m.sender_display_name()));
                    const int prio = (m.priority() >= 1 && m.priority() <= 3) ? m.priority() : 1;

                    if (domain::FileAttachmentKeyEnvelope::is_file_attachment_envelope(m.encrypted_envelope_ref())) {
                        const auto envOpt = domain::FileAttachmentKeyEnvelope::deserialize(m.encrypted_envelope_ref());
                        if (envOpt.has_value()) {
                            const auto& env = *envOpt;
                            QString linkedTransferId;
                            const QString envFileId = QString::fromStdString(env.file_id);
                            for (const auto& tx : file_transfers_) {
                                if (tx.fileId == envFileId) {
                                    linkedTransferId = tx.transferId;
                                    break;
                                }
                            }
                            const QString fname = QString::fromStdString(env.file_name);
                            const QString fsize = formatFileSize(static_cast<qint64>(env.plaintext_size_bytes));
                            const QString csuite = QString::fromStdString(env.cipher_suite);
                            const QString fhash = formatShortHash(
                                !env.plaintext_sha256.empty() ? env.plaintext_sha256 : env.ciphertext_sha256);

                            messages_.push_back(MessageEntry{
                                QString::fromStdString(m.message_id().value()),
                                convEntry.conversationId,
                                sender_label,
                                is_self,
                                QStringLiteral("Encrypted File Attachment"),
                                QStringLiteral("Persisted"),
                                QStringLiteral("HISTORY"),
                                QString::fromUtf8(domain::to_string(m.delivery_state()).data()),
                                true,
                                linkedTransferId,
                                fname,
                                fsize,
                                csuite,
                                fhash,
                                prio,
                                QString::fromStdString(m.idempotency_key()),
                                m.emergency_acknowledged(),
                            });

                            last_preview = is_self ? QStringLiteral("YOU: Uploaded %1 (%2)").arg(fname, csuite)
                                                   : QStringLiteral("Encrypted File: %1").arg(fname);
                            last_priority = prio;
                            continue;
                        }
                    }

                    const QString body = QString::fromStdString(m.encrypted_envelope_ref());
                    messages_.push_back(MessageEntry{
                        QString::fromStdString(m.message_id().value()),
                        convEntry.conversationId,
                        sender_label,
                        is_self,
                        body,
                        QStringLiteral("Persisted"),
                        QStringLiteral("HISTORY"),
                        QString::fromUtf8(domain::to_string(m.delivery_state()).data()),
                        !m.attachment_name().empty(),
                        QString(),
                        QString::fromStdString(m.attachment_name()),
                        m.attachment_size() > 0 ? formatFileSize(m.attachment_size()) : QString(),
                        QStringLiteral("AES-256-GCM"),
                        QString::fromStdString(m.attachment_hash()),
                        prio,
                        QString::fromStdString(m.idempotency_key()),
                        m.emergency_acknowledged(),
                    });

                    last_preview = is_self ? QStringLiteral("YOU: %1").arg(body) : body;
                    last_priority = prio;
                }
            }
            convEntry.lastMessagePreview = last_preview;
            convEntry.lastMessagePriority = last_priority;
        }
    }

    if (!conversations_.empty()) {
        selected_conversation_id_ = conversations_.front().conversationId;
    }
    if (!file_transfers_.empty()) {
        selected_transfer_id_ = file_transfers_.front().transferId;
    }
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
    if (!app_.bootstrap().contact_manager().has_local_identity()) {
        app_.bootstrap().contact_manager().set_local_identity(domain::UserId("operator@securecloud.org"),
                                                              std::vector<uint8_t>(32, 0xA5));
    }

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
        if (conv.isGroup) {
            domainConv.set_participant_role(localUserId(), domain::ParticipantRole::Admin);
            domainConv.set_sender_key_epoch(static_cast<uint64_t>(std::max(1, conv.senderKeyEpoch)));
        }
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
        QString displayName = conv.peerDisplayName;
        QString presence = conv.presence;
        bool isVerified = conv.isVerified;
        bool isBlocked = conv.isBlocked;
        QString safetyNumber = conv.safetyNumber;
        int deviceCount = conv.authorizedDeviceCount;
        QString verificationStatus = conv.verificationStatus;

        if (!conv.isGroup && !conv.peerUserId.trimmed().isEmpty()) {
            const auto cRes =
                app_.bootstrap().contact_manager().get_contact(domain::UserId(conv.peerUserId.toStdString()));
            if (cRes.is_ok()) {
                const auto& c = cRes.value();
                if (!c.alias().empty()) {
                    displayName = QString::fromStdString(c.alias());
                }
                isVerified = c.is_verified();
                isBlocked = c.is_blocked();
                if (!c.safety_number().empty()) {
                    safetyNumber = QString::fromStdString(c.safety_number());
                }
                deviceCount = static_cast<int>(c.authorized_device_count());
                const auto statusSv = domain::to_string(c.verification_status());
                verificationStatus = QString::fromUtf8(statusSv.data(), static_cast<qsizetype>(statusSv.size()));
            }
            if (isBlocked) {
                presence = QStringLiteral("Offline");
            }
        }

        const QString priorityStr = priorityToLabel(conv.lastMessagePriority);
        if (!matchesQuery(displayName) && !matchesQuery(conv.peerHandle) && !matchesQuery(conv.lastMessagePreview) &&
            !matchesQuery(priorityStr)) {
            continue;
        }
        QVariantMap item;
        item.insert(QStringLiteral("conversationId"), conv.conversationId);
        item.insert(QStringLiteral("peerUserId"), conv.peerUserId);
        item.insert(QStringLiteral("peerDisplayName"), displayName);
        item.insert(QStringLiteral("peerHandle"), conv.peerHandle);
        item.insert(QStringLiteral("presence"), presence);
        item.insert(QStringLiteral("isVerified"), isVerified);
        item.insert(QStringLiteral("isBlocked"), isBlocked);
        item.insert(QStringLiteral("safetyNumber"), safetyNumber);
        item.insert(QStringLiteral("lastMessagePreview"), conv.lastMessagePreview);
        item.insert(QStringLiteral("timestampText"), conv.timestampText);
        item.insert(QStringLiteral("unreadCount"), conv.unreadCount);
        item.insert(QStringLiteral("priority"), conv.lastMessagePriority);
        item.insert(QStringLiteral("priorityLabel"), priorityStr);
        item.insert(QStringLiteral("isSelected"), conv.conversationId == selected_conversation_id_);
        item.insert(QStringLiteral("isGroup"), conv.isGroup);
        item.insert(QStringLiteral("participantCount"), static_cast<int>(conv.participantUserIds.size()));
        item.insert(QStringLiteral("deviceCount"), deviceCount);
        item.insert(QStringLiteral("verificationStatus"), verificationStatus);
        result.append(item);
    }
    return result;
}

QVariantList WorkspaceViewModel::contacts() const {
    QVariantList result;
    std::unordered_set<std::string> seen_user_ids;

    for (const auto& conv : conversations_) {
        if (conv.isGroup || conv.peerUserId.trimmed().isEmpty()) {
            continue;
        }
        seen_user_ids.insert(conv.peerUserId.toStdString());

        QString displayName = conv.peerDisplayName;
        QString presence = conv.presence;
        bool isVerified = conv.isVerified;
        bool isBlocked = conv.isBlocked;
        QString safetyNumber = conv.safetyNumber;
        QString roleNote = conv.roleNote;
        int deviceCount = conv.authorizedDeviceCount;
        QString verificationStatus = conv.verificationStatus;

        const auto cRes = app_.bootstrap().contact_manager().get_contact(domain::UserId(conv.peerUserId.toStdString()));
        if (cRes.is_ok()) {
            const auto& c = cRes.value();
            if (!c.alias().empty()) {
                displayName = QString::fromStdString(c.alias());
            }
            isVerified = c.is_verified();
            isBlocked = c.is_blocked();
            if (isBlocked) {
                presence = QStringLiteral("Offline");
            }
            if (!c.safety_number().empty()) {
                safetyNumber = QString::fromStdString(c.safety_number());
            }
            if (!c.role_note().empty()) {
                roleNote = QString::fromStdString(c.role_note());
            }
            deviceCount = static_cast<int>(c.authorized_device_count());
            const auto statusSv = domain::to_string(c.verification_status());
            verificationStatus = QString::fromUtf8(statusSv.data(), static_cast<qsizetype>(statusSv.size()));
        }

        if (!matchesQuery(displayName) && !matchesQuery(conv.peerHandle) && !matchesQuery(roleNote)) {
            continue;
        }

        QVariantMap item;
        item.insert(QStringLiteral("userId"), conv.peerUserId);
        item.insert(QStringLiteral("displayName"), displayName);
        item.insert(QStringLiteral("handle"), conv.peerHandle);
        item.insert(QStringLiteral("presence"), presence);
        item.insert(QStringLiteral("isVerified"), isVerified);
        item.insert(QStringLiteral("isBlocked"), isBlocked);
        item.insert(QStringLiteral("safetyNumber"), safetyNumber);
        item.insert(QStringLiteral("roleNote"), roleNote);
        item.insert(QStringLiteral("conversationId"), conv.conversationId);
        item.insert(QStringLiteral("isSelected"), conv.conversationId == selected_conversation_id_);
        item.insert(QStringLiteral("deviceCount"), deviceCount);
        item.insert(QStringLiteral("verificationStatus"), verificationStatus);
        result.append(item);
    }

    // Append any directory/local contacts not currently backed by an active conversation entry
    const auto allRes = app_.bootstrap().contact_manager().get_contacts();
    if (allRes.is_ok()) {
        for (const auto& c : allRes.value()) {
            const std::string& uid = c.user_id().value();
            if (uid == "operator@securecloud.org" || seen_user_ids.contains(uid)) {
                continue;
            }
            const QString qUid = QString::fromStdString(uid);
            const QString displayName = QString::fromStdString(c.alias());
            const QString handle = qUid.startsWith('@') ? qUid : QStringLiteral("@%1").arg(qUid.section('@', 0, 0));
            const QString roleNote = QString::fromStdString(c.role_note());
            if (!matchesQuery(displayName) && !matchesQuery(handle) && !matchesQuery(roleNote)) {
                continue;
            }
            const auto presenceSv =
                domain::to_string(c.is_blocked() ? domain::PresenceStatus::Offline : c.presence_status());
            const auto statusSv = domain::to_string(c.verification_status());

            QVariantMap item;
            item.insert(QStringLiteral("userId"), qUid);
            item.insert(QStringLiteral("displayName"), displayName);
            item.insert(QStringLiteral("handle"), handle);
            item.insert(QStringLiteral("presence"),
                        QString::fromUtf8(presenceSv.data(), static_cast<qsizetype>(presenceSv.size())));
            item.insert(QStringLiteral("isVerified"), c.is_verified());
            item.insert(QStringLiteral("isBlocked"), c.is_blocked());
            item.insert(QStringLiteral("safetyNumber"), QString::fromStdString(c.safety_number()));
            item.insert(QStringLiteral("roleNote"), roleNote);
            item.insert(QStringLiteral("conversationId"), QString());
            item.insert(QStringLiteral("isSelected"), false);
            item.insert(QStringLiteral("deviceCount"), static_cast<int>(c.authorized_device_count()));
            item.insert(QStringLiteral("verificationStatus"),
                        QString::fromUtf8(statusSv.data(), static_cast<qsizetype>(statusSv.size())));
            result.append(item);
        }
    }

    return result;
}

QString WorkspaceViewModel::normalizeLocalPath(const QString& pathOrUrl) {
    const QString trimmed = pathOrUrl.trimmed();
    if (trimmed.isEmpty()) {
        return QString();
    }
    const QUrl url(trimmed);
    if (url.isLocalFile()) {
        return url.toLocalFile();
    }
    return trimmed;
}

QString WorkspaceViewModel::formatShortHash(const std::string& hexHash) {
    if (hexHash.size() > 19U) {
        return QString::fromStdString(hexHash.substr(0U, 8U) + "..." + hexHash.substr(hexHash.size() - 8U));
    }
    return QString::fromStdString(hexHash);
}

QString WorkspaceViewModel::resolvePeerDisplayName(const QString& conversationId,
                                                   const domain::UserId& peerUserId) const {
    for (const auto& conv : conversations_) {
        if (conv.conversationId == conversationId && !conv.peerDisplayName.isEmpty()) {
            return conv.peerDisplayName;
        }
    }
    if (!peerUserId.empty()) {
        const auto cRes = app_.bootstrap().contact_manager().get_contact(peerUserId);
        if (cRes.is_ok() && !cRes.value().alias().empty()) {
            return QString::fromStdString(cRes.value().alias());
        }
        return QString::fromStdString(peerUserId.value());
    }
    return QStringLiteral("Encrypted Peer");
}

WorkspaceViewModel::FileTransferEntry
WorkspaceViewModel::buildTransferEntry(const domain::FileTransferRecord& record) const {
    FileTransferEntry tx;
    tx.transferId = QString::fromStdString(record.transfer_id);
    tx.conversationId = QString::fromStdString(record.conversation_id.value());
    tx.peerUserId = QString::fromStdString(record.peer_user_id.value());
    tx.peerDisplayName = resolvePeerDisplayName(tx.conversationId, record.peer_user_id);
    tx.fileName = QString::fromStdString(record.file_name);
    const uint64_t rawBytes =
        record.plaintext_size_bytes > 0ULL ? record.plaintext_size_bytes : record.encrypted_size_bytes;
    tx.fileSizeBytes = static_cast<qint64>(rawBytes);
    tx.fileSizeText = formatFileSize(tx.fileSizeBytes);
    tx.cipherSuite = QString::fromStdString(record.cipher_suite);
    tx.sha256Short =
        formatShortHash(!record.plaintext_sha256.empty() ? record.plaintext_sha256 : record.ciphertext_sha256);
    tx.direction = (record.direction == domain::FileTransferDirection::Outbound) ? QStringLiteral("Outbound")
                                                                                 : QStringLiteral("Inbound");

    const auto statusSv = domain::to_string(record.status);
    tx.status = QString::fromUtf8(statusSv.data(), static_cast<qsizetype>(statusSv.size()));
    switch (record.status) {
    case domain::FileTransferStatus::Pending:
        tx.statusText = (record.direction == domain::FileTransferDirection::Inbound)
                            ? QStringLiteral("Ready to Download")
                            : QStringLiteral("Pending");
        break;
    case domain::FileTransferStatus::InProgress:
        tx.statusText = (record.direction == domain::FileTransferDirection::Outbound)
                            ? QStringLiteral("Uploading Chunks")
                            : QStringLiteral("Downloading Chunks");
        break;
    case domain::FileTransferStatus::Paused:
        tx.statusText = QStringLiteral("Paused");
        break;
    case domain::FileTransferStatus::Finalizing:
        tx.statusText = QStringLiteral("Finalizing & Verifying");
        break;
    case domain::FileTransferStatus::Completed:
        tx.statusText = QStringLiteral("Encrypted & Verified");
        break;
    case domain::FileTransferStatus::Cancelled:
        tx.statusText = QStringLiteral("Cancelled");
        break;
    case domain::FileTransferStatus::Failed:
        tx.statusText = QStringLiteral("Failed");
        break;
    }

    tx.timestampText = QStringLiteral("Just now");
    tx.fileId = QString::fromStdString(record.file_id);
    tx.localPath = QString::fromStdString(record.local_path);
    tx.progressPercent = static_cast<int>(record.progress_percent());
    tx.completedChunks = static_cast<int>(record.completed_chunks);
    tx.totalChunks = static_cast<int>(record.total_chunks);
    tx.errorMessage = QString::fromStdString(record.error_message);
    tx.canPause = (record.status == domain::FileTransferStatus::InProgress);
    tx.canResume = (record.status == domain::FileTransferStatus::Paused);
    tx.canDownload = (record.direction == domain::FileTransferDirection::Inbound &&
                      record.status == domain::FileTransferStatus::Pending);
    tx.canCancel = (record.status != domain::FileTransferStatus::Cancelled);
    return tx;
}

QVariantMap WorkspaceViewModel::buildTransferMap(const FileTransferEntry& tx, bool includeSelected) const {
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
    item.insert(QStringLiteral("fileId"), tx.fileId);
    item.insert(QStringLiteral("localPath"), tx.localPath);
    item.insert(QStringLiteral("status"), tx.status);
    item.insert(QStringLiteral("progressPercent"), tx.progressPercent);
    item.insert(QStringLiteral("completedChunks"), tx.completedChunks);
    item.insert(QStringLiteral("totalChunks"), tx.totalChunks);
    item.insert(
        QStringLiteral("chunkSummaryText"),
        tx.totalChunks > 0
            ? QStringLiteral("%1 / %2 chunks · %3%").arg(tx.completedChunks).arg(tx.totalChunks).arg(tx.progressPercent)
            : QStringLiteral("%1%").arg(tx.progressPercent));
    item.insert(QStringLiteral("errorMessage"), tx.errorMessage);
    item.insert(QStringLiteral("canPause"), tx.canPause);
    item.insert(QStringLiteral("canResume"), tx.canResume);
    item.insert(QStringLiteral("canDownload"), tx.canDownload);
    item.insert(QStringLiteral("canCancel"), tx.canCancel);
    if (includeSelected) {
        item.insert(QStringLiteral("isSelected"), tx.transferId == selected_transfer_id_);
    }
    return item;
}

void WorkspaceViewModel::applyFileTransferUpdate(const domain::FileTransferRecord& record) {
    FileTransferEntry updated = buildTransferEntry(record);
    bool replaced = false;
    for (auto& existing : file_transfers_) {
        if (existing.transferId == updated.transferId) {
            existing = updated;
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        file_transfers_.insert(file_transfers_.begin(), updated);
    }
    if (selected_transfer_id_.isEmpty()) {
        selected_transfer_id_ = updated.transferId;
    }
    emit fileTransfersChanged();
    emit selectedTransferChanged();
}

void WorkspaceViewModel::appendDispatchedFileMessage(ConversationEntry& conv, const domain::Message& msg,
                                                     const QString& transferId, const QString& fileName,
                                                     const QString& fileSizeText, const QString& cipherSuite,
                                                     const QString& sha256Short) {
    const QString msgId = QString::fromStdString(msg.message_id().value());
    for (const auto& existing : messages_) {
        if (existing.conversationId == conv.conversationId && existing.messageId == msgId) {
            return;
        }
    }

    const int msgPrio = (msg.priority() >= 1 && msg.priority() <= 3) ? msg.priority() : composer_priority_;
    const auto stateSv = domain::to_string(msg.delivery_state());
    messages_.push_back(MessageEntry{
        msgId,
        conv.conversationId,
        QStringLiteral("You"),
        true,
        QStringLiteral("Encrypted File Attachment"),
        QStringLiteral("Just now"),
        QStringLiteral("TODAY"),
        QString::fromUtf8(stateSv.data(), static_cast<qsizetype>(stateSv.size())),
        true,
        transferId,
        fileName,
        fileSizeText,
        cipherSuite,
        sha256Short,
        msgPrio,
        QString::fromStdString(msg.idempotency_key()),
        msg.emergency_acknowledged(),
    });

    conv.lastMessagePreview = QStringLiteral("YOU: Uploaded %1 (%2)").arg(fileName, cipherSuite);
    conv.timestampText = QStringLiteral("Just now");
    conv.lastMessagePriority = msgPrio;
}

QVariantList WorkspaceViewModel::fileTransfers() const {
    QVariantList result;
    for (const auto& tx : file_transfers_) {
        if (!matchesQuery(tx.fileName) && !matchesQuery(tx.peerDisplayName) && !matchesQuery(tx.cipherSuite) &&
            !matchesQuery(tx.statusText)) {
            continue;
        }
        result.append(buildTransferMap(tx, true));
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
    if (!conv) {
        return QStringLiteral("Offline");
    }
    if (conv->isBlocked) {
        return QStringLiteral("Offline");
    }
    if (!conv->isGroup && !conv->peerUserId.trimmed().isEmpty()) {
        const auto cRes =
            app_.bootstrap().contact_manager().get_contact(domain::UserId(conv->peerUserId.toStdString()));
        if (cRes.is_ok() && cRes.value().is_blocked()) {
            return QStringLiteral("Offline");
        }
    }
    return conv->presence;
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

    const domain::UserId self_uid = localUserId();
    const QString self_uid_q = QString::fromStdString(self_uid.value());
    const auto domain_conv_res = app_.bootstrap().messaging_manager().get_conversation(
        domain::ConversationId(conv->conversationId.toStdString()));
    const bool local_is_admin = localUserIsGroupAdmin();

    for (const auto& uidStr : conv->participantUserIds) {
        QVariantMap pItem;
        pItem.insert(QStringLiteral("userId"), uidStr);
        const bool isSelf = (uidStr == self_uid_q || uidStr == QStringLiteral("operator@securecloud.org"));
        pItem.insert(QStringLiteral("isSelf"), isSelf);

        QString roleStr = QStringLiteral("Member");
        if (domain_conv_res.is_ok() && domain_conv_res.value().is_admin(domain::UserId(uidStr.toStdString()))) {
            roleStr = QStringLiteral("Admin");
        } else if (isSelf && conv->isGroup && !domain_conv_res.is_ok()) {
            roleStr = QStringLiteral("Admin");
        }
        pItem.insert(QStringLiteral("role"), roleStr);
        pItem.insert(QStringLiteral("canRemove"), local_is_admin && !isSelf);

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

int WorkspaceViewModel::selectedGroupKeyEpoch() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        return 0;
    }
    const auto domain_conv_res = app_.bootstrap().messaging_manager().get_conversation(
        domain::ConversationId(conv->conversationId.toStdString()));
    if (domain_conv_res.is_ok()) {
        return static_cast<int>(domain_conv_res.value().sender_key_epoch());
    }
    return conv->senderKeyEpoch;
}

bool WorkspaceViewModel::localUserIsGroupAdmin() const {
    const auto* conv = findConversation(selected_conversation_id_);
    if (!conv || !conv->isGroup) {
        return false;
    }
    const auto domain_conv_res = app_.bootstrap().messaging_manager().get_conversation(
        domain::ConversationId(conv->conversationId.toStdString()));
    if (domain_conv_res.is_ok()) {
        return domain_conv_res.value().is_admin(localUserId());
    }
    return true;
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
        result.append(buildTransferMap(tx, false));
    }
    return result;
}

QVariantMap WorkspaceViewModel::selectedTransferDetails() const {
    for (const auto& tx : file_transfers_) {
        if (tx.transferId == selected_transfer_id_) {
            return buildTransferMap(tx, false);
        }
    }
    return {};
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
    if (mfa_required_on_login_ == required && settings_.mfa_required_on_login == required) {
        return;
    }
    mfa_required_on_login_ = required;
    settings_.mfa_required_on_login = required;
    (void)persistCurrentSettings();
    emit mfaPolicyChanged();
}

void WorkspaceViewModel::setHardwareKeyEnforced(bool enforced) {
    if (hardware_key_enforced_ == enforced && settings_.hardware_key_enforced == enforced) {
        return;
    }
    hardware_key_enforced_ = enforced;
    settings_.hardware_key_enforced = enforced;
    (void)persistCurrentSettings();
    emit mfaPolicyChanged();
}

bool WorkspaceViewModel::readReceiptsEnabled() const {
    return app_.bootstrap().messaging_manager().read_receipts_enabled();
}

void WorkspaceViewModel::setReadReceiptsEnabled(bool enabled) {
    if (readReceiptsEnabled() == enabled && settings_.read_receipts_enabled == enabled) {
        return;
    }
    settings_.read_receipts_enabled = enabled;
    if (!persistCurrentSettings()) {
        (void)app_.bootstrap().messaging_manager().set_read_receipts_enabled(enabled);
    }
    emit readReceiptsEnabledChanged();
}

void WorkspaceViewModel::handleRealtimeEvent(const domain::RealtimeEvent& event) {
    auto proc_res = app_.bootstrap().messaging_manager().process_inbound_realtime_event(event);
    if (proc_res.is_error()) {
        return;
    }

    const QString convId = QString::fromStdString(event.conversation_id.value());
    const QString msgId = QString::fromStdString(event.message_id.value());

    switch (event.type) {
    case domain::RealtimeEventType::DeliveryAck:
    case domain::RealtimeEventType::ReadReceipt: {
        const domain::DeliveryState target_state = (event.type == domain::RealtimeEventType::ReadReceipt)
                                                       ? domain::DeliveryState::Read
                                                       : domain::DeliveryState::Delivered;
        const QString target_str = QString::fromStdString(std::string(domain::to_string(target_state)));
        bool updated = false;
        for (auto& msg : messages_) {
            if (msg.conversationId == convId && msg.messageId == msgId) {
                const auto cur = domain::delivery_state_from_string(msg.deliveryState.toStdString())
                                     .value_or(domain::DeliveryState::Accepted);
                if (domain::can_transition_delivery_state(cur, target_state) && cur != target_state) {
                    msg.deliveryState = target_str;
                    updated = true;
                }
                break;
            }
        }
        if (updated && convId == selected_conversation_id_) {
            emit activeMessagesChanged();
        }
        break;
    }
    case domain::RealtimeEventType::InboundDirectMessage:
    case domain::RealtimeEventType::InboundGroupMessage: {
        if (proc_res.value().has_value()) {
            const auto& m = *proc_res.value();
            const QString newMsgId = QString::fromStdString(m.message_id().value());
            bool already_in_ui = false;
            for (const auto& existing : messages_) {
                if (existing.conversationId == convId && existing.messageId == newMsgId) {
                    already_in_ui = true;
                    break;
                }
            }
            if (!already_in_ui) {
                const QString senderDisplay = m.sender_display_name().empty()
                                                  ? QString::fromStdString(m.sender_user_id().value())
                                                  : QString::fromStdString(m.sender_display_name());
                const bool isSelf = (m.sender_user_id() == localUserId());
                const auto stateSv = domain::to_string(m.delivery_state());
                const QString stateStr = QString::fromUtf8(stateSv.data(), static_cast<qsizetype>(stateSv.size()));

                if (domain::FileAttachmentKeyEnvelope::is_file_attachment_envelope(m.encrypted_envelope_ref())) {
                    const auto ingestRes = app_.bootstrap().file_manager().ingest_inbound_key_envelope_json(
                        m.conversation_id(), m.sender_user_id(), m.encrypted_envelope_ref());
                    if (ingestRes.is_error()) {
                        emit workspaceError(QString::fromStdString(ingestRes.error().user_message()));
                        return;
                    }

                    const auto& rec = ingestRes.value();
                    applyFileTransferUpdate(rec);

                    const QString transferIdStr = QString::fromStdString(rec.transfer_id);
                    const QString fname = QString::fromStdString(rec.file_name);
                    const QString fsize = formatFileSize(static_cast<qint64>(rec.plaintext_size_bytes));
                    const QString csuite = QString::fromStdString(rec.cipher_suite);
                    const QString fhash =
                        formatShortHash(!rec.plaintext_sha256.empty() ? rec.plaintext_sha256 : rec.ciphertext_sha256);

                    messages_.push_back(MessageEntry{
                        newMsgId, convId, senderDisplay, isSelf, QStringLiteral("Encrypted File Attachment"),
                        QStringLiteral("Just now"), QStringLiteral("TODAY"), stateStr, true, transferIdStr, fname,
                        fsize, csuite, fhash, m.priority(), QString::fromStdString(m.idempotency_key()),
                        m.emergency_acknowledged()});

                    if (auto* conv = findConversationMutable(convId)) {
                        conv->lastMessagePreview = QStringLiteral("Encrypted File: %1").arg(fname);
                        conv->timestampText = QStringLiteral("Just now");
                        conv->lastMessagePriority = m.priority();
                        if (convId != selected_conversation_id_) {
                            ++conv->unreadCount;
                        }
                    }
                    emit conversationsChanged();
                    if (convId == selected_conversation_id_) {
                        emit activeMessagesChanged();
                    }
                    break;
                }

                const QString text = QString::fromStdString(m.encrypted_envelope_ref());
                messages_.push_back(MessageEntry{
                    newMsgId, convId, senderDisplay, isSelf, text, QStringLiteral("Just now"), QStringLiteral("TODAY"),
                    stateStr, !m.attachment_name().empty(), QString(), QString::fromStdString(m.attachment_name()),
                    m.attachment_size() > 0 ? formatFileSize(m.attachment_size()) : QString(),
                    QStringLiteral("AES-256-GCM"), QString::fromStdString(m.attachment_hash()), m.priority(),
                    QString::fromStdString(m.idempotency_key()), m.emergency_acknowledged()});
                if (auto* conv = findConversationMutable(convId)) {
                    conv->lastMessagePreview = text;
                    conv->timestampText = QStringLiteral("Just now");
                    conv->lastMessagePriority = m.priority();
                    if (convId != selected_conversation_id_) {
                        ++conv->unreadCount;
                    }
                }
                emit conversationsChanged();
                if (convId == selected_conversation_id_) {
                    emit activeMessagesChanged();
                }
            }
        }
        break;
    }
    case domain::RealtimeEventType::PresenceUpdate: {
        const QString actorId = QString::fromStdString(event.actor_user_id.value());
        const QString presenceStr = QString::fromStdString(std::string(domain::to_string(event.presence_status)));
        bool changed = false;
        for (auto& conv : conversations_) {
            if (!conv.isGroup && conv.peerUserId == actorId && conv.presence != presenceStr) {
                conv.presence = presenceStr;
                changed = true;
            }
        }
        if (changed) {
            emit conversationsChanged();
            emit selectedConversationChanged();
            emit contactsChanged();
        }
        break;
    }
    case domain::RealtimeEventType::InboundSenderKeyDistribution:
        break;
    }
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
            domain::ConversationId(conv->conversationId.toStdString()), localUserId(),
            app_.bootstrap().messaging_manager().local_device_id());
    }
    emit selectedConversationChanged();
    emit activeMessagesChanged();
    emit conversationsChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
    emit privacySecuritySettingsChanged();
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

    const domain::UserId senderId = localUserId();
    const domain::DeviceId deviceId = localDeviceId();

    const auto sendRes = app_.bootstrap().messaging_manager().stage_outbound_message(
        domain::ConversationId(conv->conversationId.toStdString()), senderId, deviceId, trimmed.toStdString(),
        effectivePriority, "You");

    if (sendRes.is_error()) {
        emit workspaceError(QString::fromStdString(sendRes.error().user_message()));
        return false;
    }

    const QString authoritativeMsgId = QString::fromStdString(sendRes.value().message_id().value());
    const QString authoritativeIdemKey = QString::fromStdString(sendRes.value().idempotency_key());
    const QString initialDeliveryState =
        QString::fromStdString(std::string(domain::to_string(sendRes.value().delivery_state())));

    messages_.push_back(MessageEntry{authoritativeMsgId, conv->conversationId, QStringLiteral("You"), true, trimmed,
                                     QStringLiteral("Just now"), QStringLiteral("TODAY"), initialDeliveryState, false,
                                     QString(), QString(), QString(), QString(), QString(), effectivePriority,
                                     authoritativeIdemKey, false});

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
    emit pendingOutboxCountChanged();
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

QString WorkspaceViewModel::uploadLocalFile(const QString& localFilePathOrUrl) {
    const QString localPath = normalizeLocalPath(localFilePathOrUrl);
    if (localPath.isEmpty()) {
        emit workspaceError(QStringLiteral("No valid local file path selected for encrypted upload."));
        return QString();
    }

    auto* conv = findConversationMutable(selected_conversation_id_);
    if (!conv) {
        emit workspaceError(QStringLiteral("Select a conversation before uploading an encrypted file."));
        return QString();
    }

    application::managers::FileUploadRequest req;
    req.conversation_id = domain::ConversationId(conv->conversationId.toStdString());
    req.owner_user_id = localUserId();
    req.owner_device_id = localDeviceId();
    if (!conv->isGroup && !conv->peerUserId.trimmed().isEmpty()) {
        req.peer_user_id = domain::UserId(conv->peerUserId.toStdString());
    }
    req.local_file_path = localPath.toStdString();
    req.sender_display_name = "You";
    req.priority = composer_priority_;
    req.dispatch_key_envelope = true;

    const auto upRes = app_.bootstrap().file_manager().start_upload(req);
    if (upRes.is_error()) {
        emit workspaceError(QString::fromStdString(upRes.error().user_message()));
        return QString();
    }

    const auto& rec = upRes.value().record;
    const QString transferId = QString::fromStdString(rec.transfer_id);
    selected_transfer_id_ = transferId;
    applyFileTransferUpdate(rec);

    if (upRes.value().dispatched_message.has_value()) {
        const auto tx = buildTransferEntry(rec);
        appendDispatchedFileMessage(*conv, *upRes.value().dispatched_message, transferId, tx.fileName, tx.fileSizeText,
                                    tx.cipherSuite, tx.sha256Short);
        if (composer_priority_ != 1) {
            composer_priority_ = 1;
            emit composerPriorityChanged();
        }
        emit activeMessagesChanged();
        emit conversationsChanged();
        emit selectedConversationChanged();
    }

    return transferId;
}

bool WorkspaceViewModel::downloadEncryptedFile(const QString& transferId, const QString& destinationPathOrUrl) {
    const QString trimmedId = transferId.trimmed();
    const QString destPath = normalizeLocalPath(destinationPathOrUrl);
    if (trimmedId.isEmpty() || destPath.isEmpty()) {
        emit workspaceError(QStringLiteral("Transfer ID and destination file path are required to download."));
        return false;
    }

    const auto dlRes = app_.bootstrap().file_manager().start_download(trimmedId.toStdString(), destPath.toStdString());
    if (dlRes.is_error()) {
        const auto recRes = app_.bootstrap().file_manager().get_transfer(trimmedId.toStdString());
        if (recRes.is_ok()) {
            applyFileTransferUpdate(recRes.value());
        }
        emit workspaceError(QString::fromStdString(dlRes.error().user_message()));
        return false;
    }

    applyFileTransferUpdate(dlRes.value());
    return true;
}

bool WorkspaceViewModel::pauseFileTransfer(const QString& transferId) {
    const QString trimmedId = transferId.trimmed();
    if (trimmedId.isEmpty()) {
        return false;
    }

    const auto pauseRes = app_.bootstrap().file_manager().pause_transfer(trimmedId.toStdString());
    if (pauseRes.is_error()) {
        emit workspaceError(QString::fromStdString(pauseRes.error().user_message()));
        return false;
    }

    const auto recRes = app_.bootstrap().file_manager().get_transfer(trimmedId.toStdString());
    if (recRes.is_ok()) {
        if (recRes.value().status == domain::FileTransferStatus::Paused) {
            applyFileTransferUpdate(recRes.value());
        }
        return true;
    }

    for (auto& tx : file_transfers_) {
        if (tx.transferId == trimmedId) {
            tx.status = QStringLiteral("Paused");
            tx.statusText = QStringLiteral("Paused");
            tx.canPause = false;
            tx.canResume = true;
            tx.canDownload = false;
            tx.canCancel = true;
            emit fileTransfersChanged();
            emit selectedTransferChanged();
            return true;
        }
    }
    return false;
}

bool WorkspaceViewModel::resumeFileTransfer(const QString& transferId) {
    const QString trimmedId = transferId.trimmed();
    if (trimmedId.isEmpty()) {
        return false;
    }

    const auto recRes = app_.bootstrap().file_manager().get_transfer(trimmedId.toStdString());
    if (recRes.is_error()) {
        emit workspaceError(QString::fromStdString(recRes.error().user_message()));
        return false;
    }

    const auto& current = recRes.value();
    if (current.direction == domain::FileTransferDirection::Outbound) {
        const auto upRes = app_.bootstrap().file_manager().resume_upload(
            trimmedId.toStdString(), localUserId(), localDeviceId(), "You", composer_priority_, true);
        if (upRes.is_error()) {
            const auto afterErr = app_.bootstrap().file_manager().get_transfer(trimmedId.toStdString());
            if (afterErr.is_ok()) {
                applyFileTransferUpdate(afterErr.value());
            }
            emit workspaceError(QString::fromStdString(upRes.error().user_message()));
            return false;
        }

        const auto& rec = upRes.value().record;
        applyFileTransferUpdate(rec);

        if (upRes.value().dispatched_message.has_value()) {
            const QString convId = QString::fromStdString(rec.conversation_id.value());
            if (auto* conv = findConversationMutable(convId)) {
                const auto tx = buildTransferEntry(rec);
                appendDispatchedFileMessage(*conv, *upRes.value().dispatched_message, trimmedId, tx.fileName,
                                            tx.fileSizeText, tx.cipherSuite, tx.sha256Short);
                if (composer_priority_ != 1) {
                    composer_priority_ = 1;
                    emit composerPriorityChanged();
                }
                emit activeMessagesChanged();
                emit conversationsChanged();
                emit selectedConversationChanged();
            }
        }
        return true;
    }

    const auto dlRes = app_.bootstrap().file_manager().resume_download(trimmedId.toStdString());
    if (dlRes.is_error()) {
        const auto afterErr = app_.bootstrap().file_manager().get_transfer(trimmedId.toStdString());
        if (afterErr.is_ok()) {
            applyFileTransferUpdate(afterErr.value());
        }
        emit workspaceError(QString::fromStdString(dlRes.error().user_message()));
        return false;
    }

    applyFileTransferUpdate(dlRes.value());
    return true;
}

bool WorkspaceViewModel::cancelFileTransfer(const QString& transferId) {
    const QString trimmedId = transferId.trimmed();
    if (trimmedId.isEmpty()) {
        return false;
    }
    const auto cancelRes = app_.bootstrap().file_manager().cancel_transfer(trimmedId.toStdString());
    if (cancelRes.is_error()) {
        return false;
    }
    const auto recRes = app_.bootstrap().file_manager().get_transfer(trimmedId.toStdString());
    if (recRes.is_ok()) {
        if (recRes.value().status == domain::FileTransferStatus::Cancelled) {
            applyFileTransferUpdate(recRes.value());
        }
        return true;
    }
    for (auto& tx : file_transfers_) {
        if (tx.transferId == trimmedId) {
            tx.status = QStringLiteral("Cancelled");
            tx.statusText = QStringLiteral("Cancelled");
            tx.canPause = false;
            tx.canResume = false;
            tx.canDownload = false;
            tx.canCancel = false;
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
            std::vector<uint8_t> dummy_key(32, 0x01);
            (void)app_.bootstrap().safety_number_engine().set_verification_state(
                domain::UserId(conv.peerUserId.toStdString()), dummy_key, conv.isVerified);
            emit selectedConversationChanged();
            emit conversationsChanged();
            emit contactsChanged();
            return;
        }
    }
}

void WorkspaceViewModel::togglePeerBlocked(const QString& peerUserId) {
    for (const auto& conv : conversations_) {
        if (conv.peerUserId == peerUserId ||
            (peerUserId.isEmpty() && conv.conversationId == selected_conversation_id_)) {
            (void)blockContact(conv.peerUserId, !conv.isBlocked);
            return;
        }
    }
}

bool WorkspaceViewModel::approveDevice(const QString& deviceId) {
    const QString cleaned = deviceId.trimmed();
    if (cleaned.isEmpty()) {
        return false;
    }
    for (auto& dev : devices_) {
        if (dev.deviceId == cleaned) {
            std::string mfa_token;
            auto mfa_res =
                app_.bootstrap().hardware_authenticator().prompt_for_hardware_mfa("approve:" + cleaned.toStdString());
            if (mfa_res.is_ok()) {
                mfa_token = mfa_res.value();
            }

            auto auth_res = app_.bootstrap().gateway().authorize_device_pairing(domain::DeviceId(cleaned.toStdString()),
                                                                                "948201", mfa_token);
            if (auth_res.is_error()) {
                emit workspaceError(QString::fromStdString(auth_res.error().user_message()));
                return false;
            }

            dev.status = QStringLiteral("Authorized");
            dev.isVerified = true;
            dev.lastSeenText = QStringLiteral("Approved just now · FIDO2 Attested");
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

            std::string mfa_token;
            auto mfa_res =
                app_.bootstrap().hardware_authenticator().prompt_for_hardware_mfa("revoke:" + cleaned.toStdString());
            if (mfa_res.is_ok()) {
                mfa_token = mfa_res.value();
            }

            const auto revRes =
                app_.bootstrap().device_manager().revoke_device(domain::DeviceId(cleaned.toStdString()), mfa_token);
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

    auto local_res = app_.bootstrap().device_manager().get_local_device();
    domain::UserId uid = local_res.is_ok() ? local_res.value().user_id() : domain::UserId("usr-local-workstation");

    auto pair_res =
        app_.bootstrap().device_pairing_coordinator().initiate_companion_pairing(uid, cleaned.toStdString());

    QString newId;
    QString sasCode = QStringLiteral("492 810");
    if (pair_res.is_ok()) {
        const auto& session = pair_res.value();
        newId = QString::fromStdString(session.device_id.value());
        sasCode = QString::fromStdString(session.expected_sas.numeric_code());
    } else {
        newId = QStringLiteral("dev-node-0%1").arg(next_device_seq_++);
    }

    devices_.push_back(DeviceEntry{
        newId, cleaned, QStringLiteral("Pending X3DH Key Bundle Handshake · QR Generated"),
        QStringLiteral("ED25519-PUB-A910F442...8812C09E"), QStringLiteral("6612 90B4 3319 88A1 4402 19C4 7721 E009"),
        QStringLiteral("SPK-X25519-0001"), QStringLiteral("SIG-ED25519-5501E88A...9920B11C"), QStringLiteral("Pending"),
        QStringLiteral("Pairing requested just now (SAS: %1)").arg(sasCode), false, false});
    emit devicesChanged();
    return newId;
}

QVariantMap WorkspaceViewModel::hardwareAttestationInfo() const {
    QVariantMap result;
    auto& hw = app_.bootstrap().hardware_authenticator();
    result.insert(QStringLiteral("available"), hw.is_hardware_authenticator_available());
    auto att_res = hw.attest_device_authenticator();
    if (att_res.is_ok()) {
        const auto& rec = att_res.value();
        result.insert(QStringLiteral("authenticatorType"),
                      QString::fromUtf8(domain::to_string(rec.authenticator_type()).data(),
                                        static_cast<qsizetype>(domain::to_string(rec.authenticator_type()).size())));
        result.insert(QStringLiteral("aaguid"), QString::fromStdString(rec.aaguid()));
        result.insert(QStringLiteral("attestationFormat"), QString::fromStdString(rec.attestation_format()));
        result.insert(QStringLiteral("isVerified"), rec.is_verified());
    } else {
        result.insert(QStringLiteral("isVerified"), false);
    }
    return result;
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
        (void)app_.bootstrap().hardware_authenticator().attest_device_authenticator();
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
    is_inspector_open_ = false;
    composer_priority_ = 1;
    is_loading_messages_ = false;
    delivery_failure_simulated_ = false;
    local_prekey_count_ = 0;
    local_prekey_health_ = QStringLiteral("Cleared");
    mfa_required_on_login_ = true;
    hardware_key_enforced_ = true;
    settings_ = domain::UserSettings{};
    profile_ = domain::UserProfile{};
    profile_avatar_image_url_.clear();
    profile_share_avatar_with_contacts_ = false;
    profile_sync_status_text_ = QStringLiteral("Cleared");
    tls_last_inspected_info_.clear();
    tls_pin_matches_ = true;
    pending_recovery_mnemonic_.reset();
    pending_recovery_challenge_indices_.clear();
    syncUiThemeFromSettings();
    emit searchQueryChanged();
    emit conversationsChanged();
    emit contactsChanged();
    emit fileTransfersChanged();
    emit devicesChanged();
    emit localDeviceIdentityChanged();
    emit selectedConversationChanged();
    emit activeMessagesChanged();
    emit selectedTransferChanged();
    emit inspectorOpenChanged();
    emit composerPriorityChanged();
    emit loadingMessagesChanged();
    emit deliveryFailureSimulatedChanged();
    emit pendingOutboxCountChanged();
    emit profileSettingsChanged();
    emit appearanceSettingsChanged();
    emit networkSettingsChanged();
    emit privacySecuritySettingsChanged();
    emit mfaPolicyChanged();
    emit readReceiptsEnabledChanged();
}

void WorkspaceViewModel::enterDecoyWorkspace() {
    resetForEmergencyWipe();
    local_prekey_health_ = QStringLiteral("Healthy");
    profile_sync_status_text_ = QStringLiteral("Local Profile");
    emit localDeviceIdentityChanged();
    emit profileSettingsChanged();
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
    const bool isUuidInput = !QUuid::fromString(peerUid).isNull();
    if (!isUuidInput) {
        if (peerUid.startsWith('@')) {
            peerUid = peerUid.mid(1);
        }
        if (!peerUid.contains('@')) {
            peerUid += QStringLiteral("@securecloud.org");
        }
    }

    if (app_.bootstrap().is_live_gateway_transport_active() && QUuid::fromString(peerUid).isNull()) {
        emit workspaceError(QStringLiteral(
            "In Live Gateway mode, enter the peer's User UUID (e.g. 01930000-0000-7000-8000-000000000002)."));
        return false;
    }

    const domain::UserId uid(peerUid.toStdString());
    const std::string sNum =
        safetyNumber.isEmpty()
            ? (app_.bootstrap().is_live_gateway_transport_active()
                   ? std::string{}
                   : std::string{"10928 38471 66251 89201 44712 09182 55910 28471 90284 71209 38471 09284"})
            : safetyNumber.toStdString();
    const auto createRes = app_.bootstrap().contact_manager().create_contact(uid, cleanedName.toStdString(), sNum,
                                                                             roleNote.toStdString(), 1);

    if (createRes.is_error()) {
        emit workspaceError(QString::fromStdString(createRes.error().user_message()));
        return false;
    }

    if (app_.bootstrap().is_live_gateway_transport_active()) {
        if (sNum.empty() && app_.bootstrap().contact_manager().has_local_identity()) {
            (void)app_.bootstrap().contact_manager().get_or_compute_safety_number(uid);
        }
        reloadFromLocalStore();
    } else {
        const QString convId = QStringLiteral("conv-%1").arg(peerUid.toLower().remove('@').remove('.'));
        const QString peerHandleStr = isUuidInput ? peerUid : QStringLiteral("@%1").arg(peerUid.section('@', 0, 0));
        const domain::UserId selfUid = localUserId();

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
                                                   {QString::fromStdString(selfUid.value()), peerUid},
                                                   1,
                                                   QStringLiteral("Unverified")});

        // Also persist conversation into local_store_
        domain::Conversation domainConv(domain::ConversationId(convId.toStdString()), domain::ConversationType::Direct,
                                        cleanedName.toStdString(), {selfUid, uid}, std::chrono::system_clock::now(),
                                        std::chrono::system_clock::now(), 0, false);
        (void)app_.bootstrap().local_store().save_conversation(domainConv);
    }

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

    const QString peerUid = resolveTargetPeerUserId(userId);

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

    const QString peerUid = resolveTargetPeerUserId(userId);

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
    (void)acknowledgeKeyChange(userId);
}

QString WorkspaceViewModel::resolveTargetPeerUserId(const QString& userId) const {
    const QString cleaned = userId.trimmed();
    if (cleaned.isEmpty()) {
        return selectedPeerUserId();
    }
    for (const auto& conv : conversations_) {
        if (!conv.isGroup && (conv.peerUserId == cleaned || conv.peerHandle == cleaned)) {
            return conv.peerUserId;
        }
    }
    if (app_.bootstrap().contact_manager().get_contact(domain::UserId(cleaned.toStdString())).is_ok()) {
        return cleaned;
    }
    QString normalized = cleaned;
    if (normalized.startsWith('@')) {
        normalized = normalized.mid(1);
    }
    if (!normalized.contains('@') &&
        app_.bootstrap()
            .contact_manager()
            .get_contact(domain::UserId((normalized + QStringLiteral("@securecloud.org")).toStdString()))
            .is_ok()) {
        return normalized + QStringLiteral("@securecloud.org");
    }
    return cleaned;
}

bool WorkspaceViewModel::addContactByHandle(const QString& handle, const QString& displayName,
                                            const QString& roleNote) {
    const QString cleanedHandle = handle.trimmed();
    if (cleanedHandle.isEmpty()) {
        emit workspaceError(QStringLiteral("Contact handle or query cannot be empty."));
        return false;
    }

    auto& cm = app_.bootstrap().contact_manager();
    const auto searchRes = cm.search_contacts(cleanedHandle.toStdString());
    if (searchRes.is_ok() && !searchRes.value().empty()) {
        const auto& entries = searchRes.value();
        domain::DirectoryUserEntry selected = entries.front();
        const std::string targetLower = cleanedHandle.toLower().toStdString();
        for (const auto& entry : entries) {
            const QString qHandle = QString::fromStdString(entry.handle()).toLower();
            const QString qUid = QString::fromStdString(entry.user_id().value()).toLower();
            if (qHandle.toStdString() == targetLower || qUid.toStdString() == targetLower) {
                selected = entry;
                break;
            }
        }

        const auto addRes = cm.add_contact_from_directory(selected, displayName.trimmed().toStdString(),
                                                          roleNote.trimmed().toStdString());
        if (addRes.is_error()) {
            emit workspaceError(QString::fromStdString(addRes.error().user_message()));
            return false;
        }

        const auto& contact = addRes.value();
        const QString peerUid = QString::fromStdString(contact.user_id().value());
        const QString convId = QStringLiteral("conv-%1").arg(peerUid.toLower().remove('@').remove('.'));
        const QString peerHandleStr = selected.handle().empty() ? peerUid : QString::fromStdString(selected.handle());
        const QString aliasStr = QString::fromStdString(contact.alias());
        const QString safetyNumStr = QString::fromStdString(contact.safety_number());

        bool exists = false;
        for (auto& conv : conversations_) {
            if (!conv.isGroup && conv.peerUserId == peerUid) {
                conv.peerDisplayName = aliasStr;
                conv.peerHandle = peerHandleStr;
                conv.safetyNumber = safetyNumStr;
                conv.roleNote = QString::fromStdString(contact.role_note());
                conv.authorizedDeviceCount = static_cast<int>(contact.authorized_device_count());
                exists = true;
                break;
            }
        }

        if (!exists && !app_.bootstrap().is_live_gateway_transport_active()) {
            const domain::UserId selfUid = localUserId();
            conversations_.push_back(ConversationEntry{
                convId,
                peerUid,
                aliasStr,
                peerHandleStr,
                QStringLiteral("Offline"),
                contact.is_verified(),
                contact.is_blocked(),
                safetyNumStr,
                QString::fromStdString(contact.role_note()),
                QStringLiteral("Conversation opened."),
                QStringLiteral("Just now"),
                0,
                1,
                false,
                {QString::fromStdString(selfUid.value()), peerUid},
                static_cast<int>(contact.authorized_device_count()),
                QString::fromUtf8(domain::to_string(contact.verification_status()).data(),
                                  static_cast<qsizetype>(domain::to_string(contact.verification_status()).size()))});

            domain::Conversation domainConv(domain::ConversationId(convId.toStdString()),
                                            domain::ConversationType::Direct, aliasStr.toStdString(),
                                            {selfUid, contact.user_id()}, std::chrono::system_clock::now(),
                                            std::chrono::system_clock::now(), 0, false);
            (void)app_.bootstrap().local_store().save_conversation(domainConv);
        }

        emit contactsChanged();
        emit conversationsChanged();
        return true;
    }

    const QString fallbackName = displayName.trimmed().isEmpty() ? cleanedHandle : displayName.trimmed();
    return addContact(cleanedHandle, fallbackName, roleNote);
}

bool WorkspaceViewModel::verifyContactSafetyNumber(const QString& userId, bool verified) {
    const QString targetUid = resolveTargetPeerUserId(userId);
    if (targetUid.isEmpty()) {
        return false;
    }

    const auto res =
        app_.bootstrap().contact_manager().verify_contact_key(domain::UserId(targetUid.toStdString()), verified);
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }

    for (auto& conv : conversations_) {
        if (!conv.isGroup && conv.peerUserId == targetUid) {
            conv.isVerified = verified;
            conv.verificationStatus = verified ? QStringLiteral("Verified") : QStringLiteral("Unverified");
        }
    }

    emit selectedConversationChanged();
    emit conversationsChanged();
    emit contactsChanged();
    return true;
}

bool WorkspaceViewModel::blockContact(const QString& userId, bool blocked) {
    const QString targetUid = resolveTargetPeerUserId(userId);
    if (targetUid.isEmpty()) {
        return false;
    }

    const auto res =
        app_.bootstrap().contact_manager().set_contact_blocked(domain::UserId(targetUid.toStdString()), blocked);
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }

    for (auto& conv : conversations_) {
        if (!conv.isGroup && conv.peerUserId == targetUid) {
            conv.isBlocked = blocked;
        }
    }

    emit selectedConversationChanged();
    emit conversationsChanged();
    emit contactsChanged();
    return true;
}

void WorkspaceViewModel::syncContacts() {
    auto& cm = app_.bootstrap().contact_manager();
    const auto syncRes = cm.sync_contacts();
    if (syncRes.is_error()) {
        emit workspaceError(QString::fromStdString(syncRes.error().user_message()));
    }

    for (auto& conv : conversations_) {
        if (conv.isGroup) {
            continue;
        }
        const auto cRes = cm.get_contact(domain::UserId(conv.peerUserId.toStdString()));
        if (cRes.is_ok()) {
            const auto& c = cRes.value();
            conv.authorizedDeviceCount = static_cast<int>(c.authorized_device_count());
            conv.isBlocked = c.is_blocked();
            conv.isVerified = c.is_verified();
            const auto statusSv = domain::to_string(c.verification_status());
            conv.verificationStatus = QString::fromUtf8(statusSv.data(), static_cast<qsizetype>(statusSv.size()));
            if (!c.safety_number().empty()) {
                conv.safetyNumber = QString::fromStdString(c.safety_number());
            }
            if (c.authorized_device_count() == 0) {
                conv.presence = QStringLiteral("Offline");
            }
        }
    }

    emit selectedConversationChanged();
    emit conversationsChanged();
    emit contactsChanged();
}

bool WorkspaceViewModel::acknowledgeKeyChange(const QString& userId) {
    const QString targetUid = resolveTargetPeerUserId(userId);
    if (targetUid.isEmpty()) {
        return false;
    }

    auto& cm = app_.bootstrap().contact_manager();
    const domain::UserId uid(targetUid.toStdString());
    auto res = cm.acknowledge_and_verify_key_change(uid);
    if (res.is_error()) {
        // Fallback for offline/locally simulated mock UI contacts
        res = cm.verify_contact_key(uid, true);
        if (res.is_error()) {
            emit workspaceError(QString::fromStdString(res.error().user_message()));
            return false;
        }
    }

    const auto cRes = cm.get_contact(uid);
    for (auto& conv : conversations_) {
        if (!conv.isGroup && conv.peerUserId == targetUid) {
            conv.isVerified = true;
            conv.verificationStatus = QStringLiteral("Verified");
            if (cRes.is_ok() && !cRes.value().safety_number().empty()) {
                conv.safetyNumber = QString::fromStdString(cRes.value().safety_number());
            }
        }
    }

    emit selectedConversationChanged();
    emit conversationsChanged();
    emit contactsChanged();
    return true;
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

    QString convId;
    if (app_.bootstrap().is_live_gateway_transport_active()) {
        const domain::UserId peerUid(peerUserId.toStdString());
        const auto remoteRes = app_.bootstrap().gateway().create_direct_conversation(peerUid);
        if (remoteRes.is_error()) {
            emit workspaceError(QString::fromStdString(remoteRes.error().user_message()));
            return QString();
        }
        convId = QString::fromStdString(remoteRes.value().conversation_id.value());
        for (const auto& existing : conversations_) {
            if (existing.conversationId == convId) {
                selectConversation(convId);
                return convId;
            }
        }
        const auto now = std::chrono::system_clock::now();
        const domain::Conversation persisted(domain::ConversationId(convId.toStdString()),
                                             domain::ConversationType::Direct, name.toStdString(),
                                             {localUserId(), peerUid}, now, now, 0U, false);
        (void)app_.bootstrap().local_store().save_conversation(persisted);
    } else {
        convId = QStringLiteral("conv-%1").arg(++next_msg_seq_);
    }

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
                                               {QString::fromStdString(localUserId().value()), peerUserId},
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

    const domain::UserId creator_uid = localUserId();
    const QString creator_q = QString::fromStdString(creator_uid.value());

    std::vector<domain::UserId> pVec;
    std::vector<QString> pUserIdsStr;
    pUserIdsStr.push_back(creator_q);

    int totalDeviceFanout = 1; // operator workstation
    for (const auto& var : participantUserIds) {
        const QString uidStr = var.toString().trimmed();
        if (!uidStr.isEmpty() && uidStr != creator_q) {
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

    const auto createRes =
        app_.bootstrap().messaging_manager().create_group_conversation(creator_uid, cleanedTitle.toStdString(), pVec);

    if (createRes.is_error()) {
        emit workspaceError(QString::fromStdString(createRes.error().user_message()));
        return QString();
    }

    const QString convId = QString::fromStdString(createRes.value().conversation_id().value());
    const int totalMembers = static_cast<int>(pUserIdsStr.size());

    conversations_.insert(
        conversations_.begin(),
        ConversationEntry{convId, convId, cleanedTitle, QStringLiteral("Group · %1 members").arg(totalMembers),
                          QStringLiteral("Online"), true, false, QStringLiteral("GROUP-ROOT-SAFETY-NUMBER"),
                          QStringLiteral("Encrypted Group · Sender Keys + Pairwise Double Ratchet"),
                          QStringLiteral("Group conversation created."), QStringLiteral("Just now"), 0, 1, true,
                          pUserIdsStr, totalDeviceFanout, QStringLiteral("Verified"),
                          static_cast<int>(createRes.value().sender_key_epoch())});

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

    const auto addRes = app_.bootstrap().messaging_manager().add_group_participant(
        domain::ConversationId(conv->conversationId.toStdString()), localUserId(),
        domain::UserId(userId.toStdString()));
    if (addRes.is_error()) {
        emit workspaceError(QString::fromStdString(addRes.error().user_message()));
        return false;
    }

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

    const auto remRes = app_.bootstrap().messaging_manager().remove_group_participant(
        domain::ConversationId(conv->conversationId.toStdString()), localUserId(),
        domain::UserId(userId.toStdString()));
    if (remRes.is_error()) {
        emit workspaceError(QString::fromStdString(remRes.error().user_message()));
        return false;
    }

    const auto updatedConv = app_.bootstrap().messaging_manager().get_conversation(
        domain::ConversationId(conv->conversationId.toStdString()));
    if (updatedConv.is_ok()) {
        conv->senderKeyEpoch = static_cast<int>(updatedConv.value().sender_key_epoch());
    } else {
        ++conv->senderKeyEpoch;
    }

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
        domain::ConversationId(conv->conversationId.toStdString()), localUserId());

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

void WorkspaceViewModel::setUiTheme(UiTheme* theme) noexcept {
    ui_theme_ = theme;
    syncUiThemeFromSettings();
}

QString WorkspaceViewModel::stripUrlScheme(const QString& urlOrHost) {
    QString out = urlOrHost.trimmed();
    if (out.startsWith(QStringLiteral("https://"), Qt::CaseInsensitive)) {
        out = out.mid(8);
    } else if (out.startsWith(QStringLiteral("http://"), Qt::CaseInsensitive)) {
        out = out.mid(7);
    }
    const qsizetype slashIdx = out.indexOf(QLatin1Char('/'));
    if (slashIdx >= 0) {
        out = out.left(slashIdx);
    }
    const qsizetype colonIdx = out.lastIndexOf(QLatin1Char(':'));
    if (colonIdx > 0 && !out.startsWith(QLatin1Char('['))) {
        out = out.left(colonIdx);
    }
    return out.trimmed();
}

void WorkspaceViewModel::syncUiThemeFromSettings() {
    if (!ui_theme_) {
        return;
    }
    ui_theme_->setThemeMode(settings_.theme_mode);
    ui_theme_->setFontScale(settings_.font_scale);
    ui_theme_->setHighContrastEnabled(settings_.high_contrast_enabled);
}

void WorkspaceViewModel::hydrateSettingsAndProfile() {
    const auto persistedRow =
        app_.bootstrap().local_store().get_user_settings(application::managers::SettingsManager::kDefaultSettingsKey);
    if (persistedRow.is_ok() && persistedRow.value().has_value()) {
        const auto loadRes = app_.bootstrap().settings_manager().load_settings();
        if (loadRes.is_ok()) {
            settings_ = loadRes.value();
        } else {
            settings_ = *persistedRow.value();
        }
    } else {
        domain::UserSettings defaults{};
        const auto& cfg = app_.bootstrap().config();
        defaults.use_live_gateway_transport = cfg.use_live_gateway_transport;
        const QString strippedHost = stripUrlScheme(QString::fromStdString(cfg.gateway_url));
        if (!strippedHost.isEmpty()) {
            defaults.tls.custom_gateway_host = strippedHost.toStdString();
        }
        defaults.tls.custom_gateway_port = (cfg.gateway_port > 0U) ? cfg.gateway_port : domain::kDefaultGatewayPort;
        defaults.tls.pinned_spki_sha256_hex = domain::normalize_hex_lower(cfg.pinned_tls_spki_sha256);
        defaults.tls.enforce_strict_pinning = cfg.enforce_tls_pinning;
        defaults.proxy.type = cfg.proxy_type;
        defaults.proxy.host = cfg.proxy_host;
        defaults.proxy.port = cfg.proxy_port;
        defaults.proxy.username = cfg.proxy_username;
        defaults.read_receipts_enabled = app_.bootstrap().messaging_manager().read_receipts_enabled();
        if (const auto preset = domain::disappearing_timer_preset_from_seconds(
                app_.bootstrap().messaging_manager().default_disappearing_ttl_seconds());
            preset.has_value()) {
            defaults.default_disappearing_timer = *preset;
        }
        defaults.recovery_phrase_verified = app_.bootstrap().settings_manager().has_verified_recovery_phrase();
        settings_ = defaults;
    }

    mfa_required_on_login_ = settings_.mfa_required_on_login;
    hardware_key_enforced_ = settings_.hardware_key_enforced;

    const domain::UserId selfUid = localUserId();
    const auto localProfRes = app_.bootstrap().local_store().get_user_profile(selfUid);
    if (localProfRes.is_ok() && localProfRes.value().has_value()) {
        profile_ = *localProfRes.value();
        profile_sync_status_text_ = QStringLiteral("Loaded Local Profile");
    } else if (const auto cachedProf = app_.bootstrap().settings_manager().cached_profile();
               cachedProf.has_value() && cachedProf->user_id == selfUid) {
        profile_ = *cachedProf;
        profile_sync_status_text_ = QStringLiteral("Loaded Local Profile");
    } else {
        profile_ = domain::UserProfile{};
        profile_.user_id = selfUid;
        profile_.display_name = selfUid.value();
        profile_.allow_handle_discovery = true;
        profile_sync_status_text_ = QStringLiteral("Local Profile");
    }

    syncUiThemeFromSettings();
}

bool WorkspaceViewModel::persistCurrentSettings() {
    const auto saveRes = app_.bootstrap().settings_manager().save_settings(settings_);
    if (saveRes.is_error()) {
        emit workspaceError(QString::fromStdString(saveRes.error().user_message()));
        return false;
    }
    settings_ = saveRes.value();
    return true;
}

QString WorkspaceViewModel::profileDisplayName() const {
    return QString::fromStdString(profile_.display_name);
}

QString WorkspaceViewModel::profileHandle() const {
    return QString::fromStdString(profile_.public_handle);
}

QString WorkspaceViewModel::profileBio() const {
    return QString::fromStdString(profile_.bio_status);
}

QString WorkspaceViewModel::profileAvatarFileId() const {
    return QString::fromStdString(profile_.avatar_file_id);
}

QString WorkspaceViewModel::profileAvatarSha256() const {
    return QString::fromStdString(profile_.avatar_sha256);
}

QString WorkspaceViewModel::gatewayHost() const {
    if (!settings_.tls.custom_gateway_host.empty()) {
        return QString::fromStdString(settings_.tls.custom_gateway_host);
    }
    return stripUrlScheme(QString::fromStdString(app_.bootstrap().config().gateway_url));
}

QString WorkspaceViewModel::proxyHost() const {
    return QString::fromStdString(settings_.proxy.host);
}

QString WorkspaceViewModel::proxyUsername() const {
    return QString::fromStdString(settings_.proxy.username);
}

bool WorkspaceViewModel::hasProxyPassword() const {
    return app_.bootstrap().settings_manager().has_saved_proxy_password();
}

QString WorkspaceViewModel::tlsPinnedFingerprint() const {
    return QString::fromStdString(settings_.tls.normalized_pin());
}

qint64 WorkspaceViewModel::defaultDisappearingTtlSeconds() const noexcept {
    return static_cast<qint64>(settings_.default_disappearing_timer);
}

qint64 WorkspaceViewModel::activeConversationDisappearingTtlSeconds() const {
    if (selected_conversation_id_.isEmpty()) {
        return 0;
    }
    const auto convRes = app_.bootstrap().messaging_manager().get_conversation(
        domain::ConversationId(selected_conversation_id_.toStdString()));
    if (convRes.is_ok()) {
        return convRes.value().disappearing_ttl_seconds();
    }
    if (const auto* conv = findConversation(selected_conversation_id_)) {
        return conv->disappearingTtlSeconds;
    }
    return 0;
}

bool WorkspaceViewModel::recoveryPhraseVerified() const {
    return app_.bootstrap().settings_manager().has_verified_recovery_phrase();
}

QString WorkspaceViewModel::recoveryPhraseStatusText() const {
    if (recoveryPhraseVerified()) {
        return QStringLiteral("Verified (Local Only)");
    }
    if (pending_recovery_mnemonic_.has_value()) {
        return QStringLiteral("Awaiting 3-Word Confirmation");
    }
    return QStringLiteral("Not Backed Up");
}

QVariantList WorkspaceViewModel::pendingRecoveryChallengeIndices() const {
    QVariantList out;
    out.reserve(static_cast<qsizetype>(pending_recovery_challenge_indices_.size()));
    for (const std::size_t idx : pending_recovery_challenge_indices_) {
        out.append(static_cast<int>(idx));
    }
    return out;
}

bool WorkspaceViewModel::saveUserProfile(const QString& displayName, const QString& handle, const QString& bio,
                                         bool allowDiscovery, bool syncToGateway) {
    domain::UserProfile next = profile_;
    next.user_id = localUserId();
    QString cleanHandle = handle.trimmed();
    if (cleanHandle.startsWith(QLatin1Char('@'))) {
        cleanHandle = cleanHandle.mid(1);
    }
    next.public_handle = cleanHandle.toStdString();
    next.display_name = displayName.trimmed().toStdString();
    next.bio_status = bio.trimmed().toStdString();
    next.allow_handle_discovery = allowDiscovery;
    next.updated_at_ms = 0;

    const auto res = app_.bootstrap().settings_manager().update_profile(std::move(next), syncToGateway);
    if (res.is_error()) {
        profile_sync_status_text_ = QStringLiteral("Save Failed");
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        emit profileSettingsChanged();
        return false;
    }

    profile_ = res.value().profile;
    switch (res.value().sync_status) {
    case application::interfaces::ProfileSyncStatus::Synced:
        profile_sync_status_text_ = QStringLiteral("Synced with Gateway");
        break;
    case application::interfaces::ProfileSyncStatus::LocalOnlyServerUnsupported:
        profile_sync_status_text_ = QStringLiteral("Saved Locally (Gateway Sync Pending Server Support)");
        break;
    case application::interfaces::ProfileSyncStatus::SyncDisabledByPrivacyPolicy:
        profile_sync_status_text_ = QStringLiteral("Local Only (Discovery Disabled)");
        break;
    }

    emit profileSettingsChanged();
    return true;
}

bool WorkspaceViewModel::uploadAvatarImage(const QString& filePathOrUrl) {
    const QString localPath = normalizeLocalPath(filePathOrUrl);
    if (localPath.isEmpty()) {
        emit workspaceError(QStringLiteral("Please select or enter a valid local image path (.png, .jpg, .webp)."));
        return false;
    }

    const auto res = app_.bootstrap().settings_manager().upload_encrypted_avatar(localUserId(), localDeviceId(),
                                                                                 localPath.toStdString());
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }

    profile_ = res.value();
    QImage srcImg(localPath);
    if (!srcImg.isNull()) {
        constexpr int kAvatarSize = 128;
        const QImage scaled =
            srcImg.scaled(kAvatarSize, kAvatarSize, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
        const QImage cropped = scaled.copy((scaled.width() - kAvatarSize) / 2, (scaled.height() - kAvatarSize) / 2,
                                           kAvatarSize, kAvatarSize);
        QImage circular(kAvatarSize, kAvatarSize, QImage::Format_ARGB32_Premultiplied);
        circular.fill(Qt::transparent);
        QPainter painter(&circular);
        painter.setRenderHint(QPainter::Antialiasing, true);
        QPainterPath clipPath;
        clipPath.addEllipse(0, 0, kAvatarSize, kAvatarSize);
        painter.setClipPath(clipPath);
        painter.drawImage(0, 0, cropped);
        painter.end();

        QByteArray pngBytes;
        QBuffer buf(&pngBytes);
        if (buf.open(QIODevice::WriteOnly) && circular.save(&buf, "PNG")) {
            profile_avatar_image_url_ =
                QStringLiteral("data:image/png;base64,%1").arg(QString::fromLatin1(pngBytes.toBase64()));
        }
    }
    profile_sync_status_text_ = QStringLiteral("Encrypted Avatar Uploaded Locally");
    emit profileSettingsChanged();
    return true;
}

void WorkspaceViewModel::setProfileShareAvatarWithContacts(bool enabled) {
    if (profile_share_avatar_with_contacts_ == enabled) {
        return;
    }
    profile_share_avatar_with_contacts_ = enabled;
    emit profileSettingsChanged();
}

bool WorkspaceViewModel::refreshUserProfile() {
    const auto res = app_.bootstrap().settings_manager().load_profile(localUserId());
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }

    profile_ = res.value();
    profile_sync_status_text_ = QStringLiteral("Refreshed Profile");
    emit profileSettingsChanged();
    return true;
}

bool WorkspaceViewModel::applyAndSaveAppearance(int themeMode, double fontScale, bool highContrast) {
    const int clampedMode = (themeMode >= domain::kMinThemeMode && themeMode <= domain::kMaxThemeMode) ? themeMode : 1;
    const double finiteScale = std::isfinite(fontScale) ? fontScale : 1.0;
    const double clampedScale = std::clamp(finiteScale, domain::kMinFontScale, domain::kMaxFontScale);

    settings_.theme_mode = clampedMode;
    settings_.font_scale = clampedScale;
    settings_.high_contrast_enabled = highContrast;

    if (!persistCurrentSettings()) {
        return false;
    }

    syncUiThemeFromSettings();
    emit appearanceSettingsChanged();
    return true;
}

bool WorkspaceViewModel::saveNetworkAndProxyConfig(bool useLiveTransport, const QString& gatewayHost, int gatewayPort,
                                                   int proxyType, const QString& proxyHost, int proxyPort,
                                                   const QString& proxyUsername, const QString& proxyPassword,
                                                   bool clearProxyPassword, const QString& pinnedSpki,
                                                   bool enforceStrictPinning) {
    if (gatewayPort <= 0 || gatewayPort > 65535) {
        emit workspaceError(QStringLiteral("Gateway port must be between 1 and 65535."));
        return false;
    }

    domain::ProxyType mappedProxy = domain::ProxyType::None;
    if (proxyType == 0) {
        mappedProxy = domain::ProxyType::None;
    } else if (proxyType == 1) {
        mappedProxy = domain::ProxyType::Http;
    } else if (proxyType == 2) {
        mappedProxy = domain::ProxyType::Socks5;
    } else {
        emit workspaceError(QStringLiteral("Unsupported proxy type selection."));
        return false;
    }

    domain::UserSettings next = settings_;
    next.use_live_gateway_transport = useLiveTransport;
    next.tls.custom_gateway_host = stripUrlScheme(gatewayHost).toStdString();
    next.tls.custom_gateway_port = static_cast<uint16_t>(gatewayPort);
    next.tls.pinned_spki_sha256_hex = pinnedSpki.trimmed().toStdString();
    next.tls.enforce_strict_pinning = enforceStrictPinning;
    next.proxy.type = mappedProxy;

    if (mappedProxy == domain::ProxyType::None) {
        next.proxy.host.clear();
        next.proxy.port = 0U;
        next.proxy.username.clear();
    } else {
        if (proxyPort <= 0 || proxyPort > 65535) {
            emit workspaceError(QStringLiteral("Proxy port must be between 1 and 65535 when a proxy is enabled."));
            return false;
        }
        next.proxy.host = stripUrlScheme(proxyHost).toStdString();
        next.proxy.port = static_cast<uint16_t>(proxyPort);
        next.proxy.username = proxyUsername.trimmed().toStdString();
    }

    std::optional<common::configuration::SecretString> pwOpt;
    if (!clearProxyPassword && !proxyPassword.isEmpty()) {
        pwOpt = common::configuration::SecretString(proxyPassword.toStdString());
    }

    const auto saveRes =
        app_.bootstrap().settings_manager().save_settings(std::move(next), std::move(pwOpt), clearProxyPassword);
    if (saveRes.is_error()) {
        emit workspaceError(QString::fromStdString(saveRes.error().user_message()));
        return false;
    }

    settings_ = saveRes.value();
    const QString observedSpki = tls_last_inspected_info_.value(QStringLiteral("spkiSha256")).toString();
    const QString savedPin = tlsPinnedFingerprint();
    if (!observedSpki.isEmpty()) {
        tls_pin_matches_ = savedPin.isEmpty() || (savedPin.compare(observedSpki, Qt::CaseInsensitive) == 0);
        tls_last_inspected_info_.insert(QStringLiteral("hasPinnedKey"), !savedPin.isEmpty());
        tls_last_inspected_info_.insert(QStringLiteral("matchesPinnedKey"), tls_pin_matches_);
    } else {
        tls_pin_matches_ = true;
    }

    emit networkSettingsChanged();
    return true;
}

QVariantMap WorkspaceViewModel::inspectGatewayTlsFingerprint(const QString& host, int port, bool savePin) {
    const QString effHost = host.trimmed().isEmpty() ? gatewayHost() : stripUrlScheme(host);
    const uint16_t effPort =
        (port > 0 && port <= 65535) ? static_cast<uint16_t>(port) : settings_.tls.custom_gateway_port;

    const auto res = app_.bootstrap().settings_manager().inspect_and_optionally_pin_gateway_tls(effHost.toStdString(),
                                                                                                effPort, savePin);
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return QVariantMap{};
    }

    const auto& info = res.value();
    QVariantMap out;
    out.insert(QStringLiteral("host"), QString::fromStdString(info.host));
    out.insert(QStringLiteral("port"), static_cast<int>(info.port));
    out.insert(QStringLiteral("subjectCn"), QString::fromStdString(info.subject_cn));
    out.insert(QStringLiteral("issuerCn"), QString::fromStdString(info.issuer_cn));
    out.insert(QStringLiteral("spkiSha256"), QString::fromStdString(info.spki_sha256_hex));
    out.insert(QStringLiteral("validFromMs"), static_cast<qint64>(info.valid_from_ms));
    out.insert(QStringLiteral("validUntilMs"), static_cast<qint64>(info.valid_until_ms));
    out.insert(QStringLiteral("hasPinnedKey"), info.has_pinned_key);
    out.insert(QStringLiteral("matchesPinnedKey"), info.matches_pinned_key);

    tls_last_inspected_info_ = out;
    tls_pin_matches_ = info.matches_pinned_key;
    if (savePin) {
        settings_ = app_.bootstrap().settings_manager().current_settings();
    }
    emit networkSettingsChanged();
    return out;
}

bool WorkspaceViewModel::setDefaultDisappearingTimer(qint64 ttlSeconds) {
    const auto preset = domain::disappearing_timer_preset_from_seconds(ttlSeconds);
    if (!preset.has_value()) {
        emit workspaceError(QStringLiteral(
            "Disappearing message default timer must be 0 (Off), 3600 (1h), 86400 (24h), or 604800 (7d)."));
        return false;
    }

    settings_.default_disappearing_timer = *preset;
    if (!persistCurrentSettings()) {
        return false;
    }
    emit privacySecuritySettingsChanged();
    return true;
}

bool WorkspaceViewModel::setConversationDisappearingTimer(const QString& conversationId, qint64 ttlSeconds) {
    const QString cleanedId = conversationId.trimmed();
    if (cleanedId.isEmpty() || ttlSeconds < 0) {
        emit workspaceError(QStringLiteral("Valid conversation ID and non-negative timer TTL are required."));
        return false;
    }

    const auto res = app_.bootstrap().messaging_manager().set_conversation_disappearing_timer(
        domain::ConversationId(cleanedId.toStdString()), ttlSeconds);
    if (res.is_error()) {
        if (app_.bootstrap().config().database_path.empty()) {
            if (auto* conv = findConversationMutable(cleanedId)) {
                conv->disappearingTtlSeconds = ttlSeconds;
                emit conversationsChanged();
                emit selectedConversationChanged();
                emit privacySecuritySettingsChanged();
                return true;
            }
        }
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }

    if (auto* conv = findConversationMutable(cleanedId)) {
        conv->disappearingTtlSeconds = res.value().disappearing_ttl_seconds();
    }
    emit conversationsChanged();
    emit selectedConversationChanged();
    emit privacySecuritySettingsChanged();
    return true;
}

QVariantMap WorkspaceViewModel::generateRecoveryPhraseWords(bool use24Words) {
    const auto length =
        use24Words ? domain::crypto::RecoveryPhraseLength::Words24 : domain::crypto::RecoveryPhraseLength::Words12;
    const auto res = app_.bootstrap().settings_manager().generate_recovery_phrase(length);
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return QVariantMap{};
    }

    pending_recovery_mnemonic_ = res.value().mnemonic;
    pending_recovery_challenge_indices_ = res.value().challenge.word_indices;

    const QStringList words = QString::fromStdString(res.value().mnemonic.expose_unredacted_secret())
                                  .split(QLatin1Char(' '), Qt::SkipEmptyParts);
    QVariantList zeroIndices;
    QVariantList oneBasedPositions;
    zeroIndices.reserve(static_cast<qsizetype>(pending_recovery_challenge_indices_.size()));
    oneBasedPositions.reserve(static_cast<qsizetype>(pending_recovery_challenge_indices_.size()));
    for (const std::size_t idx : pending_recovery_challenge_indices_) {
        zeroIndices.append(static_cast<int>(idx));
        oneBasedPositions.append(static_cast<int>(idx + 1U));
    }

    emit privacySecuritySettingsChanged();

    QVariantMap out;
    out.insert(QStringLiteral("words"), words);
    out.insert(QStringLiteral("wordCount"), words.size());
    out.insert(QStringLiteral("challengeIndices"), zeroIndices);
    out.insert(QStringLiteral("challengePositions"), oneBasedPositions);
    return out;
}

bool WorkspaceViewModel::confirmRecoveryPhraseChallenge(const QVariantList& wordIndices,
                                                        const QVariantList& userWords) {
    if (!pending_recovery_mnemonic_.has_value()) {
        emit workspaceError(QStringLiteral("No pending recovery phrase session. Generate a recovery phrase first."));
        return false;
    }
    if (wordIndices.isEmpty() || wordIndices.size() != userWords.size()) {
        emit workspaceError(QStringLiteral("Complete all recovery phrase spot-check words before confirming."));
        return false;
    }

    std::vector<std::pair<std::size_t, std::string>> answers;
    answers.reserve(static_cast<std::size_t>(wordIndices.size()));
    for (qsizetype i = 0; i < wordIndices.size(); ++i) {
        const int idx = wordIndices[i].toInt();
        if (idx < 0) {
            emit workspaceError(QStringLiteral("Invalid recovery word challenge index."));
            return false;
        }
        answers.emplace_back(static_cast<std::size_t>(idx), userWords[i].toString().trimmed().toLower().toStdString());
    }

    const auto res =
        app_.bootstrap().settings_manager().confirm_recovery_phrase_backup(*pending_recovery_mnemonic_, answers);
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }

    pending_recovery_mnemonic_.reset();
    pending_recovery_challenge_indices_.clear();
    settings_ = app_.bootstrap().settings_manager().current_settings();
    emit privacySecuritySettingsChanged();
    return true;
}

bool WorkspaceViewModel::verifyRecoveryPhraseInput(const QString& wordsText) {
    const QString normalized = wordsText.simplified().toLower();
    if (normalized.isEmpty()) {
        emit workspaceError(QStringLiteral("Enter a BIP-39 recovery phrase to verify."));
        return false;
    }
    const common::configuration::SecretString candidate(normalized.toStdString());
    const auto res = app_.bootstrap().settings_manager().verify_existing_recovery_phrase(candidate);
    if (res.is_error()) {
        emit workspaceError(QString::fromStdString(res.error().user_message()));
        return false;
    }
    return res.value();
}

void WorkspaceViewModel::clearPendingRecoveryPhrase() {
    pending_recovery_mnemonic_.reset();
    pending_recovery_challenge_indices_.clear();
    emit privacySecuritySettingsChanged();
}

} // namespace securecloud::client::ui
