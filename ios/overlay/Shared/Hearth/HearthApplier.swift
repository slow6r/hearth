//
//  HearthApplier.swift
//  Hearth — применение bundle узла к ядру и поддержание этого состояния
//

import Foundation
import SimpleXChat

enum HearthApplyError: LocalizedError {
    case invalidServers(String)

    var errorDescription: String? {
        switch self {
        case let .invalidServers(details): "Ядро не приняло серверы узла: \(details)"
        }
    }
}

enum HearthApplier {
    private static let notificationsSetKey = "hearthNotificationsSet"

    /// Применить отложенный bundle к текущему профилю. Если не вышло — бросает, а bundle
    /// остаётся ждать следующей попытки.
    static func applyPendingBundle() async throws {
        guard let raw = HearthEnrollment.pendingBundle else { return }
        let bundle = try HearthBundle.parse(raw)
        try await setServers(bundle)
        networkSMPProxyModeGroupDefault.set(.always)
        try setNetworkConfig(getNetCfg())
        UserDefaults.standard.set(bundle.ice, forKey: DEFAULT_WEBRTC_ICE_SERVERS)
        UserDefaults.standard.set(true, forKey: DEFAULT_WEBRTC_POLICY_RELAY)
        HearthEnrollment.remember(bundle)
        // В bundle пароли релеев: держать его дольше применения незачем.
        HearthEnrollment.pendingBundle = nil
        await ensureNotifications()
    }

    /// Свои серверы включены, всё остальное выключено. Порядок как на Android
    /// (HearthApplier.kt): сначала серверы профиля, потом операторы отдельной командой —
    /// именно она пересобирает серверы агента.
    private static func setServers(_ bundle: HearthBundle) async throws {
        var servers = try await getUserServers()
        for i in servers.indices where servers[i].operator != nil {
            servers[i].operator?.enabled = false
        }
        if let i = servers.firstIndex(where: { $0.operator == nil }) {
            servers[i].smpServers = merge(servers[i].smpServers, bundle.smp)
            servers[i].xftpServers = merge(servers[i].xftpServers, bundle.xftp)
        } else {
            servers.append(UserOperatorServers(
                operator: nil,
                smpServers: merge([], bundle.smp),
                xftpServers: merge([], bundle.xftp),
                chatRelays: []
            ))
        }
        let (errors, _) = try await validateServers(userServers: servers)
        if !errors.isEmpty {
            throw HearthApplyError.invalidServers(errors.map { String(describing: $0) }.joined(separator: "; "))
        }
        try await setUserServers(userServers: servers)
        try await disableOperators()
    }

    /// Уже записанные адреса оставляем с их serverId — иначе ядро заведёт вторую запись;
    /// всё, чего нет в bundle, помечаем удалённым.
    private static func merge(_ existing: [UserServer], _ addresses: [String]) -> [UserServer] {
        var result = existing.map { server in
            var s = server
            s.enabled = addresses.contains(s.server)
            s.deleted = !s.enabled
            return s
        }
        for address in addresses where !existing.contains(where: { $0.server == address }) {
            result.append(UserServer(serverId: nil, server: address, preset: false, tested: nil, enabled: true, deleted: false))
        }
        return result.filter { $0.serverId != nil || !$0.deleted }
    }

    static func disableOperators() async throws {
        let conditions = try await getServerOperators()
        guard conditions.serverOperators.contains(where: { $0.enabled }) else { return }
        let operators = conditions.serverOperators.map { op in
            var o = op
            o.enabled = false
            return o
        }
        let updated = try await setServerOperators(operators: operators)
        await MainActor.run { ChatModel.shared.conditions = updated }
    }

    /// Upstream включает уведомления на экране «Ваша сеть», которого в сборке нет. Режим
    /// Instant ставится один раз: если человек потом выключил уведомления сам, при
    /// следующем запуске это не отменяется.
    private static func ensureNotifications() async {
        guard !UserDefaults.standard.bool(forKey: notificationsSetKey) else { return }
        let m = ChatModel.shared
        await MainActor.run { m.notificationMode = .instant }
        guard let token = m.deviceToken else { return }
        do {
            let status = try await apiRegisterToken(token: token, notificationMode: .instant)
            await MainActor.run { m.tokenStatus = status }
            UserDefaults.standard.set(true, forKey: notificationsSetKey)
        } catch {
            logger.error("Hearth: регистрация токена: \(responseError(error))")
        }
    }

    @MainActor static func completeOnboarding() {
        onboardingStageDefault.set(.onboardingComplete)
        // Как completeOnboarding upstream: смена стадии не из обработчика глубокой навигации.
        dismissAllSheets(animated: false) {
            DispatchQueue.main.async {
                ChatModel.shared.onboardingStage = .onboardingComplete
            }
        }
    }

    /// После каждого старта чата у заведённого устройства. Шаги независимы: сбой одного
    /// не отменяет остальные (android HearthStartup.kt).
    static func onChatStarted() {
        guard HearthEnrollment.isEnrolled else { return }
        Task {
            do {
                try await disableOperators()
            } catch {
                logger.error("Hearth: выключение операторов: \(responseError(error))")
            }
            await ensureNotifications()
            await refreshIceServers()
        }
    }

    /// Свежие TURN-креды при каждом старте: креды из bundle умирают на ротации секрета, и
    /// сломанный звонок при живых сообщениях читается как поломка микрофона (ADR 0010).
    static func refreshIceServers() async {
        guard let node = HearthEnrollment.node,
              let anchor = HearthEnrollment.anchor,
              let token = HearthEnrollment.nodeToken else { return }
        do {
            let ice = try await HearthNodeClient(node: node, anchor: anchor).turnCredentials(deviceToken: token)
            UserDefaults.standard.set(ice, forKey: DEFAULT_WEBRTC_ICE_SERVERS)
        } catch {
            logger.error("Hearth: обновление TURN: \(String(describing: error))")
        }
    }
}
