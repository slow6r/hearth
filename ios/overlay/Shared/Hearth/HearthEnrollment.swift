//
//  HearthEnrollment.swift
//  Hearth — состояние заведения устройства на домашнем узле
//

import Foundation
import UIKit
import SimpleXChat

/// Экрана операторов SimpleX и их условий в сборке нет: выключенного оператора можно
/// включить обратно, отсутствующий экран — нет (ТЗ §1.2, android/patches/0002).
let HEARTH_PRESETS_ENABLED = false

/// ICE приходит с узла. Ручная правка списка — единственный путь вернуть публичные
/// STUN/TURN, поэтому экрана правки нет (android/patches/0004).
let HEARTH_ICE_EDITABLE = false

enum HearthEnrollment {
    private static let pendingBundleKey = "hearthPendingBundle"
    private static let deviceIdKey = "hearthDeviceId"
    private static let nodeTokenKey = "hearthNodeToken"
    private static let installIdKey = "hearthInstallId"

    /// Ресурсы узла вшиты во фреймворк ядра — он общий у приложения и расширений.
    static var resources: Bundle { Bundle(for: HearthNodeClient.self) }
    static var node: HearthNode? { HearthNode.loadBaked(from: resources) }
    static var anchor: SecCertificate? { HearthNode.loadBakedCA(from: resources) }

    /// Bundle, полученный по коду, но ещё не применённый. Серверы пишутся только в
    /// существующий профиль, а профиля в момент ввода кода ещё нет (ADR 0011,
    /// «Когда именно применяется bundle»).
    static var pendingBundle: Data? {
        get { UserDefaults.standard.data(forKey: pendingBundleKey) }
        set { UserDefaults.standard.set(newValue, forKey: pendingBundleKey) }
    }

    static var deviceId: String? { UserDefaults.standard.string(forKey: deviceIdKey) }
    static var nodeToken: String? { UserDefaults.standard.string(forKey: nodeTokenKey) }
    static var isEnrolled: Bool { !(deviceId ?? "").isEmpty }
    static var needsAccessCode: Bool { !isEnrolled && pendingBundle == nil }

    static func remember(_ bundle: HearthBundle) {
        UserDefaults.standard.set(bundle.device, forKey: deviceIdKey)
        UserDefaults.standard.set(bundle.node?.token, forKey: nodeTokenKey)
    }

    /// Повтор `/claim` после потерянного ответа не тратит код: узел узнаёт устройство по
    /// этому идентификатору. Живёт в UserDefaults и умирает вместе с приложением —
    /// переустановка просит новый код, как и задумано в ADR 0012.
    static var installId: String {
        if let id = UserDefaults.standard.string(forKey: installIdKey) { return id }
        let id = UUID().uuidString.lowercased()
        UserDefaults.standard.set(id, forKey: installIdKey)
        return id
    }

    /// Имя в реестре узла. Имя телефона iOS отдаёт только с отдельным правом Apple,
    /// поэтому — модель, например «Apple iPhone15,2».
    static var deviceName: String {
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return "Apple \(machine.isEmpty ? UIDevice.current.model : machine)"
    }
}
