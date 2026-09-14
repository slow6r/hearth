//
//  HearthAccessCodeView.swift
//  Hearth — код доступа до онбординга и завершение онбординга без экранов операторов
//

import SwiftUI
import SimpleXChat

/// Первый экран сборки (ADR 0012). Без кода приложение не открывает ничего.
struct HearthAccessCodeView: View {
    @EnvironmentObject var theme: AppTheme
    @State private var code = ""
    @State private var inProgress = false
    @State private var errorText: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Hearth")
                .font(.largeTitle)
                .bold()
            Text("Введите код доступа, который вам выдали лично. Без него приложение не подключится к домашнему узлу.")
                .foregroundColor(theme.colors.secondary)
            TextField("H7K4-P9QX-M3TV", text: $code)
                .font(.system(.title2, design: .monospaced))
                .textInputAutocapitalization(.characters)
                .disableAutocorrection(true)
                .keyboardType(.asciiCapable)
                .disabled(inProgress)
                .onChange(of: code) { raw in
                    // Храним уже нормализованный код в группах: так человек видит то же, что
                    // уйдёт на узел, а O/I/L с бумажки молча становятся 0/1.
                    let shown = HearthAccessCode.formatGroups(
                        String(HearthAccessCode.normalize(raw).prefix(HearthAccessCode.length))
                    )
                    if shown != raw { code = shown }
                }
            if let e = errorText {
                Text(e).foregroundColor(.red)
            }
            Button {
                claim()
            } label: {
                ZStack {
                    Text("Подключиться").opacity(inProgress ? 0 : 1)
                    if inProgress { ProgressView() }
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(inProgress || !HearthAccessCode.isValid(HearthAccessCode.normalize(code)))
            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func claim() {
        guard let node = HearthEnrollment.node, let anchor = HearthEnrollment.anchor else {
            errorText = hearthClaimErrorText(HearthNodeError.incompleteBuild)
            return
        }
        let normalized = HearthAccessCode.normalize(code)
        inProgress = true
        errorText = nil
        Task {
            do {
                let (_, raw) = try await HearthNodeClient(node: node, anchor: anchor).claim(
                    code: normalized,
                    deviceName: HearthEnrollment.deviceName,
                    installId: HearthEnrollment.installId
                )
                await MainActor.run {
                    HearthEnrollment.pendingBundle = raw
                    onboardingStageDefault.set(.step2_CreateProfile)
                    ChatModel.shared.onboardingStage = .step2_CreateProfile
                    inProgress = false
                }
            } catch {
                await MainActor.run {
                    errorText = hearthClaimErrorText(error)
                    inProgress = false
                }
            }
        }
    }
}

func hearthClaimErrorText(_ error: Error) -> String {
    switch error as? HearthNodeError {
    case .refused: "Код не подошёл. Проверьте его или попросите новый."
    case .throttled: "Слишком много попыток. Подождите час и попробуйте снова."
    case .noSlots: "На узле закончились места для устройств."
    case .badRequest: "Узел отклонил запрос. Проверьте код."
    case let .status(code): "Узел ответил \(code)."
    case let .transport(message): "Нет связи с домашним узлом: \(message)"
    case let .badResponse(message): "Узел прислал неверные настройки: \(message)"
    case .incompleteBuild: "Сборка неполная: в ней нет адреса домашнего узла. Нужна другая сборка."
    case .none: error.localizedDescription
    }
}

/// Стадии онбординга про операторов и условия в сборке не показываются: вместо них
/// применяется bundle узла, и онбординг завершается (android/patches/0013).
struct HearthOnboardingFinishView: View {
    @EnvironmentObject var theme: AppTheme
    @State private var failure: String? = nil

    var body: some View {
        VStack(spacing: 16) {
            if let f = failure {
                Text("Не удалось применить настройки узла")
                    .font(.headline)
                Text(f)
                    .foregroundColor(theme.colors.secondary)
                    .multilineTextAlignment(.center)
                Button("Повторить") {
                    Task { await finish() }
                }
                .buttonStyle(.borderedProminent)
            } else {
                ProgressView()
                Text("Подключаемся к домашнему узлу…")
                    .foregroundColor(theme.colors.secondary)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationBarBackButtonHidden(true)
        .task { await finish() }
    }

    private func finish() async {
        await MainActor.run { failure = nil }
        do {
            if HearthEnrollment.pendingBundle != nil {
                try await HearthApplier.applyPendingBundle()
            } else if !HearthEnrollment.isEnrolled {
                await MainActor.run {
                    failure = "В приложении нет настроек узла. Удалите приложение, установите заново и введите код доступа."
                }
                return
            }
            HearthApplier.completeOnboarding()
        } catch {
            await MainActor.run { failure = error.localizedDescription }
        }
    }
}
