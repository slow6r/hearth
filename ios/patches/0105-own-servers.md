# 0105 — Свои серверы после создания профиля, операторы выключены

## Что делаем
1. После создания профиля вместо «Вашей сети» и условий операторов открывается
   `HearthOnboardingFinishView`: применяет отложенный bundle (серверы профиля, операторы
   выключены, ICE, приватный роутинг, Instant) и завершает онбординг. Не вышло — экран с
   причиной и «Повторить», bundle остаётся ждать.
2. Стадии `step3_ChooseServerOperators`, `step4_SetNotificationsMode`,
   `step4_NetworkCommitments` ведут туда же — в том числе после перезапуска посреди
   онбординга, куда их ставит `startChat`.
3. При каждом старте чата у заведённого устройства: операторы выключаются, если кто-то
   включён, TURN-креды обновляются с узла (`HearthApplier.onChatStarted`).
4. Секция «Preset servers» в настройках сети и уведомление об обновлённых условиях
   скрыты (`HEARTH_PRESETS_ENABLED = false`).

## Почему
ТЗ §1.2, android/patches/0001, 0002, 0013 и ADR 0011 («Когда именно применяется
bundle»): `/_servers` требует пользователя, до создания профиля записать серверы нельзя.

## Точка интеграции
```bash
rg -n "nextStepDestinationView|step4_NetworkCommitments|HEARTH_PRESETS_ENABLED|HearthApplier" apps/ios/Shared
```
- `Views/Onboarding/CreateProfile.swift` — `nextStepDestinationView`;
- `Views/Onboarding/OnboardingView.swift` — ветки step3/step4;
- `Model/SimpleXAPI.swift` — `startChat`, ветка `!onboarding`;
- `Views/UserSettings/NetworkAndServers/NetworkAndServers.swift`, `ContentView.swift`.

Экраны операторов не удалены — недостижимы. Удаление файла дало бы конфликт на каждом
ребейзе.

## Проверка
- Ручная: после онбординга в «Сеть и серверы» — ровно один SMP и один XFTP, оба на узле.
- На узле растёт `simplex_smp_queues_created` после создания ссылки
  (android/patches/0013).
