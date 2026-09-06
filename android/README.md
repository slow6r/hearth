# android/ — конфиг-форк Android-клиента

**Здесь нет кода upstream и нет самого форка.** Здесь лежит всё, что делает форк
форком: overlay-файлы, описания патчей, скрипты сборки и проверки.

Сам форк подключается как submodule (ТЗ Приложение A) и в этот репозиторий не
вкладывается:

```bash
git submodule add https://github.com/<ваш-аккаунт>/simplex-chat.git android/simplex-chat
cd android/simplex-chat
git remote add upstream https://github.com/simplex-chat/simplex-chat.git
git fetch upstream --tags
git switch -c hearth/<upstream-tag> <upstream-tag>
```

Ветка форка всегда называется `hearth/<upstream-tag>` — по имени видно, на чём стоим.

```
android/
├── overlay/      файлы, которые форк ДОБАВЛЯЕТ (в чужих файлах не живут → не конфликтуют)
├── patches/      описания изменений в файлах upstream + порядок коммитов
├── scripts/      rebase-upstream.sh, build-release.sh, verify-apk.sh
└── UPSTREAM      пинованный тег
```

---

## Стратегия (ТЗ §8.1)

Haskell-ядро (`.so`) в v1 **не собираем**: берём релизные библиотеки upstream с
проверкой хеша. Своя сборка ядра — фаза 2 (ТЗ §13).

Всё, что меняем, — Kotlin-обвязка, ресурсы и дефолты. Целевой дифф — **< 500 строк,
0 в Haskell**. Проверяется автоматически в `scripts/rebase-upstream.sh`: если в диффе
появился `.hs`, скрипт останавливается — это блокер ревью (ТЗ §2.2).

Почему так строго: любой переписанный upstream-экран удорожает каждый следующий
ребейз, а ребейз надо делать за ≤ 7 дней после security-релиза (ТЗ §1.4). Дешёвый
ребейз — это не удобство, это часть модели безопасности.

---

## Что меняем (ТЗ §8.2) и что нет (ТЗ §8.3)

| Меняем | Не меняем |
|---|---|
| Пресеты серверов → пустые, адреса приходят с QR | Формат `smp://`-адресов |
| Экран операторов → скрыт | Рукопожатие, парсеры, крипта |
| ICE → только свой coturn | Логику очередей |
| Уведомления → Instant, без пуш-сервера | Любой Haskell |
| `allowBackup=false`, FLAG_SECURE, биометрия | Upstream-экраны сверх необходимого |
| Приватный роутинг Always, TTL 7 дней | — |
| Брендинг, `applicationId`, тема | — |
| In-app обновления → выключены | — |

Никаких SDK: аналитики, крэш-репортов, FCM, Play Services. Проверяется
`scripts/verify-apk.sh` (acceptance-тест A5).

---

## Рабочий цикл

```bash
# обновление на новый upstream-тег
./scripts/rebase-upstream.sh v6.x.y     # проверит подпись тега, дифф и отсутствие .hs
./scripts/build-release.sh              # сборка, только arm64-v8a
./scripts/verify-apk.sh <apk>           # A5, A9 и отсутствие публичных адресов
# подпись — ручной шаг офлайновым ключом (ТЗ §8.4)
```

Порядок обновления контура — ТЗ §10.6: **сначала клиенты, потом релей**, между ними
сутки на тестовом устройстве.

---

## Overlay-файлы

| Файл | Роль |
|---|---|
| `overlay/common/.../HearthBundle.kt` | Разбор и валидация bundle (ТЗ Приложение B) |
| `overlay/common/.../HearthPresets.kt` | Сетевые дефолты: пустые пресеты, ICE, Instant |
| `overlay/common/.../HearthOnboarding.kt` | Экран «Отсканируй QR» + применение bundle |
| `overlay/common/.../HearthBundleTest.kt` | JVM-тесты контракта bundle (без эмулятора) |
| `overlay/android/.../AndroidManifest-hearth.xml` | `allowBackup=false`, удаление лишних разрешений |
| `overlay/android/.../hearth_data_extraction_rules.xml` | Исключение из облачных бэкапов (A9) |
| `overlay/android/.../hearth_network_security_config.xml` | Нет cleartext, нет user CA |

Валидация bundle на устройстве дублирует валидацию в `hearthd`. Это не паранойя, а
дешёвая страховка: подменённый или протухший QR не должен молча увести телефон на чужой
релей.

---

## Раскатка (ТЗ §8.2 п.9)

Канал — **собственный F-Droid-репозиторий на `hearth-node`, доступный только из WG**.
Публикации в App Store / Google Play / RuStore / публичный F-Droid нет и не будет
(ТЗ §1.2).

Fallback, если репозиторий недоступен: APK передаётся через сам мессенджер, подпись
проверяется вручную по известному отпечатку.
