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
├── scripts/      sync-overlay.sh, bake-invite.sh, rebase-upstream.sh, build-release.sh, verify-apk.sh
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
| `overlay/common/.../HearthUpdate.kt` | Манифест обновления и его валидация, оркестрация проверки |
| `overlay/common/.../HearthUpdate.android.kt` | Транспорт до узла: манифест, докачка по `Range`, sha256, enroll |
| `overlay/common/.../HearthUpdateService.android.kt` | Загрузка в foreground-сервисе + намерение установки |
| `overlay/common/.../HearthSettings.kt` + `*.android.kt` | Экран «Домашний узел»: обновление и приглашение устройства |
| `overlay/android/.../hearth_icon_foreground.xml`, `hearth_icon.xml` | Иконка-костёр (adaptive) |
| `overlay/android/.../mipmap-anydpi-v26-icon.xml` | Раскладывается в `icon.xml` и `icon_round.xml` |
| `overlay/android/.../raw/hearth_ca.pem` | CA узла для пиннинга в network security config |
| `overlay/common/.../HearthInvite.kt` | Вшитое приглашение: разбор, валидация, первый запуск (ADR 0011) |
| `overlay/common/.../HearthInvite.android.kt` | Чтение ресурса приглашения и `POST /claim` |
| `overlay/common/.../HearthTurn.kt` + `*.android.kt` | Автообновление ICE при запуске — иначе звонки умирают по календарю |

Перед сборкой overlay раскладывается по форку скриптом `scripts/sync-overlay.sh`;
`build-release.sh` вызывает его сам. Собрать форк, не разложив overlay, — значит
получить сборку без части правок и не заметить этого.

Валидация bundle на устройстве дублирует валидацию в `hearthd`. Это не паранойя, а
дешёвая страховка: подменённый или протухший QR не должен молча увести телефон на чужой
релей.

---

## Десктоп (Windows)

Ядро для десктопа мы тоже не собираем, а берём из официального релиза upstream — как
и для Android. Отличие в том, что для Windows оно лежит внутри `.msi`:

```bash
curl -L -o u.msi https://github.com/simplex-chat/simplex-chat/releases/download/v7.0.1/simplex-desktop-windows-x86_64.msi
sha256sum u.msi     # bcb227c15189615a3dd67193e1cb5842f4873c24e53d2e33284dbcae48dbb810
7z e u.msi filec6d138a347f4390987170efb9d87b121   # 136 МБ, это libsimplex.dll
```

Хеш обязателен и проверяется **из двух сетей** — та же процедура, что для релеев
(`relays/README.md`). Записанные значения:

| Файл | sha256 |
|---|---|
| `simplex-desktop-windows-x86_64.msi` (v7.0.1) | `bcb227c15189615a3dd67193e1cb5842f4873c24e53d2e33284dbcae48dbb810` |
| `libsimplex.dll` из него | `5586c3b77a1ddb2844a8aa62bb3e774fac4f62d7671fe2d10da32340d23ae929` |

Дальше DLL кладётся в `common/src/commonMain/cpp/desktop/libs/windows-x86_64/` и в
`desktop/build/cmake/main/windows-amd64/` (оттуда её забирает `cmakeBuildAndCopy`), и:

```bash
./gradlew :desktop:cmakeBuildAndCopy :desktop:createDistributable   # готовое приложение
./gradlew :desktop:packageMsi                                       # установщик, нужен WiX
```

Что должно быть на машине: `cmake`, `gcc` (MinGW-w64), `make` — плагин генерирует
Unix Makefiles, и `mingw32-make` сам по себе не подходит, нужен именно `make` в PATH.
Для MSI дополнительно WiX Toolset 3.x (`winget install WiXToolset.WiXToolset`,
требует прав администратора).

---

## Раскатка (ТЗ §8.2 п.9)

Канал — **собственный F-Droid-репозиторий на `hearth-node`, доступный из домашней сети**.
Публикации в App Store / Google Play / RuStore / публичный F-Droid нет и не будет
(ТЗ §1.2).

Fallback, если репозиторий недоступен: APK передаётся через сам мессенджер, подпись
проверяется вручную по известному отпечатку.
