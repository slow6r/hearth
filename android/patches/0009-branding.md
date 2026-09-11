# 0009 — Брендинг и applicationId

## Что делаем
Имя приложения, иконка, `applicationId`, тема. Экран «О программе»: ссылка на upstream
и текст лицензии AGPLv3.

## Почему
ТЗ §8.2 п.8. Отдельный `applicationId` нужен, чтобы форк ставился рядом со стоковым
SimpleX и не конфликтовал с ним при обновлениях. Ссылка на исходники и AGPLv3 —
обязательство лицензии, а не пожелание.

Открытый вопрос ТЗ §15.5 (`applicationId` под ООО или нейтральный) решить **до первой
раскатки**: смена потом = переустановка на всех устройствах с потерей базы.

## Точка интеграции
- `apps/multiplatform/android/build.gradle.kts` → `applicationId`, `versionName`.
- `res/mipmap-*` → иконка; `res/values*/strings.xml` → `app_name`.

### Что пришлось трогать сверх этого

Замысел «тема отдельным модулем, не размазывая по чужим файлам» не выдержал
столкновения с реальностью: бренд у upstream размазан сам. Перечисляю всё, иначе при
ребейзе половина вернётся синей и с чужим именем.

| Где | Что |
|---|---|
| `MR/*/strings.xml` (38 локалей) | SimpleX → Hearth в **значениях**; имена ресурсов и комментарии не трогать — по ним ищут |
| `MR/images/logo@4x`, `logo_light@4x` | надпись: костёр + «Hearth» |
| `MR/images/ic_simplex_*`, `ic_simplex*.svg` | квадратная иконка и иконки трея |
| `MR/images/icon_foreground_common@4x` | **логотип в центре QR** (десктоп) |
| `platform/Images.android.kt` | логотип в центре QR (Android) — по имени ресурса, наша drawable в другом модуле |
| `ui/theme/Color.kt`, `Theme.kt` | `SimplexBlue` → огонь; четыре палитры, включая пузыри сообщений |
| `MR/*/strings.xml` | `#0088ff` → `#d9480f` в ссылках внутри текстов |
| `newchat/OnboardingCards.kt` | градиент карточек приглашений — OKLCH прямо в коде, тона в огонь |
| `DesktopApp.kt`, `NtfManager.desktop.kt` | заголовок окна и подпись в трее — жёстко зашитые `"SimpleX"` |
| `usersettings/Appearance.android.kt` | секция выбора иконки: второй вариант — синяя иконка SimpleX |
| `model/SimpleXAPI.kt` → `simplexChatLink` | показ ссылки как `https://simplex.chat/...` — домен убран |
| `SettingsView.kt`, `ChatHelpView.kt` | «Что нового», «написать письмо», «звезда», «оценить», «внести вклад», ссылка на команду |
| `NtfManager.android.kt`, `SimplexService.kt`, `CallService.kt` | акцентный цвет уведомлений `setColor(0x88FFFF)` — им система красит значок и имя приложения в шторке |
| `drawable-*/ntf_icon.png`, `drawable-*/ntf_service_icon.png` | значки в строке состояния: у сообщений и у постоянного фонового уведомления. Белый силуэт — Android берёт только альфу |
| `drawable-hdpi/icon.png` | большая картинка в уведомлении, когда у контакта нет аватара или превью скрыто |
| `mipmap-*/icon*.png`, `common/src/androidMain/res/drawable/icon_foreground_android_common.png`, `@color/icon_dark_blue_background` | старые растровые иконки. При `minSdk 26` лаунчер их не берёт, но они в APK, и запасной ярлык `icon_dark_blue` в манифесте на них ссылается |
| `desktop/build.gradle.kts` | `packageName`, иконки, `upgradeUuid`, `bundleID`, копирайт |

Схема `simplex:` в ссылках-приглашениях **остаётся**: её разбирает ядро на принимающей
стороне, и переписать её — значит сломать соединение (ТЗ §8.3 запрещает трогать
форматы адресов). Убран только домен показа.

## Проверка
- Ручная: приложение ставится рядом со стоковым SimpleX.
- Экран «О программе» содержит ссылку на upstream и AGPLv3.
