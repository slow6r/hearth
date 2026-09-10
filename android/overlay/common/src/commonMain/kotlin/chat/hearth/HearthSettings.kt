package chat.hearth

import androidx.compose.runtime.Composable

/**
 * Экран «Домашний узел»: обновление и приглашение нового устройства (ADR 0010).
 *
 * `expect`, потому что вызывается из общего кода настроек, а реализован может быть
 * только платформенно: фоновая загрузка, установка APK и `packageManager` — всё это
 * Android. На десктопе пункт есть, но пустой: обновлять там нечего, десктопная сборка
 * этого форка не выпускается.
 */
@Composable
expect fun HearthNodeSettingsView()
