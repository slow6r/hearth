package chat.hearth

import androidx.compose.runtime.Composable

/**
 * На десктопе пусто.
 *
 * Обновление ставится через системный установщик пакетов, а не приложением, и
 * десктопная сборка этого форка не выпускается вовсе. Пустая реализация нужна только
 * чтобы общий код компилировался под все цели — удалять `expect` ради этого дороже.
 */
@Composable
actual fun HearthNodeSettingsView() {
}
