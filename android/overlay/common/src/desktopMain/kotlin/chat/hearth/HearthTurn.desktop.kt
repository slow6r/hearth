package chat.hearth

/**
 * На desktop устройство заводится по QR и device API там не настроен, поэтому
 * обновлять нечего. Когда настольные сборки начнут раздаваться так же, как
 * Android-сборки, это станет копией androidMain.
 */
actual suspend fun hearthRefreshIceServers() = Unit
