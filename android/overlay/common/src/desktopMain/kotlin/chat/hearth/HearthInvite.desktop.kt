package chat.hearth

/**
 * На desktop вшитого приглашения нет.
 *
 * Раздача сборок для настольных машин у нас не автоматизирована, а класть туда
 * долгоживущий секрет «на всякий случай» — это ровно тот вечный ключ, которого мы
 * избегаем на Android. Настройка идёт по QR.
 */
actual suspend fun hearthAutoSetUp(): HearthClaimResult = HearthClaimResult.NoInvite
