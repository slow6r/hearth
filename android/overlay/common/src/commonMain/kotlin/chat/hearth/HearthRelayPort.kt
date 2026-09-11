package chat.hearth

/**
 * Порт, на котором телефоны ходят к своему релею.
 *
 * # Почему 8443, а не 443 и не 5223
 *
 * К узлу не мог подключиться никто и ниоткуда — ни из офиса, ни через VPN, ни с
 * сервера в Москве, — хотя openssl с тех же машин соединялся без проблем. Разбор по
 * пакетам показал: домашний провайдер узла на входе досматривает порты 443 и 5223 и
 * выбрасывает именно TLS-приветствие клиента SimpleX (213 байт, по «отпечатку» —
 * даже с изменённым random). Тот же пакет на любой другой порт доходит; проверено на
 * двадцати портах. Роутер, узел и сети клиентов ни при чём: изнутри дома то же
 * приветствие на 443 получает ответ.
 *
 * 8443 — обычный «альтернативный HTTPS», его пропускают и офисные сети. Релей слушает
 * и старые порты, так что переписывание ничего не ломает.
 */
const val HEARTH_RELAY_WEB_PORT = 8443
private const val SMP_DEFAULT_PORT = 5223
/** Порты, с которых переводим: родной SMP и тот, что выдавался до обнаружения DPI. */
private val MOVE_FROM = setOf(SMP_DEFAULT_PORT, 443)

// smp://<отпечаток>:<пароль>@<хост[,хост…]>[:порт]
private val SMP_ADDRESS = Regex("^(smp://[^@/?# ]+@)([A-Za-z0-9.,-]+)(?::([0-9]{1,5}))?$")

/**
 * Адрес своего релея, переведённый на 443, или `null`, если трогать нечего.
 *
 * Переписываем только SMP, только свой хост и только порты 5223 (явный или
 * подразумеваемый) и 443. Чужие серверы, XFTP (у него свой порт) и нестандартные порты,
 * которые кто-то задал сознательно, не трогаем.
 */
fun hearthRelayAddressOnWebPort(address: String, relayHost: String): String? {
  val m = SMP_ADDRESS.matchEntire(address.trim()) ?: return null
  val (prefix, hosts, port) = m.destructured
  if (hosts.split(',').none { it.equals(relayHost, ignoreCase = true) }) return null
  val current = port.toIntOrNull() ?: SMP_DEFAULT_PORT
  if (current !in MOVE_FROM) return null
  return "$prefix$hosts:$HEARTH_RELAY_WEB_PORT"
}
