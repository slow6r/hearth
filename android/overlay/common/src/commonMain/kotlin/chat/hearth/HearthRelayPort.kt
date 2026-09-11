package chat.hearth

/**
 * Порт, на котором телефоны ходят к своему релею.
 *
 * # Почему 443, а не 5223
 *
 * 5223 — родной порт SMP, но нестандартный, и его режут офисный и публичный Wi-Fi и
 * часть провайдеров: соединение пропускают, а первое сообщение шифрования глушат.
 * Именно так телефон «не мог создать ссылку» — на узле было видно, что соединение
 * открывается, а до сервера не доходит ни байта, и через 60 секунд сервер его
 * закрывает. 443 — порт обычных сайтов, его не режет почти никто.
 *
 * Серверы SimpleX клиент и сам водит через 443 (`smpWebPortServers = preset` в ядре);
 * поэтому ссылки на их серверах из той же сети создавались, а на наших — нет.
 *
 * Релей слушает оба порта, так что переписывание ничего не ломает: уже созданные
 * очереди продолжают жить на 5223, новые идут через 443.
 */
const val HEARTH_RELAY_WEB_PORT = 443
private const val SMP_DEFAULT_PORT = 5223

// smp://<отпечаток>:<пароль>@<хост[,хост…]>[:порт]
private val SMP_ADDRESS = Regex("^(smp://[^@/?# ]+@)([A-Za-z0-9.,-]+)(?::([0-9]{1,5}))?$")

/**
 * Адрес своего релея, переведённый на 443, или `null`, если трогать нечего.
 *
 * Переписываем только SMP, только свой хост и только порт 5223 — явный или
 * подразумеваемый. Чужие серверы, XFTP (у него свой порт) и нестандартные порты,
 * которые кто-то задал сознательно, не трогаем.
 */
fun hearthRelayAddressOnWebPort(address: String, relayHost: String): String? {
  val m = SMP_ADDRESS.matchEntire(address.trim()) ?: return null
  val (prefix, hosts, port) = m.destructured
  if (hosts.split(',').none { it.equals(relayHost, ignoreCase = true) }) return null
  val current = port.toIntOrNull() ?: SMP_DEFAULT_PORT
  if (current != SMP_DEFAULT_PORT) return null
  return "$prefix$hosts:$HEARTH_RELAY_WEB_PORT"
}
