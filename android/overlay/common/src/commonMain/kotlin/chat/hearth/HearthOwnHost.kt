package chat.hearth

/**
 * Один разбор хоста на весь оверлей — и решение «эта ссылка на нашем узле или нет».
 *
 * # Что было
 *
 * Принадлежность ссылки своему узлу определялась подстрокой:
 * `link.contains(host, ignoreCase = true)`. Ошибка при этом идёт в опасную сторону.
 * Адрес `smp://…@myhearth.example.com.evil.net` содержит `myhearth.example.com` как
 * подстроку, значит считался своим — и [hearthCleanUpForeignLinks] оставлял профиль
 * на чужом сервере, а чужое приглашение не удалял. Ровно этот класс промаха уже
 * приводил к живым ссылкам на `smp8.simplex.im` (см. шапку HearthServers.kt).
 *
 * Строгий разбор в проекте был — в HearthBundle.kt, — но к ссылкам его не применяли.
 * Теперь правило одно и живёт здесь.
 *
 * # Почему неразобранная ссылка считается ЧУЖОЙ
 *
 * Неизвестный формат — это отсутствие доказательства, что ссылка наша. Считать её
 * своей означало бы: нашёлся формат, которого мы не знаем, — значит оставляем всё
 * как есть. Тогда достаточно выдать ссылку в непривычном виде, чтобы приведение к
 * своим серверам молча ничего не сделало. Обратная ошибка дешевле: адрес будет
 * пересоздан на своём узле, приглашение — выдано заново.
 */

/**
 * Хост из адреса: после `://`, после последнего `@`, до первого `/`, `?` или `#`,
 * без порта. Порт необязателен — короткие ссылки ядра его чаще всего не несут.
 *
 * `null` — хоста в строке нет.
 */
fun hearthHostOf(uri: String): String? {
  val afterScheme = uri.trim().substringAfter("://", "")
  if (afterScheme.isEmpty()) return null
  // authority кончается там, где начинается путь, запрос или якорь. Без этого
  // `https://evil.net/x?u=myhearth.ru` дал бы хост из ЗАПРОСА, а не из адреса.
  val authority = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }
  if (authority.isEmpty()) return null
  val hostPort = authority.substringAfterLast('@', authority)
  if (hostPort.isEmpty()) return null
  val host = if (hostPort.startsWith("[")) {
    // IPv6 в скобках: двоеточий внутри полно, отрезать порт по последнему нельзя.
    val end = hostPort.indexOf(']')
    if (end <= 0) return null
    hostPort.substring(0, end + 1)
  } else {
    hostPort.substringBefore(':')
  }
  return host.ifEmpty { null }
}

/**
 * Все хосты, на которые указывает ссылка-приглашение ядра.
 *
 * Форм две, и обе настоящие:
 *
 *  - короткая: `https://relay.example.org:5223/a#данные` — хост прямо в адресе;
 *  - полная: `simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40relay.example.org` —
 *    у неё хоста в адресе НЕТ вовсе, релеи лежат внутри параметра `smp` в процентном
 *    кодировании, и их может быть несколько через запятую.
 *
 * Полную форму пришлось разобрать по-настоящему: если считать её «неразобранной», то
 * чистка чужих ссылок удалила бы все наши собственные приглашения — а это семья без
 * связи, то есть отказ дороже дыры, которую он закрывает.
 *
 * Пустой набор — разобрать не удалось.
 */
fun hearthLinkHosts(link: String): Set<String> {
  val text = link.trim()
  if (text.isEmpty()) return emptySet()
  hearthHostOf(text)?.let { return setOf(it) }

  val fragment = text.substringAfter('#', "")
  if (fragment.isEmpty()) return emptySet()
  val query = fragment.substringAfter('?', "")
  if (query.isEmpty()) return emptySet()

  val hosts = LinkedHashSet<String>()
  for (pair in query.split('&')) {
    val name = pair.substringBefore('=', "")
    // Ядро складывает адреса релеев в эти параметры; остальное — версия, ключи и
    // прочее, где хоста быть не должно.
    if (name != "smp" && name != "srv" && name != "xftp") continue
    for (entry in hearthPercentDecode(pair.substringAfter('=', "")).split(',')) {
      hearthHostOf(entry)?.let { hosts.add(it) }
    }
  }
  return hosts
}

/**
 * Лежит ли ссылка на своём узле.
 *
 * Своей считается только та, у которой разобрался ХОТЯ БЫ один хост и ВСЕ разобранные
 * хосты — наши. «Хотя бы один» отсекает нечитаемую строку, «все» — ссылку, где наш
 * узел подмешан к чужому: один релей свой, второй чужой — это не своя ссылка.
 */
fun hearthLinksAreOn(links: List<String>, host: String): Boolean {
  if (host.isBlank()) return false
  val hosts = links.filter { it.isNotBlank() }.flatMap { hearthLinkHosts(it) }
  if (hosts.isEmpty()) return false
  return hosts.all { it.equals(host, ignoreCase = true) }
}

/**
 * Хост СВОЕГО узла — один явный источник на весь клиент.
 *
 * # Почему источник должен быть один
 *
 * Их было два, и они расходились. Пин ICE перед звонком брал хост из `hearthUpdateHost`
 * — это адрес device API узла. А сам bundle проверял ICE по хосту ПЕРВОГО SMP-адреса,
 * то есть по хосту релея. Сегодня это одна и та же строка только потому, что hearthd
 * кладёт `config.node.host` и туда, и туда (configgen/mod.rs). Разведи оператор device
 * API и релей по разным именам — и записи ICE, только что принятые bundle'ом, стали бы
 * «чужими» на пути звонка. Раньше это означало молчаливую потерю звонков у всей семьи
 * разом; теперь — отброшенный список и предупреждение, но и того не должно быть.
 *
 * Поэтому источник объявлен: хост РЕЛЕЯ, тот самый, по которому bundle проверял свои
 * ICE, — [HearthPrefs.bundleHost]. Его пишет применение bundle из `HearthBundle.host()`,
 * то есть из QR или кода доступа, который человек получил лично. Из базы он не
 * выводится никогда: база приезжает с архивом восстановления, в том числе чужим, и
 * тогда проверка «наш ли это узел» подтверждала бы сама себя.
 *
 * @param updateHost адрес device API. Он остаётся ЗАПАСНЫМ и только ради устройств,
 *   заведённых сборкой, в которой [HearthPrefs.bundleHost] ещё не писался: у них
 *   другого объявленного хоста нет вовсе, и отнимать у них пин незачем.
 *
 * `null` — своего узла это устройство не знает. Тогда сверять не с чем, и проверки,
 * которые на хост опираются, не выдумываются (см. [hearthPinnedIce]).
 */
fun hearthOwnNodeHost(bundleHost: String?, updateHost: String? = null): String? =
  bundleHost?.trim()?.ifEmpty { null } ?: updateHost?.trim()?.ifEmpty { null }

/**
 * Совпадают ли хост релея и хост device API.
 *
 * Расхождение — не поломка и не повод что-либо запрещать: узел вправе раздавать
 * обновления с другого имени. Но это ровно тот случай, в котором раньше молча
 * исчезали звонки, поэтому он должен быть ВИДЕН — отсюда отдельная проверка, а не
 * соглашение «так исторически совпало».
 *
 * `true`, если сравнивать нечего: отсутствие второго имени расхождением не является.
 */
fun hearthNodeHostsAgree(bundleHost: String?, updateHost: String?): Boolean {
  val relay = bundleHost?.trim()?.ifEmpty { null } ?: return true
  val api = updateHost?.trim()?.ifEmpty { null } ?: return true
  return relay.equals(api, ignoreCase = true)
}

/**
 * Процентное декодирование.
 *
 * Своё, а не платформенное: это commonMain. Некорректная последовательность
 * оставляется как есть — задача здесь не «разобрать любой ввод», а найти хост там,
 * где он действительно записан.
 */
internal fun hearthPercentDecode(value: String): String {
  if (!value.contains('%')) return value
  val out = StringBuilder(value.length)
  var i = 0
  while (i < value.length) {
    val c = value[i]
    if (c == '%' && i + 2 < value.length) {
      val hex = value.substring(i + 1, i + 3).toIntOrNull(16)
      if (hex != null) {
        out.append(hex.toChar())
        i += 3
        continue
      }
    }
    out.append(c)
    i++
  }
  return out.toString()
}
