package chat.hearth

/**
 * Hearth network defaults — the single place where "which servers does this app talk to"
 * is decided (ТЗ §8.2 п.1–5).
 *
 * Upstream ships a list of SimpleX operators and their relays. In this fork that list is
 * empty and the operator screen is hidden: the app must be incapable of reaching the
 * public network, not merely configured not to (ТЗ §1.2).
 *
 * INTEGRATION POINTS (see ../../../../../patches/0001-presets.md):
 *   - upstream preset list  -> return [presetServers] (empty until a bundle is imported)
 *   - upstream ICE defaults -> [defaultIceServers]
 *   - upstream operator UI  -> hidden, see patches/0002-hide-operators.md
 */
object HearthPresets {

  /**
   * Servers shipped in the APK: none.
   *
   * The relay address contains a password (ТЗ §6.2), so it cannot be baked into a
   * binary that is passed around on a USB stick — it arrives with the bundle QR and
   * lives in the app's encrypted storage from then on.
   */
  val presetServers: List<String> = emptyList()

  /** Public operator presets are off, permanently. */
  const val PRESETS_ENABLED = false

  /**
   * Показывать ли переключатель «Защитить экран приложения» (patches/0006).
   *
   * Нет. FLAG_SECURE ставится безусловно в MainActivity; переключатель, который может
   * его снять, — это настройка, которую рано или поздно выключат, и именно на том
   * устройстве, которое потеряют (ТЗ §3.1, §8.2 п.6).
   */
  const val SHOW_SCREEN_PROTECTION_TOGGLE = false

  /**
   * Показывать ли пункты, ведущие в публичную сеть SimpleX («написать основателю»,
   * краудфандинг и подобное).
   *
   * Нет. Операторы выключены, публичные релеи недостижимы, поэтому такая кнопка —
   * это кнопка, которая молча не сработает. Плюс её адрес — адрес публичной сети,
   * зашитый в APK, что запрещает ТЗ §1.2 и ловит A5.
   */
  const val SHOW_UPSTREAM_LINKS = false

  /**
   * Показывать ли экран ручной правки ICE-серверов (Настройки → «Аудио и видео звонки»).
   *
   * Нет. Список ICE — это маршрут медиа: вписав туда чужой TURN, человек с
   * разблокированным телефоном уводит звонок через сервер третьей стороны, которой
   * достаются адреса обоих собеседников. Upstream проверяет при сохранении только то,
   * что строки разбираются парсером, — `turn:u:c@evil.example:3478` разбирается.
   *
   * Второй вход на тот же экран (из «Сеть и серверы») форк уже закрыл флагом
   * [SHOW_UPSTREAM_LINKS], а третий — из настроек звонков — остался открытым. На iOS
   * решение то же: `HEARTH_ICE_EDITABLE = false`.
   *
   * Скрытый экран — не защита, а уборка. Запрет держит HearthIcePolicy.kt: его
   * `hearthPinnedIceServers()` стоит в `views/call/WebRTC.kt`, внутри `getIceServers()`,
   * то есть в той единственной точке, где список ICE действительно берут перед звонком.
   *
   * Обещание надо ограничить честно, иначе оно было бы неправдой. Сверка идёт с хостом
   * СВОЕГО узла, а хост берётся из того, что человек применил лично: хост bundle либо,
   * для старых установок, адрес device API узла. Если ни того, ни другого нет — сверять
   * не с чем, и список проходит как есть. Это осознанный fail-open ровно на один случай:
   * устройство, не знающее своего узла, не должно остаться без звонков.
   *
   * Но проходит он ПОМЕЧЕННЫМ: непроверенный список снимает relay-only
   * ([hearthUseRelay]), потому что иначе медиа принудительно пошло бы через сервер, чью
   * принадлежность никто не подтвердил, — и человеку про это сказано словами. Вписанный
   * руками чужой TURN остаётся одним из возможных маршрутов, но перестаёт быть
   * единственным.
   *
   * # Почему не `const`
   *
   * `const` подставляется прямо в место вызова, поэтому условие `if (ICE_EDITABLE)`
   * в `views/usersettings/CallSettings.kt` вычислено ещё при компиляции, а ветка под
   * ним недостижима по построению. Пожаловаться на это некому: компилятор об этом
   * молчит (проверено сборкой), тест туда не заходит — ветка тихо перестаёт быть
   * кодом и остаётся текстом, который следующий читатель вправе удалить как мусор.
   *
   * Удалять нельзя. Вторая ветка — это возврат к upstream-поведению правкой одной
   * строки здесь, и нужен он ровно в том случае, ради которого всё написано: если
   * пин ICE однажды оставит семью без звонков, а решать придётся в тот же вечер.
   * Обычный `val` читается в момент отрисовки экрана: условие остаётся настоящим,
   * обе ветки — настоящим кодом, а флаг по-прежнему меняется в одном месте.
   */
  val ICE_EDITABLE = false

  /**
   * Пускать медиа только через ретранслятор (`iceTransportPolicy: "relay"`).
   *
   * Да, и это инвариант контура, а не предпочтение человека. Upstream оставляет
   * переключатель «Всегда использовать ретранслятор» включённым по умолчанию, но
   * выключаемым; выключенный он переводит ICE в режим `all`, и собеседник по семье
   * видит реальный адрес устройства. Наружу при этом ничего не утекает — список ICE
   * остаётся своим, — поэтому риск ниже, чем у правки самого списка, но это ровно та
   * настройка, которую однажды выключат «чтобы позвонить», и обратно не включат.
   *
   * Цена решения названа честно: при протухших TURN-кредах звонок в режиме `relay`
   * не состоится вовсе, тогда как в `all` он мог бы пройти напрямую. Это тот же
   * размен, что в patches/0004: неработающий звонок виден и чинится, утечка — нет.
   *
   * Не `const` по той же причине, что и у [ICE_EDITABLE]: иначе `else`-ветка
   * переключателя в `CallSettings.kt` и `ALWAYS_RELAY || preferRelay` в
   * [hearthUseRelay] вычисляются при компиляции, и код, которым откатывают инвариант,
   * превращается в текст без единой проверки — то есть в мусор на вид.
   */
  val ALWAYS_RELAY = true

  /** ТЗ §8.2 п.5: private message routing is on by default and not weakened. */
  const val PRIVATE_ROUTING_DEFAULT = "always"

  /**
   * Delivery is a foreground service holding a persistent connection to our relay.
   * There is no notification server in the contour, so Periodic/Push are not offered.
   */
  const val NOTIFICATION_MODE = "instant"

  /** ТЗ §8.2 п.6: disappearing messages default for new contacts. */
  const val DEFAULT_DISAPPEARING_MESSAGES_SECONDS = 7 * 24 * 60 * 60

  /**
   * ICE servers currently configured on this device.
   *
   * Empty until a bundle is imported. Upstream's fallback to public STUN must be
   * removed rather than left as a fallback: an empty ICE list means calls fail loudly,
   * which is the correct outcome — a call that succeeds via `stun.l.google.com` has
   * already leaked the participant's address (ТЗ §6.4).
   */
  fun defaultIceServers(applied: HearthBundle?): List<String> =
    applied?.ice ?: emptyList()

  /**
   * Servers to hand to the SimpleX core after a bundle import.
   *
   * Returns them in upstream's own `smp://` / `xftp://` string form: this fork never
   * touches the address format or the parser (ТЗ §8.3).
   */
  fun serversFrom(bundle: HearthBundle): HearthServers = HearthServers(
    smp = bundle.smp,
    xftp = bundle.xftp,
    ice = bundle.ice,
  )
}

/** The set of servers this device uses. Nothing else is reachable. */
data class HearthServers(
  val smp: List<String>,
  val xftp: List<String>,
  val ice: List<String>,
)
