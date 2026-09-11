package chat.hearth

import chat.simplex.common.model.ChatController
import chat.simplex.common.model.SMPProxyMode
import chat.simplex.common.model.UserOperatorServers
import chat.simplex.common.model.UserServer
import chat.simplex.common.platform.chatModel

/**
 * [HearthBundleApplier] against the upstream controller API of the pinned tag (v7.0.1).
 *
 * # Почему это не «подменить константу с пресетами»
 *
 * patches/0001-presets.md предписывает заменить список предустановленных серверов на
 * пустой. В v7.0.1 такого списка в Kotlin НЕТ: операторы и их релеи живут в
 * Haskell-ядре и приходят наверх через `apiGetServerOperators` / `getUserServers`.
 * Kotlin их только отображает. Править Haskell запрещает ТЗ §8.3 — это блокер ревью.
 *
 * Поэтому вместо «пресетов нет» делается «пресеты выключены и заменены»:
 *
 *   1. все операторы upstream переводятся в `enabled = false`;
 *   2. добавляется запись без оператора (`operator = null` — «nil operator», форма,
 *      в которой upstream хранит пользовательские серверы) ровно с нашими SMP и XFTP;
 *   3. экран операторов скрыт (patches/0002), включить обратно из UI нельзя.
 *
 * Разница в гарантии, и её надо называть вслух: приложение НЕ «неспособно» уйти в
 * публичную сеть, как формулирует 0002 — ядро по-прежнему знает публичных операторов.
 * Оно настроено не уходить, и настройку не видно. Для семейного контура этого
 * достаточно; обещать большее без диффа в Haskell нельзя.
 */
class HearthCoreApplier : HearthBundleApplier {

  override suspend fun setServers(servers: HearthServers) {
    val rh = chatModel.remoteHostId()
    val current = ChatController.getUserServers(rh)
      ?: throw IllegalStateException("не удалось прочитать текущие серверы")

    // Операторы upstream остаются в списке, но выключенными. Удалять их нельзя:
    // ядро их всё равно знает, а запись с чужим operatorId, исчезнувшая из списка,
    // приводит к рассинхрону при следующем getUserServers.
    val disabledOperators = current
      .filter { it.operator != null }
      .map { entry -> entry.copy(operator = entry.operator?.copy(enabled = false)) }

    val ours = UserOperatorServers(
      operator = null,
      smpServers = servers.smp.map { userServer(it) },
      xftpServers = servers.xftp.map { userServer(it) },
    )

    val updated = disabledOperators + ours

    // Проверяем ДО записи: ядро умеет объяснить, что не так с набором серверов,
    // и лучше отказать при импорте, чем оставить устройство в полурабочем виде.
    val validation = ChatController.validateServers(rh, updated)
    val errors = validation?.first.orEmpty()
    if (errors.isNotEmpty()) {
      throw IllegalStateException("ядро отвергло набор серверов: ${errors.joinToString()}")
    }

    if (!ChatController.setUserServers(rh, updated)) {
      throw IllegalStateException("не удалось записать серверы")
    }

    // Перечитать: ядро присваивает serverId вновь добавленным записям, и без этого
    // модель в UI разойдётся с тем, что реально записано.
    ChatController.getServerOperators(rh)?.let { chatModel.conditions.value = it }
    // И выключить операторов отдельной командой. setUserServers выключает их тоже, но
    // именно APISetServerOperators сразу пересобирает списки серверов агента: без неё
    // до перезапуска очереди могли уходить на прежние серверы (HearthServers.kt).
    hearthDisableOperators()

    // ICE (patches/0004). Хранятся строками через перевод строки — тот же формат,
    // который читает `getIceServers()` и разбирает `parseRTCIceServers`. Именно под
    // него hearthd собирает строки вида `turn:<user>:<cred>@host:port`.
    //
    // Пустой список пишем как пустую строку, а не оставляем настройку неустановленной:
    // разница в поведении нулевая (в обоих случаях ICE нет и звонок не состоится), но
    // явно записанное значение видно в настройках и не выглядит как «забыли настроить».
    ChatController.appPrefs.webrtcIceServers.set(servers.ice.joinToString(separator = "\n"))
  }

  /** `preset = false`: это НАШ сервер, а не предустановленный оператором upstream. */
  private fun userServer(address: String) = UserServer(
    remoteHostId = null,
    serverId = null,
    server = address,
    preset = false,
    tested = null,
    enabled = true,
    deleted = false,
  )

  override suspend fun applyNetworkDefaults(prefs: HearthNetPrefs) {
    // Приватный роутинг. В v7.0.1 `SMPProxyMode.default` УЖЕ `Always`, то есть
    // patches/0008 в этой части — пустышка. Выставляем всё равно: дефолт upstream
    // может измениться на следующем теге, а bundle требует именно `always`, и
    // HearthBundle.validate это проверяет на входе.
    val mode = when (prefs.privateRouting.lowercase()) {
      "always" -> SMPProxyMode.Always
      "unknown" -> SMPProxyMode.Unknown
      "unprotected" -> SMPProxyMode.Unprotected
      "never" -> SMPProxyMode.Never
      else -> throw IllegalArgumentException("неизвестный режим роутинга: ${prefs.privateRouting}")
    }
    if (mode != SMPProxyMode.Always) {
      // Ослаблять роутинг ниже Always в этом контуре нельзя (ТЗ §8.2 п.5): релей не
      // должен видеть, кто с кем. Bundle с таким значением — испорченный bundle.
      throw IllegalArgumentException("приватный роутинг обязан быть always, получено ${prefs.privateRouting}")
    }

    val cfg = ChatController.getNetCfg().copy(smpProxyMode = mode)
    if (!ChatController.apiSetNetworkConfig(cfg)) {
      throw IllegalStateException("не удалось применить сетевые настройки")
    }
    ChatController.setNetCfg(cfg)
  }

  override suspend fun rememberDevice(deviceId: String, issued: String) {
    // Идентификатор устройства нужен для отзыва (ТЗ §10.4): по нему администратор
    // понимает, какой bundle отзывать. Это не секрет — секреты в адресах серверов.
    ChatController.appPrefs.hearthDeviceId.set(deviceId)
    ChatController.appPrefs.hearthEnrolledAt.set(issued)
  }

  override suspend fun rememberNode(node: HearthNodeApi?) {
    // Пишем даже null: bundle, выданный узлом без device API, должен СТИРАТЬ старые
    // координаты, а не оставлять устройство стучаться туда, куда его больше не звали.
    ChatController.appPrefs.hearthUpdateHost.set(node?.host)
    ChatController.appPrefs.hearthUpdateToken.set(node?.token)
    ChatController.appPrefs.hearthUpdatePort.set(node?.port?.toString())
  }
}
