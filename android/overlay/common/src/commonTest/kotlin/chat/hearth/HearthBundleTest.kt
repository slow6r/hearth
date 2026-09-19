package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The device-side half of the bundle contract.
 *
 * Runs on the JVM without an emulator, so an upstream rebase that changes a default
 * fails here rather than on a family member's phone.
 */
class HearthBundleTest {

  private val host = "relay.example.org"

  private val valid = """
    {"v":1,
     "smp":["smp://fp1:pass1@relay.example.org:5223"],
     "xftp":["xftp://fp2:pass2@relay.example.org:5443"],
     "ice":["stun:relay.example.org:3478",
            "turn:1757160000:aGVhcnRoK2NyZWQ=@relay.example.org:3478"],
     "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
     "issued":"2026-09-06T12:00:00Z",
     "device":"mama-pixel8"}
  """.trimIndent()

  @Test
  fun parsesTheDocumentHearthdProduces() {
    val bundle = HearthBundle.parse(valid).getOrThrow()
    assertEquals(1, bundle.v)
    assertEquals("mama-pixel8", bundle.device)
    assertEquals(host, bundle.host())
    assertEquals(2, bundle.ice.size)
    assertFalse(bundle.net.presetsEnabled)
  }

  @Test
  fun rejectsAPublicRelay() {
    val payload = valid.replace("smp://fp1:pass1@relay.example.org:5223", "smp://fp1:pass1@smp8.simplex.im:5223")
    assertTrue(HearthBundle.parse(payload).isFailure, "a foreign relay must never be accepted")
  }

  @Test
  fun rejectsAPublicStun() {
    val payload = valid.replace("stun:relay.example.org:3478", "stun:stun.simplex.im:443")
    assertTrue(HearthBundle.parse(payload).isFailure, "a public STUN would leak the caller's address")
  }

  @Test
  fun rejectsAMixedHostBundle() {
    val payload = valid.replace("xftp://fp2:pass2@relay.example.org:5443", "xftp://fp2:pass2@other.example.org:5443")
    assertTrue(HearthBundle.parse(payload).isFailure)
  }

  @Test
  fun rejectsTurnWithoutCredentials() {
    val payload = valid.replace("turn:1757160000:aGVhcnRoK2NyZWQ=@relay.example.org:3478", "turn:relay.example.org:3478")
    assertTrue(HearthBundle.parse(payload).isFailure)
  }

  @Test
  fun rejectsCredentialsTheClientWouldDiscard() {
    // A '/' in the credential starts a URI path; parseRTCIceServers then returns null
    // for the whole list and the client silently falls back to public servers.
    val payload = valid.replace("aGVhcnRoK2NyZWQ=", "aGVhcnRo/2NyZWQ=")
    assertTrue(HearthBundle.parse(payload).isFailure)
  }

  @Test
  fun rejectsEnabledOperatorPresets() {
    assertTrue(HearthBundle.parse(valid.replace("\"presetsEnabled\":false", "\"presetsEnabled\":true")).isFailure)
  }

  @Test
  fun rejectsNonInstantDelivery() {
    assertTrue(HearthBundle.parse(valid.replace("\"ntfMode\":\"instant\"", "\"ntfMode\":\"periodic\"")).isFailure)
  }

  @Test
  fun rejectsARelayAddressWithoutAPassword() {
    assertTrue(HearthBundle.parse(valid.replace("smp://fp1:pass1@", "smp://fp1@")).isFailure)
  }

  @Test
  fun rejectsAnUnsupportedVersion() {
    assertTrue(HearthBundle.parse(valid.replace("\"v\":1", "\"v\":2")).isFailure)
  }

  @Test
  fun rejectsGarbage() {
    assertTrue(HearthBundle.parse("not json").isFailure)
    assertTrue(HearthBundle.parse("").isFailure)
  }

  @Test
  fun acceptsABareIpHost() {
    val payload = valid.replace("relay.example.org", "203.0.113.10")
    val bundle = HearthBundle.parse(payload).getOrThrow()
    assertEquals("203.0.113.10", bundle.host())
  }

  @Test
  fun importerAppliesEverythingOnce() = kotlinx.coroutines.runBlocking {
    val applier = RecordingApplier()
    val result = HearthOnboardingImporter(applier).import(valid)
    assertTrue(result is HearthImportResult.Applied)
    assertEquals(1, applier.serversCalls)
    assertEquals(1, applier.defaultsCalls)
    assertEquals("mama-pixel8", applier.deviceId)
  }

  @Test
  fun importerReportsRejectionWithoutTouchingTheCore() = kotlinx.coroutines.runBlocking {
    val applier = RecordingApplier()
    val result = HearthOnboardingImporter(applier).import("{}")
    assertTrue(result is HearthImportResult.Rejected)
    assertEquals(0, applier.serversCalls, "a bad bundle must not reach the SimpleX core")
  }

  @Test
  fun bundleWithoutNodeSectionStillImportsAndClearsCoordinates() = kotlinx.coroutines.runBlocking {
    // Узел без device API — валидный случай (ADR 0010). Импорт обязан пройти, а
    // координаты обязаны быть перезаписаны в null: устройство не должно продолжать
    // стучаться туда, куда его больше не звали.
    val applier = RecordingApplier()
    val result = HearthOnboardingImporter(applier).import(valid)
    assertTrue(result is HearthImportResult.Applied)
    assertEquals(1, applier.nodeCalls, "rememberNode должен вызываться всегда, даже с null")
    assertEquals(null, applier.node)
  }

  @Test
  fun theOwnHostIsDeclaredAtImportAndNotGuessedLater() = kotlinx.coroutines.runBlocking {
    // UPD-9. Раньше «свой хост» при пустом адресе device API выводился из базы — из
    // первого не операторского SMP-сервера. База приезжает с архивом восстановления,
    // в том числе чужим, и тогда чужой узел объявлял себя своим. Теперь хост объявляет
    // применение bundle — того самого, который человек получил лично.
    val applier = RecordingApplier()
    assertTrue(HearthOnboardingImporter(applier).import(valid) is HearthImportResult.Applied)
    assertEquals(1, applier.bundleHostCalls, "хост обязан объявляться при каждом применении")
    assertEquals(host, applier.bundleHost)
  }

  @Test
  fun aBundleThatDeclaresNoHostDeclaresNothing() = kotlinx.coroutines.runBlocking {
    // Хост берётся из первого SMP-адреса. Bundle без разбираемого адреса до применения
    // не доходит (validate его отвергает) — и это правильный порядок: пустой хост лучше
    // угаданного, но ещё лучше не пускать такой bundle дальше разбора вовсе.
    val applier = RecordingApplier()
    val payload = valid.replace("smp://fp1:pass1@relay.example.org:5223", "не-адрес")
    assertTrue(HearthOnboardingImporter(applier).import(payload) is HearthImportResult.Rejected)
    assertEquals(0, applier.bundleHostCalls)
  }

  // --- срок годности QR (UPD-6) ------------------------------------------------------

  // 2026-09-08, то есть через двое суток после issued в фикстуре.
  private val soonAfterIssue = hearthEpochSecondsOf("2026-09-08T12:00:00Z")!!

  @Test
  fun aFreshQrIsAccepted() {
    assertTrue(HearthBundle.parse(valid, soonAfterIssue).isSuccess)
  }

  @Test
  fun aQrOlderThanTheLimitIsRefused() {
    // Сфотографированный год назад QR оставался рабочим, хотя в нём пароли релеев.
    val old = soonAfterIssue + (HearthBundle.MAX_AGE_DAYS + 1) * HEARTH_SECONDS_PER_DAY
    val result = HearthBundle.parse(valid, old)
    assertTrue(result.isFailure)
    // Текст обязан быть действием, а не диагнозом: человек стоит перед кодом.
    assertEquals(
      HearthBundle.staleMessage("2026-09-06T12:00:00Z"),
      result.exceptionOrNull()?.message,
      "отказ по возрасту обязан идти человеку тем самым текстом",
    )
  }

  @Test
  fun theStaleQrRefusalReadsLikeAnExplanationAndNotLikeACrash() {
    // Строгости к возрасту QR в HEAD не было, и первое, что она дала, — человек на
    // первом экране нового телефона видел строку, похожую на внутреннюю ошибку, и
    // решал, что приложение сломано. Проверяем не «есть слово», а всё, без чего текст
    // не работает: что случилось, что приложение цело, что делать и куда смотреть,
    // если дата на телефоне врёт.
    val message = HearthBundle.staleMessage("2026-09-06T12:00:00Z")
    assertTrue(message.contains("2026-09-06"), message)
    assertTrue(message.contains("устарел"), message)
    assertTrue(message.contains("в порядке"), message)
    assertTrue(message.contains("новый"), message)
    assertTrue(message.contains("дата на телефоне"), message)
    // И ни следа разбора: ни времени с часовым поясом, ни слова «bundle».
    assertFalse(message.contains("T12:00:00Z"), message)
    assertFalse(message.lowercase().contains("bundle"), message)
  }

  @Test
  fun aQrRightOnTheLimitIsStillAccepted() {
    val edge = soonAfterIssue + HearthBundle.MAX_AGE_DAYS * HEARTH_SECONDS_PER_DAY - 2 * HEARTH_SECONDS_PER_DAY
    assertTrue(HearthBundle.parse(valid, edge).isSuccess)
  }

  @Test
  fun aQrFromTheFutureIsRefusedButBlamesTheClock() {
    // Доверенных часов нет: свежий телефон вполне может стоять с неверной датой, и
    // человек должен знать, куда смотреть, а не пересканировать годный QR по кругу.
    val behind = soonAfterIssue - 10 * HEARTH_SECONDS_PER_DAY
    val result = HearthBundle.parse(valid, behind)
    assertTrue(result.isFailure)
    val message = result.exceptionOrNull()?.message.orEmpty()
    assertTrue(message.contains("сбита дата"), message)
    assertTrue(message.contains("часовой пояс"), message)
  }

  @Test
  fun aQrWithAnUnreadableIssueDateIsRefused() {
    val payload = valid.replace("2026-09-06T12:00:00Z", "давно")
    assertTrue(HearthBundle.parse(payload, soonAfterIssue).isFailure)
    // Без часов возраст не судим — тогда и непонятная дата не повод отказывать.
    assertTrue(HearthBundle.parse(payload).isSuccess)
  }

  @Test
  fun withoutAClockTheAgeIsNotJudged() {
    // Применение УЖЕ принятого bundle возрастом не судит: телефон мог пролежать в
    // ящике, а заведён он честно. Проверяет возраст тот, кто принимает QR от человека.
    val old = soonAfterIssue + 365 * HEARTH_SECONDS_PER_DAY
    assertTrue(HearthBundle.parse(valid).isSuccess)
    assertTrue(HearthBundle.parse(valid, old).isFailure)
  }

  private class RecordingApplier : HearthBundleApplier {
    var serversCalls = 0
    var defaultsCalls = 0
    var deviceId: String? = null
    var node: HearthNodeApi? = null
    var nodeCalls = 0
    var bundleHost: String? = null
    var bundleHostCalls = 0

    override suspend fun setServers(servers: HearthServers) {
      serversCalls++
    }

    override suspend fun applyNetworkDefaults(prefs: HearthNetPrefs) {
      defaultsCalls++
    }

    override suspend fun rememberDevice(deviceId: String, issued: String) {
      this.deviceId = deviceId
    }

    override suspend fun rememberNode(node: HearthNodeApi?) {
      this.node = node
      nodeCalls++
    }

    override suspend fun rememberBundleHost(host: String?) {
      this.bundleHost = host
      bundleHostCalls++
    }
  }
}
