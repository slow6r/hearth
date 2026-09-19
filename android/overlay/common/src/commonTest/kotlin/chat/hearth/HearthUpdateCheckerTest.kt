package chat.hearth

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Оркестрация проверки обновления — на фальшивом транспорте.
 *
 * Здесь проверяется не арифметика доверия (она в HearthUpdateTrustTest), а то, что
 * проверяющий вообще СОБИРАЕТ факты, прежде чем решать: раньше при сборке без ключа
 * подпись не запрашивалась совсем, и вердикт выносился до того, как появлялись
 * основания. Плюс то, что телефон запоминает: день появления новой отметки и день
 * удавшейся проверки. Без первого не поймать заморозку, без второго — молчание узла.
 */
class HearthUpdateCheckerTest {

  private val today = hearthEpochDaysOf("2026-09-12T00:00:00Z")!!

  private val manifest = """
    {"v":1,"versionName":"7.0.1-h22","versionCode":22,
     "sha256":"$SHA","file":"hearth.apk","issued":"2026-09-12T08:00:00Z"}
  """.trimIndent()

  private class Fake(
    val body: String,
    val signature: String? = "c2ln",
    /** Узел вообще не ответил: нет сети, узел выключен, порт закрыт. */
    val unreachable: Boolean = false,
  ) : HearthUpdateTransport {
    var manifestAsked = 0
    var signatureAsked = 0

    override suspend fun fetchManifest(): Result<String> {
      manifestAsked++
      if (unreachable) return Result.failure(IllegalStateException("узел недоступен"))
      return Result.success(body)
    }

    override suspend fun fetchManifestSignature(): Result<String?> {
      signatureAsked++
      return Result.success(signature)
    }

    override suspend fun download(
      file: String,
      expectedSha256: String,
      onProgress: (Long, Long) -> Unit,
    ): HearthDownloadResult = HearthDownloadResult.Failed("не нужно в этом тесте")

    override suspend fun enroll(name: String): Result<String> =
      Result.failure(IllegalStateException("не нужно в этом тесте"))
  }

  @Test
  fun a_build_without_a_key_refuses_but_still_asks_for_the_signature() = runBlocking {
    val transport = Fake(manifest)
    val checker = HearthUpdateChecker(
      transport = transport,
      installedVersionCode = 1,
      pinnedKey = null,
      nowEpochDays = today,
    )

    val result = checker.check()

    assertTrue(result is HearthUpdateCheck.Failed, "ожидался отказ, получено: $result")
    assertTrue((result as HearthUpdateCheck.Failed).reason.contains("нет ключа"), result.reason)
    // Отказ обязан дойти до человека, а не остаться в логе: сам он не пройдёт никогда.
    assertTrue(result.actionable, "отказ политики помечен как сетевая осечка")
    // Подпись обязана запрашиваться ВСЕГДА: иначе «сборка по QR» неотличима от
    // сборки, из которой ресурс с ключом вырезали.
    assertEquals(1, transport.signatureAsked)
  }

  @Test
  fun an_unreachable_node_is_not_something_to_bother_the_person_with() = runBlocking {
    // Разница, ради которой появился признак: до узла не дошли — обычное дело (метро,
    // роутер, выключенный узел), и одна такая неудача не новость. Новостью становится
    // МОЛЧАНИЕ, и его считает отдельное правило — по попыткам, а не по календарю.
    val result = HearthUpdateChecker(
      transport = Fake(manifest, unreachable = true),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today,
    ).check()

    assertTrue(result is HearthUpdateCheck.Failed, "получено: $result")
    assertFalse((result as HearthUpdateCheck.Failed).actionable, result.reason)
  }

  @Test
  fun a_manifest_past_its_expiry_is_a_refusal_the_person_must_see() = runBlocking {
    // Узел на связи и отдаёт подписанный документ — просто срок вышел. Человеку надо
    // сходить к владельцу узла, и сказать об этом обязаны экран и шторка, а не лог.
    val stale = """
      {"v":1,"versionName":"7.0.1-h22","versionCode":22,
       "sha256":"$SHA","file":"hearth.apk","issued":"2026-06-01T08:00:00Z",
       "expires":"2026-07-01T00:00:00Z"}
    """.trimIndent()
    val result = HearthUpdateChecker(
      transport = Fake(stale),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today,
    ).check()

    assertTrue(result is HearthUpdateCheck.Failed, "получено: $result")
    assertTrue((result as HearthUpdateCheck.Failed).actionable, result.reason)
    assertTrue(result.reason.contains("срок годности"), result.reason)
  }

  @Test
  fun a_signed_new_version_is_offered_and_remembered() = runBlocking {
    var issued: String? = null
    var firstSeen: Long? = null
    var checked: Long? = null
    val checker = HearthUpdateChecker(
      transport = Fake(manifest),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      lastSeenIssued = null,
      rememberIssued = { issued = it },
      nowEpochDays = today,
      rememberFirstSeenDay = { firstSeen = it },
      rememberCheckedDay = { checked = it },
    )

    val result = checker.check()

    assertTrue(result is HearthUpdateCheck.Available, "получено: $result")
    assertEquals("2026-09-12T08:00:00Z", issued)
    assertEquals(today, firstSeen)
    assertEquals(today, checked)
  }

  @Test
  fun an_unchanged_timestamp_does_not_move_the_first_seen_day() = runBlocking {
    // Иначе каждая проверка отодвигала бы срок, и правило «узел две недели отдаёт одно
    // и то же» не сработало бы никогда — заморозку нечем было бы поймать.
    var firstSeen: Long? = null
    var issued: String? = null
    val checker = HearthUpdateChecker(
      transport = Fake(manifest),
      installedVersionCode = 99,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      lastSeenIssued = "2026-09-12T08:00:00Z",
      rememberIssued = { issued = it },
      nowEpochDays = today,
      firstSeenEpochDays = today - 3,
      rememberFirstSeenDay = { firstSeen = it },
    )

    val result = checker.check()

    assertEquals(HearthUpdateCheck.UpToDate(), result)
    assertNull(firstSeen, "день первого появления перезаписан на неизменной отметке")
    assertNull(issued, "отметка переписана на саму себя")
  }

  @Test
  fun a_successful_check_marks_the_day_even_when_there_is_nothing_new() = runBlocking {
    // «Новостей нет» — это ответ. Молчание — нет, и отличать их надо именно здесь.
    var checked: Long? = null
    val checker = HearthUpdateChecker(
      transport = Fake(manifest),
      installedVersionCode = 99,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      lastSeenIssued = "2026-09-12T08:00:00Z",
      nowEpochDays = today,
      firstSeenEpochDays = today,
      rememberCheckedDay = { checked = it },
    )

    assertEquals(HearthUpdateCheck.UpToDate(), checker.check())
    assertEquals(today, checked)
  }

  @Test
  fun a_refused_check_marks_nothing() = runBlocking {
    // Отказ — это не «узел ответил»: записать день значило бы спрятать молчание.
    var checked: Long? = null
    var firstSeen: Long? = null
    val checker = HearthUpdateChecker(
      transport = Fake(manifest, signature = null),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today,
      rememberFirstSeenDay = { firstSeen = it },
      rememberCheckedDay = { checked = it },
    )

    assertTrue(checker.check() is HearthUpdateCheck.Failed)
    assertNull(checked)
    assertNull(firstSeen)
  }

  @Test
  fun a_frozen_node_stops_being_believed() = runBlocking {
    // Подпись верна, откат отсутствует, версия та же — и всё равно отказ: телефон
    // прожил с этим манифестом всё окно.
    val checker = HearthUpdateChecker(
      transport = Fake(manifest),
      installedVersionCode = 99,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      lastSeenIssued = "2026-09-12T08:00:00Z",
      nowEpochDays = today + HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS,
      firstSeenEpochDays = today,
    )

    val result = checker.check()

    assertTrue(result is HearthUpdateCheck.Failed, "получено: $result")
    assertFalse((result as HearthUpdateCheck.Failed).reason.isBlank())
  }

  @Test
  fun a_manifest_that_carries_its_own_expiry_is_believed_past_the_age_fallback() = runBlocking {
    // Серверная половина UPD-2: оператор подписывает манифест вместе со сроком. Клиент
    // верит сроку, а не запасу по возрасту, — иначе манифест месячной давности отрезал
    // бы семью от обновлений, хотя оператор явно сказал, до какого числа он годен.
    val dated = """
      {"v":1,"versionName":"7.0.1-h22","versionCode":22,
       "sha256":"$SHA","file":"hearth.apk","issued":"2026-07-01T08:00:00Z",
       "expires":"2026-12-01T00:00:00Z"}
    """.trimIndent()
    val checker = HearthUpdateChecker(
      transport = Fake(dated),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today,
    )

    val result = checker.check()

    assertTrue(result is HearthUpdateCheck.Available, "получено: $result")
    assertNull((result as HearthUpdateCheck.Available).notice, "срок назначен — говорить не о чем")
  }

  @Test
  fun a_manifest_past_its_own_expiry_is_refused() = runBlocking {
    val stale = """
      {"v":1,"versionName":"7.0.1-h22","versionCode":22,
       "sha256":"$SHA","file":"hearth.apk","issued":"2026-09-10T08:00:00Z",
       "expires":"2026-09-11T00:00:00Z"}
    """.trimIndent()
    var checked: Long? = null
    val checker = HearthUpdateChecker(
      transport = Fake(stale),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today,
      rememberCheckedDay = { checked = it },
    )

    val result = checker.check()

    assertTrue(result is HearthUpdateCheck.Failed, "получено: $result")
    // Человеку сказано, что делать, а не только что случилось.
    assertTrue((result as HearthUpdateCheck.Failed).reason.contains("владельцем узла"), result.reason)
    assertNull(checked, "отказ — это не «узел ответил»")
  }

  @Test
  fun a_manifest_without_an_expiry_still_gets_the_old_age_fallback() = runBlocking {
    // Вторая ветка: манифесты прежних версий поля не несут. Запас по возрасту остаётся,
    // но теперь он в полгода, а на второй неделе молчания клиент говорит, а не отказывает:
    // узел переподписать манифест не может, и отказ на тридцатый день был бы наказанием
    // семье за то, что релизов давно не выпускали.
    val quiet = """
      {"v":1,"versionName":"7.0.1-h22","versionCode":22,
       "sha256":"$SHA","file":"hearth.apk","issued":"2026-09-02T08:00:00Z"}
    """.trimIndent()
    val offered = HearthUpdateChecker(
      transport = Fake(quiet),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today,
    ).check()
    assertTrue(offered is HearthUpdateCheck.Available, "получено: $offered")
    assertTrue(
      (offered as HearthUpdateCheck.Available).notice.orEmpty().contains("молчит"),
      "получено: ${offered.notice}",
    )

    // А вот через полгода — отказ, и он тоже объясняет, что делать.
    val old = HearthUpdateChecker(
      transport = Fake(quiet),
      installedVersionCode = 1,
      pinnedKey = "key",
      verify = { _, _, _ -> true },
      nowEpochDays = today + HearthUpdateTrust.MAX_MANIFEST_AGE_DAYS + 1,
    ).check()
    assertTrue(old is HearthUpdateCheck.Failed, "получено: $old")
    assertTrue((old as HearthUpdateCheck.Failed).reason.contains("владельца узла"), old.reason)
  }

  private companion object {
    const val SHA = "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
