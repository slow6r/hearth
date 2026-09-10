package chat.hearth

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Контракт вшитого приглашения и первого запуска.
 *
 * Гоняется на JVM без эмулятора: сборка, раздаваемая семье, обязана либо завестись
 * сама, либо честно упасть в сканер, и узнавать об этом надо здесь, а не по звонку
 * «у меня ничего не работает».
 */
class HearthInviteTest {

  private val token = "a".repeat(64)

  private val valid = """
    {"host":"relay.example.org","port":7444,"token":"$token"}
  """.trimIndent()

  private val bundle = """
    {"v":1,
     "smp":["smp://fp1:pass1@relay.example.org:5223"],
     "xftp":["xftp://fp2:pass2@relay.example.org:5443"],
     "ice":["stun:relay.example.org:3478"],
     "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
     "issued":"2026-09-10T12:00:00Z",
     "device":"xiaomi-22101316g"}
  """.trimIndent()

  @Test
  fun parsesWhatTheBakeScriptWrites() {
    val invite = HearthBakedInvite.parse(valid).getOrThrow()
    assertEquals("relay.example.org", invite.host)
    assertEquals(7444, invite.port)
    assertEquals(token, invite.token)
  }

  @Test
  fun portDefaultsToTheDeviceApiPort() {
    val invite = HearthBakedInvite.parse("""{"host":"h.example","token":"$token"}""").getOrThrow()
    assertEquals(HearthBakedInvite.DEFAULT_PORT, invite.port)
  }

  @Test
  fun refusesAUrlInsteadOfAHost() {
    // Подставлять адрес из файла нельзя даже когда файл свой: однажды он окажется
    // не своим, и «host» вида https://чужое/ увёл бы заведение на чужой узел.
    assertTrue(
      HearthBakedInvite.parse("""{"host":"https://evil.example/","token":"$token"}""").isFailure
    )
  }

  @Test
  fun refusesAShortOrNonHexToken() {
    assertTrue(HearthBakedInvite.parse("""{"host":"h.example","token":"abc"}""").isFailure)
    assertTrue(
      HearthBakedInvite.parse("""{"host":"h.example","token":"${"Z".repeat(64)}"}""").isFailure
    )
  }

  @Test
  fun refusesAnImpossiblePort() {
    assertTrue(
      HearthBakedInvite.parse("""{"host":"h.example","port":0,"token":"$token"}""").isFailure
    )
  }

  @Test
  fun withoutAnInviteItIsAnOrdinaryQrBuild() = runBlocking {
    val enroller = enroller(
      transport = { _, _ -> error("транспорт не должен вызываться") },
      accept = { error("принимать нечего") },
    )
    assertEquals(HearthClaimResult.NoInvite, enroller.setUp(null, "Pixel"))
  }

  @Test
  fun aClaimedBundleIsAccepted() = runBlocking {
    // Применение отложено до появления профиля: на этом экране пользователя ещё нет,
    // и apiSetUserServers отказал бы. Здесь проверяется, что bundle принят и передан
    // дальше целиком.
    val accepted = mutableListOf<String>()
    val enroller = enroller(
      transport = { _, name ->
        assertEquals("Xiaomi 22101316G", name)
        Result.success(bundle)
      },
      accept = { payload ->
        accepted += payload
        val parsed = HearthBundle.parse(payload).getOrThrow()
        HearthImportResult.Applied(HearthPresets.serversFrom(parsed), parsed.device)
      },
    )
    val invite = HearthBakedInvite.parse(valid).getOrThrow()
    val result = enroller.setUp(invite, "Xiaomi 22101316G")
    assertEquals(HearthClaimResult.Applied("xiaomi-22101316g"), result)
    assertEquals(listOf(bundle), accepted)
  }

  @Test
  fun aDeadInviteFallsBackToTheScannerWithAReason() = runBlocking {
    val enroller = enroller(
      transport = { _, _ -> Result.failure(IllegalStateException("приглашение больше не действует")) },
      accept = { error("принимать нечего") },
    )
    val invite = HearthBakedInvite.parse(valid).getOrThrow()
    val result = enroller.setUp(invite, "Pixel")
    assertTrue(result is HearthClaimResult.Failed)
    assertEquals("приглашение больше не действует", (result as HearthClaimResult.Failed).reason)
  }

  @Test
  fun aBundleThatFailsValidationIsNotStashed() = runBlocking {
    var stashed = 0
    val enroller = enroller(
      // Узел доверенный, но ответ всё равно проверяется: подменённый или разъехавшийся
      // по версии формата документ не должен молча настроить телефон.
      transport = { _, _ -> Result.success("""{"v":99}""") },
      accept = { payload ->
        HearthBundle.parse(payload).fold(
          onSuccess = {
            stashed++
            HearthImportResult.Applied(HearthPresets.serversFrom(it), it.device)
          },
          onFailure = { HearthImportResult.Rejected(it.message ?: "плохой bundle") },
        )
      },
    )
    val invite = HearthBakedInvite.parse(valid).getOrThrow()
    assertTrue(enroller.setUp(invite, "Pixel") is HearthClaimResult.Failed)
    assertEquals(0, stashed)
  }
}

/** Транспорт из лямбды — чтобы каждый тест не заводил свой класс. */
private fun enroller(
  transport: suspend (HearthBakedInvite, String) -> Result<String>,
  accept: suspend (String) -> HearthImportResult,
) = HearthSelfEnroller(
  object : HearthClaimTransport {
    override suspend fun claim(invite: HearthBakedInvite, deviceName: String) =
      transport(invite, deviceName)
  },
  accept,
)
