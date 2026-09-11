package chat.hearth

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Контракт вшитого адреса узла и первого запуска по коду доступа (ADR 0012).
 *
 * Гоняется на JVM без эмулятора: сборка, которую раздают людям, обязана либо завести
 * себя по коду, либо честно объяснить отказ, и узнавать об этом надо здесь, а не по
 * звонку «у меня ничего не работает».
 */
class HearthInviteTest {

  private val valid = """
    {"host":"relay.example.org","port":7444}
  """.trimIndent()

  private val bundle = """
    {"v":1,
     "smp":["smp://fp1:pass1@relay.example.org:8443"],
     "xftp":["xftp://fp2:pass2@relay.example.org:5443"],
     "ice":["stun:relay.example.org:3478"],
     "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
     "issued":"2026-09-10T12:00:00Z",
     "device":"xiaomi-22101316g"}
  """.trimIndent()

  private val code = "H7K4P9QXM3TV"

  @Test
  fun parsesWhatTheBakeScriptWrites() {
    val node = HearthBakedNode.parse(valid).getOrThrow()
    assertEquals("relay.example.org", node.host)
    assertEquals(7444, node.port)
  }

  @Test
  fun portDefaultsToDeviceApi() {
    val node = HearthBakedNode.parse("""{"host":"h.example"}""").getOrThrow()
    assertEquals(HearthBakedNode.DEFAULT_PORT, node.port)
  }

  @Test
  fun refusesAUrlInsteadOfAHost() {
    // Подставлять из файла произвольный адрес нельзя даже когда файл свой.
    assertTrue(HearthBakedNode.parse("""{"host":"https://evil.example/"}""").isFailure)
  }

  @Test
  fun refusesAnImpossiblePort() {
    assertTrue(HearthBakedNode.parse("""{"host":"h.example","port":0}""").isFailure)
    assertTrue(HearthBakedNode.parse("""{"host":"h.example","port":70000}""").isFailure)
  }

  @Test
  fun aBuildWithoutANodeAsksForQr() = runBlocking {
    val enroller = enroller(transport = { _, _, _ -> error("сети быть не должно") })
    assertEquals(HearthClaimResult.NoNode, enroller.enrol(null, code, "Pixel"))
  }

  @Test
  fun anIncompleteCodeNeverReachesTheNode() = runBlocking {
    var called = false
    val enroller = enroller(transport = { _, _, _ -> called = true; Result.success(bundle) })
    val node = HearthBakedNode.parse(valid).getOrThrow()

    val result = enroller.enrol(node, "H7K4-P9QX", "Pixel")

    assertEquals(HearthClaimResult.Failed(HearthOnboardingText.CODE_INCOMPLETE), result)
    assertTrue(!called, "неполный код не должен тратить попытку у узла")
  }

  @Test
  fun theCodeIsNormalizedBeforeItIsSent() = runBlocking {
    var sent: String? = null
    val enroller = enroller(transport = { _, sentCode, _ -> sent = sentCode; Result.success(bundle) })
    val node = HearthBakedNode.parse(valid).getOrThrow()

    enroller.enrol(node, " h7k4-p9qx-m3tv ", "Pixel")

    // Узел хранит канонический вид, и сравнение у него посимвольное: то, что человек
    // набрал с дефисами и в нижнем регистре, обязано доехать приведённым.
    assertEquals(code, sent)
  }

  @Test
  fun aSpentCodeIsReportedInWordsAPersonCanAct_on() = runBlocking {
    val enroller = enroller(
      transport = { _, _, _ -> Result.failure(IllegalStateException(HearthOnboardingText.CODE_REFUSED)) }
    )
    val node = HearthBakedNode.parse(valid).getOrThrow()

    val result = enroller.enrol(node, code, "Pixel")

    assertEquals(HearthClaimResult.Failed(HearthOnboardingText.CODE_REFUSED), result)
  }

  @Test
  fun aNodeThatDoesNotAnswerIsNotADeadEnd() = runBlocking {
    val enroller = enroller(transport = { _, _, _ -> Result.failure(IllegalStateException()) })
    val node = HearthBakedNode.parse(valid).getOrThrow()

    val result = enroller.enrol(node, code, "Pixel")

    assertTrue(result is HearthClaimResult.Failed)
    assertNull((result as? HearthClaimResult.Applied)?.device)
  }

  @Test
  fun aGoodCodeEnrolsTheDevice() = runBlocking {
    val enroller = enroller(transport = { _, _, _ -> Result.success(bundle) })
    val node = HearthBakedNode.parse(valid).getOrThrow()

    val result = enroller.enrol(node, code, "Pixel")

    assertEquals(HearthClaimResult.Applied("xiaomi-22101316g"), result)
  }

  @Test
  fun aBundleTheClientRefusesIsNotSilentlyAccepted() = runBlocking {
    val enroller = enroller(
      transport = { _, _, _ -> Result.success("""{"v":1}""") },
      accept = { HearthImportResult.Rejected("bundle is not valid") },
    )
    val node = HearthBakedNode.parse(valid).getOrThrow()

    val result = enroller.enrol(node, code, "Pixel")

    assertEquals(HearthClaimResult.Failed("bundle is not valid"), result)
  }

  private fun enroller(
    transport: suspend (HearthBakedNode, String, String) -> Result<String>,
    accept: suspend (String) -> HearthImportResult = { payload ->
      HearthBundle.parse(payload).fold(
        onSuccess = { HearthImportResult.Applied(HearthPresets.serversFrom(it), it.device) },
        onFailure = { HearthImportResult.Rejected(it.message ?: "bundle is not valid") },
      )
    },
  ) = HearthCodeEnroller(
    object : HearthClaimTransport {
      override suspend fun claim(node: HearthBakedNode, code: String, deviceName: String) =
        transport(node, code, deviceName)
    },
    accept,
  )
}
