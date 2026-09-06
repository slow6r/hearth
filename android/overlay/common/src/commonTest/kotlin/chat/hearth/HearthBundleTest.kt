package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The device-side half of the bundle contract (ТЗ Приложение B).
 *
 * These run on the JVM without an emulator, and they exist so that an upstream rebase
 * that changes serialization defaults fails here rather than on a family member's phone.
 */
class HearthBundleTest {

  private val valid = """
    {"v":1,
     "smp":["smp://fp1:pass1@10.66.10.10:5223"],
     "xftp":["xftp://fp2:pass2@10.66.10.10:5443"],
     "ice":[{"urls":["stun:10.66.10.10:3478"]},
            {"urls":["turn:10.66.10.10:3478"],"username":"1757160000:hearth","credential":"aGk="}],
     "net":{"privateRouting":"always","presetsEnabled":false,"ntfMode":"instant"},
     "issued":"2026-09-06T12:00:00Z",
     "device":"mama-pixel8"}
  """.trimIndent()

  @Test
  fun parsesTheDocumentHearthdProduces() {
    val bundle = HearthBundle.parse(valid).getOrThrow()
    assertEquals(1, bundle.v)
    assertEquals("mama-pixel8", bundle.device)
    assertEquals(listOf("10.66.10.10"), bundle.hosts())
    assertEquals(2, bundle.ice.size)
    assertFalse(bundle.net.presetsEnabled)
  }

  @Test
  fun rejectsAPublicRelay() {
    val payload = valid.replace("smp://fp1:pass1@10.66.10.10:5223", "smp://fp1:pass1@smp8.simplex.im:5223")
    assertTrue(HearthBundle.parse(payload).isFailure, "a public relay must never be accepted")
  }

  @Test
  fun rejectsAPublicStun() {
    val payload = valid.replace("stun:10.66.10.10:3478", "stun:stun.l.google.com:19302")
    assertTrue(HearthBundle.parse(payload).isFailure, "a public STUN would leak the address")
  }

  @Test
  fun rejectsEnabledOperatorPresets() {
    val payload = valid.replace("\"presetsEnabled\":false", "\"presetsEnabled\":true")
    assertTrue(HearthBundle.parse(payload).isFailure)
  }

  @Test
  fun rejectsNonInstantDelivery() {
    val payload = valid.replace("\"ntfMode\":\"instant\"", "\"ntfMode\":\"periodic\"")
    assertTrue(HearthBundle.parse(payload).isFailure)
  }

  @Test
  fun rejectsARelayAddressWithoutAPassword() {
    val payload = valid.replace("smp://fp1:pass1@", "smp://fp1@")
    assertTrue(HearthBundle.parse(payload).isFailure)
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
  fun ipLiteralDetection() {
    assertTrue(isIpLiteral("10.66.10.10"))
    assertFalse(isIpLiteral("smp8.simplex.im"))
    assertFalse(isIpLiteral("10.66.10"))
    assertFalse(isIpLiteral("999.1.1.1"))
  }

  @Test
  fun importerAppliesEverythingOnce() = kotlinx.coroutines.test.runTest {
    val applier = RecordingApplier()
    val result = HearthOnboardingImporter(applier).import(valid)
    assertTrue(result is HearthImportResult.Applied)
    assertEquals(1, applier.serversCalls)
    assertEquals(1, applier.defaultsCalls)
    assertEquals("mama-pixel8", applier.deviceId)
  }

  @Test
  fun importerReportsRejectionWithoutTouchingTheCore() = kotlinx.coroutines.test.runTest {
    val applier = RecordingApplier()
    val result = HearthOnboardingImporter(applier).import("{}")
    assertTrue(result is HearthImportResult.Rejected)
    assertEquals(0, applier.serversCalls, "a bad bundle must not reach the SimpleX core")
  }

  private class RecordingApplier : HearthBundleApplier {
    var serversCalls = 0
    var defaultsCalls = 0
    var deviceId: String? = null

    override suspend fun setServers(servers: HearthServers) {
      serversCalls++
    }

    override suspend fun applyNetworkDefaults(prefs: HearthNetPrefs) {
      defaultsCalls++
    }

    override suspend fun rememberDevice(deviceId: String, issued: String) {
      this.deviceId = deviceId
    }
  }
}
