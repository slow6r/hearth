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

  private class RecordingApplier : HearthBundleApplier {
    var serversCalls = 0
    var defaultsCalls = 0
    var deviceId: String? = null
    var node: HearthNodeApi? = null
    var nodeCalls = 0

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
  }
}
