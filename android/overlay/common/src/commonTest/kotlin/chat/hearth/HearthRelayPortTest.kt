package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Переписывание адреса своего релея на порт 8443.
 *
 * Ошибка здесь не падает, а тихо оставляет телефон на порту, который режут, — снова
 * «ссылка крутится и не создаётся». Поэтому проверяется каждый случай, включая те,
 * которые трогать нельзя.
 */
class HearthRelayPortTest {

  private val host = "relay.myhearth.ru"
  private val fp = "dl4E-N71pfkpNzTLXnI5sHuAeT-zDx21sCkqMCQNk9M="

  @Test
  fun anExplicit5223MovesTo8443() {
    assertEquals(
      "smp://$fp:pass_123-x@$host:8443",
      hearthRelayAddressOnWebPort("smp://$fp:pass_123-x@$host:5223", host),
    )
  }

  @Test
  fun aMissingPortMeans5223AndAlsoMoves() {
    assertEquals("smp://$fp:p@$host:8443", hearthRelayAddressOnWebPort("smp://$fp:p@$host", host))
  }

  @Test
  fun alreadyOn8443IsLeftAlone() {
    assertNull(hearthRelayAddressOnWebPort("smp://$fp:p@$host:8443", host))
  }

  @Test
  fun theInspected443AlsoMoves() {
    // 443 выдавался один день, пока не выяснилось, что провайдер его досматривает.
    assertEquals("smp://$fp:p@$host:8443", hearthRelayAddressOnWebPort("smp://$fp:p@$host:443", host))
  }

  @Test
  fun someoneElsesServerIsLeftAlone() {
    assertNull(hearthRelayAddressOnWebPort("smp://$fp:p@smp8.simplex.im:5223", host))
  }

  @Test
  fun xftpIsLeftAlone() {
    // У XFTP свой порт, 443 на этом адресе уже занят SMP.
    assertNull(hearthRelayAddressOnWebPort("xftp://$fp:p@$host:5443", host))
  }

  @Test
  fun aDeliberateCustomPortIsLeftAlone() {
    assertNull(hearthRelayAddressOnWebPort("smp://$fp:p@$host:7000", host))
  }

  @Test
  fun hostComparisonIgnoresCaseAndSpaces() {
    assertEquals("smp://$fp:p@RELAY.myhearth.ru:8443", hearthRelayAddressOnWebPort("  smp://$fp:p@RELAY.myhearth.ru:5223  ", host))
  }

  @Test
  fun aListOfHostsWithOursMoves() {
    assertEquals(
      "smp://$fp:p@$host,backup.myhearth.ru:8443",
      hearthRelayAddressOnWebPort("smp://$fp:p@$host,backup.myhearth.ru:5223", host),
    )
  }

  @Test
  fun garbageIsLeftAlone() {
    assertNull(hearthRelayAddressOnWebPort("не адрес", host))
    assertNull(hearthRelayAddressOnWebPort("", host))
  }
}
