package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Значок с числом непрочитанных: что уходит наружу и кому.
 *
 * Сама рассылка живёт в androidMain (нужен Context) и здесь не проверяется — её проверяют
 * на живом Huawei (см. отчёт). Здесь закреплено то, что можно закрепить без Android:
 * у рассылки всегда есть явный адресат, и наружу уходит только число 0..99.
 */
class HearthBadgeTest {

  @Test
  fun every_broadcast_target_is_an_explicit_package() {
    assertTrue(HearthBadgeTargets.LAUNCHERS.isNotEmpty())
    assertEquals(HearthBadgeTargets.LAUNCHERS.distinct(), HearthBadgeTargets.LAUNCHERS)
    for (pkg in HearthBadgeTargets.LAUNCHERS) {
      assertTrue(HearthBadgeTargets.isAddressable(pkg), "не адрес: $pkg")
    }
  }

  @Test
  fun an_empty_or_broken_address_is_not_an_address() {
    // Пустая строка страшнее всего: setPackage("") выглядит как адресация, но ею не является.
    assertFalse(HearthBadgeTargets.isAddressable(""))
    assertFalse(HearthBadgeTargets.isAddressable("launcher"))
    assertFalse(HearthBadgeTargets.isAddressable(".com.huawei"))
    assertFalse(HearthBadgeTargets.isAddressable("com.huawei."))
    assertFalse(HearthBadgeTargets.isAddressable("com..huawei"))
    assertFalse(HearthBadgeTargets.isAddressable("com.Huawei.launcher"))
    assertFalse(HearthBadgeTargets.isAddressable("com.huawei.launcher/Receiver"))
    assertFalse(HearthBadgeTargets.isAddressable("a." + "x".repeat(255)))
  }

  @Test
  fun the_list_that_actually_goes_out_is_the_filtered_one() {
    // Раньше isAddressable была написана и покрыта тестом, но на пути рассылки не стояла:
    // HearthBadge перебирал LAUNCHERS напрямую. Проверка, которую никто не зовёт, — это
    // не защита, а украшение. Теперь между списком и sendBroadcast стоит broadcastTargets.
    assertEquals(HearthBadgeTargets.LAUNCHERS, HearthBadgeTargets.broadcastTargets())
    for (pkg in HearthBadgeTargets.broadcastTargets()) {
      assertTrue(HearthBadgeTargets.isAddressable(pkg), "в рассылку ушёл не адрес: $pkg")
    }
  }

  @Test
  fun the_number_that_leaves_the_app_is_clamped() {
    assertEquals(0, HearthBadgeTargets.badgeNumber(0))
    assertEquals(0, HearthBadgeTargets.badgeNumber(-3))
    assertEquals(7, HearthBadgeTargets.badgeNumber(7))
    assertEquals(99, HearthBadgeTargets.badgeNumber(99))
    assertEquals(99, HearthBadgeTargets.badgeNumber(1000))
  }
}
