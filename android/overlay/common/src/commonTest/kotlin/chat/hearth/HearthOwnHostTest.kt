package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * «Своя ли это ссылка» — таблица случаев.
 *
 * Раньше ответ давала подстрока, и ошибалась она в опасную сторону: чужой домен,
 * содержащий имя нашего узла, считался своим, и приведение к своим серверам молча
 * ничего не делало. Ровно этот класс промаха уже приводил к живым ссылкам на
 * smp8.simplex.im.
 *
 * Обратная ошибка тоже опасна, но иначе: посчитать СВОЮ ссылку чужой значит удалить
 * работающее приглашение. Поэтому полная ссылка ядра, у которой хоста в адресе нет
 * вовсе, разбирается по-настоящему — через параметр `smp`.
 */
class HearthOwnHostTest {

  private val host = "relay.myhearth.ru"

  @Test
  fun a_plain_address_gives_its_host() {
    assertEquals(host, hearthHostOf("smp://fp:pass@$host:5223"))
    assertEquals(host, hearthHostOf("https://$host/i#data"))
    assertEquals(host, hearthHostOf("https://$host:5223/a#data?c=x&p=5223"))
  }

  @Test
  fun a_host_in_the_path_or_query_is_not_the_host() {
    // Именно здесь ломалась подстрока.
    assertEquals("evil.net", hearthHostOf("https://evil.net/$host#data"))
    assertEquals("evil.net", hearthHostOf("https://evil.net/x?u=$host"))
  }

  @Test
  fun an_address_without_a_scheme_has_no_host() {
    assertNull(hearthHostOf("relay.myhearth.ru:5223"))
    assertNull(hearthHostOf(""))
  }

  @Test
  fun ipv6_keeps_its_brackets_and_loses_its_port() {
    assertEquals("[::1]", hearthHostOf("smp://fp:pass@[::1]:5223"))
  }

  @Test
  fun an_exact_short_link_is_ours() {
    assertTrue(hearthLinksAreOn(listOf("https://$host/i#abc"), host))
  }

  @Test
  fun a_port_of_its_own_does_not_make_a_link_foreign() {
    // Перевод релея на 443 — наша же миграция, и ссылки после неё остаются своими.
    assertTrue(hearthLinksAreOn(listOf("https://$host:443/a#abc"), host))
  }

  @Test
  fun our_host_as_a_prefix_of_a_foreign_domain_is_foreign() {
    assertFalse(hearthLinksAreOn(listOf("https://$host.evil.net/i#abc"), host))
    assertFalse(hearthLinksAreOn(listOf("smp://fp:pass@$host.evil.net:5223"), host))
  }

  @Test
  fun our_host_inside_the_path_is_foreign() {
    assertFalse(hearthLinksAreOn(listOf("https://evil.net/$host#abc"), host))
    assertFalse(hearthLinksAreOn(listOf("https://evil.net/i#abc?u=$host"), host))
  }

  @Test
  fun a_link_nobody_can_parse_is_foreign() {
    // Неизвестный формат — это отсутствие доказательства, что ссылка наша. Считать её
    // своей означало бы: выдай ссылку в непривычном виде — и приведение пропустит её.
    assertFalse(hearthLinksAreOn(listOf("не ссылка вовсе"), host))
    assertFalse(hearthLinksAreOn(emptyList(), host))
    assertFalse(hearthLinksAreOn(listOf(""), host))
  }

  @Test
  fun a_full_core_link_is_read_through_its_smp_parameter() {
    // У полной ссылки хоста в адресе нет — релеи лежат в параметре в процентном
    // кодировании. Если бы её считали неразобранной, чистка удалила бы ВСЕ наши
    // собственные приглашения, то есть оставила бы семью без связи.
    val ours = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40$host"
    assertTrue(hearthLinksAreOn(listOf(ours), host))

    val foreign = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40smp8.simplex.im"
    assertFalse(hearthLinksAreOn(listOf(foreign), host))
  }

  @Test
  fun a_full_link_that_mixes_hosts_is_foreign() {
    // Один релей свой, второй чужой — это не своя ссылка: очередь может жить на любом.
    val mixed = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40$host,smp%3A%2F%2Ffp%40smp8.simplex.im"
    assertFalse(hearthLinksAreOn(listOf(mixed), host))
  }

  @Test
  fun a_readable_full_link_decides_when_the_short_one_cannot_be_read() {
    // Короткой ссылки может не быть или она может быть в формате, которого мы не знаем.
    val full = "simplex:/invitation#/?v=2-7&smp=smp%3A%2F%2Ffp%40$host"
    assertTrue(hearthLinksAreOn(listOf("", full), host))
    assertFalse(hearthLinksAreOn(listOf("https://evil.net/i#abc", full), host))
  }

  @Test
  fun percent_decoding_leaves_broken_sequences_alone() {
    assertEquals("smp://fp@host", hearthPercentDecode("smp%3A%2F%2Ffp%40host"))
    assertEquals("100%zz", hearthPercentDecode("100%zz"))
  }
}
