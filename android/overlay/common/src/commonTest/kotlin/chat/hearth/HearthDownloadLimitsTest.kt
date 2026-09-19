package chat.hearth

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Потолок объёма при загрузке APK — таблица случаев.
 *
 * Сам цикл ввода-вывода без устройства не прогнать, поэтому правила вынесены в чистую
 * арифметику. Проверяются три входа, которыми узел может злоупотребить: обещанная
 * длина, необещанная длина (поток до бесконечности) и докачка по частям.
 */
class HearthDownloadLimitsTest {

  private val limit = 100L
  private val mb = 1024L * 1024

  @Test
  fun a_declared_size_within_the_limit_passes() {
    assertNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(90 * mb, 0, limit * mb))
    assertNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(limit * mb, 0, limit * mb))
  }

  @Test
  fun a_declared_size_over_the_limit_is_refused_before_the_stream_opens() {
    val reason = assertNotNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(limit * mb + 1, 0, limit * mb))
    assertTrue(reason.contains("обещает"), reason)
  }

  @Test
  fun what_is_already_on_disk_counts_towards_the_limit() {
    // Докачка по Range иначе обходила бы потолок по частям: каждый кусок «в пределах»,
    // а файл растёт без конца.
    assertNotNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(60 * mb, 50 * mb, limit * mb))
    assertNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(40 * mb, 50 * mb, limit * mb))
  }

  @Test
  fun an_undeclared_length_is_not_a_reason_to_refuse_up_front() {
    // Content-Length может быть -1 при chunked-ответе — это законно.
    assertNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(-1, 0, limit * mb))
    assertNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(0, 0, limit * mb))
  }

  @Test
  fun the_written_bytes_are_the_second_line_of_defence() {
    // Длину узел мог не назвать или назвать неправду. Тогда ловит только счётчик.
    assertNull(HearthDownloadLimits.refuseIfWrittenTooLarge(limit * mb, limit * mb))
    val reason = assertNotNull(HearthDownloadLimits.refuseIfWrittenTooLarge(limit * mb + 1, limit * mb))
    assertTrue(reason.contains("поток"), reason)
  }

  @Test
  fun there_must_be_room_for_the_file_and_a_little_more() {
    // Забить внутреннюю память под ноль — сломать не обновление, а всю переписку.
    assertNull(HearthDownloadLimits.refuseIfNoSpace(10 * mb, 100 * mb, 5 * mb))
    val reason = assertNotNull(HearthDownloadLimits.refuseIfNoSpace(10 * mb, 12 * mb, 5 * mb))
    assertTrue(reason.contains("не хватает"), reason)
  }

  @Test
  fun the_refusal_says_how_much_is_missing() {
    // Замечание критика: «нужно 312, свободно 280» человек вычитает в уме и ошибается.
    // Главное число — сколько не хватает: это уже задача, которую видно, как решить.
    val reason = assertNotNull(HearthDownloadLimits.refuseIfNoSpace(250 * mb, 240 * mb, 16 * mb))
    assertTrue(reason.contains("не хватает 26 МБ"), reason)
    assertTrue(reason.contains("240"), reason)
    // И что делать, а не только что случилось.
    assertTrue(reason.contains("Удалите"), reason)
  }

  @Test
  fun a_missing_half_megabyte_is_not_reported_as_zero() {
    // Округление вниз дало бы «не хватает 0 МБ» — сообщение, которое нечего делать.
    val reason = assertNotNull(HearthDownloadLimits.refuseIfNoSpace(10 * mb, 10 * mb - mb / 2, 0))
    assertTrue(reason.contains("не хватает 1 МБ"), reason)
  }

  @Test
  fun the_margin_fits_a_phone_that_is_already_full() {
    // Замечание критика: с запасом в 64 МБ нынешней сборке (около 250 МБ) требовалось
    // ~312 МБ свободных, и на забитом телефоне обновление не ставилось НИКОГДА. Запас
    // нужен ровно затем, чтобы ядру было куда дописать базу переписки, — этого хватает
    // с большим избытком, а лишние полсотни мегабайт стоили семье связи с обновлениями.
    assertTrue(
      HearthDownloadLimits.FREE_SPACE_MARGIN_BYTES <= 16 * mb,
      "запас снова требует от забитого телефона невозможного",
    )
    // 250 МБ сборки при 270 МБ свободных — уже не отказ.
    assertNull(HearthDownloadLimits.refuseIfNoSpace(250 * mb, 270 * mb))
  }

  @Test
  fun a_leftover_from_another_build_is_not_reused() {
    // Недокачанное от прошлой версии докачивать бессмысленно: хеш всё равно не сойдётся,
    // а сотни мегабайт оно занимает — и проверка места отказывает из-за мусора, который
    // сама же и держит. Поэтому такой остаток опознаётся и удаляется ДО проверки.
    val wanted = "a".repeat(64)
    val other = "b".repeat(64)
    assertTrue(HearthDownloadLimits.leftoverIsUsable(wanted, wanted))
    // Регистр пометки значения не имеет: hex пишут по-разному.
    assertTrue(HearthDownloadLimits.leftoverIsUsable(wanted.uppercase(), wanted))
    assertFalse(HearthDownloadLimits.leftoverIsUsable(other, wanted))
    // Пометки нет — происхождение остатка неизвестно, значит он чужой.
    assertFalse(HearthDownloadLimits.leftoverIsUsable(null, wanted))
    assertFalse(HearthDownloadLimits.leftoverIsUsable("  ", wanted))
  }

  @Test
  fun an_unknown_size_or_unknown_free_space_is_not_judged() {
    // Отказать «на всякий случай» здесь значило бы оставить семью без обновлений там,
    // где всё в порядке: usableSpace на некоторых прошивках возвращает ноль.
    assertNull(HearthDownloadLimits.refuseIfNoSpace(-1, 12 * mb))
    assertNull(HearthDownloadLimits.refuseIfNoSpace(10 * mb, 0))
  }

  @Test
  fun an_undeclared_length_no_longer_means_no_space_check_at_all() {
    // Дыра, найденная критиком: refuseIfNoSpace зовут с declared, а при chunked-ответе
    // declared = -1, и проверка выходит на первой строке. То есть узлу достаточно было
    // не назвать длину, чтобы место не проверялось ВОВСЕ.
    assertNull(HearthDownloadLimits.refuseIfNoSpace(-1, 1 * mb, 64 * mb))
    // Теперь тот же случай ловит проверка по остатку места — ей длина не нужна.
    val reason = assertNotNull(HearthDownloadLimits.refuseIfSpaceRanOut(1 * mb, 64 * mb))
    assertTrue(reason.contains("место"), reason)
    // И человеку сказано, ЧТО ДЕЛАТЬ и СКОЛЬКО не хватает, а не только что случилось.
    assertTrue(reason.contains("Освободите"), reason)
    assertTrue(reason.contains("не хватает"), reason)
  }

  @Test
  fun room_above_the_margin_is_not_a_reason_to_stop() {
    // Отказ посреди загрузки стоит людям обновления, поэтому граница ровно одна:
    // свободного меньше запаса. Столько же — ещё можно.
    assertNull(HearthDownloadLimits.refuseIfSpaceRanOut(64 * mb, 64 * mb))
    assertNull(HearthDownloadLimits.refuseIfSpaceRanOut(500 * mb, 64 * mb))
    // Прошивка не ответила (0) — не судим, как и в проверке по обещанной длине.
    assertNull(HearthDownloadLimits.refuseIfSpaceRanOut(0, 64 * mb))
    assertNull(HearthDownloadLimits.refuseIfSpaceRanOut(-1, 64 * mb))
  }

  @Test
  fun the_space_check_does_not_run_on_every_buffer() {
    // usableSpace — системный вызов. На каждые 64 КБ это четыре тысячи вызовов на файл
    // в четверть гигабайта: проверка, которая сама стоит дороже того, что охраняет.
    assertTrue(HearthDownloadLimits.shouldRecheckSpace(4 * mb, 0))
    assertFalse(HearthDownloadLimits.shouldRecheckSpace(4 * mb - 1, 0))
    // Докачка начинается не с нуля, и отсчёт ведётся от того места, где спросили.
    assertFalse(HearthDownloadLimits.shouldRecheckSpace(100 * mb, 99 * mb))
    assertTrue(HearthDownloadLimits.shouldRecheckSpace(108 * mb, 100 * mb))
    // Запас заметно больше шага: за один шаг память не кончится.
    assertTrue(HearthDownloadLimits.FREE_SPACE_MARGIN_BYTES > HearthDownloadLimits.SPACE_CHECK_EVERY_BYTES)
  }

  @Test
  fun the_shipped_limit_leaves_room_for_the_real_build() {
    // Сборки сейчас около 250 МБ. Слишком тесный потолок оставил бы семью без
    // обновлений на ровном месте — это не строгость, а поломка.
    assertTrue(HearthDownloadLimits.APK_LIMIT_BYTES >= 400L * mb)
    assertNull(HearthDownloadLimits.refuseIfDeclaredTooLarge(260 * mb, 0))
  }
}
