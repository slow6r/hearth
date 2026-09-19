package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Индекс и наборы стикеров: разбор того, что кладёт импорт, и белый список имён. */
class HearthStickersTest {

  // Ровно то, что пишет stickers/import-telegram.py, — дайджесты и размеры настоящие,
  // из stickers/dist/animals/pack.json.
  private val sha1 = "68879979bb762394a9721cd9e9a59d4885f44abbf21eedbfd271e212a6f492af"
  private val sha2 = "aa085440889323d52f89b9176f6b394b730fbbe2fd342ff2a3bbdae69877887f"
  private val index = """{"v": 1, "packs": [{"name": "animals", "title": "Just zoo it!", "count": 50, "cover": "001.webp"}]}"""
  private val pack = """{"v": 1, "name": "animals", "title": "Just zoo it!", "source": "telegram:Animals",
    "stickers": [{"file": "001.webp", "emoji": "🐱", "sha256": "$sha1", "bytes": 37624},
                 {"file": "002.webp", "emoji": "🐶", "sha256": "$sha2", "bytes": 35060}]}"""

  @Test
  fun the_importer_output_parses() {
    val i = HearthStickers.parseIndex(index).getOrThrow()
    assertEquals(1, i.packs.size)
    assertEquals("Just zoo it!", i.packs[0].title)
    val p = HearthStickers.parsePack(pack).getOrThrow()
    assertEquals(2, p.stickers.size)
    assertEquals("🐶", p.stickers[1].emoji)
    // Ничего не отброшено: то, что выложено на узле, должно доходить до людей целиком.
    assertEquals(0, p.dropped)
  }

  @Test
  fun unknown_fields_do_not_break_older_apps() {
    val withExtra = index.replace("\"v\": 1", "\"v\": 1, \"future\": true")
    assertTrue(HearthStickers.parseIndex(withExtra).isSuccess)
  }

  @Test
  fun unsafe_names_are_dropped_not_trusted() {
    val bad = """{"packs": [{"name": "../updates", "title": "x"}, {"name": "Animals", "title": "x"}, {"name": "ok_1", "title": "x"}]}"""
    assertEquals(listOf("ok_1"), HearthStickers.parseIndex(bad).getOrThrow().packs.map { it.name })
    val badFiles = """{"name": "ok", "stickers": [{"file": "../../x.webp", "sha256": "$sha1"}, {"file": "1.webp", "sha256": "$sha1"},
      {"file": "001.png", "sha256": "$sha1"}, {"file": "007.webp", "sha256": "$sha1"}]}"""
    assertEquals(listOf("007.webp"), HearthStickers.parsePack(badFiles).getOrThrow().stickers.map { it.file })
  }

  @Test
  fun a_pack_with_a_bad_name_is_rejected_whole() {
    assertTrue(HearthStickers.parsePack("""{"name": "../x"}""").isFailure)
  }

  @Test
  fun a_sticker_without_a_digest_is_dropped() {
    // Файл, который нечем сверить, для приложения не существует: раньше такой стикер
    // уходил собеседнику вообще без проверки.
    val p = """{"name": "ok", "stickers": [{"file": "001.webp", "sha256": "$sha1"}, {"file": "002.webp", "emoji": "🐶"}]}"""
    val parsed = HearthStickers.parsePack(p).getOrThrow()
    assertEquals(listOf("001.webp"), parsed.stickers.map { it.file })
    assertEquals(1, parsed.dropped)
  }

  @Test
  fun a_malformed_digest_is_dropped() {
    val bad = listOf(
      "ab",                       // огрызок
      sha1.uppercase(),           // верхний регистр: сравнение в сторе побайтовое
      sha1.substring(1),          // 63
      sha1 + "0",                 // 65
      sha1.dropLast(1) + "z",     // не hex
      sha1.dropLast(1) + " ",     // пробел
    )
    for (sha in bad) {
      val p = """{"name": "ok", "stickers": [{"file": "001.webp", "sha256": "$sha"}]}"""
      assertTrue(HearthStickers.parsePack(p).getOrThrow().stickers.isEmpty(), "принят дайджест: $sha")
    }
  }

  @Test
  fun an_oversized_sticker_is_dropped() {
    // Потолок один и тот же у разбора и у загрузки: то, что не скачается, не должно
    // висеть в сетке вечным индикатором.
    val big = HearthStickers.MAX_STICKER_BYTES + 1
    val p = """{"name": "ok", "stickers": [{"file": "001.webp", "sha256": "$sha1", "bytes": $big},
      {"file": "002.webp", "sha256": "$sha2", "bytes": ${HearthStickers.MAX_STICKER_BYTES}}]}"""
    assertEquals(listOf("002.webp"), HearthStickers.parsePack(p).getOrThrow().stickers.map { it.file })
  }

  @Test
  fun a_pack_the_node_must_republish_is_empty_but_says_so() {
    // Набор старого импорта (без sha256): сетка пустая, но dropped > 0 — панель по этому
    // отличает «надо перевыложить» от «в наборе пусто» и не молчит.
    val old = """{"name": "ok", "stickers": [{"file": "001.webp", "emoji": "🐱"}, {"file": "002.webp", "emoji": "🐶"}]}"""
    val parsed = HearthStickers.parsePack(old).getOrThrow()
    assertTrue(parsed.stickers.isEmpty())
    assertEquals(2, parsed.dropped)
    val empty = HearthStickers.parsePack("""{"name": "ok", "stickers": []}""").getOrThrow()
    assertTrue(empty.stickers.isEmpty())
    assertEquals(0, empty.dropped)
  }

  @Test
  fun duplicate_files_collapse_to_one() {
    // Имя файла — ключ ячейки в сетке; два одинаковых ключа роняют Compose на открытии.
    val p = """{"name": "ok", "stickers": [{"file": "001.webp", "sha256": "$sha1"},
      {"file": "001.webp", "sha256": "$sha2"}, {"file": "002.webp", "sha256": "$sha2"}]}"""
    val parsed = HearthStickers.parsePack(p).getOrThrow()
    assertEquals(listOf("001.webp", "002.webp"), parsed.stickers.map { it.file })
    // Побеждает первая запись: разбор не выбирает «правильную», он лишь не даёт двойника.
    assertEquals(sha1, parsed.stickers[0].sha256)
    assertEquals(1, parsed.dropped)
  }

  @Test
  fun duplicate_packs_collapse_to_one() {
    val i = """{"packs": [{"name": "animals", "title": "Раз"}, {"name": "animals", "title": "Два"}, {"name": "cats", "title": "Три"}]}"""
    val parsed = HearthStickers.parseIndex(i).getOrThrow()
    assertEquals(listOf("animals", "cats"), parsed.packs.map { it.name })
    assertEquals("Раз", parsed.packs[0].title)
  }

  @Test
  fun the_sample_size_keeps_the_decoded_sticker_bounded() {
    val budget = 1024 * 1024
    assertEquals(1, HearthStickers.sampleSizeFor(512, 512, budget))
    assertEquals(1, HearthStickers.sampleSizeFor(1024, 1024, budget))
    // 4 МиБ WEBP законно кодирует 16383×16383 — около гигабайта ARGB_8888 без прореживания.
    assertEquals(16, HearthStickers.sampleSizeFor(16383, 16383, budget))
    for (w in listOf(1, 3, 512, 1025, 4096, 16383, 30000)) {
      for (h in listOf(1, 3, 512, 1025, 4096, 16383, 30000)) {
        val s = HearthStickers.sampleSizeFor(w, h, budget)
        assertTrue(s >= 1 && s and (s - 1) == 0, "не степень двойки: $s ($w×$h)")
        assertTrue((w / s).toLong() * (h / s) <= budget, "бюджет пробит: $w×$h → $s")
      }
    }
  }

  @Test
  fun the_sample_size_survives_degenerate_bounds() {
    // Решать, что делать с нечитаемым файлом, — дело вызывающего; арифметика не падает.
    assertEquals(1, HearthStickers.sampleSizeFor(0, 0, 1024))
    assertEquals(1, HearthStickers.sampleSizeFor(1, 1, 1024))
    assertEquals(1, HearthStickers.sampleSizeFor(-8, 16, 1024))
    assertEquals(1, HearthStickers.sampleSizeFor(16, 16, 0))
  }

  @Test
  fun the_whitelist_matches_the_node() {
    assertTrue(HearthStickers.isSafePack("animals"))
    assertFalse(HearthStickers.isSafePack(""))
    assertFalse(HearthStickers.isSafePack("x".repeat(65)))
    assertTrue(HearthStickers.isSafeFile("pack.json"))
    assertTrue(HearthStickers.isSafeFile("001.webp"))
    assertFalse(HearthStickers.isSafeFile("index.json"))
    assertTrue(HearthStickers.isSafeDigest(sha1))
    assertFalse(HearthStickers.isSafeDigest(""))
    assertFalse(HearthStickers.isSafeDigest(sha1.uppercase()))
    assertFalse(HearthStickers.isSafeDigest("g".repeat(64)))
    assertFailsWith<IllegalArgumentException> { HearthStickers.path("a/b", "001.webp") }
    assertEquals("/stickers/animals/001.webp", HearthStickers.path("animals", "001.webp"))
  }
}
