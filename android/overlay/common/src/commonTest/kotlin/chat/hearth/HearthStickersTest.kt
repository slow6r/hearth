package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Индекс и наборы стикеров: разбор того, что кладёт импорт, и белый список имён. */
class HearthStickersTest {

  // Ровно то, что пишет stickers/import-telegram.py.
  private val index = """{"v": 1, "packs": [{"name": "animals", "title": "Just zoo it!", "count": 50, "cover": "001.webp"}]}"""
  private val pack = """{"v": 1, "name": "animals", "title": "Just zoo it!", "source": "telegram:Animals",
    "stickers": [{"file": "001.webp", "emoji": "🐱", "sha256": "ab", "bytes": 12345}, {"file": "002.webp", "emoji": "🐶"}]}"""

  @Test
  fun the_importer_output_parses() {
    val i = HearthStickers.parseIndex(index).getOrThrow()
    assertEquals(1, i.packs.size)
    assertEquals("Just zoo it!", i.packs[0].title)
    val p = HearthStickers.parsePack(pack).getOrThrow()
    assertEquals(2, p.stickers.size)
    assertEquals("🐶", p.stickers[1].emoji)
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
    val badFiles = """{"name": "ok", "stickers": [{"file": "../../x.webp"}, {"file": "1.webp"}, {"file": "001.png"}, {"file": "007.webp"}]}"""
    assertEquals(listOf("007.webp"), HearthStickers.parsePack(badFiles).getOrThrow().stickers.map { it.file })
  }

  @Test
  fun a_pack_with_a_bad_name_is_rejected_whole() {
    assertTrue(HearthStickers.parsePack("""{"name": "../x"}""").isFailure)
  }

  @Test
  fun the_whitelist_matches_the_node() {
    assertTrue(HearthStickers.isSafePack("animals"))
    assertFalse(HearthStickers.isSafePack(""))
    assertFalse(HearthStickers.isSafePack("x".repeat(65)))
    assertTrue(HearthStickers.isSafeFile("pack.json"))
    assertTrue(HearthStickers.isSafeFile("001.webp"))
    assertFalse(HearthStickers.isSafeFile("index.json"))
    assertFailsWith<IllegalArgumentException> { HearthStickers.path("a/b", "001.webp") }
    assertEquals("/stickers/animals/001.webp", HearthStickers.path("animals", "001.webp"))
  }
}
