package chat.hearth

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Стикеры: что лежит на узле и как это читать.
 *
 * # Откуда берутся
 *
 * Наборы импортируются из Telegram с рабочей станции (`stickers/import-telegram.py`) и
 * выкладываются на узел в `/srv/hearth/stickers`: `index.json` со списком наборов и по
 * каталогу на набор — `pack.json` и `NNN.webp`. Узел раздаёт их через device API по
 * токену устройства, тем же замком, что обновления. Только статические WEBP: для
 * анимированных в приложении нет проигрывателя.
 *
 * # Как уходят в чат
 *
 * Стикер отправляется как обычная картинка: файл WEBP как есть (без перекодирования, как
 * GIF — прозрачность сохраняется) плюс маленькое PNG-превью для списка сообщений. Значит
 * получатель на любой версии приложения увидит картинку, даже если стикеров у него нет.
 *
 * # Имена
 *
 * Правила те же, что на узле (`is_safe_sticker_pack` / `is_safe_sticker_file`): всё, что не
 * прошло белый список, отбрасывается ещё при разборе индекса и не превращается в путь.
 */
@Serializable
data class HearthStickerIndex(val v: Int = 1, val packs: List<HearthStickerPackRef> = emptyList())

@Serializable
data class HearthStickerPackRef(val name: String, val title: String = "", val count: Int = 0, val cover: String = "")

@Serializable
data class HearthStickerPack(
  val v: Int = 1,
  val name: String,
  val title: String = "",
  val source: String = "",
  val stickers: List<HearthSticker> = emptyList(),
)

@Serializable
data class HearthSticker(val file: String, val emoji: String = "", val sha256: String = "", val bytes: Long = 0)

object HearthStickers {

  const val INDEX_PATH = "/stickers/index.json"

  private val json = Json { ignoreUnknownKeys = true }

  fun parseIndex(payload: String): Result<HearthStickerIndex> = runCatching {
    val index = json.decodeFromString(HearthStickerIndex.serializer(), payload)
    index.copy(packs = index.packs.filter { isSafePack(it.name) && (it.cover.isEmpty() || isSafeFile(it.cover)) })
  }

  fun parsePack(payload: String): Result<HearthStickerPack> = runCatching {
    val pack = json.decodeFromString(HearthStickerPack.serializer(), payload)
    if (!isSafePack(pack.name)) throw IllegalArgumentException("недопустимое имя набора")
    pack.copy(stickers = pack.stickers.filter { isSafeFile(it.file) && it.file != "pack.json" })
  }

  fun isSafePack(name: String): Boolean =
    name.isNotEmpty() && name.length <= 64 && name.all { it in 'a'..'z' || it in '0'..'9' || it == '_' }

  fun isSafeFile(file: String): Boolean =
    file == "pack.json" || (file.length == 8 && file.endsWith(".webp") && file.substring(0, 3).all { it.isDigit() })

  /** Путь на узле; вызывать только для имён, прошедших проверку. */
  fun path(pack: String, file: String): String {
    require(isSafePack(pack) && isSafeFile(file)) { "недопустимый путь стикера" }
    return "/stickers/$pack/$file"
  }
}
