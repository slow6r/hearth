package chat.hearth

import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
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
 *
 * # Дайджест обязателен
 *
 * `sha256` — не украшение: только по нему видно, что пришёл тот файл, который описан в
 * наборе, и что кэш на телефоне не испорчен. Запись без корректного дайджеста разбор
 * отбрасывает: файл, который нечем сверить, для приложения не существует. Отбрасывается
 * запись, а не весь набор — остальные стикеры пусть работают. Импорт пишет `sha256`
 * всегда, так что текущие наборы этого не заметят; набор, выложенный руками или старым
 * импортом, станет пустым, и панель скажет перевыложить его с узла (см. HearthStickerPicker).
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
  /**
   * Сколько записей отбросил разбор: без дайджеста, с дублирующимся или недопустимым
   * именем файла, крупнее потолка. Не поле формата (@Transient), а результат разбора:
   * по нему панель отличает «набор надо перевыложить» от «в наборе пусто» и не показывает
   * молча пустую сетку.
   */
  @Transient val dropped: Int = 0,
)

@Serializable
data class HearthSticker(val file: String, val emoji: String = "", val sha256: String = "", val bytes: Long = 0)

object HearthStickers {

  const val INDEX_PATH = "/stickers/index.json"

  /**
   * Потолок на файл стикера. Импорт даёт десятки килобайт (самый большой в наборах — 45 КБ),
   * так что полумегабайта хватает с десятикратным запасом, а разница с прежними 4 МиБ — это
   * ровно тот разрыв, в котором живёт «маленький файл, разворачивающийся в гигабайтный растр».
   * Читают его и разбор (объявленный `bytes`), и загрузка (потолок чтения из сети).
   */
  const val MAX_STICKER_BYTES = 512 * 1024

  private val json = Json { ignoreUnknownKeys = true }

  fun parseIndex(payload: String): Result<HearthStickerIndex> = runCatching {
    val index = json.decodeFromString(HearthStickerIndex.serializer(), payload)
    // distinctBy: два одноимённых набора дают две вкладки, и выделенными выглядят обе
    // (вкладка сравнивается по имени), а открывается всё равно один и тот же каталог.
    index.copy(
      packs = index.packs
        .filter { isSafePack(it.name) && (it.cover.isEmpty() || isSafeFile(it.cover)) }
        .distinctBy { it.name }
    )
  }

  fun parsePack(payload: String): Result<HearthStickerPack> = runCatching {
    val pack = json.decodeFromString(HearthStickerPack.serializer(), payload)
    if (!isSafePack(pack.name)) throw IllegalArgumentException("недопустимое имя набора")
    val kept = pack.stickers
      // Дайджест обязателен (см. докблок), объявленный размер — в пределах потолка.
      .filter {
        isSafeFile(it.file) && it.file != "pack.json" &&
          isSafeDigest(it.sha256) && it.bytes >= 0 && it.bytes <= MAX_STICKER_BYTES
      }
      // Имя файла служит ключом ячейки в сетке панели: два одинаковых ключа — это
      // IllegalArgumentException в Compose при композиции, то есть падение на открытии
      // панели. Уникальность держим здесь, чтобы она не зависела от того, кто рисует.
      .distinctBy { it.file }
    pack.copy(stickers = kept, dropped = pack.stickers.size - kept.size)
  }

  fun isSafePack(name: String): Boolean =
    name.isNotEmpty() && name.length <= 64 && name.all { it in 'a'..'z' || it in '0'..'9' || it == '_' }

  fun isSafeFile(file: String): Boolean =
    file == "pack.json" || (file.length == 8 && file.endsWith(".webp") && file.substring(0, 3).all { it.isDigit() })

  /**
   * Дайджест стикера: ровно 64 шестнадцатеричные цифры в нижнем регистре — то, что пишет
   * импорт (`hashlib.sha256(...).hexdigest()`). Верхний регистр не принимаем намеренно:
   * сравнение в сторе побайтовое, и «почти правильный» дайджест не должен выглядеть
   * рабочим до первой загрузки.
   */
  fun isSafeDigest(sha: String): Boolean =
    sha.length == 64 && sha.all { it in '0'..'9' || it in 'a'..'f' }

  /**
   * `inSampleSize` для декодирования стикера: наименьшая степень двойки, при которой в
   * растре останется не больше `maxPixels` пикселей.
   *
   * Зачем: потолки на обоих концах — байтовые, а память ест число пикселей. 4 МиБ WEBP
   * законно кодирует 16383×16383, это около гигабайта ARGB_8888 — OutOfMemoryError на
   * открытии панели. Связи между размером файла и числом пикселей у WEBP нет, поэтому
   * бюджет нужен отдельный. Степени двойки — требование контракта `BitmapFactory`:
   * другие значения он всё равно округлит вниз до степени двойки.
   *
   * Вырожденные входы (нулевые или отрицательные размеры, нулевой бюджет) дают 1: решать,
   * что делать с нечитаемым файлом, — дело вызывающего, а не арифметики.
   */
  fun sampleSizeFor(width: Int, height: Int, maxPixels: Int): Int {
    if (width <= 0 || height <= 0 || maxPixels <= 0) return 1
    var s = 1
    // Цикл конечен: деление рано или поздно даёт нулевую сторону, а ноль не больше бюджета.
    while ((width / s).toLong() * (height / s) > maxPixels) s *= 2
    return s
  }

  /** Путь на узле; вызывать только для имён, прошедших проверку. */
  fun path(pack: String, file: String): String {
    require(isSafePack(pack) && isSafeFile(file)) { "недопустимый путь стикера" }
    return "/stickers/$pack/$file"
  }
}
