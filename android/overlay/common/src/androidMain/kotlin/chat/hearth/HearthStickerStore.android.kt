package chat.hearth

import android.content.Context
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Локальный кэш стикеров: `filesDir/hearth-stickers/<набор>/`.
 *
 * Индекс и описание набора перечитываются с узла не чаще раза в час; сами файлы
 * адресуются дайджестом и потому живут, пока живут. filesDir, а не cacheDir: систему
 * никто не просил чистить кэш посреди открытой панели, но она вправе.
 *
 * Почему у `pack.json` тот же час, что у индекса: именно он задаёт sha стикеров. Пока он
 * кэшировался навсегда, набор, перевыложенный на узле, не доезжал до уже установленного
 * телефона никогда — и ни одна правка описания (в том числе появление дайджестов) не
 * доходила до людей.
 *
 * Каждый файл сверяется с sha256 из `pack.json` — и при скачивании, и при повторном
 * открытии: подменённый или недокачанный файл не уйдёт собеседнику. Записи в кэш идут
 * через временный файл и переименование: процесс, убитый посреди записи, оставит `.tmp`,
 * а не обрезанный `pack.json`, который потом не разберётся.
 */
object HearthStickerStore {

  private const val INDEX_TTL_MS = 60L * 60 * 1000

  private fun root(context: Context): File = File(context.filesDir, "hearth-stickers").apply { mkdirs() }

  suspend fun index(context: Context, transport: HearthAndroidUpdateTransport): Result<HearthStickerIndex> {
    val cache = File(root(context), "index.json")
    val text = refresh(cache) { transport.fetchText(HearthStickers.INDEX_PATH) }
      .getOrElse { return Result.failure(it) }
    return HearthStickers.parseIndex(text)
  }

  suspend fun pack(context: Context, transport: HearthAndroidUpdateTransport, name: String): Result<HearthStickerPack> {
    if (!HearthStickers.isSafePack(name)) return Result.failure(IllegalArgumentException("недопустимое имя набора"))
    val cache = File(File(root(context), name).apply { mkdirs() }, "pack.json")
    val text = refresh(cache) { transport.fetchText(HearthStickers.path(name, "pack.json")) }
      .getOrElse { return Result.failure(it) }
    return HearthStickers.parsePack(text)
  }

  /**
   * Свежая копия текстового файла с узла или кэш, если узел недоступен.
   *
   * Разбираем скачанное, а не перечитанное с диска: сохранить не удалось — панель всё
   * равно откроется, а в следующий раз попробуем снова. Обратное (всегда перечитывать)
   * означало бы, что одна неудачная запись ломает панель до конца TTL.
   */
  private suspend fun refresh(cache: File, fetch: suspend () -> Result<String>): Result<String> {
    val fresh = cache.isFile && System.currentTimeMillis() - cache.lastModified() < INDEX_TTL_MS
    if (!fresh) {
      val fetched = fetch()
      val error = fetched.exceptionOrNull()
      if (error == null) {
        val text = fetched.getOrThrow()
        runCatching { writeAtomically(cache, text.toByteArray()) }
        return Result.success(text)
      }
      // Узел недоступен, а старая копия есть — работаем на ней: стикеры уже в кэше.
      if (!cache.isFile) return Result.failure(error)
    }
    return runCatching { cache.readText() }
  }

  suspend fun file(context: Context, transport: HearthAndroidUpdateTransport, pack: String, sticker: HearthSticker): Result<File> {
    if (!HearthStickers.isSafePack(pack) || !HearthStickers.isSafeFile(sticker.file) || sticker.file == "pack.json") {
      return Result.failure(IllegalArgumentException("недопустимый путь стикера"))
    }
    // Сверять не с чем — значит не берём вовсе. Разбор набора такие записи уже отбросил;
    // это второй замок на случай другого вызывающего, и он же — причина, по которой обе
    // сверки ниже безусловны: раньше пустой sha256 выключал их обе.
    if (!HearthStickers.isSafeDigest(sticker.sha256)) {
      return Result.failure(IllegalArgumentException("в наборе нет контрольной суммы стикера"))
    }
    val f = File(File(root(context), pack).apply { mkdirs() }, sticker.file)
    if (f.isFile) {
      // Чтение кэша тоже может отказать (том занят, файл увели) — тогда просто скачиваем.
      if (runCatching { sha256(f.readBytes()) }.getOrNull() == sticker.sha256) return Result.success(f)
      // Не совпал: кэш испорчен или набор перевыложен другим содержимым. Удаляем, иначе
      // битый файл залипает навсегда, а скачивание ниже всё равно пишет поверх.
      f.delete()
    }
    val fetched = transport.fetchBytes(HearthStickers.path(pack, sticker.file), HearthStickers.MAX_STICKER_BYTES)
    val bytes = fetched.getOrElse { return Result.failure(it) }
    // Объявленный размер — дешёвая сверка до хеширования; 0 значит «не объявлен».
    if (sticker.bytes > 0 && bytes.size.toLong() != sticker.bytes) {
      return Result.failure(IllegalStateException("размер стикера не совпал с описанием набора"))
    }
    if (sha256(bytes) != sticker.sha256) {
      return Result.failure(IllegalStateException("стикер не совпал с описанием набора"))
    }
    runCatching { writeAtomically(f, bytes) }.getOrElse { return Result.failure(it) }
    return Result.success(f)
  }

  /**
   * Запись через временный файл рядом и переименование: на одном томе переименование
   * атомарно, поэтому читатель видит либо старый файл целиком, либо новый целиком.
   */
  private fun writeAtomically(target: File, bytes: ByteArray) {
    val tmp = File(target.parentFile, target.name + ".tmp")
    tmp.writeBytes(bytes)
    if (!tmp.renameTo(target)) {
      // На filesDir этого быть не должно; если всё же — не оставляем мусор в кэше.
      tmp.delete()
      throw IOException("не удалось сохранить " + target.name)
    }
  }

  private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
