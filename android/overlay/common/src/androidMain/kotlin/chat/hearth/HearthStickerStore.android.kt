package chat.hearth

import android.content.Context
import java.io.File
import java.security.MessageDigest

/**
 * Локальный кэш стикеров: `filesDir/hearth-stickers/<набор>/`.
 *
 * Индекс перечитывается с узла не чаще раза в час; описание набора и сами файлы
 * скачиваются один раз и живут, пока живёт приложение. filesDir, а не cacheDir: систему
 * никто не просил чистить кэш посреди открытой панели, но она вправе.
 *
 * Каждый файл сверяется с sha256 из `pack.json` — и при скачивании, и при повторном
 * открытии: подменённый или недокачанный файл не уйдёт собеседнику.
 */
object HearthStickerStore {

  private const val INDEX_TTL_MS = 60L * 60 * 1000

  private fun root(context: Context): File = File(context.filesDir, "hearth-stickers").apply { mkdirs() }

  suspend fun index(context: Context, transport: HearthAndroidUpdateTransport): Result<HearthStickerIndex> {
    val cache = File(root(context), "index.json")
    val fresh = cache.isFile && System.currentTimeMillis() - cache.lastModified() < INDEX_TTL_MS
    if (!fresh) {
      val fetched = transport.fetchText(HearthStickers.INDEX_PATH)
      fetched.onSuccess { cache.writeText(it) }
      // Узел недоступен, а старый индекс есть — показываем его: стикеры уже в кэше.
      val error = fetched.exceptionOrNull()
      if (error != null && !cache.isFile) return Result.failure(error)
    }
    return HearthStickers.parseIndex(cache.readText())
  }

  suspend fun pack(context: Context, transport: HearthAndroidUpdateTransport, name: String): Result<HearthStickerPack> {
    if (!HearthStickers.isSafePack(name)) return Result.failure(IllegalArgumentException("недопустимое имя набора"))
    val cache = File(File(root(context), name).apply { mkdirs() }, "pack.json")
    if (!cache.isFile) {
      val fetched = transport.fetchText(HearthStickers.path(name, "pack.json"))
      fetched.onSuccess { cache.writeText(it) }
      val error = fetched.exceptionOrNull()
      if (error != null) return Result.failure(error)
    }
    return HearthStickers.parsePack(cache.readText())
  }

  suspend fun file(context: Context, transport: HearthAndroidUpdateTransport, pack: String, sticker: HearthSticker): Result<File> {
    if (!HearthStickers.isSafePack(pack) || !HearthStickers.isSafeFile(sticker.file) || sticker.file == "pack.json") {
      return Result.failure(IllegalArgumentException("недопустимый путь стикера"))
    }
    val f = File(File(root(context), pack).apply { mkdirs() }, sticker.file)
    if (f.isFile && (sticker.sha256.isEmpty() || sha256(f.readBytes()) == sticker.sha256)) return Result.success(f)
    val fetched = transport.fetchBytes(HearthStickers.path(pack, sticker.file))
    val bytes = fetched.getOrElse { return Result.failure(it) }
    if (sticker.sha256.isNotEmpty() && sha256(bytes) != sticker.sha256) {
      return Result.failure(IllegalStateException("стикер не совпал с описанием набора"))
    }
    f.writeBytes(bytes)
    return Result.success(f)
  }

  private fun sha256(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
