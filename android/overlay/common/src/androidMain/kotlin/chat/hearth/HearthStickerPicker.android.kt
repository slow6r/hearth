package chat.hearth

import android.content.Context
import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import chat.simplex.common.helpers.toURI
import chat.simplex.common.platform.resizeImageToStrSize
import chat.simplex.common.ui.theme.DEFAULT_PADDING
import chat.simplex.common.views.helpers.AppBarTitle
import chat.simplex.common.views.helpers.ModalManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.URI

/**
 * Панель выбора стикера.
 *
 * Наборы — с узла (HearthStickerStore), сетка четыре в ряд, вкладки по наборам. Выбранный
 * стикер уходит в превью сообщения как картинка из галереи: файл WEBP как есть и
 * PNG-превью с прозрачностью; отправка — той же кнопкой, что у любой картинки.
 */
object HearthStickerPicker {

  fun show(onPicked: (URI, String) -> Unit) {
    ModalManager.end.showModalCloseable { close ->
      HearthStickerPickerView { uri, preview ->
        close()
        onPicked(uri, preview)
      }
    }
  }
}

@Composable
private fun HearthStickerPickerView(onPicked: (URI, String) -> Unit) {
  val context = LocalContext.current
  val transport = remember { HearthAndroidUpdateTransport.fromPrefs(context) }
  val index = remember { mutableStateOf<Result<HearthStickerIndex>?>(null) }
  val selected = remember { mutableStateOf<String?>(null) }
  val pack = remember { mutableStateOf<HearthStickerPack?>(null) }

  LaunchedEffect(Unit) {
    if (transport == null) return@LaunchedEffect
    val loaded = HearthStickerStore.index(context, transport)
    index.value = loaded
    selected.value = loaded.getOrNull()?.packs?.firstOrNull()?.name
  }
  LaunchedEffect(selected.value) {
    val name = selected.value ?: return@LaunchedEffect
    if (transport == null) return@LaunchedEffect
    pack.value = null
    pack.value = HearthStickerStore.pack(context, transport, name).getOrNull()
  }

  Column(Modifier.fillMaxSize()) {
    AppBarTitle("Стикеры")
    val loaded = index.value
    when {
      transport == null -> Note("Узел не настроен: стикеры берутся с него.")
      loaded == null -> Note("Загружаем список…")
      loaded.isFailure -> Note("Не удалось получить список с узла: ${loaded.exceptionOrNull()?.message}")
      loaded.getOrThrow().packs.isEmpty() -> Note("На узле пока нет наборов.")
      else -> {
        val packs = loaded.getOrThrow().packs
        Row(
          Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = DEFAULT_PADDING),
          horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          packs.forEach { p ->
            val active = p.name == selected.value
            TextButton(onClick = { selected.value = p.name }) {
              Text(
                p.title.ifEmpty { p.name },
                color = if (active) MaterialTheme.colors.primary else MaterialTheme.colors.onBackground,
              )
            }
          }
        }
        val current = pack.value
        if (current == null) {
          Note("Загружаем набор…")
        } else {
          LazyVerticalGrid(
            columns = GridCells.Fixed(4),
            modifier = Modifier.fillMaxSize().padding(horizontal = DEFAULT_PADDING / 2),
          ) {
            items(current.stickers, key = { it.file }) { st ->
              StickerCell(context, transport, current.name, st, onPicked)
            }
          }
        }
      }
    }
  }
}

@Composable
private fun StickerCell(
  context: Context,
  transport: HearthAndroidUpdateTransport,
  packName: String,
  st: HearthSticker,
  onPicked: (URI, String) -> Unit,
) {
  val bitmap = remember(packName, st.file) { mutableStateOf<ImageBitmap?>(null) }
  val file = remember(packName, st.file) { mutableStateOf<File?>(null) }
  LaunchedEffect(packName, st.file) {
    val f = HearthStickerStore.file(context, transport, packName, st).getOrNull() ?: return@LaunchedEffect
    val bm = withContext(Dispatchers.IO) { BitmapFactory.decodeFile(f.absolutePath)?.asImageBitmap() } ?: return@LaunchedEffect
    file.value = f
    bitmap.value = bm
  }
  Box(
    Modifier
      .aspectRatio(1f)
      .padding(6.dp)
      .clickable(enabled = bitmap.value != null) {
        val f = file.value ?: return@clickable
        val bm = bitmap.value ?: return@clickable
        // content://, а не file://: имя файла upstream берёт через contentResolver, и для
        // file:// он вернёт null — стикер ушёл бы под именем .gif. Провайдер приложения
        // покрывает весь filesDir (file_paths.xml, my_files).
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.provider", f).toURI()
        // Превью — как у любой картинки; для картинки с прозрачностью upstream сам берёт PNG.
        onPicked(uri, resizeImageToStrSize(bm, maxDataSize = 14000))
      },
    contentAlignment = Alignment.Center,
  ) {
    val bm = bitmap.value
    if (bm != null) Image(bm, contentDescription = st.emoji, Modifier.fillMaxSize())
    else CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
  }
}

@Composable
private fun Note(text: String) {
  Text(text, Modifier.fillMaxWidth().padding(DEFAULT_PADDING), textAlign = TextAlign.Center, style = MaterialTheme.typography.body1)
}
