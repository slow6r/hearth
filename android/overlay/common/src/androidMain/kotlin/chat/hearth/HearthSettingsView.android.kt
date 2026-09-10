package chat.hearth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import chat.simplex.common.model.ChatController
import chat.simplex.common.ui.theme.DEFAULT_PADDING
import chat.simplex.common.platform.ColumnWithScrollBar
import chat.simplex.common.views.helpers.AppBarTitle
// Секции настроек upstream объявлены БЕЗ package — в корневом пакете (Section.kt),
// и импортируются именно так. Выглядит странно, но это факт пинованного тега, и
// повторять его дешевле, чем переносить чужой файл в пакет и получать конфликт при
// каждом ребейзе.
import SectionDividerSpaced
import SectionItemView
import SectionTextFooter
import SectionView
import chat.simplex.common.views.newchat.QRCode
import kotlinx.coroutines.launch

@Composable
actual fun HearthNodeSettingsView() {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val status = remember { mutableStateOf<String?>(null) }
  val busy = remember { mutableStateOf(false) }
  val inviteName = remember { mutableStateOf("") }
  val inviteBundle = remember { mutableStateOf<String?>(null) }

  val host = ChatController.appPrefs.hearthUpdateHost.get()
  val deviceId = ChatController.appPrefs.hearthDeviceId.get()

  ColumnWithScrollBar {
    AppBarTitle("Домашний узел")

    SectionView("ЭТО УСТРОЙСТВО") {
      SectionTextFooter(
        "Заведено как: ${deviceId ?: "не настроено"}\n" +
          "Узел: ${host ?: "не настроен — отсканируйте QR настроек"}"
      )
    }
    SectionDividerSpaced()

    // --- обновление ---------------------------------------------------------------
    SectionView("ОБНОВЛЕНИЕ") {
      SectionItemView(click = {
        if (busy.value) return@SectionItemView
        busy.value = true
        status.value = "спрашиваем узел…"
        scope.launch {
          val transport = HearthAndroidUpdateTransport.fromPrefs(context)
          if (transport == null) {
            status.value = "узел не настроен: сначала отсканируйте QR настроек"
            busy.value = false
            return@launch
          }
          val installed = installedVersionCode(context)
          when (val r = HearthUpdateChecker(transport, installed).check()) {
            is HearthUpdateCheck.UpToDate ->
              status.value = "установлена последняя версия ($installed)"
            is HearthUpdateCheck.Failed ->
              status.value = "не вышло: ${r.reason}"
            is HearthUpdateCheck.Available -> {
              status.value =
                "есть версия ${r.manifest.versionName}. Загрузка идёт в фоне — " +
                  "приложение можно свернуть, прогресс виден в шторке."
              HearthUpdateService.start(context, r.manifest)
            }
          }
          busy.value = false
        }
      }) {
        Text("Проверить обновление", color = MaterialTheme.colors.primary)
      }
    }
    SectionTextFooter(
      "Обновление приходит с вашего узла, не из магазина приложений. Скачивание идёт " +
        "в фоне и переживает сворачивание; установку Android всегда показывает своим " +
        "диалогом — обойти это приложение не может."
    )
    SectionDividerSpaced()

    // --- приглашение --------------------------------------------------------------
    SectionView("НОВОЕ УСТРОЙСТВО") {
      OutlinedTextField(
        value = inviteName.value,
        onValueChange = { inviteName.value = it },
        label = { Text("Имя, например «Брат — Redmi»") },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(horizontal = DEFAULT_PADDING),
      )
      SectionItemView(click = {
        val name = inviteName.value.trim()
        if (busy.value || name.isEmpty()) return@SectionItemView
        busy.value = true
        status.value = "просим узел завести устройство…"
        scope.launch {
          val transport = HearthAndroidUpdateTransport.fromPrefs(context)
          if (transport == null) {
            status.value = "узел не настроен"
            busy.value = false
            return@launch
          }
          transport.enroll(name)
            .onSuccess {
              inviteBundle.value = it
              status.value = "готово: покажите QR новому телефону"
            }
            .onFailure { status.value = "не вышло: ${it.message}" }
          busy.value = false
        }
      }) {
        Text("Пригласить устройство", color = MaterialTheme.colors.primary)
      }
    }
    SectionTextFooter(
      "Узел заведёт отдельную запись со своим ключом, поэтому потерянный телефон " +
        "можно будет отозвать, не трогая остальные."
    )

    val bundle = inviteBundle.value
    if (bundle != null) {
      Spacer(Modifier.height(DEFAULT_PADDING))
      QRCode(connReq = bundle, withLogo = false)
      Text(
        "QR содержит пароли релеев. Показывайте лично, не пересылайте и не сохраняйте " +
          "в галерею.",
        style = MaterialTheme.typography.body2,
        color = MaterialTheme.colors.error,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth().padding(horizontal = DEFAULT_PADDING),
      )
    }

    val text = status.value
    if (text != null) {
      Spacer(Modifier.height(DEFAULT_PADDING))
      Text(
        text,
        style = MaterialTheme.typography.body2,
        textAlign = TextAlign.Center,
        modifier = Modifier.fillMaxWidth().padding(horizontal = DEFAULT_PADDING),
      )
    }
    Spacer(Modifier.height(DEFAULT_PADDING * 2))
  }
}

/**
 * versionCode установленной сборки.
 *
 * Именно code, а не versionName: строку человек пишет руками и может ошибиться, а
 * code монотонен по требованию Android — на нём и строится сравнение «новее ли».
 */
private fun installedVersionCode(context: android.content.Context): Int = runCatching {
  val info = context.packageManager.getPackageInfo(context.packageName, 0)
  if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
    info.longVersionCode.toInt()
  } else {
    @Suppress("DEPRECATION")
    info.versionCode
  }
}.getOrDefault(0)
