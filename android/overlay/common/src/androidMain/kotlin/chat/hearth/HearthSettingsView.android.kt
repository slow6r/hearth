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
    AppBarTitle("Узел")

    SectionView("ЭТО УСТРОЙСТВО") {
      SectionTextFooter(
        "Заведено как: ${deviceId ?: "не настроено"}\n" +
          "Узел: ${host ?: "не настроен — отсканируйте QR настроек"}"
      )
    }
    SectionDividerSpaced()

    // --- фон --------------------------------------------------------------------------
    //
    // Одиннадцать телефонов из тринадцати в семье — Huawei, а там система гасит фоновую
    // службу своим «менеджером запуска», о котором стандартная проверка батареи не знает.
    // Пункт есть всегда: на других телефонах он открывает сведения о приложении.
    SectionView("ФОНОВАЯ РАБОТА") {
      SectionItemView(click = { HearthHuawei.openLaunchSettings(context) }) {
        Text(if (HearthHuawei.isHuawei) "Разрешить работу в фоне (Huawei)" else "Приложение в настройках системы")
      }
      SectionTextFooter(
        if (HearthHuawei.isHuawei) HearthHuawei.FOOTER
        else "Если сообщения приходят только при открытии приложения, проверьте, что системе разрешено держать его в фоне."
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
          val checker = HearthUpdateChecker(
            transport = transport,
            installedVersionCode = installed,
            pinnedKey = HearthReleaseKey.pinned(context),
            verify = HearthReleaseKey::verify,
            lastSeenIssued = ChatController.appPrefs.hearthLastManifestIssued.get()?.ifBlank { null },
            rememberIssued = { ChatController.appPrefs.hearthLastManifestIssued.set(it) },
          )
          when (val r = checker.check()) {
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

    // --- новое устройство ----------------------------------------------------------
    //
    // Здесь была кнопка «Пригласить устройство»: узел заводил запись и отдавал QR с
    // паролями релеев. Этот путь отменён (ADR 0012) по двум причинам. Первая — QR
    // содержал самый ценный секрет контура, и одно случайное касание отправляло его
    // в галерею или облако. Вторая — заведение с чужого устройства обходило учёт:
    // любой действующий телефон бессрочно плодил новые, и отзыв исходного их не гасил.
    //
    // Новое устройство заводится кодом доступа, который выдают лично.
    SectionView("НОВОЕ УСТРОЙСТВО") {
      SectionTextFooter(
        "Новый телефон или компьютер заводится кодом доступа: поставьте на нём " +
          "приложение и введите код при первом запуске. Код выдаёт владелец узла — " +
          "по одному на устройство."
      )
    }
    SectionDividerSpaced()

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
