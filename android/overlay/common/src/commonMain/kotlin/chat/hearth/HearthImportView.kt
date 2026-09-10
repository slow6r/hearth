package chat.hearth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import chat.simplex.common.model.ChatController
import chat.simplex.common.ui.theme.DEFAULT_PADDING
import chat.simplex.common.views.newchat.QRCodeScanner
import chat.simplex.common.views.onboarding.OnboardingStage

/**
 * Onboarding step 0 — импорт bundle узла (patches/0003-onboarding-import.md).
 *
 * Единственный экран, который форк добавляет. Он идёт ПЕРЕД стоковым онбордингом и,
 * применив bundle, отдаёт управление upstream нетронутым — именно это делает ребейз
 * механическим (ТЗ §8.1, §8.5).
 *
 * Сканер берётся upstream'овский. Своя камера означала бы новую зависимость, новое
 * разрешение и новую поверхность атаки ради экрана, который в жизни устройства
 * используется один раз.
 */
@Composable
fun HearthImportView() {
  val importer = remember { HearthOnboardingImporter(HearthCoreApplier()) }
  val error = remember { mutableStateOf<String?>(null) }
  val busy = remember { mutableStateOf(false) }
  val showScanner = remember { mutableStateOf(true) }

  Column(
    Modifier
      .fillMaxSize()
      .verticalScroll(rememberScrollState())
      .padding(horizontal = DEFAULT_PADDING),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Spacer(Modifier.height(DEFAULT_PADDING * 2))
    Text(
      HearthOnboardingText.TITLE,
      style = MaterialTheme.typography.h1,
      textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(DEFAULT_PADDING))
    Text(
      HearthOnboardingText.BODY,
      style = MaterialTheme.typography.body1,
      textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(DEFAULT_PADDING))

    QRCodeScanner(showScanner) { payload ->
      // Повторные срабатывания сканера при уже идущем импорте игнорируем: applier
      // не идемпотентен, а камера отдаёт один и тот же код несколько раз подряд.
      if (busy.value) return@QRCodeScanner false
      busy.value = true
      error.value = null

      when (val result = importer.import(payload)) {
        is HearthImportResult.Applied -> {
          showScanner.value = false
          // Дальше — обычный онбординг upstream, без единой правки.
          ChatController.appPrefs.onboardingStage.set(OnboardingStage.Step1_SimpleXInfo)
          true
        }

        is HearthImportResult.Rejected -> {
          // Ошибку показываем на экране, а не всплывающим окном: человек стоит с
          // телефоном перед чужим QR, и текст должен остаться на виду, пока он
          // разбирается. Сканер оставляем включённым — можно сразу сканировать снова.
          error.value = result.reason
          busy.value = false
          false
        }
      }
    }

    val message = error.value
    if (message != null) {
      Spacer(Modifier.height(DEFAULT_PADDING))
      Text(
        message,
        color = MaterialTheme.colors.error,
        style = MaterialTheme.typography.body2,
        textAlign = TextAlign.Center,
      )
    }

    Spacer(Modifier.height(DEFAULT_PADDING))
    Text(
      HearthOnboardingText.NETWORK_HINT,
      style = MaterialTheme.typography.body2,
      textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(DEFAULT_PADDING * 2))
  }
}
