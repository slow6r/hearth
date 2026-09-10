package chat.hearth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.CircularProgressIndicator
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
 * Onboarding step 0 — настройка домашнего узла (patches/0003, ADR 0011).
 *
 * Единственный экран, который форк добавляет. Он идёт ПЕРЕД стоковым онбордингом и,
 * применив bundle, отдаёт управление upstream нетронутым — именно это делает ребейз
 * механическим (ТЗ §8.1, §8.5).
 *
 * Путей внутрь два, и первый обычно не виден человеку:
 *
 *  1. **Вшитое приглашение.** Если сборка раздана семье, экран сам спрашивает узел,
 *     заводится и уходит дальше. Человек видит полсекунды «настраиваем» — это и есть
 *     «поставил и пользуйся», как в SimpleX.
 *  2. **QR.** Обычная сборка, или приглашение кончилось. Тогда показывается сканер.
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
  // Пока не знаем, есть ли приглашение, — не показываем ни сканер, ни объяснение про
  // QR: иначе человек со вшитым приглашением увидит вспышку камеры и текст, которые
  // через мгновение исчезнут.
  val autoSetUp = remember { mutableStateOf(true) }

  LaunchedEffect(Unit) {
    when (val result = hearthAutoSetUp()) {
      is HearthClaimResult.Applied -> {
        // Дальше — обычный онбординг upstream, без единой правки.
        ChatController.appPrefs.onboardingStage.set(OnboardingStage.Step1_SimpleXInfo)
      }
      is HearthClaimResult.NoInvite -> autoSetUp.value = false
      is HearthClaimResult.Failed -> {
        // Приглашение было, но не сработало: сеть, просроченный токен, полный узел.
        // Человека не оставляем в тупике — показываем сканер и причину.
        error.value = result.reason
        autoSetUp.value = false
      }
    }
  }

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

    if (autoSetUp.value) {
      Text(
        HearthOnboardingText.AUTO_BODY,
        style = MaterialTheme.typography.body1,
        textAlign = TextAlign.Center,
      )
      Spacer(Modifier.height(DEFAULT_PADDING * 2))
      CircularProgressIndicator(Modifier.size(48.dp), color = MaterialTheme.colors.secondary)
      Spacer(Modifier.height(DEFAULT_PADDING * 2))
      return@Column
    }

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
