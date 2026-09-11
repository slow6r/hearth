package chat.hearth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Button
import androidx.compose.material.CircularProgressIndicator
import androidx.compose.material.MaterialTheme
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import chat.simplex.common.model.ChatController
import chat.simplex.common.ui.theme.DEFAULT_PADDING
import chat.simplex.common.views.newchat.QRCodeScanner
import chat.simplex.common.views.onboarding.OnboardingStage
import kotlinx.coroutines.launch

/**
 * Onboarding step 0 — вход по коду доступа (patches/0003, ADR 0011, ADR 0012).
 *
 * Единственный экран, который форк добавляет. Он идёт ПЕРЕД стоковым онбордингом и,
 * применив bundle, отдаёт управление upstream нетронутым — именно это делает ребейз
 * механическим (ТЗ §8.1, §8.5).
 *
 * Путей внутрь два:
 *
 *  1. **Код доступа.** Обычный случай. В сборке вшит только адрес узла, а секрет
 *     приносит человек — код, выданный лично. Без кода приложение не открывает
 *     ничего, поэтому сам файл сборки можно передавать как угодно.
 *  2. **QR.** Сборка без вшитого адреса узла. Тогда показывается сканер, как раньше.
 *
 * Сканер берётся upstream'овский. Своя камера означала бы новую зависимость, новое
 * разрешение и новую поверхность атаки ради экрана, который в жизни устройства
 * используется один раз.
 */
@Composable
fun HearthImportView() {
  // Адрес узла читается один раз: он вшит в сборку и за время экрана не изменится.
  val node = remember { hearthBakedNode() }
  val error = remember { mutableStateOf<String?>(null) }
  val busy = remember { mutableStateOf(false) }
  val showScanner = remember { mutableStateOf(true) }
  val code = remember { mutableStateOf("") }
  val scope = rememberCoroutineScope()

  Column(
    Modifier
      .fillMaxSize()
      .verticalScroll(rememberScrollState())
      .padding(horizontal = DEFAULT_PADDING),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Spacer(Modifier.height(DEFAULT_PADDING * 2))
    Text(
      if (node == null) HearthOnboardingText.TITLE else HearthOnboardingText.CODE_TITLE,
      style = MaterialTheme.typography.h1,
      textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(DEFAULT_PADDING))

    if (node != null) {
      Text(
        HearthOnboardingText.CODE_BODY,
        style = MaterialTheme.typography.body1,
        textAlign = TextAlign.Center,
      )
      Spacer(Modifier.height(DEFAULT_PADDING))

      OutlinedTextField(
        // В поле всегда канонический код, разбитый по четыре: человек сверяет его с
        // бумажкой, и группы для этого и нужны. Лишние знаки просто не появляются.
        value = HearthAccessCode.formatGroups(code.value),
        onValueChange = { typed ->
          if (!busy.value) {
            code.value = HearthAccessCode.normalize(typed).take(HearthAccessCode.LENGTH)
            error.value = null
          }
        },
        singleLine = true,
        enabled = !busy.value,
        keyboardOptions = KeyboardOptions(
          capitalization = KeyboardCapitalization.Characters,
          autoCorrect = false,
          imeAction = ImeAction.Done,
        ),
        textStyle = MaterialTheme.typography.h3.copy(textAlign = TextAlign.Center),
        modifier = Modifier.fillMaxWidth(),
      )
      Spacer(Modifier.height(DEFAULT_PADDING / 2))
      Text(
        HearthOnboardingText.CODE_HINT,
        style = MaterialTheme.typography.body2,
        textAlign = TextAlign.Center,
      )
      Spacer(Modifier.height(DEFAULT_PADDING))

      if (busy.value) {
        Text(
          HearthOnboardingText.CODE_WORKING,
          style = MaterialTheme.typography.body1,
          textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(DEFAULT_PADDING))
        CircularProgressIndicator(Modifier.size(48.dp), color = MaterialTheme.colors.secondary)
      } else {
        Button(
          onClick = {
            busy.value = true
            error.value = null
            scope.launch {
              when (val result = hearthClaimWithCode(code.value)) {
                is HearthClaimResult.Applied -> {
                  // Дальше — обычный онбординг upstream, без единой правки.
                  ChatController.appPrefs.onboardingStage.set(OnboardingStage.Step1_SimpleXInfo)
                }
                // Адрес узла был, иначе мы бы сюда не попали; на всякий случай
                // ведём себя как при отказе, а не падаем.
                is HearthClaimResult.NoNode -> {
                  error.value = HearthOnboardingText.CODE_REFUSED
                  busy.value = false
                }
                is HearthClaimResult.Failed -> {
                  error.value = result.reason
                  busy.value = false
                }
              }
            }
          },
          enabled = HearthAccessCode.isValid(code.value),
        ) {
          Text(HearthOnboardingText.CODE_BUTTON)
        }
      }
    } else {
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

        when (val result = hearthAcceptBundle(payload)) {
          is HearthImportResult.Applied -> {
            showScanner.value = false
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
