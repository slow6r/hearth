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
import androidx.compose.material.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import chat.simplex.common.model.ChatController
import chat.simplex.common.platform.chatModel
import chat.simplex.common.ui.theme.DEFAULT_PADDING
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
  val code = remember { mutableStateOf("") }
  val scope = rememberCoroutineScope()
  // Профиль уже есть — значит это не первый запуск, а восстановление из архива или
  // очистка настроек приложения системой. Человек в этом случае старый, переписка у
  // него на месте, и экран обязан выглядеть иначе: тот же «Код доступа» посреди
  // рабочего дня читается как «приложение забыло всё». См. HearthNodeSetup.
  val restored = remember { chatModel.currentUser.value != null }

  Column(
    Modifier
      .fillMaxSize()
      .verticalScroll(rememberScrollState())
      .padding(horizontal = DEFAULT_PADDING),
    horizontalAlignment = Alignment.CenterHorizontally,
  ) {
    Spacer(Modifier.height(DEFAULT_PADDING * 2))
    Text(
      if (restored) HearthNodeText.RESTORED_TITLE else HearthOnboardingText.CODE_TITLE,
      style = MaterialTheme.typography.h1,
      textAlign = TextAlign.Center,
    )
    Spacer(Modifier.height(DEFAULT_PADDING))

    if (node != null) {
      Text(
        if (restored) HearthNodeText.RESTORED_BODY else HearthOnboardingText.CODE_BODY,
        style = MaterialTheme.typography.body1,
        textAlign = TextAlign.Center,
      )
      Spacer(Modifier.height(DEFAULT_PADDING))

      OutlinedTextField(
        // В поле всегда канонический код, разбитый по четыре: человек сверяет его с
        // бумажкой, и группы для этого и нужны. Лишние знаки просто не появляются.
        // В поле — ровно то, что набрал человек. Дефисы добавляет
        // HearthCodeTransformation при отрисовке, вместе с пересчётом позиции
        // курсора: раньше значение форматировалось прямо здесь, и курсор уезжал
        // после каждой правки.
        value = code.value,
        onValueChange = { typed ->
          if (!busy.value) {
            code.value = HearthAccessCode.normalize(typed).take(HearthAccessCode.LENGTH)
            error.value = null
          }
        },
        singleLine = true,
        enabled = !busy.value,
        visualTransformation = HearthCodeTransformation,
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
                  // Цепочка приведения могла в этом процессе уже отработать и
                  // пометиться выполненной — тогда принятый сейчас bundle применить
                  // было бы некому до перезапуска приложения.
                  HearthStartup.reset()
                  if (chatModel.currentUser.value != null) {
                    // Профиль уже есть: это восстановленная из архива база, которую
                    // человек привёл сюда с плашки над списком чатов (UPD-9).
                    // Вести её в стоковый онбординг нельзя — там создают ПЕРВЫЙ
                    // профиль, а он уже создан. Ядро здесь тоже уже запущено, второй
                    // раз startChat никто не позовёт, поэтому приведение запускаем сами.
                    hearthAfterChatStarted()
                    // Устройство заведено — плашке больше не о чем напоминать.
                    HearthNodeSetup.done()
                    ChatController.appPrefs.onboardingStage.set(OnboardingStage.OnboardingComplete)
                  } else {
                    // Чистая установка: дальше — обычный онбординг upstream, без
                    // единой правки.
                    ChatController.appPrefs.onboardingStage.set(OnboardingStage.Step1_SimpleXInfo)
                  }
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
      // Сборка без вшитого адреса узла. Раньше здесь показывался сканер QR — и это
      // был единственный путь, которым экран «Настройка узла» вообще мог появиться
      // на глаза человеку. Сканера больше нет: настройка по QR отменена в пользу
      // кода доступа (ADR 0012), а показывать камеру на экране, который человек
      // видит один раз в жизни и не понимает, — худший из возможных ответов.
      Text(
        HearthOnboardingText.INCOMPLETE_BUILD,
        style = MaterialTheme.typography.body1,
        textAlign = TextAlign.Center,
      )
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

    // Выход. Только для устройства с уже существующей перепиской: на чистой установке
    // выходить некуда — там за этим экраном нет ни профиля, ни чатов.
    //
    // Без этой кнопки экран был ловушкой: код доступа требует и владельца узла, и
    // доступного узла, а «узел недоступен неделю» — обычное дело. Человек с рабочей
    // базой не видел при этом ни одного чата. Ровно тот случай, когда строгость
    // отнимает связь и не защищает ничего: переписка уже лежит на устройстве.
    if (restored && !busy.value) {
      Spacer(Modifier.height(DEFAULT_PADDING))
      TextButton(onClick = {
        ChatController.appPrefs.onboardingStage.set(OnboardingStage.OnboardingComplete)
      }) {
        Text(HearthNodeText.RESTORED_LATER, color = MaterialTheme.colors.secondary)
      }
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
