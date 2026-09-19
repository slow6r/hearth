package chat.hearth

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import chat.simplex.common.model.ChatController
import chat.simplex.common.ui.theme.DEFAULT_PADDING
import chat.simplex.common.ui.theme.DEFAULT_PADDING_HALF
import chat.simplex.common.views.helpers.AppBarHeight
import chat.simplex.common.views.onboarding.OnboardingStage

/**
 * Плашка «телефон не подключён к домашнему узлу» над списком чатов.
 *
 * Разбор — в шапке [HearthNodeSetup]. Здесь только показ: правка в дереве форка
 * (`views/chatlist/ChatListView.kt`) — одна строка, и потому переживает ребейз.
 *
 * Не чистая (Compose, настройки) и потому не покрыта commonTest; правило видимости —
 * [hearthNodeBannerVisible], и оно проверяется тестом.
 *
 * @param oneHandUI режим «управление одной рукой»: панель инструментов внизу, значит
 *   плашке место вверху, и наоборот. Иначе она накрыла бы панель.
 */
@Composable
fun HearthNodeBanner(oneHandUI: Boolean) {
  HearthNodeSetup.load()
  val visible = hearthNodeBannerVisible(
    notOnNode = HearthNodeSetup.notOnNode.value,
    dismissedDay = HearthNodeSetup.dismissedDay.value,
    today = hearthNowEpochDays(),
  )
  if (!visible) return

  Box(Modifier.fillMaxSize()) {
    Column(
      Modifier
        .align(if (oneHandUI) Alignment.TopCenter else Alignment.BottomCenter)
        // Отступ на ту сторону, где стоит панель инструментов списка чатов.
        .padding(
          top = if (oneHandUI) DEFAULT_PADDING_HALF else 0.dp,
          bottom = if (oneHandUI) 0.dp else AppBarHeight + DEFAULT_PADDING_HALF,
        )
        .padding(horizontal = DEFAULT_PADDING_HALF)
        .clip(RoundedCornerShape(16.dp))
        .background(MaterialTheme.colors.background)
        .border(1.dp, MaterialTheme.colors.primary, RoundedCornerShape(16.dp))
        .padding(DEFAULT_PADDING_HALF),
    ) {
      Text(
        HearthNodeText.BANNER_TITLE,
        style = MaterialTheme.typography.subtitle1,
        color = MaterialTheme.colors.onBackground,
      )
      Spacer(Modifier.height(DEFAULT_PADDING_HALF / 2))
      Text(
        HearthNodeText.BANNER_BODY,
        style = MaterialTheme.typography.body2,
        color = MaterialTheme.colors.onBackground,
      )
      Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.End,
      ) {
        // «Позже» стоит первой и выглядит скромнее: выход должен быть виден сразу, но
        // подсказывать надо действие, а не откладывание.
        TextButton(onClick = { HearthNodeSetup.dismiss() }) {
          Text(HearthNodeText.BANNER_LATER, color = MaterialTheme.colors.secondary)
        }
        Spacer(Modifier.width(DEFAULT_PADDING_HALF))
        TextButton(onClick = { hearthOpenNodeSetup() }) {
          Text(HearthNodeText.BANNER_CONNECT, color = MaterialTheme.colors.primary)
        }
      }
    }
  }
}

/**
 * Открыть экран подключения к узлу.
 *
 * Тем же способом, что и раньше, — через `onboardingStage`. Разница в том, КТО это
 * решает: раньше ветка запуска на каждом старте, теперь человек нажатием. Выход с
 * экрана есть (`HearthImportView`, кнопка «Позже, к чатам»), поэтому запереть себя
 * этим нажатием нельзя.
 */
fun hearthOpenNodeSetup() {
  runCatching { ChatController.appPrefs.onboardingStage.set(OnboardingStage.Step0_HearthImport) }
}
