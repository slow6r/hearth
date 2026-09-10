package chat.hearth

import chat.simplex.common.model.ChatController
import chat.simplex.common.model.ChatDeleteMode
import chat.simplex.common.model.ChatInfo
import chat.simplex.common.model.ChatType
import chat.simplex.common.platform.Log
import chat.simplex.common.platform.chatModel

/**
 * Убрать карточку контакта «Ask SimpleX Team», которую заводит само ядро.
 *
 * # Что происходит без этого
 *
 * При создании профиля ядро внутри обработки `CreateActiveUser` заводит
 * предустановленную карточку контакта: имя «Ask SimpleX Team», аватар — логотип
 * SimpleX, адрес — их публичный сервер. Человек её не просил и убрать не может.
 * В списке чатов она скрыта, но видна там, куда как раз и идут за разговором —
 * в листе «Новый чат», и по нажатию телефон честно пойдёт соединяться с чужим ботом.
 *
 * # Почему это чинится здесь, а не в ядре
 *
 * Карточку создаёт Haskell, но собственного ядра у нас нет: `libsimplex` берётся
 * готовым из релиза upstream ([android/README.md](../../../../../../README.md),
 * раздел «Стратегия»), и править его исходники некуда — они не участвуют в сборке.
 * Значит лечим на своей стороне: убираем карточку из UI (patches/0020) и стираем
 * запись из базы здесь.
 *
 * Удаление идёт при каждом запуске, а не один раз: карточка заводится на КАЖДЫЙ
 * новый профиль — второй профиль, профиль-обманка для самоуничтожающего пароля,
 * профиль после восстановления из бэкапа.
 */
suspend fun hearthRemovePresetContactCards() {
  val cards = chatModel.chats.value.mapNotNull { chat ->
    val info = chat.chatInfo
    if (info is ChatInfo.Direct && info.contact.isContactCard) info.contact else null
  }
  if (cards.isEmpty()) return

  for (contact in cards) {
    // Full(notify = false): уведомлять некого — соединения нет, карточка только
    // «заготовка». notify = true заставил бы ядро попробовать достучаться до чужого
    // сервера, то есть ровно то исходящее соединение, которого мы избегаем.
    val deleted = runCatching {
      ChatController.apiDeleteChat(
        rh = null,
        type = ChatType.Direct,
        id = contact.contactId,
        chatDeleteMode = ChatDeleteMode.Full(notify = false),
      )
    }.getOrElse { e ->
      Log.w("hearth", "карточка ${contact.contactId} не удалилась: ${e.message}")
      false
    }
    if (deleted) {
      Log.d("hearth", "удалена предустановленная карточка контакта ${contact.contactId}")
    }
  }
}
