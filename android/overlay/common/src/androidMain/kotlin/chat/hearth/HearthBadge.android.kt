package chat.hearth

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import chat.simplex.common.platform.chatModel

/**
 * Число непрочитанных на иконке приложения.
 *
 * # Как это устроено в Android
 *
 * Единого способа нет. Большинство лаунчеров (Samsung, Xiaomi, Pixel — точкой) берут
 * число из `setNumber()` уведомления, и это делает `NtfManager`. Huawei и Honor число из
 * уведомления не читают вовсе: их лаунчер ждёт отдельный вызов своего провайдера
 * `content://com.huawei.android.launcher.settings/badge/` (старые EMUI — рассылку
 * `CHANGE_BADGE`), и на это нужно разрешение `com.huawei.android.launcher.permission.CHANGE_BADGE`
 * в манифесте. Без вызова на Huawei число не появится никогда — а Huawei в семье
 * одиннадцать из тринадцати.
 *
 * # Когда обновляется
 *
 *   * при каждом показанном уведомлении о сообщении — число выросло;
 *   * при выходе приложения на передний план и при уходе с него — человек прочитал
 *     сообщения, число должно упасть; ловить каждое «прочитано» внутри чата незачем,
 *     на иконку смотрят снаружи приложения.
 *
 * Считаются только чаты с включёнными уведомлениями: если человек чат заглушил, число
 * на иконке не должно его дёргать так же, как не дёргает уведомление.
 */
object HearthBadge {

  fun totalUnread(): Int = try {
    chatModel.chats.value.sumOf { chat ->
      // Те же правила, что у уведомлений: ntfsEnabled(userMention) решает, дёргать ли
      // человека. Заглушённый чат — ноль; «только упоминания» — только упоминания.
      val info = chat.chatInfo
      when {
        info.ntfsEnabled(userMention = false) -> chat.chatStats.unreadCount
        info.ntfsEnabled(userMention = true) -> chat.chatStats.unreadMentions
        else -> 0
      }
    }
  } catch (_: Exception) {
    0
  }

  fun sync(context: Context) = apply(context, totalUnread())

  fun apply(context: Context, count: Int) {
    if (!HearthHuawei.isHuawei) return
    val launcher = context.packageManager
      .getLaunchIntentForPackage(context.packageName)?.component?.className ?: return
    val n = HearthBadgeTargets.badgeNumber(count)
    try {
      context.contentResolver.call(
        Uri.parse("content://com.huawei.android.launcher.settings/badge/"),
        "change_badge",
        null,
        Bundle().apply {
          putString("package", context.packageName)
          putString("class", launcher)
          putInt("badgenumber", n)
        },
      )
    } catch (_: Exception) {
      // Старые EMUI: провайдера нет, работает рассылка.
      broadcast(context, launcher, n)
    }
  }

  /**
   * Рассылка о значке — только названному лаунчеру.
   *
   * Раньше здесь был неявный intent: система разносила его любому receiver'у с подходящим
   * фильтром, и постороннее приложение, уже работающее на телефоне, читало из него имя
   * нашего пакета и число непрочитанных. Содержимого сообщений там нет, но сам факт
   * «Очагом пользуются, непрочитанных семь» — тоже не его дело.
   *
   * setPackage на каждый известный лаунчер: получателей у такой рассылки ровно столько,
   * сколько названо, а подделать имя системного пакета на устройстве нельзя. Слать в цикле
   * дёшево — лишний пакет просто не найдётся, исключения на этом пути нет.
   *
   * receiverPermission (CHANGE_BADGE) сюда сознательно НЕ добавлен: это разрешение
   * лаунчер требует от отправителя (потому оно и стоит в нашем манифесте), а в
   * receiverPermission оно означало бы обратное — что им владеет сам лаунчер. Проверить
   * это можно только на живом EMUI, а ошибка стоит молча переставшего обновляться значка
   * у тех, у кого нет провайдера. Адресность уже даёт setPackage.
   *
   * Список адресатов берётся через [HearthBadgeTargets.broadcastTargets], а не напрямую:
   * фильтр отбрасывает строку, которая адресом не является (пустая, с опечаткой), — иначе
   * `setPackage("")` выглядел бы адресацией, ею не будучи. Проверка стоит на пути рассылки,
   * а не рядом с ним.
   */
  private fun broadcast(context: Context, launcher: String, n: Int) {
    for (pkg in HearthBadgeTargets.broadcastTargets()) {
      try {
        context.sendBroadcast(
          Intent(HearthBadgeTargets.CHANGE_BADGE).apply {
            setPackage(pkg)
            putExtra("package", context.packageName)
            putExtra("class", launcher)
            putExtra("badgenumber", n)
          }
        )
      } catch (_: Exception) {
        // лаунчер не Huawei или без поддержки — число покажет уведомление
      }
    }
  }
}
