package chat.hearth

import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation

/**
 * Показ кода доступа группами по четыре, без вмешательства в сам код.
 *
 * # Зачем
 *
 * Сначала поле хранило код без дефисов, а показывало с ними — значение форматировалось
 * прямо при отрисовке. Выглядело правильно, работало отвратительно: после каждой
 * правки курсор уезжал не туда, знаки вставлялись не в том порядке, и человеку
 * приходилось тыкать в строку, чтобы продолжить набор. Ровно на том экране, который
 * он видит один раз в жизни и где ошибаться нельзя.
 *
 * Причина простая: когда показанный текст длиннее хранимого, система не знает, куда
 * ставить курсор, — а мы ей не сказали.
 *
 * # Как правильно
 *
 * Поле хранит ровно то, что ввёл человек, — двенадцать знаков без дефисов. Дефисы
 * добавляются только при отображении, вместе с пересчётом позиции курсора в обе
 * стороны. Арифметика вынесена в [HearthAccessCode] и покрыта тестами: проверять её
 * на телефоне пальцами — то же самое, что не проверять.
 */
object HearthCodeTransformation : VisualTransformation {

  override fun filter(text: AnnotatedString): TransformedText {
    val code = text.text.take(HearthAccessCode.LENGTH)
    return TransformedText(
      AnnotatedString(HearthAccessCode.formatGroups(code)),
      object : OffsetMapping {
        /** Где знак из кода окажется в показанной строке. */
        override fun originalToTransformed(offset: Int): Int =
          HearthAccessCode.displayOffset(offset).coerceAtMost(
            HearthAccessCode.formatGroups(code).length
          )

        /** И обратно — куда попадёт курсор, поставленный в показанной строке. */
        override fun transformedToOriginal(offset: Int): Int =
          HearthAccessCode.codeOffset(offset).coerceAtMost(code.length)
      },
    )
  }
}
