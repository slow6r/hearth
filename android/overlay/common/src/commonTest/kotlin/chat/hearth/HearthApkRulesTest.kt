package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Таблица случаев для допуска обновления к установке.
 *
 * Проверяет ровно то, ради чего правила вынесены из платформенного кода: что будет,
 * если узел раздачи захвачен и подсовывает не то. Иначе единственным способом это
 * узнать была бы установка чужого пакета на живой телефон.
 */
class HearthApkRulesTest {

  private val ours = setOf("608e713c")

  private fun facts(
    packageName: String? = "ru.myhearth.chat",
    versionCode: Long = 387,
    installedVersionCode: Long = 386,
    expectedVersionCode: Long = 387,
    signatures: Set<String> = ours,
    installedSignatures: Set<String> = ours,
  ) = HearthApkRules.Facts(
    packageName = packageName,
    ownPackageName = "ru.myhearth.chat",
    versionCode = versionCode,
    installedVersionCode = installedVersionCode,
    expectedVersionCode = expectedVersionCode,
    signatures = signatures,
    installedSignatures = installedSignatures,
  )

  private fun refusalFor(facts: HearthApkRules.Facts): String {
    val verdict = HearthApkRules.decide(facts)
    assertTrue(verdict is HearthApkRules.Verdict.Refuse, "ожидался отказ, получено: $verdict")
    return (verdict as HearthApkRules.Verdict.Refuse).reason
  }

  @Test
  fun a_proper_update_is_allowed() {
    assertEquals(HearthApkRules.Verdict.Allow, HearthApkRules.decide(facts()))
  }

  @Test
  fun a_file_that_does_not_parse_is_refused() {
    assertTrue(refusalFor(facts(packageName = null)).contains("не разбирается"))
  }

  @Test
  fun another_application_is_refused() {
    val reason = refusalFor(facts(packageName = "com.example.other"))
    assertTrue(reason.contains("другое приложение"), reason)
  }

  @Test
  fun a_foreign_signature_is_refused() {
    // Главный случай: узел захвачен и раздаёт свою сборку.
    val reason = refusalFor(facts(signatures = setOf("deadbeef")))
    assertTrue(reason.contains("другим ключом"), reason)
  }

  @Test
  fun an_unsigned_file_is_refused() {
    assertTrue(refusalFor(facts(signatures = emptySet())).contains("нет подписи"))
  }

  @Test
  fun an_unreadable_own_signature_is_refused() {
    // Сравнивать не с чем — это не повод разрешить.
    val reason = refusalFor(facts(installedSignatures = emptySet()))
    assertTrue(reason.contains("установленного приложения"), reason)
  }

  @Test
  fun a_downgrade_is_refused() {
    // Откат возвращает уже закрытую дыру, поэтому запрещён даже со своей подписью.
    val reason = refusalFor(facts(versionCode = 385, expectedVersionCode = 385))
    assertTrue(reason.contains("не новее"), reason)
  }

  @Test
  fun the_same_version_is_refused() {
    val reason = refusalFor(facts(versionCode = 386, expectedVersionCode = 386))
    assertTrue(reason.contains("не новее"), reason)
  }

  @Test
  fun a_file_that_disagrees_with_the_manifest_is_refused() {
    // Хеш сошёлся, а содержимое другое: манифест и файл разошлись.
    val reason = refusalFor(facts(versionCode = 400, expectedVersionCode = 387))
    assertTrue(reason.contains("не та, что обещал узел"), reason)
  }

  @Test
  fun a_node_that_names_no_version_still_gets_the_other_checks() {
    // expectedVersionCode = 0 — узел не назвал версию; остальные правила в силе.
    assertEquals(
      HearthApkRules.Verdict.Allow,
      HearthApkRules.decide(facts(expectedVersionCode = 0))
    )
    assertTrue(refusalFor(facts(expectedVersionCode = 0, versionCode = 300)).contains("не новее"))
  }
}
