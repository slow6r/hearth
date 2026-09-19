package chat.hearth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Выбор способа добычи подписей APK по версии Android.
 *
 * minSdk 26, а `GET_SIGNING_CERTIFICATES` и `PackageInfo.signingInfo` появились оба в
 * API 28. Раньше флаг ставился один на все версии, а поле читалось напрямую: на
 * Android 8.0/8.1 это давало NoSuchFieldError ровно в момент осмотра уже скачанного
 * файла. Сам вызов PackageManager без устройства не прогнать — а выбор ветки, который
 * и ломался, прогнать можно.
 */
class HearthApkSigningApiTest {

  @Test
  fun android_8_uses_the_legacy_signatures() {
    // 26 и 27 — Android 8.0 и 8.1, наш минимум.
    assertFalse(HearthApkSigningApi.usesSigningInfo(26))
    assertFalse(HearthApkSigningApi.usesSigningInfo(27))
    assertEquals("GET_SIGNATURES", HearthApkSigningApi.pick(26, "GET_SIGNING_CERTIFICATES", "GET_SIGNATURES"))
    assertEquals("GET_SIGNATURES", HearthApkSigningApi.pick(27, "GET_SIGNING_CERTIFICATES", "GET_SIGNATURES"))
  }

  @Test
  fun android_9_and_newer_use_signing_info() {
    assertTrue(HearthApkSigningApi.usesSigningInfo(28))
    assertTrue(HearthApkSigningApi.usesSigningInfo(35))
    assertEquals(
      "GET_SIGNING_CERTIFICATES",
      HearthApkSigningApi.pick(28, "GET_SIGNING_CERTIFICATES", "GET_SIGNATURES"),
    )
  }

  @Test
  fun the_boundary_is_api_28() {
    // Обе половины пары появились в одном API — граница обязана быть одна.
    assertEquals(28, HearthApkSigningApi.SIGNING_INFO_SINCE)
  }

  @Test
  fun the_legacy_branch_feeds_the_same_rules() {
    // Ветка для Android 8 обязана давать ТОТ ЖЕ вердикт, а не смягчённый: набор
    // отпечатков нормализован одинаково, поэтому HearthApkRules не отличает источник.
    val same = setOf("aa")
    val allow = HearthApkRules.decide(
      HearthApkRules.Facts(
        packageName = "chat.hearth",
        ownPackageName = "chat.hearth",
        versionCode = 22,
        installedVersionCode = 21,
        expectedVersionCode = 22,
        signatures = same,
        installedSignatures = same,
      )
    )
    assertEquals(HearthApkRules.Verdict.Allow, allow)

    // А пустой набор — это отказ, а не «пропустить»: именно так выглядела бы попытка
    // спросить подписи старым флагом и не разобрать ответ.
    val refuse = HearthApkRules.decide(
      HearthApkRules.Facts(
        packageName = "chat.hearth",
        ownPackageName = "chat.hearth",
        versionCode = 22,
        installedVersionCode = 21,
        expectedVersionCode = 22,
        signatures = emptySet(),
        installedSignatures = same,
      )
    )
    assertTrue(refuse is HearthApkRules.Verdict.Refuse, "получено: $refuse")
  }
}
