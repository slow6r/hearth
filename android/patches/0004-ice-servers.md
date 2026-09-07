# 0004 — ICE-серверы: только свой coturn

## Что делаем
Публичные STUN/TURN из дефолтов звонков удаляем. ICE-конфиг берётся из bundle.

## Почему
Клиент, ушедший на `stun.simplex.im` или `stun.l.google.com`, раскрывает свой реальный
адрес третьей стороне.

**Fallback'а быть не должно.** Если ICE пуст — звонок должен честно не состояться.
Молчаливый откат на публичный STUN хуже неработающего звонка.

## Формат — это главное в этом патче

Клиент хранит ICE-серверы **строкой** и разбирает её так
(`views/call/WebRTC.kt`, v7.0.1):

```kotlin
// turn:USER:CRED@host:port  ->  "turn://USER:CRED@host:port"  ->  URI(...)
val userInfo = u.userInfo?.split(":")
if (u.path == "" && scheme in setOf("stun","stuns","turn","turns")) { ... }
```

Отсюда три жёстких ограничения, которые обязан соблюдать и узел, и этот патч:

1. **username без `:`** — иначе `split(":")` сдвинет границы полей. hearthd использует
   голый timestamp, а не `<expiry>:<userid>`.
2. **credential без `/`** — `/` начинает path, `u.path == ""` становится ложным, запись
   отбрасывается. hearthd подбирает timestamp, у которого base64 HMAC не содержит `/`.
3. **Одна плохая запись убивает весь список.** `parseRTCIceServers` возвращает `null`,
   и клиент берёт `defaultIceServers` — то есть **публичные** серверы SimpleX. Ошибка
   формата приводит не к сломанным звонкам, а к тихой утечке на третью сторону.

Именно поэтому валидация формата продублирована в `HearthBundle.kt`, а не оставлена
на узле.

## Точка интеграции
```bash
rg -n "defaultIceServers|parseRTCIceServers|WebRTC.kt" apps/multiplatform/common/src
```

Значение по умолчанию → `HearthPresets.defaultIceServers(appliedBundle)`; список
приходит из bundle уже в правильном строковом виде и передаётся в
`parseRTCIceServers` как есть.

## Проверка
- A8: звонок между двумя устройствами в разных сетях; среди кандидатов только `node.host`.
- `rg "stun\.l\.google\.com|stun\.simplex\.im" apps/` — пусто.
- `HearthBundleTest.rejectsAPublicStun`, `rejectsCredentialsTheClientWouldDiscard`.
