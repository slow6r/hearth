# 0108 — Дефолты: приватный роутинг, блокировка

## Что делаем
1. Private message routing = `Always` по умолчанию: и в зарегистрированных дефолтах
   группы, и в `withDefault` у `networkSMPProxyModeGroupDefault`. Bundle тоже ставит
   `always` при применении.
2. Предложение включить блокировку приложения показывается при втором запуске после
   онбординга, без условия upstream «больше двух чатов».

## Что осознанно не сделано
Исчезающие сообщения по умолчанию. android/patches/0008 их описывает, но в коде
Android-форка их нет; iOS держит паритет с тем, что реально работает. Решать для обеих
платформ разом.

## Почему
ТЗ §8.2 п.5, п.6; android/patches/0008.

## Точка интеграции
```bash
rg -n "GROUP_DEFAULT_NETWORK_SMP_PROXY_MODE|networkSMPProxyModeGroupDefault" apps/ios/SimpleXChat/AppGroup.swift
rg -n "prefLANoticeShown && prefShowLANotice" apps/ios/Shared/ContentView.swift
```
Эффективное значение берётся из группового дефолта, а не из `NetCfg.defaults` —
поэтому правка в `AppGroup.swift`, а не в `APITypes.swift`.

## Проверка
- Ручная: «Сеть и серверы → Расширенные» после чистой установки показывает Always.
