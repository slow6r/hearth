# Политика конфиденциальности Hearth

Дата последнего изменения: 22 сентября 2026 года.

*English version below.*

## Коротко

Hearth не собирает о вас никаких данных. У приложения нет ни сервера разработчика, ни
аналитики, ни рекламы. Переписка идёт через домашний узел, который держит тот, кто вас
пригласил, и больше никуда.

## Кто обрабатывает данные

Разработчик приложения не получает и не хранит ничего. Приложение не обращается ни к
каким серверам, кроме одного домашнего узла, адрес которого вшит в сборку.

Узел принадлежит не нам, а тому человеку или семье, которые его установили. Мы к нему
доступа не имеем.

## Что собирает приложение

Ничего. У Hearth нет учётных записей: не нужны ни номер телефона, ни адрес электронной
почты, ни имя пользователя. Регистрации не существует — приложение открывается по коду
доступа, который вам выдали лично.

Мы не используем аналитику, не показываем рекламу, не встраиваем счётчики и трекеры.

## Где хранятся ваши данные

**На вашем устройстве.** Сообщения, файлы и профиль лежат в локальной базе приложения.
При удалении приложения они удаляются вместе с ним.

**На домашнем узле.** Узел передаёт зашифрованные сообщения между устройствами. Он не
может прочитать их содержимое: шифрование сквозное, ключи есть только у собеседников.

## Шифрование

Hearth основан на SimpleX Chat и использует его протокол со сквозным шифрованием.
Содержимое сообщений недоступно ни разработчику, ни владельцу узла, ни кому-либо между
вами и собеседником.

## Уведомления

Когда в приложении включены push-уведомления, они доставляются через службу Apple Push
Notification service. В этом случае Apple получает технический идентификатор устройства.
Содержимое сообщений в уведомлениях не передаётся: push сообщает только о том, что для
вас что-то есть, а расшифровка происходит на устройстве.

## Передача данных третьим лицам

Не передаём, потому что не собираем.

## Дети

Приложение не предназначено для самостоятельного использования детьми младше
установленного возраста и не собирает данные детей.

## Исходный код

Приложение с открытым исходным кодом, лицензия AGPLv3. Наши изменения опубликованы:
<https://github.com/slow6r/hearth>. Проверить сказанное здесь можно по коду.

## Изменения

Если политика изменится, новая редакция будет опубликована по этому же адресу с новой
датой.

## Связь

Вопросы — через раздел Issues репозитория: <https://github.com/slow6r/hearth/issues>

---

# Privacy Policy for Hearth

Last updated: 22 September 2026.

## Summary

Hearth collects no data about you. There is no developer server, no analytics and no
advertising. Messages travel through a home server run by the person who invited you,
and nowhere else.

## Who processes data

The developer receives and stores nothing. The app contacts no servers other than the
single home node whose address is built into the app.

That node belongs to the person or family who set it up, not to us. We have no access
to it.

## What the app collects

Nothing. Hearth has no accounts: no phone number, no email address, no username. There
is no sign-up — the app is opened with an access code given to you in person.

We use no analytics, show no advertising and embed no trackers.

## Where your data is stored

**On your device.** Messages, files and your profile are stored in the app's local
database and are deleted when the app is deleted.

**On the home node.** The node relays encrypted messages between devices. It cannot
read their content: encryption is end-to-end and the keys exist only on the devices of
the people talking.

## Encryption

Hearth is based on SimpleX Chat and uses its end-to-end encrypted protocol. Message
content is not available to the developer, to the node operator, or to anyone between
you and the person you are talking to.

## Notifications

When push notifications are enabled, they are delivered through the Apple Push
Notification service, and Apple receives a technical device identifier. Message content
is not sent in the push: it only signals that something is waiting, and decryption
happens on the device.

## Sharing with third parties

We share nothing, because we collect nothing.

## Children

The app is not directed at children below the applicable age and collects no data from
children.

## Source code

The app is open source under AGPLv3. Our changes are published at
<https://github.com/slow6r/hearth> and everything stated here can be verified in the
source.

## Changes

If this policy changes, the new version will be published at this address with a new
date.

## Contact

Questions: through the repository issue tracker at
<https://github.com/slow6r/hearth/issues>
