#!/usr/bin/env bash
# Воспроизводимая сборка hearthd и hearthctl для узла (REPRO-1).
#
#   hearthd/deploy/build-reproducible.sh        # результат — hearthd/dist/
#
# ГДЕ ЗАПУСКАТЬ. На рабочей станции с Docker, НЕ на узле: у узла нет egress, а сборке
# нужен crates.io. Образ — linux/amd64 (узел x86_64).
#
# ЗАЧЕМ. Независимая полная сборка не выполнялась ни разу: README и runbook описывают
# её одной строкой `cargo build --release --target x86_64-unknown-linux-musl` на чьей-
# то машине с плавающим stable. Проверить «этот бинарник собран из этого кода» второй
# парой рук было нельзя.
#
# ЧТО ЗАКРЕПЛЕНО, А ЧТО НЕТ. Честный список, как в relays/ntf/build-ntf-server.sh:
#   закреплено:   базовый образ по digest; версия rustc (RUST_VERSION ниже); все
#                 зависимости (Cargo.lock + --locked); абсолютные пути в бинарнике
#                 (--remap-path-prefix); время сборки (SOURCE_DATE_EPOCH из даты
#                 коммита); build-id (детерминированный sha1 по содержимому);
#   НЕ закреплено: версия musl-libc и пакеты apk в базовом образе. Они влияют на
#                 линковку, а не на наш код. Поэтому побайтовое совпадение ожидается,
#                 но НЕ гарантируется при смене образа: digest образа — часть паспорта
#                 ровно по этой причине.
#
# ПОЧЕМУ rust-toolchain.toml остался плавающим. `channel = "stable"` там стоит ради
# разработчиков (в том числе на Windows, где musl-таргет намеренно не подтягивается).
# Пин версии живёт здесь: сборка для узла идёт только этим скриптом, а разработчику
# менять тулчейн ради узла незачем. Это осознанный компромисс, а не недосмотр: цена —
# сборка `cargo build --release` руками воспроизводимой НЕ будет.
#
# ПОЛНЫМ ПРОГОНОМ СКРИПТ НЕ ПРОВЕРЕН: в среде, где он писался, нет Docker. Первая
# настоящая сборка — повод поправить его, если в цепочке что-то сдвинулось.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$CRATE/.." && pwd)"
OUT="${1:-$CRATE/dist}"

# Версия компилятора. Меняется здесь и больше нигде; она попадает в паспорт сборки,
# поэтому расхождение с тем, что вшито в бинарник, видно сразу.
RUST_VERSION=1.97.1
# rust:<версия>-alpine — musl по построению, без возни с целевым тулчейном.
# ЗАМЕНИТЬ на реальный digest перед первым выпуском: `docker buildx imagetools inspect
# rust:1.97.1-alpine`. Тег без digest воспроизводимости не даёт — его переписывают.
IMAGE="rust:$RUST_VERSION-alpine"
IMAGE_DIGEST="${HEARTH_RUST_IMAGE_DIGEST:-}"
[ -n "$IMAGE_DIGEST" ] && IMAGE="rust:$RUST_VERSION-alpine@$IMAGE_DIGEST"

TARGET=x86_64-unknown-linux-musl

if command -v sha256sum >/dev/null 2>&1; then
    SUM=(sha256sum)
else
    SUM=(shasum -a 256)
fi

cd "$REPO"

git rev-parse --git-dir >/dev/null 2>&1 || {
    echo "$REPO не git-репозиторий: паспорт сборки будет пустым, собирать нечего" >&2
    exit 1
}

# Тот же гейт, что у релизной сборки Android и у publish-src.sh. Сборка из
# изменённого дерева не сопоставима с исходниками, и раздавать её нельзя.
DIRTY="$(git status --porcelain)"
if [ -n "$DIRTY" ]; then
    echo "== рабочее дерево изменено:" >&2
    printf '%s\n' "$DIRTY" >&2
    if [ "${HEARTH_ALLOW_DIRTY:-0}" = "1" ]; then
        echo "ВНИМАНИЕ: HEARTH_ALLOW_DIRTY=1 — собираю из изменённого дерева." >&2
        echo "Паспорт такой сборки скажет dirty=true, и на узел её ставить нельзя." >&2
    else
        echo >&2
        echo "Закоммитьте изменения и повторите." >&2
        echo "Для заведомо черновой сборки: HEARTH_ALLOW_DIRTY=1 $0" >&2
        exit 1
    fi
fi

COMMIT="$(git rev-parse HEAD)"
# Время сборки из даты коммита: при двух прогонах одного коммита оно обязано совпасть,
# иначе сравнивать бинарники бессмысленно.
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$COMMIT")"

echo "== сборка hearthd из $COMMIT"
echo "   образ:  $IMAGE"
echo "   таргет: $TARGET"
[ -z "$IMAGE_DIGEST" ] && echo "   ВНИМАНИЕ: образ взят по тегу, без digest — воспроизводимость не гарантирована"

mkdir -p "$OUT"

# --remap-path-prefix: rustc по умолчанию вшивает абсолютные пути к исходникам и к
# registry в panic-сообщения. У другого сборщика они другие, и бинарники разойдутся
# побайтно при совершенно идентичном коде — то есть проверка «собери и сравни»
# провалилась бы не из-за подмены, а из-за имени домашнего каталога.
#
# --build-id=sha1: linker по умолчанию кладёт туда случайное значение.
#
# Каталог с исходниками монтируется только для чтения: сборка не имеет права ничего
# менять в дереве, из которого делает паспорт.
docker run --rm --platform linux/amd64 \
    -v "$REPO:/src:ro" \
    -v "$OUT:/out" \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e CARGO_HOME=/cargo \
    -e RUSTFLAGS="--remap-path-prefix=/src=/hearth --remap-path-prefix=/cargo=/cargo -C link-arg=-Wl,--build-id=sha1" \
    "$IMAGE" sh -euc '
        apk add --no-cache git musl-dev >/dev/null
        # git отказывается работать с чужим по uid деревом; выгрузки это дерево
        # только читает, поэтому исключение безопасно и ограничено этим прогоном.
        git config --global --add safe.directory /src
        rustup target add '"$TARGET"' >/dev/null
        cd /src/hearthd
        cargo build --locked --release --target '"$TARGET"'
        for b in hearthd hearthctl; do
            install -m 0755 "target/'"$TARGET"'/release/$b" "/out/$b"
        done
    '

echo "== результат"
for b in hearthd hearthctl; do
    echo "   $OUT/$b  $("${SUM[@]}" "$OUT/$b" | cut -d" " -f1)"
done

# Паспорт того же формата, что печатает сам бинарник: одно и то же число в двух местах
# — это и есть проверяемое утверждение.
INFO="$OUT/hearthd.build-info.txt"
{
    echo "image=$IMAGE"
    echo "rust_version=$RUST_VERSION"
    echo "target=$TARGET"
    echo "source_date_epoch=$SOURCE_DATE_EPOCH"
    for b in hearthd hearthctl; do
        echo "${b}_sha256=$("${SUM[@]}" "$OUT/$b" | cut -d' ' -f1)"
    done
    echo "# ниже — паспорт, вшитый в сам бинарник (hearthd build-info)"
    docker run --rm --platform linux/amd64 -v "$OUT:/out:ro" "$IMAGE" /out/hearthd build-info
} > "$INFO"
cat "$INFO"

cat <<'NEXT'

== проверка второй парой рук

   1. Чистый клон того же коммита, тот же скрипт, другая машина.
   2. sha256 обоих бинарников обязаны совпасть. Разошлись — сначала сверьте
      digest базового образа: он единственное, что здесь не пиннится по умолчанию.
   3. `commit` и `tree_sha256` в паспорте обязаны совпасть с тем, что печатает
      hearthd build-info на узле.

== что делать с результатом

   1. Скопировать dist/hearthd и dist/hearthctl на узел (USB, ТЗ §6.1).
   2. sudo ./deploy/install.sh — он сам запишет происхождение в
      /var/lib/hearth/installed.build-info и запинит хеши в манифест.
   3. tests/acceptance/a16-provenance.sh — сверка всех четырёх записей.

NEXT
