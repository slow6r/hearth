#!/usr/bin/env bash
# Сборка ntf-server для узла: simplexmq v7.0.1 + патчи из relays/ntf/patches (ADR 0016).
#
#   relays/ntf/build-ntf-server.sh          # результат — relays/ntf/dist/
#
# ГДЕ ЗАПУСКАТЬ. На рабочей станции с Docker, НЕ на узле: у узла нет egress, а сборке
# нужны GHC и несколько сотен пакетов Hackage. Образ — linux/amd64 (узел x86_64); на Mac
# с Docker Desktop он работает так же.
#
# ПОЧЕМУ НЕ РЕЛИЗНЫЙ БИНАРЬ. `ntf-server-ubuntu-22_04-x86-64` из релиза upstream шлёт
# пуши только приложению SimpleX: команда и bundle ID зашиты в код
# (Notifications/Server/Push/APNS.hs, defaultAPNSPushClientConfig). Патч делает их
# настраиваемыми через APNS_TEAM_ID и APNS_TOPIC; без переменных поведение прежнее.
#
# ЧТО ЗАКРЕПЛЕНО, А ЧТО НЕТ.
#   закреплено:   коммит тега; базовый образ (digest); ghcup (sha256); версии GHC и cabal
#                 (как в Dockerfile upstream); индекс Hackage (index-state в cabal.project
#                 upstream); git-зависимости (коммиты в cabal.project upstream);
#   НЕ закреплено: apt-пакеты сборочного образа — -dev библиотеки из текущего архива
#                 Ubuntu 22.04. Они влияют на линковку, а не на код, но побитовой
#                 повторяемости это не даёт, да GHC её и не обещает.
# Поэтому доверие держится не на повторяемости сборки, а на манифесте: хеш того, что
# собрали и проверили, пиннится на узле (hearthctl manifest pin), и A12 ловит любую
# подмену после.
#
# ПОЛНЫМ ПРОГОНОМ СКРИПТ НЕ ПРОВЕРЕН: сборка идёт часы. Первая настоящая сборка — повод
# поправить его, если в цепочке что-то сдвинулось.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TAG=v7.0.1
COMMIT=27a37387be98d9c7ec0e62373e125539675d0095
REPO=https://github.com/simplex-chat/simplexmq.git
# Ubuntu 22.04 — на нём upstream собирает релизные бинари (.github/workflows/build.yml).
# glibc там старше, чем в Debian 13 на узле, поэтому бинарь на узле запустится.
IMAGE=ubuntu:22.04@sha256:829f6df217bcbae2b371026e81711d1a787c61b2967ad09d015063663ebafbf7
GHC_VERSION=9.6.3
CABAL_VERSION=3.12.1.0
GHCUP_VERSION=0.1.50.2
GHCUP_SHA256=ff6288df9758211372d8242fe830d8e6be6a8365d9406f1c9bde144b7e744143
OUT="${OUT:-$HERE/dist}"

command -v docker >/dev/null || { echo "нужен docker" >&2; exit 1; }
command -v git    >/dev/null || { echo "нужен git" >&2; exit 1; }
if command -v sha256sum >/dev/null; then
    SUM=(sha256sum)
else
    SUM=(shasum -a 256)
fi

shopt -s nullglob
patches=("$HERE"/patches/*.patch)
shopt -u nullglob
[[ ${#patches[@]} -gt 0 ]] || { echo "нет патчей в $HERE/patches" >&2; exit 1; }
VERSION_LABEL="$TAG+hearth.${#patches[@]}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== 1. simplexmq $TAG"
git clone --quiet --depth 1 --branch "$TAG" "$REPO" "$WORK/simplexmq"
ACTUAL="$(git -C "$WORK/simplexmq" rev-parse HEAD)"
if [[ "$ACTUAL" != "$COMMIT" ]]; then
    echo "!! тег $TAG указывает на $ACTUAL, а не на $COMMIT." >&2
    echo "   Тег в upstream перевесили — разбираться до сборки, а не после." >&2
    exit 1
fi

echo "== 2. патчи"
for patch in "${patches[@]}"; do
    git -C "$WORK/simplexmq" apply --check "$patch"
    git -C "$WORK/simplexmq" apply "$patch"
    echo "   $(basename "$patch")"
done
git -C "$WORK/simplexmq" diff --stat | tail -1

echo "== 3. сборка в контейнере (первая — часы)"
# Heredoc без кавычек: версии и хеши подставляются здесь, а экранированное (\$) уходит
# в Dockerfile как есть и раскрывается уже внутри образа.
cat > "$WORK/Dockerfile" <<DOCKERFILE
FROM $IMAGE
ENV DEBIAN_FRONTEND=noninteractive
# То же, что ставит Dockerfile.build upstream, плюс то, что нужно бинарным сборкам GHC.
RUN apt-get update && apt-get install -y --no-install-recommends \\
        ca-certificates curl git build-essential pkg-config \\
        libgmp-dev libffi-dev libncurses-dev libtinfo5 zlib1g-dev libnuma-dev \\
        libssl-dev libpq-dev llvm \\
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /usr/local/bin/ghcup \\
        https://downloads.haskell.org/~ghcup/$GHCUP_VERSION/x86_64-linux-ghcup-$GHCUP_VERSION \\
    && echo "$GHCUP_SHA256  /usr/local/bin/ghcup" | sha256sum -c - \\
    && chmod 0755 /usr/local/bin/ghcup
ENV GHCUP_INSTALL_BASE_PREFIX=/opt
ENV PATH=/opt/.ghcup/bin:\$PATH
RUN ghcup install ghc $GHC_VERSION --set && ghcup install cabal $CABAL_VERSION --set
COPY simplexmq /src
WORKDIR /src
# server_postgres — не выбор: без этого флага исполняемый ntf-server в v7.0.1 не
# собирается вовсе (simplexmq.cabal: buildable: False).
RUN cabal update && cabal build --jobs exe:ntf-server -fserver_postgres
RUN bin="\$(find dist-newstyle -type f -name ntf-server -perm -u+x | head -1)" \\
    && install -m 0755 "\$bin" /ntf-server \\
    && strip /ntf-server \\
    && ldd /ntf-server > /ntf-server.ldd
DOCKERFILE

IMAGE_TAG="hearth-ntf-build:$TAG"
docker build --platform linux/amd64 -t "$IMAGE_TAG" "$WORK"

echo "== 4. результат"
mkdir -p "$OUT"
cid="$(docker create --platform linux/amd64 "$IMAGE_TAG")"
docker cp "$cid:/ntf-server" "$OUT/ntf-server"
docker cp "$cid:/ntf-server.ldd" "$OUT/ntf-server.ldd"
docker rm "$cid" >/dev/null

DIGEST="$("${SUM[@]}" "$OUT/ntf-server" | cut -d' ' -f1)"
# Паспорт сборки: по нему бинарь сопоставляется с исходниками без переписки.
{
    echo "version=$VERSION_LABEL"
    echo "simplexmq_commit=$COMMIT"
    echo "image=$IMAGE"
    echo "ghc=$GHC_VERSION"
    echo "cabal=$CABAL_VERSION"
    echo "ghcup=$GHCUP_VERSION"
    for patch in "${patches[@]}"; do
        echo "patch=$(basename "$patch") $("${SUM[@]}" "$patch" | cut -d' ' -f1)"
    done
    echo "sha256=$DIGEST"
} > "$OUT/ntf-server.build-info.txt"
cat "$OUT/ntf-server.build-info.txt"

cat <<NEXT

== Дальше (docs/runbook-ntf.md)
   Библиотеки, которые бинарь ждёт на узле — $OUT/ntf-server.ldd. Обычно это
   libpq5, libgmp10, libnuma1, zlib1g: apt install на узле.

   Перенос — USB, как у релеев:
     install -m 0755 ntf-server /usr/local/bin/ntf-server
     hearthctl manifest pin --name ntf-server --version $VERSION_LABEL

   Образ $IMAGE_TAG остался в Docker (несколько ГБ): следующая сборка пойдёт
   быстрее. Не нужен — docker image rm $IMAGE_TAG.
NEXT
