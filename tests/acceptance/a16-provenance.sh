#!/usr/bin/env bash
# A16 — цепочка «работающий процесс → файл на диске → коммит» замкнута.
#
# Проверяется не наличие бумажки, а совпадение ЧЕТЫРЁХ независимо полученных чисел:
#
#   1. sha256 файла /usr/local/bin/hearthd                    (измерение диска)
#   2. sha256, записанный при установке в installed.build-info (журнал установки)
#   3. sha256, запиненный в /etc/hearth/manifest.toml          (утверждение)
#   4. exe_sha256, который называет сам работающий процесс     (журнал демона)
#
# Плюс коммит: он обязан быть один и тот же в паспорте бинарника, в журнале установки
# и в манифесте.
#
# До появления build.rs и `hearthd build-info` ни одного из этих чисел, кроме первого,
# не существовало: установленный демон умел сообщить о себе строку `0.1.0`, одинаковую
# для любой сборки любого коммита за всю историю ветки.
set -uo pipefail

# Пути переопределяются переменными: так эту же проверку можно прогнать на стенде и
# на распакованной копии, не притворяясь узлом.
BIN="${HEARTHD_BIN:-/usr/local/bin/hearthd}"
LOG="${HEARTH_BUILD_LOG:-/var/lib/hearth/installed.build-info}"
MANIFEST="${MANIFEST:-/etc/hearth/manifest.toml}"

[[ -x "$BIN" ]] || { echo "нет $BIN — пропуск"; exit 77; }

status=0
bad() { echo "  !! $*"; status=1; }

is_hex() { [[ "$2" =~ ^[0-9a-f]{$1}$ ]]; }

# --- 1. что лежит на диске ---------------------------------------------------
DISK="$(sha256sum "$BIN" | cut -d' ' -f1)"
echo "  файл на диске:      $DISK"

# --- 2. что говорит о себе сам файл ------------------------------------------
if ! INFO="$("$BIN" build-info 2>&1)"; then
    echo "  !! $BIN не умеет build-info — это сборка до появления паспорта."
    echo "     Пересоберите: hearthd/deploy/build-reproducible.sh"
    exit 1
fi
COMMIT="$(grep '^commit=' <<<"$INFO" | cut -d= -f2-)"
TREE="$(grep '^tree_sha256=' <<<"$INFO" | cut -d= -f2-)"
DIRTY="$(grep '^dirty=' <<<"$INFO" | cut -d= -f2-)"
SELF="$(grep '^exe_sha256=' <<<"$INFO" | cut -d= -f2-)"
echo "  коммит:             $COMMIT"
echo "  хеш дерева:         $TREE"

is_hex 40 "$COMMIT" || bad "коммит не записан ($COMMIT): сборка не сопоставима с исходниками"
is_hex 64 "$TREE"   || bad "хеш дерева не записан ($TREE)"
[[ "$DIRTY" == "false" ]] || bad "узел работает на сборке из ИЗМЕНЁННОГО дерева (dirty=$DIRTY)"
[[ "$SELF" == "$DISK" ]]  || bad "файл назвал чужой хеш: $SELF против $DISK"

# --- 3. журнал установки -----------------------------------------------------
if [[ -f "$LOG" ]]; then
    # Берём блок [hearthd] — в файле накапливаются все установки, нужна последняя.
    BLOCK="$(awk '/^\[hearthd\]$/{buf=""} /^\[hearthd\]$/,/^$/{buf=buf $0 "\n"} END{printf "%s", buf}' "$LOG")"
    LOG_SHA="$(grep '^sha256=' <<<"$BLOCK" | tail -1 | cut -d= -f2-)"
    LOG_COMMIT="$(grep '^commit=' <<<"$BLOCK" | tail -1 | cut -d= -f2-)"
    [[ "$LOG_SHA" == "$DISK" ]] \
        || bad "журнал установки помнит другой файл: $LOG_SHA против $DISK"
    [[ "$LOG_COMMIT" == "$COMMIT" ]] \
        || bad "журнал установки помнит другой коммит: $LOG_COMMIT против $COMMIT"
else
    bad "нет $LOG — установка прошла мимо install.sh, происхождение не записано"
fi

# --- 4. манифест -------------------------------------------------------------
if [[ -r "$MANIFEST" ]]; then
    ENTRY="$(awk '/name = "hearthd"/,/^$/' "$MANIFEST")"
    PIN_SHA="$(grep -E '^sha256' <<<"$ENTRY" | sed -E 's/.*"(.*)".*/\1/')"
    PIN_COMMIT="$(grep -E '^commit' <<<"$ENTRY" | sed -E 's/.*"(.*)".*/\1/')"
    [[ "$PIN_SHA" == "$DISK" ]] \
        || bad "манифест пиннит другой файл: $PIN_SHA против $DISK"
    if [[ -z "$PIN_COMMIT" ]]; then
        bad "в манифесте у hearthd нет коммита: hearthctl manifest pin --name hearthd"
    elif [[ "$PIN_COMMIT" != "$COMMIT" ]]; then
        bad "манифест пиннит другой коммит: $PIN_COMMIT против $COMMIT"
    fi
else
    echo "  манифест недоступен на чтение — пункт пропущен (нужен sudo)"
fi

# --- 5. работающий процесс ---------------------------------------------------
# Читаем журнал, а не /proc/<pid>/exe: последний требует ptrace, то есть права читать
# память релеев. Именно поэтому демон называет свой хеш сам при старте.
if command -v journalctl >/dev/null 2>&1; then
    RUNNING="$(journalctl -u hearthd --no-pager 2>/dev/null \
        | grep -o 'exe_sha256=[0-9a-f]\{64\}' | tail -1 | cut -d= -f2)"
    if [[ -z "$RUNNING" ]]; then
        echo "  журнал не содержит exe_sha256 — демон не перезапускался после обновления?"
    elif [[ "$RUNNING" != "$DISK" ]]; then
        bad "РАБОТАЕТ НЕ ТОТ ФАЙЛ: процесс назвал $RUNNING, на диске $DISK"
    else
        echo "  работающий процесс:  совпадает"
    fi
fi

if [[ $status -eq 0 ]]; then
    echo "  ok цепочка «процесс → файл → коммит» замкнута"
    echo
    echo "  Независимая проверка коммита (на рабочей станции, чистый клон):"
    echo "    git checkout $COMMIT && hearthd/deploy/build-reproducible.sh"
fi
exit $status
