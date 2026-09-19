#!/usr/bin/env bash
# A15 — гейт режима узла: релей не поднимается в карантине/переносе (ADR 0013).
#
# Проверка НЕ трогает рабочие службы: она не останавливает и не запускает релеи и не
# пишет в /var/lib/hearth. Разрушающая половина — «записать карантин, дать
# `systemctl start smp-server` и убедиться, что юнит пропущен» — делается только на
# стенде, см. docs/acceptance-tests.md, раздел A15.
set -uo pipefail

command -v hearthctl >/dev/null || { echo "нет hearthctl — пропуск"; exit 77; }
command -v systemctl >/dev/null || { echo "нет systemctl — пропуск"; exit 77; }

status=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

gate() { hearthctl mode gate --file "$1" >/dev/null 2>&1; echo $?; }

check() {
    local what="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        echo "  ok  $what -> $actual"
    else
        echo "  !!  $what: ожидался код $expected, получен $actual"
        status=1
    fi
}

# 1. Решение гейта по содержимому файла. Отсутствие файла — обычный узел: иначе
#    первый же запуск на чистой машине встал бы колом.
check "файла режима нет" 0 "$(gate "$tmp/no-such-file.json")"

printf '{"mode":"normal","since":"2026-01-01T00:00:00Z"}' > "$tmp/normal.json"
check "режим normal" 0 "$(gate "$tmp/normal.json")"

for mode in quarantine migration maintenance; do
    printf '{"mode":"%s","since":"2026-01-01T00:00:00Z","reason":"A15"}' "$mode" > "$tmp/$mode.json"
    check "режим $mode" 1 "$(gate "$tmp/$mode.json")"
done

# Битый файл не отличим от подчищенного: fail-closed.
printf '{это не json' > "$tmp/broken.json"
check "битый файл режима" 1 "$(gate "$tmp/broken.json")"

# 2. Гейт прописан в юнитах и подхвачен systemd. Файл на диске мало что доказывает:
#    без `daemon-reload` он не действует.
for unit in smp-server xftp-server ntf-server coturn; do
    if ! systemctl cat "$unit.service" >/dev/null 2>&1; then
        echo "  --  $unit.service не установлен, пропуск"
        continue
    fi
    loaded="$(systemctl show "$unit.service" -p ExecCondition --value 2>/dev/null)"
    if [[ "$loaded" == *hearthctl* && "$loaded" == *gate* ]]; then
        echo "  ok  $unit.service спрашивает гейт режима"
    else
        echo "  !!  $unit.service стартует в обход режима: нет ExecCondition с гейтом."
        echo "      Разверните drop-in (hearthd/deploy/install.sh кладёт его каждому"
        echo "      юниту режима) и повторите: systemctl daemon-reload"
        status=1
    fi
done

# 3. Выход из запрета обязан существовать и быть локальным. Блокировка, которую нельзя
#    снять на самом узле без hearthd и без админского сертификата, однажды превратится
#    в «связи нет и не будет» (ADR 0013, docs/runbook-node-mode.md).
if hearthctl mode clear --help 2>/dev/null | grep -q -- '--local'; then
    echo "  ok  локальный выход есть: hearthctl mode clear --local"
else
    echo "  !!  нет локального снятия режима: запрет снимается только через admin API,"
    echo "      то есть при неподнявшемся hearthd — никак"
    status=1
fi

# 3a. Сломанная конфигурация НЕ глушит релеи. Гейт берёт путь по умолчанию и громко
#     говорит об этом в journal — при любом решении, включая разрешающее. Раньше
#     нечитаемый hearthd.toml давал Deny всем четырём юнитам, и `mode clear --local`
#     из этого состояния не выводил.
printf 'это не toml\n' > "$tmp/broken.toml"
if hearthctl --config "$tmp/broken.toml" mode gate 2>&1 | grep -q 'ВНИМАНИЕ'; then
    echo "  ok  сломанный hearthd.toml: гейт предупреждает и работает по пути по умолчанию"
else
    echo "  !!  сломанный hearthd.toml: нет предупреждения о подмене пути."
    echo "      Молчаливое «решил по другому файлу» — это тот же fail-open, ради"
    echo "      которого путь стали брать из конфигурации."
    status=1
fi

# 3b. Гейт обязан дождаться монтирования каталога состояния. Иначе при state_dir на
#     отдельном разделе юнит стартует раньше монтирования, гейт не находит файла
#     режима и МОЛЧА разрешает старт релея в карантине.
STATE_DIR_CFG="$(sed -n 's/^[[:space:]]*state_dir[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    /etc/hearth/hearthd.toml 2>/dev/null | head -1 || true)"
STATE_DIR_CFG="${STATE_DIR_CFG:-/var/lib/hearth}"
for unit in smp-server xftp-server ntf-server coturn; do
    systemctl cat "$unit.service" >/dev/null 2>&1 || continue
    mounts="$(systemctl show "$unit.service" -p RequiresMountsFor --value 2>/dev/null)"
    if [[ "$mounts" == *"$STATE_DIR_CFG"* ]]; then
        echo "  ok  $unit.service ждёт монтирования $STATE_DIR_CFG"
    else
        echo "  !!  $unit.service не ждёт $STATE_DIR_CFG: при отдельном разделе гейт"
        echo "      прочитает пустоту и разрешит старт в карантине."
        echo "      Лечится повторным запуском hearthd/deploy/install.sh"
        status=1
    fi
done

# 3c. Провал preflight обязан быть терминальным, а не петлёй из рестартов каждые 5 с:
#     иначе локальное снятие режима «держится» ровно до следующего запуска демона.
if systemctl cat hearthd.service >/dev/null 2>&1; then
    if [[ "$(systemctl show hearthd.service -p RestartPreventExitStatus --value 2>/dev/null)" == *78* ]]; then
        echo "  ok  hearthd не перезапускается после терминального отказа (код 78)"
    else
        echo "  !!  hearthd.service перезапускается при любом коде выхода: провал preflight"
        echo "      (нет ca.pem или manifest.toml) даст петлю карантина каждые 5 секунд"
        status=1
    fi
fi

# 4. Действующий режим узла. Путь гейт берёт из конфигурации узла — тем же способом,
#    что и демон; зашитый путь молча разрешал старт в карантине.
hearthctl mode gate >/dev/null 2>&1 && live=0 || live=$?
echo "  гейт по конфигурации узла -> $live (0 = релеям можно)"
MODE_FILE="${MODE_FILE:-/var/lib/hearth/node-mode.json}"
if [[ -e "$MODE_FILE" ]]; then
    echo "  режим на диске ($MODE_FILE): $(cat "$MODE_FILE" 2>/dev/null || echo '<не прочитан>')"
    if [[ "$(gate "$MODE_FILE")" != "$live" ]]; then
        echo "  !!  гейт по конфигурации и по $MODE_FILE отвечают по-разному:"
        echo "      paths.state_dir в /etc/hearth/hearthd.toml указывает не сюда"
        status=1
    fi
else
    echo "  ok  файла режима по умолчанию нет"
fi

exit $status
