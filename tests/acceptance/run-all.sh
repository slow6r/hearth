#!/usr/bin/env bash
# Acceptance-тесты, которые можно прогнать на узле без человека с телефоном.
#
#   sudo tests/acceptance/run-all.sh
#
# Покрывает A1, A2, A3, A4, A12 (ТЗ §12). Остальные — вручную,
# см. docs/acceptance-tests.md.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
failed=0
skipped=0

run_test() {
    local script="$1"
    local name
    name="$(basename "$script")"
    printf '\n\033[1m== %s\033[0m\n' "$name"
    if bash "$script"; then
        printf '\033[32m   PASS\033[0m %s\n' "$name"
    else
        local code=$?
        if [[ $code -eq 77 ]]; then
            printf '\033[33m   SKIP\033[0m %s\n' "$name"
            skipped=$((skipped + 1))
        else
            printf '\033[31m   FAIL\033[0m %s\n' "$name"
            failed=$((failed + 1))
        fi
    fi
}

for script in "$HERE"/a[0-9][0-9]-*.sh; do
    [[ -f "$script" ]] || continue
    run_test "$script"
done

printf '\n=====================================\n'
if [[ $failed -eq 0 ]]; then
    printf 'Все выполнимые проверки пройдены'
    [[ $skipped -gt 0 ]] && printf ' (пропущено: %d)' "$skipped"
    printf '.\n'
else
    printf 'Провалено: %d, пропущено: %d\n' "$failed" "$skipped"
fi
cat <<'MANUAL'

Требуют человека (docs/acceptance-tests.md):
  A5, A9  — android/scripts/verify-apk.sh <apk>
  A6, A10 — проверка UI клиента
  A7      — выключить узел на 10 минут, отправить сообщения
  A8      — звонок при заблокированном P2P
  A11     — docs/runbook-restore-drill.md (квартально)
  A13     — docs/runbook-migration.md, раздел «Репетиция»
MANUAL

exit $([[ $failed -eq 0 ]] && echo 0 || echo 1)
