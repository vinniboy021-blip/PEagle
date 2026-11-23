#!/usr/bin/env bash
set -euo pipefail

RESULTS_DIR="/lab/results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$RESULTS_DIR/report_$TIMESTAMP.txt"

TOTAL_PASS=0
TOTAL_FAIL=0
SUITE_RESULTS=()

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  PEagle — Test Lab                                               ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo "  Script: /lab/PEagle.ps1"
echo "  Data  : $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

run_suite() {
    local suite_file="$1"
    local suite_name=$(basename "$suite_file" .ps1)
    echo "──────────────────────────────────────────────────────────────────"
    echo "  Rodando: $suite_name"
    echo "──────────────────────────────────────────────────────────────────"

    local out
    local exit_code=0
    out=$(pwsh -NoProfile -NonInteractive -File "$suite_file" \
               -ScriptPath /lab/PEagle.ps1 2>&1) || exit_code=$?

    echo "$out"
    echo "$out" >> "$REPORT"

    # Extrair contagem da ultima linha de resultado
    local pass fail
    pass=$(echo "$out" | grep -oP '(?<=Resultado: )\d+(?= pass)' | tail -1 || echo 0)
    fail=$(echo "$out" | grep -oP '(?<=/ )\d+(?= fail)' | tail -1 || echo 0)
    pass=${pass:-0}
    fail=${fail:-0}

    TOTAL_PASS=$((TOTAL_PASS + pass))
    TOTAL_FAIL=$((TOTAL_FAIL + fail))

    if [ "$fail" -eq 0 ]; then
        SUITE_RESULTS+=("  ✓ $suite_name ($pass pass)")
    else
        SUITE_RESULTS+=("  ✗ $suite_name ($pass pass / $fail fail)")
    fi
    echo ""
}

# Rodar todas as suites em ordem
for f in /lab/tests/0*.ps1; do
    run_tests_output=$(run_suite "$f")
    echo "$run_tests_output"
done

# Sumario final
echo "══════════════════════════════════════════════════════════════════"
echo "  SUMARIO"
echo "══════════════════════════════════════════════════════════════════"
for r in "${SUITE_RESULTS[@]}"; do
    echo "$r"
done
echo ""
echo "  Total : $TOTAL_PASS pass / $TOTAL_FAIL fail"
echo ""

if [ "$TOTAL_FAIL" -eq 0 ]; then
    echo "  RESULTADO FINAL: TODOS OS TESTES PASSARAM"
    echo "══════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Relatorio salvo: $REPORT"
    exit 0
else
    echo "  RESULTADO FINAL: $TOTAL_FAIL TESTE(S) FALHARAM"
    echo "══════════════════════════════════════════════════════════════════"
    echo ""
    echo "  Relatorio salvo: $REPORT"
    exit 1
fi
