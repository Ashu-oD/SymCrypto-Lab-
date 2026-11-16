#!/usr/bin/env bash
# Runs the whole project end to end and saves output to results/run_log.txt
set -e
cd "$(dirname "$0")"
PY=${PY:-python3}
mkdir -p results
{
  echo "=== 1. Test vectors (FIPS-197, RFC 8439, Speck) ==="; $PY -m unittest discover -s tests 2>&1 | tail -4
  echo; echo "=== 2. S-box analysis ===";          $PY cli.py analyze sbox
  echo; echo "=== 3. Avalanche / diffusion ===";   $PY cli.py analyze avalanche --trials 20
  echo; echo "=== 4. ECB vs CTR pattern leakage ==="; $PY cli.py analyze ecb-demo
  echo; echo "=== 5. Keystream randomness ===";    $PY cli.py analyze random
  echo; echo "=== 6. Differential attack (toy SPN) ==="; $PY cli.py analyze attack --rounds 4 --seed 7
  echo; echo "=== 7. Benchmark ===";               $PY cli.py bench --size 32768
  echo; echo "=== 8. Plots ===";                   $PY cli.py analyze plots || true
  echo; echo "=== 9. File encryption round-trip ==="
  echo "top secret" > results/demo.txt
  SYML_PASSWORD=demo123 $PY cli.py encrypt results/demo.txt -a aes-ctr
  SYML_PASSWORD=demo123 $PY cli.py decrypt results/demo.txt.syml -o results/demo.out.txt
  diff results/demo.txt results/demo.out.txt && echo "round-trip OK"
} 2>&1 | tee results/run_log.txt
