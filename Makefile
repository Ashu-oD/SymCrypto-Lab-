PY ?= python3
test:      ; $(PY) -m unittest discover -s tests -v
demo:      ; bash run_all.sh
attack:    ; $(PY) cli.py analyze attack
plots:     ; $(PY) cli.py analyze plots
bench:     ; $(PY) cli.py bench
