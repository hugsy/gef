PYLINTRC_PATH := ./.pylintrc
PYLINT_RULES := --disable=all --enable=F,E,unreachable,duplicate-key,unnecessary-semicolon,global-variable-not-assigned,unused-variable,binary-op-exception,bad-format-string,anomalous-backslash-in-string,bad-open-mode

test: testbins
	@cp gef.py /tmp/gef.py
	python3 tests/runtests.py
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*
	@$(MAKE) -C tests/binaries clean

Test%: testbins
	@cp gef.py /tmp/gef.py
	python3 tests/runtests.py $@
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*

testbins: tests/binaries/*.c
	@$(MAKE) -C tests/binaries all

lint:
	python3 -m pylint $(PYLINT_RULES) gef.py
	python3 -m pylint $(PYLINT_RULES) tests/*.py
