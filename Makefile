NB_CORES := $(shell grep --count '^processor' /proc/cpuinfo)
PYLINT_DISABLE:= all
PYLINT_ENABLE := F,E,unreachable,duplicate-key,unnecessary-semicolon,global-variable-not-assigned,unused-variable,binary-op-exception,bad-format-string,anomalous-backslash-in-string,bad-open-mode
PYLINT_JOBS := $(NB_CORES)
PYLINT_SUGGEST_FIX := y
PYLINT_PARAMETERS := --disable=$(PYLINT_DISABLE) --enable=$(PYLINT_ENABLE) --jobs=$(PYLINT_JOBS) --suggestion-mode=$(PYLINT_SUGGEST_FIX) --exit-zero


test: testbins
	@cp gef.py /tmp/gef.py
	python3 tests/runtests.py
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*
	@$(MAKE) -j $(NB_CORES) -C tests/binaries clean

Test%: testbins
	@cp gef.py /tmp/gef.py
	python3 tests/runtests.py $@
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*

testbins: tests/binaries/*.c
	@$(MAKE) -j $(NB_CORES) -C tests/binaries all

lint:
	python3 -m pylint $(PYLINT_PARAMETERS) gef.py
	python3 -m pylint $(PYLINT_PARAMETERS) tests/*.py
