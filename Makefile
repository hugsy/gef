NB_CORES := $(shell grep --count '^processor' /proc/cpuinfo)
PYLINT_DISABLE:= all
PYLINT_ENABLE := F,E,unreachable,duplicate-key,unnecessary-semicolon,unused-variable,binary-op-exception,bad-format-string,anomalous-backslash-in-string,bad-open-mode,dangerous-default-value,trailing-whitespace,unneeded-not,singleton-comparison,unused-import
PYLINT_TEST_ENABLE := $(PYLINT_ENABLE),line-too-long,multiple-statements,consider-using-f-string,global-variable-not-assigned
PYLINT_JOBS := $(NB_CORES)
PYLINT_SUGGEST_FIX := y
PYLINT_COMMON_PARAMETERS := --jobs=$(PYLINT_JOBS) --suggestion-mode=$(PYLINT_SUGGEST_FIX)
PYLINT_GEF_PARAMETERS := --disable=$(PYLINT_DISABLE) --enable=$(PYLINT_ENABLE) $(PYLINT_COMMON_PARAMETERS)
PYLINT_TEST_PARAMETERS := --disable=$(PYLINT_DISABLE) --enable=$(PYLINT_TEST_ENABLE) $(PYLINT_COMMON_PARAMETERS)
TARGET := $(shell lscpu | head -1 | sed -e 's/Architecture:\s*//g')

test: testbins
	@cp gef.py /tmp/gef.py
	python3 -m pytest --verbose --numprocesses=$(NB_CORES) tests/runtests.py
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*
	@$(MAKE) -j $(NB_CORES) -C tests/binaries clean

Test%: testbins
	@cp gef.py /tmp/gef.py
	python3 -m pytest --verbose --numprocesses=$(NB_CORES) tests/runtests.py $@
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*

testbins: tests/binaries/*.c
	@$(MAKE) -j $(NB_CORES) -C tests/binaries TARGET=$(TARGET) all

lint:
	python3 -m pylint $(PYLINT_GEF_PARAMETERS) gef.py
	python3 -m pylint $(PYLINT_TEST_PARAMETERS) tests/*.py
