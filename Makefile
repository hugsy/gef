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
COVERAGE_DIR ?= /tmp/cov
GEF_PATH ?= $(shell readlink -f gef.py)
TMPDIR ?= /tmp
PYTEST_PARAMETERS := --verbose -n $(NB_CORES)
ifdef DEBUG
	PYTEST_PARAMETERS += --pdb
endif

.PHONY: test test_% Test% testbins clean lint

test: $(TMPDIR) testbins
	TMPDIR=$(TMPDIR) python3 -m pytest $(PYTEST_PARAMETERS) tests/runtests.py

Test%: $(TMPDIR) testbins
	TMPDIR=$(TMPDIR) python3 -m pytest $(PYTEST_PARAMETERS) tests/runtests.py::$@

test_%: $(TMPDIR) testbins
	TMPDIR=$(TMPDIR) python3 -m pytest $(PYTEST_PARAMETERS) tests/runtests.py -k $@

testbins: $(TMPDIR) $(wildcard tests/binaries/*.c)
	@TMPDIR=$(TMPDIR) $(MAKE) -j $(NB_CORES) -C tests/binaries TARGET=$(TARGET) all

clean:
	TMPDIR=$(TMPDIR) $(MAKE) -j $(NB_CORES) -C tests/binaries clean
	@rm -rf $(TMPDIR)/gef-* $(TMPDIR)/gef.py || true

lint:
	python3 -m pylint $(PYLINT_GEF_PARAMETERS) $(GEF_PATH)
	python3 -m pylint $(PYLINT_TEST_PARAMETERS) $(wildcard tests/*.py)

coverage:
	@! ( [ -d $(COVERAGE_DIR) ] && echo "COVERAGE_DIR=$(COVERAGE_DIR) exists already")
	@mkdir -p $(COVERAGE_DIR)
	@COVERAGE_DIR=$(COVERAGE_DIR) $(MAKE) test
	@coverage combine $(COVERAGE_DIR)/*
	@coverage html --include "*/gef.py"
	@rm -rf $(COVERAGE_DIR)

$(TMPDIR):
	mkdir -p $@

