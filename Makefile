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
	python3 -m pylint --rcfile ./.pylintrc tests/*.py
