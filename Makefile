test: testbins
	@cp gef.py /tmp/gef.py
	python3 tests/runtests.py
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*
	@make -C tests/binaries clean

Test%: testbins
	@cp gef.py /tmp/gef.py
	python3 tests/runtests.py $@
	@rm -f /tmp/gef.py
	@rm -f /tmp/gef-*

testbins: tests/binaries/*.c
	@make -C tests/binaries all

lint:
	python3 -m pylint --rcfile ./.pylintrc tests/*.py
	python3 -m pylint -E gef.py
