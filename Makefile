test: testbins /tmp/gef.py
	python3 tests/runtests.py
	rm -f /tmp/gef.py
	@make -C tests/binaries clean
	rm -f /tmp/gef-*

/tmp/gef.py:
	cp gef.py /tmp/gef.py

testbins: tests/binaries/*.c
	@make -C tests/binaries all

lint:
	python2 -m py_compile gef.py
	python3 -m pylint --rcfile ./.pylintrc tests/*.py
	python3 -m pylint -E gef.py
