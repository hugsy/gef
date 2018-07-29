test:
	python tests/runtests.py

lint:
	pylint tests/*.py
	pylint -E gef.py
