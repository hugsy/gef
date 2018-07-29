test:
	python tests/runtests.py

lint:
	pylint --rcfile ./.pylintrc tests/*.py
	pylint -E gef.py
