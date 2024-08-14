VENV := .venv

.DEFAULT_GOAL := run


export PYTHONPATH=src
export LOG_LEVEL=DEBUG

.PHONY: run all venv test

$(VENV)/bin/activate: requirements.txt
	@python3 -m venv $(VENV)
	@$(VENV)/bin/pip3 install -r requirements.txt

venv: $(VENV)/bin/activate


run: venv
	python3 examples/action_example.py

test:
	coverage run -m unittest discover -s ./tests -p 'test_*.py'
	coverage report -m



all: venv run
