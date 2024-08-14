VENV := .venv

.DEFAULT_GOAL := run


export PYTHONPATH=src
export LOG_LEVEL=DEBUG

.PHONY: venv test install run

$(VENV)/bin/activate:
	@python3 -m venv $(VENV)
	@$(VENV)/bin/pip3 install -r requirements.dev.txt

venv: $(VENV)/bin/activate


run: venv
	@python3 examples/action_example.py

test: venv
	@coverage run -m unittest discover -s ./tests/unit_tests -p 'test_*.py'
	@coverage report -m

install: venv
	@pip install --upgrade pip 
	@pip install -e . 
	@pip list | grep AWSPolicies
