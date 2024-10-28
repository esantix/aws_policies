.ONESHELL:
.PHONY: setup test install run build

.DEFAULT_GOAL := run

VENV := .venv
PYTHON=$(VENV)/bin/python3
PIP=$(VENV)/bin/pip

export PYTHONPATH=src
export LOG_LEVEL=DEBUG

include .env

$(VENV)/bin/activate: requirements.txt requirements.dev.txt
	@echo "Setting up environment..."
	@deactivate 2>/dev/null
	@rm -rf $(VENV)
	@python3 -m venv $(VENV)
	@source $(VENV)/bin/activate
	@$(PIP) install --upgrade pip 1>/dev/null
	@$(PIP) install -r requirements.dev.txt 1>/dev/null
	@echo " - Using python $$(which python)"

setup: $(VENV)/bin/activate

run: setup
	@$(PYTHON) examples/action_example.py

test:
	@echo "Running unit tests..."
	@coverage run -m unittest discover -s ./tests -p 'test_*.py'
	@coverage report -m

install: setup
	@echo "Installing self..."
	@$(PIP) install -e . 
	@$(PIP) list | grep AWSPolicies

build: clear
	@$(PYTHON) src/builder/policies_builder.py

clear:
	@echo "Clearing build files..."
	@rm -rf ./data/roles/*