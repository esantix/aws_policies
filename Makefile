VENV := .venv

.DEFAULT_GOAL := all


export PYTHONPATH=src
export LOG_LEVEL=DEBUG

.PHONY: run all venv

$(VENV)/bin/activate: requirements.txt
	@python3 -m venv $(VENV)
	@$(VENV)/bin/pip3 install -r requirements.txt

venv: $(VENV)/bin/activate


all: venv
