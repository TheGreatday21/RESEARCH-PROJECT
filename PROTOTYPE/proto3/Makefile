PYTHON ?= .venv/bin/python
RUFF ?= .venv/bin/ruff
MYPY ?= .venv/bin/mypy
COMPOSE ?= docker compose -f lab/docker-compose.yml

.PHONY: test test-phase1 test-phase2 test-phase3 test-phase4 test-gui gui lint lab-up traffic integration lab-down

test:
	$(PYTHON) -m pytest -q

test-phase1:
	$(PYTHON) -m pytest phase1_acquire/tests -q

test-phase2:
	$(PYTHON) -m pytest phase2_parse/tests -q

test-phase3:
	$(PYTHON) -m pytest phase3_analyze/tests -q

test-phase4:
	$(PYTHON) -m pytest phase4_detect/tests -q

test-gui:
	$(PYTHON) -m pytest gui/tests -q

gui:
	$(PYTHON) -m gui.lapa_gui

lint:
	$(RUFF) check common phase1_acquire phase2_parse phase3_analyze phase4_detect cli gui lab
	$(MYPY)

lab/target/id_ed25519:
	ssh-keygen -q -t ed25519 -N '' -f $@
	chmod 0600 $@

lab-up: lab/target/id_ed25519
	$(COMPOSE) up -d --build target
	$(COMPOSE) ps

traffic: lab-up
	$(COMPOSE) run --rm traffic

integration: lab-up traffic
	LAPA_RUN_LAB_TESTS=1 $(PYTHON) -m pytest phase1_acquire/tests/test_lab_acquisition.py -m integration -q

lab-down:
	$(COMPOSE) down
