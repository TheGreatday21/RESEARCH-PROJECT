PYTHON ?= .venv/bin/python
RUFF ?= .venv/bin/ruff
MYPY ?= .venv/bin/mypy
COMPOSE ?= docker compose -f lab/docker-compose.yml

.PHONY: test lint lab-up traffic integration lab-down demo-phase4 demo-live demo-live-lab

test:
	$(PYTHON) -m pytest tests/unit -q

lint:
	$(RUFF) check .
	$(MYPY) src/elijah

lab/target/id_ed25519:
	ssh-keygen -q -t ed25519 -N '' -f $@
	chmod 0600 $@

lab-up: lab/target/id_ed25519
	$(COMPOSE) up -d --build target
	$(COMPOSE) ps

traffic: lab-up
	$(COMPOSE) run --rm traffic

integration: lab-up traffic
	ELIJAH_RUN_LAB_TESTS=1 $(PYTHON) -m pytest tests/integration -q

lab-down:
	$(COMPOSE) down

demo-phase4:
	sh scripts/demo_phase4.sh

demo-live:
	bash scripts/demo_live.sh

demo-live-lab:
	bash scripts/demo_live.sh --live-lab
