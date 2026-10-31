# Лимен — команды разработки. Окружение и зависимости — uv (курс MLOps); проверки — Ruff, mypy,
# PyTest, Trivy, SonarQube (курсы MLOps и DevSecOps). Полный перечень инструментов — docs/stack.md.
PY      ?= uv run
TRIVY   ?= trivy
IMAGE   ?= limen
VERSION := 0.2.0
DEMO    := data/demo
CONFIG  := configs/audit.example.yaml
MAPPING := configs/mappings/generic_csv.yaml

.PHONY: help install install-research lock hooks lint format typecheck test test-fast cov \
        sca secrets misconfig sbom security sast trivy-build image image-scan \
        demo research-smoke dvc-repro mlflow ansible-check clean

help:              ## Список команд
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-17s %s\n", $$1, $$2}'

install:           ## Окружение: ядро и инструменты разработки
	uv sync

install-research:  ## Окружение с исследовательским контуром (SciPy, CatBoost, MLflow)
	uv sync --extra research

lock:              ## Зафиксировать зависимости: uv.lock и requirements/*.txt с хешами
	uv lock
	uv export --frozen --no-dev --no-emit-project --no-header --format requirements-txt -o requirements/runtime.txt
	uv export --frozen --no-emit-project --no-header --format requirements-txt -o requirements/dev.txt
	uv export --frozen --no-dev --extra research --no-emit-project --no-header --format requirements-txt \
		-o requirements/research.txt

hooks:             ## Подключить git-хуки из .githooks (без внешних фреймворков)
	git config core.hooksPath .githooks

lint:              ## Ruff: стиль, правила Pylint и безопасности
	$(PY) ruff check src tests scripts
	$(PY) ruff format --check src tests scripts

format:            ## Автоформатирование
	$(PY) ruff format src tests scripts
	$(PY) ruff check --fix src tests scripts

typecheck:         ## mypy в строгом режиме
	$(PY) mypy src/limen

test:              ## Тесты без исследовательского контура
	$(PY) pytest -m "not research"

test-fast:         ## Быстрые тесты (без долгих проверок покрытия)
	$(PY) pytest -m "not slow and not research"

cov:               ## Тесты с покрытием (coverage.xml — для SonarQube)
	$(PY) pytest -m "not research" --cov --cov-report=term-missing --cov-report=xml

sca:               ## Trivy: уязвимости зависимостей по uv.lock
	$(TRIVY) fs --scanners vuln --severity HIGH,CRITICAL --exit-code 1 .

secrets:           ## Trivy: секреты в репозитории
	$(TRIVY) fs --scanners secret --exit-code 1 .

misconfig:         ## Trivy: ошибки конфигурации Dockerfile и манифестов
	$(TRIVY) config --severity HIGH,CRITICAL --exit-code 1 .

sbom:              ## SBOM в формате CycloneDX (перечень заимствованных компонентов)
	mkdir -p reports
	$(TRIVY) fs --format cyclonedx --output reports/sbom.cdx.json .

security: sca secrets misconfig sbom  ## Все проверки Trivy

sast:              ## SonarQube: статический анализ (нужны SONAR_HOST_URL и SONAR_TOKEN)
	sonar-scanner

trivy-build:       ## Собрать Trivy из исходников (TRIVY_VERSION, TRIVY_COMMIT)
	toolchain/trivy/build.sh

image:             ## Образ: колёса из исходников, установка без индекса пакетов
	DOCKER_BUILDKIT=1 docker build -t $(IMAGE):$(VERSION) .

image-scan:        ## Trivy: уязвимости образа
	$(TRIVY) image --severity HIGH,CRITICAL --exit-code 1 $(IMAGE):$(VERSION)

demo:              ## Сквозной прогон на синтетике: план, офлайн-страница, расчёт, проверка, отчёт, метрики
	mkdir -p $(DEMO) secrets
	$(PY) python scripts/make_synthetic_export.py --out $(DEMO)/export.csv --truth-out $(DEMO)/truth.csv
	$(PY) limen keygen --out secrets/demo.key --force
	$(PY) limen validate $(DEMO)/export.csv --mapping $(MAPPING) --config $(CONFIG)
	$(PY) limen prepare $(DEMO)/export.csv --mapping $(MAPPING) --config $(CONFIG) \
		--key secrets/demo.key --out $(DEMO)/alerts.csv
	$(PY) limen plan $(DEMO)/alerts.csv --config $(CONFIG) --out $(DEMO)/plan.csv \
		--template-out $(DEMO)/labels_template.csv --page-out $(DEMO)/labeling.html
	$(PY) python scripts/demo_label_from_truth.py --template $(DEMO)/labels_template.csv \
		--truth $(DEMO)/truth.csv --out $(DEMO)/labels.csv
	$(PY) limen estimate $(DEMO)/alerts.csv --plan $(DEMO)/plan.csv --labels $(DEMO)/labels.csv \
		--config $(CONFIG) --out $(DEMO)/result.json --audit-log $(DEMO)/limen-audit.jsonl
	$(PY) limen verify $(DEMO)/result.json --alerts $(DEMO)/alerts.csv --plan $(DEMO)/plan.csv \
		--labels $(DEMO)/labels.csv --config $(CONFIG) --audit-log $(DEMO)/limen-audit.jsonl
	$(PY) limen report $(DEMO)/result.json --format html --out $(DEMO)/report.html
	$(PY) limen metrics $(DEMO)/result.json --out $(DEMO)/limen.prom
	@echo "Готово: $(DEMO)/report.html, офлайн-страница разметки: $(DEMO)/labeling.html"

research-smoke:    ## Отладочный прогон исследования (нужен GUIDE в data/external)
	$(PY) python -m limen.research run --config configs/experiments/guide_smoke.yaml

dvc-repro:         ## Воспроизвести исследование по dvc.yaml (DVC ставится отдельно)
	dvc repro

mlflow:            ## Просмотр экспериментов MLflow из локального хранилища ./mlruns
	$(PY) mlflow ui --backend-store-uri ./mlruns --host 127.0.0.1 --port 5000

ansible-check:     ## Проверка синтаксиса плейбука развёртывания
	cd deploy/ansible && ansible-playbook -i inventory.example.ini site.yml --syntax-check

clean:             ## Удалить кэши и артефакты сборки
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov dist build src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
