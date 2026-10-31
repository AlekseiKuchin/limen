"""Командная строка «Лимен» на стандартном argparse. Все команды работают офлайн.

Порядок аудита в строгом режиме (всё у заказчика, docs/pilot-protocol.md):

    limen keygen --out secrets/pseudo.key
    limen validate export.csv --mapping configs/mappings/generic_csv.yaml --config pilot.yaml
    limen prepare export.csv --mapping ... --key secrets/pseudo.key --config pilot.yaml \\
        --out data/interim/alerts.csv
    limen plan data/interim/alerts.csv --config pilot.yaml --out plan.csv \\
        --template-out labels_template.csv --page-out labeling.html
    # аналитики размечают выборку на офлайн-странице labeling.html и выгружают labels.csv
    limen estimate data/interim/alerts.csv --plan plan.csv --labels labels.csv --config pilot.yaml \\
        --out result.json
    limen verify result.json --alerts data/interim/alerts.csv --plan plan.csv --labels labels.csv
    limen report result.json --format html --out report.html

Основной режим (наружу уходит только минимальная обезличенная таблица) — export-minimal и translate-ids.
Коды выхода: 0 — успех, 1 — ошибка входных данных, 2 — аудит по выгрузке невозможен,
3 — нарушена целостность (файл не тот, по которому строился план или считался результат).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pandas as pd

from limen import __version__
from limen.audit.labels import read_labels, write_label_template
from limen.audit.pipeline import (
    AuditResult,
    build_plan,
    config_sha256,
    evaluate,
    minimal_export,
    prepare,
)
from limen.auditlog import log_event
from limen.config import AuditConfig, load_audit_config, load_mapping
from limen.integrity import IntegrityError, require_match, sha256_file
from limen.io.loaders import automated_subset, load_export
from limen.io.validation import AuditBlockedError, validate
from limen.monitoring.metrics import render_metrics, write_metrics
from limen.privacy.pseudonymize import generate_key, load_key, translate_alert_ids
from limen.report.labeling import write_labeling_page
from limen.report.render import write_report
from limen.sampling.plans import SamplingPlan
from limen.schema import ALERT_ID, CLOSED_AT, RULE_ID
from limen.stats.binomial import cp_upper, hypergeom_upper_count, n_required
from limen.stats.fnr import fnr_upper_from_count

EXIT_OK, EXIT_INPUT, EXIT_BLOCKED, EXIT_INTEGRITY = 0, 1, 2, 3
ACTIVE_WARNING = (
    "Схема active даёт приближённую границу: при редких атаках она накрывает истину реже заявленного "
    "(docs/methodology.md). Для выводов по пилоту используйте uniform, пока схема не прошла H1."
)

Handler = Callable[[argparse.Namespace], int]


def _warn(message: str) -> None:
    print(f"Предупреждение: {message}", file=sys.stderr)


def _read_alerts(path: Path) -> pd.DataFrame:
    """Подготовленная таблица алертов (CSV после prepare или export-minimal)."""
    df = pd.read_csv(path, dtype={ALERT_ID: str, RULE_ID: str})
    if CLOSED_AT in df:
        df[CLOSED_AT] = pd.to_datetime(df[CLOSED_AT], errors="coerce", utc=True)
    return df


def _write_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = df.copy()
    clean.attrs = {}
    clean.to_csv(path, index=False)


# ----------------------------------------------------------------------------- команды
def cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return EXIT_OK


def cmd_config_hash(a: argparse.Namespace) -> int:
    """SHA-256 параметров аудита для протокола пилота — до выгрузки данных."""
    print(config_sha256(load_audit_config(a.config)))
    return EXIT_OK


def cmd_keygen(a: argparse.Namespace) -> int:
    p = generate_key(a.out, force=a.force)
    print(f"Ключ создан: {p} (права 600). Не передавайте его за пределы контура.")
    log_event(a.audit_log, "keygen", key_path=str(p))
    return EXIT_OK


def cmd_validate(a: argparse.Namespace) -> int:
    cfg = load_audit_config(a.config)
    df = load_export(a.export, load_mapping(a.mapping))
    rep = validate(df, cfg.audited_sources)
    print(f"Строк: {rep.n_rows}; правил: {rep.n_rules}; источники закрытия: {rep.counts_by_source}")
    print(f"Атак, найденных аналитиками (A_O): {rep.attacks_found_by_analysts}; период: {rep.period}")
    for w in rep.warnings:
        _warn(w)
    for e in rep.errors:
        print(f"Аудит невозможен: {e}", file=sys.stderr)
    log_event(
        a.audit_log,
        "validate",
        status="ok" if rep.ok else "blocked",
        export_sha256=sha256_file(a.export),
        rows=rep.n_rows,
        counts_by_source=rep.counts_by_source,
    )
    if not rep.ok:
        return EXIT_BLOCKED
    print("Выгрузка пригодна для аудита.")
    return EXIT_OK


def cmd_prepare(a: argparse.Namespace) -> int:
    cfg = load_audit_config(a.config)
    alerts, rep, table = prepare(
        a.export, load_mapping(a.mapping), load_key(a.key), cfg, keep_mapping=a.mapping_table_out is not None
    )
    rep.raise_if_blocked()
    _write_csv(alerts, a.out)
    if a.mapping_table_out is not None and table is not None:
        _write_csv(table, a.mapping_table_out)
        _warn(f"таблица соответствия псевдонимов {a.mapping_table_out} — не выносить за контур")
    print(f"Подготовлено {len(alerts)} алертов → {a.out}")
    log_event(
        a.audit_log,
        "prepare",
        export_sha256=sha256_file(a.export),
        alerts_sha256=sha256_file(a.out),
        rows=len(alerts),
    )
    return EXIT_OK


def cmd_export_minimal(a: argparse.Namespace) -> int:
    df = _read_alerts(a.alerts)
    key = load_key(a.key) if a.hash_ids else None
    minimal = minimal_export(df, key, hash_ids=a.hash_ids, with_reason=a.with_reason)
    _write_csv(minimal, a.out)
    print(f"Минимальная выгрузка: {a.out} ({len(minimal)} строк, поля: {', '.join(minimal.columns)})")
    log_event(
        a.audit_log,
        "export-minimal",
        alerts_sha256=sha256_file(a.alerts),
        minimal_sha256=sha256_file(a.out),
        columns=list(minimal.columns),
    )
    return EXIT_OK


def cmd_translate_ids(a: argparse.Namespace) -> int:
    df = pd.read_csv(a.file, dtype=str, keep_default_na=False)
    ids = _read_alerts(a.alerts)[ALERT_ID].astype(str)
    res = translate_alert_ids(df, ids, load_key(a.key), to="original" if a.to == "original" else "pseudonym")
    _write_csv(res, a.out)
    print(f"Переведено {len(res)} строк → {a.out}")
    log_event(a.audit_log, "translate-ids", direction=a.to, input_sha256=sha256_file(a.file), rows=len(res))
    return EXIT_OK


def cmd_plan(a: argparse.Namespace) -> int:
    cfg = load_audit_config(a.config)
    if cfg.sampling.scheme == "active":
        _warn(ACTIVE_WARNING)
    if a.page_out is not None and a.template_out is None:
        raise ValueError("--page-out требует --template-out: страница строится по шаблону разметки")
    df = _read_alerts(a.alerts)
    alerts_hash = sha256_file(a.alerts)
    plan = build_plan(df, cfg, alerts_sha256=alerts_hash)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    plan.to_csv(a.out)
    print(
        f"Схема {plan.scheme}, зерно {plan.seed}: отобрано {plan.n_selected} из {len(plan.frame)} → {a.out}"
    )
    print(f"SHA-256 таблицы алертов: {alerts_hash}")
    print(
        f"SHA-256 параметров аудита: {plan.meta['config_sha256']} — запишите оба значения в протокол пилота"
    )
    if a.template_out is not None:
        write_label_template(plan, automated_subset(df, cfg.audited_sources), a.template_out)
        print(f"Шаблон разметки: {a.template_out}")
    if a.page_out is not None:
        write_labeling_page(a.template_out, a.page_out)
        print(f"Офлайн-страница разметки: {a.page_out}")
    log_event(
        a.audit_log,
        "plan",
        alerts_sha256=alerts_hash,
        config_sha256=config_sha256(cfg),
        plan_sha256=sha256_file(a.out),
        scheme=plan.scheme,
        seed=plan.seed,
        selected=plan.n_selected,
    )
    return EXIT_OK


def cmd_labeling_page(a: argparse.Namespace) -> int:
    p = write_labeling_page(a.template, a.out, a.title)
    print(f"Офлайн-страница разметки: {p}")
    return EXIT_OK


def _inputs(a: argparse.Namespace, cfg: AuditConfig) -> dict[str, str]:
    return {
        "alerts_sha256": sha256_file(a.alerts),
        "plan_sha256": sha256_file(a.plan),
        "labels_sha256": sha256_file(a.labels),
        "config_sha256": config_sha256(cfg),
    }


def _check_plan(plan: SamplingPlan, inputs: dict[str, str], allow_config_change: bool) -> None:
    require_match("Таблица алертов", str(plan.meta.get("alerts_sha256", "")), inputs["alerts_sha256"])
    planned_cfg = str(plan.meta.get("config_sha256", ""))
    if planned_cfg and planned_cfg != inputs["config_sha256"]:
        if not allow_config_change:
            require_match("Конфигурация аудита", planned_cfg, inputs["config_sha256"])
        _warn("конфигурация отличается от той, по которой строился план (разрешено --allow-config-change)")


def cmd_estimate(a: argparse.Namespace) -> int:
    cfg = load_audit_config(a.config)
    inputs = _inputs(a, cfg)
    plan = SamplingPlan.from_csv(a.plan)
    _check_plan(plan, inputs, a.allow_config_change)
    df = _read_alerts(a.alerts)
    result = evaluate(df, plan, read_labels(a.labels), cfg, validate(df, cfg.audited_sources), inputs)
    result.save(a.out)
    if result.overall.scheme == "active":
        _warn(ACTIVE_WARNING)
    o = result.overall
    print(
        f"Перепроверено {o.n_sampled} из {o.n_closed}, атак в выборке: {o.attacks_in_sample}. "
        f"Граница доли атак среди автозакрытых: {o.for_upper:.2%}; граница FNR: {o.fnr_upper:.2%} "
        f"(уверенность {o.confidence:.0%})."
    )
    log_event(
        a.audit_log,
        "estimate",
        **inputs,
        result_sha256=sha256_file(a.out),
        for_upper=o.for_upper,
        fnr_upper=o.fnr_upper,
    )
    return EXIT_OK


def cmd_verify(a: argparse.Namespace) -> int:
    """Пересчитать хеши входов и сам расчёт; результат должен совпасть с сохранённым."""
    saved = AuditResult.load(a.result)
    cfg = AuditConfig.model_validate(saved.config) if a.config is None else load_audit_config(a.config)
    inputs = _inputs(a, cfg)
    for name, value in inputs.items():
        require_match(f"Вход {name}", str(saved.inputs.get(name, "")), value)
    df = _read_alerts(a.alerts)
    plan = SamplingPlan.from_csv(a.plan)
    again = evaluate(df, plan, read_labels(a.labels), cfg, validate(df, cfg.audited_sources), inputs)
    fields = ("n_closed", "n_sampled", "attacks_in_sample", "attacks_open", "for_upper", "fnr_upper")
    mismatched = [
        f
        for f in fields
        if not math.isclose(float(getattr(saved.overall, f)), float(getattr(again.overall, f)), rel_tol=1e-12)
    ]
    log_event(a.audit_log, "verify", status="ok" if not mismatched else "mismatch", **inputs)
    if mismatched:
        raise IntegrityError(f"Пересчёт не совпал с сохранённым результатом по полям: {mismatched}")
    print("Проверка пройдена: хеши входов совпадают, пересчёт даёт тот же результат.")
    return EXIT_OK


def cmd_report(a: argparse.Namespace) -> int:
    write_report(AuditResult.load(a.result), a.out, "html" if a.format == "html" else "md")
    print(f"Отчёт: {a.out}")
    return EXIT_OK


def cmd_metrics(a: argparse.Namespace) -> int:
    results = [(p.stem, AuditResult.load(p)) for p in a.results]
    write_metrics(a.out, render_metrics(results))
    print(f"Метрики Prometheus: {a.out} (аудитов: {len(results)})")
    return EXIT_OK


def cmd_bound(a: argparse.Namespace) -> int:
    u = cp_upper(a.k, a.n, a.confidence)
    print(f"Верхняя граница доли атак: {u:.4%} (k={a.k}, n={a.n}, уверенность {a.confidence:.0%})")
    if a.population:
        u_count = float(hypergeom_upper_count(a.k, a.n, a.population, a.confidence))
        print(f"Граница числа атак среди {a.population} автозакрытых (гипергеометрическая): {u_count:.0f}")
        if a.attacks_open is not None:
            print(f"Граница FNR: {fnr_upper_from_count(u_count, a.attacks_open):.4%}")
    return EXIT_OK


def cmd_sample_size(a: argparse.Namespace) -> int:
    n = n_required(a.target, a.confidence, a.k)
    out: dict[str, Any] = {"target": a.target, "confidence": a.confidence, "k": a.k, "n_required": n}
    print(json.dumps(out, ensure_ascii=False))
    return EXIT_OK


# ----------------------------------------------------------------------------- разбор аргументов
def _add_inputs(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--plan", type=Path, required=True, help="План выборки (CSV)")
    sp.add_argument("--labels", type=Path, required=True, help="Метки аналитиков (CSV)")
    sp.add_argument("--config", "-c", type=Path, help="YAML с параметрами аудита")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Журнал действий в JSON Lines (по умолчанию — переменная LIMEN_AUDIT_LOG)",
    )
    parser = argparse.ArgumentParser(
        prog="limen",
        description="Лимен — независимый статистический аудит автозакрытия алертов SOC (офлайн).",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="КОМАНДА")

    def add(name: str, handler: Handler, help_text: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_text, description=help_text, parents=[common])
        sp.set_defaults(handler=handler)
        return sp

    add("version", cmd_version, "Версия пакета")

    sp = add("config-hash", cmd_config_hash, "SHA-256 параметров аудита для протокола пилота")
    sp.add_argument("config", type=Path, help="YAML с параметрами аудита")

    sp = add("keygen", cmd_keygen, "Создать ключ обезличивания (остаётся у заказчика)")
    sp.add_argument("--out", type=Path, default=Path("secrets/pseudo.key"))
    sp.add_argument("--force", action="store_true", help="Перезаписать существующий ключ")

    sp = add("validate", cmd_validate, "Проверить, пригодна ли выгрузка для аудита")
    sp.add_argument("export", type=Path, help="Файл выгрузки закрытых алертов")
    sp.add_argument("--mapping", type=Path, required=True, help="YAML маппинга выгрузки")
    sp.add_argument("--config", "-c", type=Path, help="YAML с параметрами аудита")

    sp = add("prepare", cmd_prepare, "Привести выгрузку к схеме «Лимен» и обезличить")
    sp.add_argument("export", type=Path, help="Файл выгрузки закрытых алертов")
    sp.add_argument("--mapping", type=Path, required=True, help="YAML маппинга выгрузки")
    sp.add_argument("--out", type=Path, required=True, help="Обезличенная таблица (CSV)")
    sp.add_argument("--key", type=Path, help="Ключ обезличивания (или LIMEN_PSEUDO_KEY_FILE)")
    sp.add_argument("--config", "-c", type=Path, help="YAML с параметрами аудита")
    sp.add_argument("--mapping-table-out", type=Path, help="Таблица соответствия — только внутри контура")

    sp = add("export-minimal", cmd_export_minimal, "Минимальная таблица для передачи за контур")
    sp.add_argument("alerts", type=Path, help="Подготовленная таблица (после prepare)")
    sp.add_argument("--out", type=Path, required=True)
    sp.add_argument("--key", type=Path, help="Ключ обезличивания (или LIMEN_PSEUDO_KEY_FILE)")
    sp.add_argument("--no-hash-ids", dest="hash_ids", action="store_false", help="Не заменять alert_id")
    sp.add_argument(
        "--no-reason", dest="with_reason", action="store_false", help="Не передавать причину закрытия"
    )

    sp = add("translate-ids", cmd_translate_ids, "Перевести alert_id между псевдонимами и исходными ID")
    sp.add_argument("file", type=Path, help="CSV с колонкой alert_id: шаблон разметки или метки")
    sp.add_argument("--alerts", type=Path, required=True, help="Таблица с исходными alert_id (после prepare)")
    sp.add_argument("--out", type=Path, required=True)
    sp.add_argument("--to", choices=("original", "pseudonym"), default="original")
    sp.add_argument("--key", type=Path, help="Ключ обезличивания (или LIMEN_PSEUDO_KEY_FILE)")

    sp = add("plan", cmd_plan, "Построить воспроизводимый план выборки")
    sp.add_argument("alerts", type=Path, help="Подготовленная таблица алертов (CSV)")
    sp.add_argument("--out", type=Path, required=True, help="План выборки (CSV)")
    sp.add_argument("--config", "-c", type=Path, help="YAML с параметрами аудита")
    sp.add_argument("--template-out", type=Path, help="Шаблон разметки (CSV)")
    sp.add_argument("--page-out", type=Path, help="Офлайн-страница разметки (HTML)")

    sp = add("labeling-page", cmd_labeling_page, "Офлайн-страница разметки по шаблону")
    sp.add_argument("template", type=Path, help="Шаблон разметки (CSV)")
    sp.add_argument("--out", type=Path, required=True)
    sp.add_argument("--title", default=None)

    sp = add("estimate", cmd_estimate, "Посчитать границы доли атак и FNR — в целом и по правилам")
    sp.add_argument("alerts", type=Path, help="Подготовленная таблица алертов (CSV)")
    _add_inputs(sp)
    sp.add_argument("--out", type=Path, required=True, help="Результат (JSON)")
    sp.add_argument(
        "--allow-config-change",
        action="store_true",
        help="Разрешить конфигурацию, отличную от зафиксированной в плане",
    )

    sp = add("verify", cmd_verify, "Проверить хеши входов и повторить расчёт")
    sp.add_argument("result", type=Path, help="Результат аудита (JSON)")
    sp.add_argument("--alerts", type=Path, required=True, help="Подготовленная таблица алертов (CSV)")
    _add_inputs(sp)

    sp = add("report", cmd_report, "Отчёт аудита")
    sp.add_argument("result", type=Path, help="Результат аудита (JSON)")
    sp.add_argument("--out", type=Path, required=True)
    sp.add_argument("--format", choices=("md", "html"), default="md")

    sp = add("metrics", cmd_metrics, "Метрики для Prometheus (textfile collector)")
    sp.add_argument("results", type=Path, nargs="+", help="Результаты аудитов (JSON)")
    sp.add_argument("--out", type=Path, required=True, help="Файл *.prom")

    sp = add("bound", cmd_bound, "Граница по одним счётчикам, без данных")
    sp.add_argument("--n", type=int, required=True, help="Перепроверено алертов")
    sp.add_argument("--k", type=int, default=0, help="Найдено атак")
    sp.add_argument("--confidence", type=float, default=0.95)
    sp.add_argument("--population", type=int, help="Всего автозакрытых (N_C)")
    sp.add_argument("--attacks-open", type=int, help="Атак, найденных аналитиками (A_O)")

    sp = add("sample-size", cmd_sample_size, "Сколько алертов перепроверить для заданного порога")
    sp.add_argument("--target", type=float, default=0.01)
    sp.add_argument("--confidence", type=float, default=0.95)
    sp.add_argument("--k", type=int, default=0, help="Ожидаемое число найденных атак")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler: Handler = args.handler
    try:
        return handler(args)
    except AuditBlockedError as e:
        print(f"Аудит невозможен: {e}", file=sys.stderr)
        return EXIT_BLOCKED
    except IntegrityError as e:
        print(f"Нарушена целостность: {e}", file=sys.stderr)
        log_event(args.audit_log, args.command, status="integrity_error", message=str(e))
        return EXIT_INTEGRITY
    except (FileNotFoundError, FileExistsError, KeyError, ValueError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return EXIT_INPUT


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
