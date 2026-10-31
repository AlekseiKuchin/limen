# Мониторинг между аудитами

«Лимен» не открывает портов и не ходит в сеть. Итоги аудита превращаются в файл метрик, а дальше работают Prometheus, Grafana и Alertmanager заказчика.

```
limen metrics → *.prom → node_exporter (textfile collector) → Prometheus → Grafana и Alertmanager
```

1. После каждого аудита записать метрики в каталог textfile collector:

   ```bash
   limen metrics reports/pilot-2026-11.json --out /var/lib/node_exporter/textfile/limen.prom
   ```

   Файл записывается атомарно. Имя аудита в метке `audit` — имя файла результата без расширения. В файл стоит передавать только актуальные результаты: метрики старых аудитов будут продолжать срабатывать в правилах.

2. Запустить node_exporter с параметром `--collector.textfile.directory=/var/lib/node_exporter/textfile`.

3. Подключить правила оповещений `prometheus/limen-alerts.yml` в `rule_files` Prometheus. Пороги в правилах — пример и фиксируются вместе с параметрами аудита.

4. Импортировать панель `grafana/limen-dashboard.json` в Grafana и выбрать источник данных Prometheus.

| Метрика | Что показывает |
|---|---|
| `limen_fnr_upper` | верхняя граница доли пропущенных атак |
| `limen_for_upper` | верхняя граница доли атак среди автозакрытых |
| `limen_closed`, `limen_sampled`, `limen_attacks_in_sample`, `limen_attacks_open` | счётчики аудита |
| `limen_finite_sample_valid` | 1 — гарантия на конечной выборке, 0 — приближённая |
| `limen_rule_for_upper` | граница доли атак по правилу |
| `limen_rule_decision` | решение по правилу (метка `decision`) |
| `limen_audit_timestamp_seconds` | время расчёта аудита |

Правила и панель в этой среде не запускались: перед использованием их нужно проверить на Prometheus и Grafana заказчика (`promtool check rules prometheus/limen-alerts.yml`).
