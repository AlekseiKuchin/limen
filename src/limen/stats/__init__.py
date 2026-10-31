"""Статистические границы для аудита автозакрытия.

Обозначения (см. docs/methodology.md):
* C — алерты, закрытые автоматически, N_C = |C|; A_C — число атак среди них (неизвестно);
* A_O — атаки, найденные аналитиками среди остальных алертов (известно из вердиктов);
* FOR = A_C / N_C — доля атак среди автозакрытых;
* FNR = A_C / (A_C + A_O) — доля пропущенных атак среди всех атак.
"""

from limen.stats.binomial import (
    cp_lower,
    cp_upper,
    hypergeom_upper_count,
    n_required,
    zero_failure_n,
)
from limen.stats.fnr import AuditEstimate, fnr_upper_from_count

__all__ = [
    "AuditEstimate",
    "cp_lower",
    "cp_upper",
    "fnr_upper_from_count",
    "hypergeom_upper_count",
    "n_required",
    "zero_failure_n",
]
