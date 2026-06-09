from __future__ import annotations

# Compatibility facade for harness-related commands. The implementation lives
# in focused modules so discovery, workorders, guidance, QA, and validation can
# evolve independently without turning this into another large command file.

from .harness_candidates import _candidate_by_id, _candidate_context, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data, harness_ai_plan, scan_harness_points
from .harness_guidance import (
    _apply_blocker_classifications,
    _blocker_classification,
    _blocker_classification_matches,
    _classification_values,
    _normalized_path,
    harness_blockers,
    iterate_harness,
)
from .harness_metrics import (
    BANNED_PATTERNS,
    _best_file_rows,
    _build_artifacts,
    _coverage_reports,
    _coverage_target_total,
    _coverage_total,
    _is_harness_coverage_row,
    _is_harness_source_path,
    _is_header_coverage_row,
    _latest_fuzz_run,
    _parse_llvm_coverage_report,
    _review_data,
    _seed_count,
    review_harnesses,
)
from .harness_qa import harness_qa
from .harness_suspicious import suspicious_points
from .harness_validation import scaffold_harness, score_harnesses, validate_harnesses
from .harness_synthesis import _build_candidate_source, _draft_harness, synthesize_harness_attempt
from .harness_workorders import (
    _candidate_prompt,
    harness_prompt,
    index_harness_candidates,
    write_candidate_knowledge,
    write_harness_work_order,
)


__all__ = [
    "BANNED_PATTERNS",
    "_ai_plan_data",
    "_apply_blocker_classifications",
    "_best_file_rows",
    "_blocker_classification",
    "_blocker_classification_matches",
    "_build_artifacts",
    "_build_candidate_source",
    "_candidate_by_id",
    "_candidate_context",
    "_candidate_prompt",
    "_classification_values",
    "_coverage_reports",
    "_coverage_target_total",
    "_coverage_total",
    "_draft_harness",
    "_enrich_candidates_with_context",
    "_is_harness_coverage_row",
    "_is_harness_source_path",
    "_is_header_coverage_row",
    "_latest_fuzz_run",
    "_normalized_path",
    "_parse_llvm_coverage_report",
    "_review_data",
    "_seed_count",
    "harness_ai_plan",
    "harness_blockers",
    "harness_prompt",
    "harness_qa",
    "index_harness_candidates",
    "iterate_harness",
    "review_harnesses",
    "scan_harness_points",
    "scaffold_harness",
    "score_harnesses",
    "suspicious_points",
    "synthesize_harness_attempt",
    "validate_harnesses",
    "write_candidate_knowledge",
    "write_harness_work_order",
]
