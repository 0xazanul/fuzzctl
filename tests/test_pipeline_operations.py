import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fuzz_pipeline.build_context import context_flags_for_source
from fuzz_pipeline.builder import _profile_env
from fuzz_pipeline.campaign_common import _asan_env, _count_crash_artifacts, _merge_harness_env, _worker_counts
from fuzz_pipeline.corpus import corpus_enrich, corpus_prune_crashers
from fuzz_pipeline.advanced_tools import advanced_tool_status
from fuzz_pipeline.advanced_triage import advanced_triage_run
from fuzz_pipeline.crash_value import analyze_crash_item, analyze_target_crash_value, crash_value_path
from fuzz_pipeline.coverage import collect_coverage_inputs
from fuzz_pipeline.dashboard import _redact_log_text, _target_findings
from fuzz_pipeline.docker_runtime import docker_run_command
from fuzz_pipeline.grammar import grammar_configure, grammar_plan
from fuzz_pipeline.harness import (
    _apply_blocker_classifications,
    _best_file_rows,
    _build_artifacts,
    _coverage_target_total,
    _coverage_total,
    _is_harness_coverage_row,
    _latest_fuzz_run,
    _parse_llvm_coverage_report,
    _review_data,
    _seed_count,
    harness_blockers,
    harness_qa,
    suspicious_points,
    validate_harnesses,
)
from fuzz_pipeline.hybrid import symcc_hybrid_run
from fuzz_pipeline.fuzztest import write_fuzztest_plan, write_fuzztest_template
from fuzz_pipeline.manifest import Harness, TargetManifest
from fuzz_pipeline.monitor import _raw_crash_events, _snapshot
from fuzz_pipeline.oss_fuzz_gen import write_llm_gen_workorder
from fuzz_pipeline.post_cycle import post_cycle_run
from fuzz_pipeline.readiness import target_readiness
from fuzz_pipeline.supervisor import _active_afl_worker_counts, _campaign_mismatch_reason, _classify_cmdline
from fuzz_pipeline.triage import _better_sanitizer_repro, _choose_harness, _crash_files, _crash_type, _preserve_reproducer_metadata, _severity
from fuzz_pipeline.util import FuzzCtlError, write_json
from fuzz_pipeline.util import find_latest_run


def _manifest(tmp_path: Path) -> TargetManifest:
    source = tmp_path / "repo"
    (source / "seeds").mkdir(parents=True)
    return TargetManifest(
        name="target",
        language="c",
        source_path=str(source),
        build_system="raw",
        seed_corpus="seeds",
        harnesses=[Harness(name="parser_file", type="file", argv=["@@"], source="fuzzer.c")],
    )


class PipelineOperationsTests(unittest.TestCase):
    def test_collect_coverage_inputs_includes_afl_queue_and_dedupes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            manifest = _manifest(tmp_path)
            harness = manifest.harnesses[0]
            source = manifest.source_dir(tmp_path)
            (source / "seeds" / "seed").write_bytes(b"seed")

            run_dir = tmp_path / "runs" / "target" / "run"
            queue = run_dir / "aflpp" / harness.name / "findings" / "main" / "queue"
            queue.mkdir(parents=True)
            (queue / "id:000000").write_bytes(b"seed")
            (queue / "id:000001").write_bytes(b"new-coverage")

            inputs, summary = collect_coverage_inputs(tmp_path, manifest, run_dir, harness, max_inputs=10)

            self.assertEqual([p.read_bytes() for p in inputs], [b"seed", b"new-coverage"])
            self.assertEqual(summary["sources"]["seed"]["selected"], 1)
            self.assertEqual(summary["sources"]["afl_queue"]["selected"], 1)
            self.assertEqual(summary["deduped"], 1)

    def test_corpus_enrich_writes_per_harness_structural_seeds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "seeds").mkdir(parents=True)
            (source / "seeds" / "base").write_bytes(b"base")
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                seed_corpus="seeds",
                harnesses=[
                    Harness(name="dns_wire_file", type="file", source="fuzz_harnesses/dns_wire_fuzzer.c"),
                    Harness(name="config_parse_file", type="file", source="fuzz_harnesses/config_parse_fuzzer.c"),
                    Harness(name="ddns_settings_config_file", type="file", source="fuzz_harnesses/ddns_settings_config_fuzzer.c"),
                    Harness(name="responder_readline_file", type="file", source="fuzz_harnesses/responder_readline_fuzzer.c"),
                    Harness(name="dns_rdata_file", type="file", source="fuzz_harnesses/dns_rdata_fuzzer.c"),
                    Harness(name="dnssec_rdata_file", type="file", source="fuzz_harnesses/dnssec_rdata_fuzzer.c"),
                    Harness(name="srp_filedata_file", type="file", source="fuzz_harnesses/srp_filedata_fuzzer.c"),
                ],
            )

            corpus_enrich(workspace, manifest)

            self.assertTrue((workspace / "corpora" / "target" / "dns_wire_file" / "current" / "dns-query-a.local.bin").exists())
            self.assertTrue((workspace / "corpora" / "target" / "config_parse_file" / "current" / "config-minimal.conf").exists())
            self.assertTrue((workspace / "corpora" / "target" / "ddns_settings_config_file" / "current" / "ddns-settings-valid.conf").exists())
            self.assertTrue((workspace / "corpora" / "target" / "responder_readline_file" / "current" / "readline-nul-prefix.conf").exists())
            self.assertTrue((workspace / "corpora" / "target" / "dns_rdata_file" / "current" / "rdata-srv.bin").exists())
            self.assertTrue((workspace / "corpora" / "target" / "dnssec_rdata_file" / "current" / "dnssec-rrsig.bin").exists())
            self.assertTrue((workspace / "corpora" / "target" / "srp_filedata_file" / "current" / "srp-filedata-ipv6.bin").exists())

    def test_seed_count_includes_per_harness_enriched_corpora(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "seeds").mkdir(parents=True)
            (source / "seeds" / "base").write_bytes(b"base")
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                seed_corpus="seeds",
                harnesses=[
                    Harness(name="parser_file", type="file", source="fuzzer.c"),
                    Harness(name="parser_libfuzzer", type="libfuzzer", source="fuzzer.c"),
                ],
            )
            curated = workspace / "corpora" / "target" / "parser_file" / "current"
            curated.mkdir(parents=True)
            (curated / "a").write_bytes(b"a")
            (curated / "b").write_bytes(b"b")

            self.assertEqual(_seed_count(workspace, manifest), 3)

    def test_corpus_prune_crashers_quarantines_bad_curated_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_file", type="file", argv=["@@"], source="fuzzer.c")],
            )
            current = workspace / "corpora" / "target" / "parser_file" / "current"
            current.mkdir(parents=True)
            (current / "good.bin").write_bytes(b"good")
            (current / "bad.bin").write_bytes(b"bad")
            binary = workspace / "build" / "target" / "afl_asan_ubsan" / "parser_file"
            binary.parent.mkdir(parents=True)
            binary.write_text("#!/bin/sh\ncase \"$(cat \"$1\")\" in *bad*) exit 1;; *) exit 0;; esac\n")
            binary.chmod(0o755)

            corpus_prune_crashers(workspace, manifest, timeout_seconds=1)

            self.assertTrue((current / "good.bin").exists())
            self.assertFalse((current / "bad.bin").exists())
            quarantined = list((workspace / "corpora" / "target" / "parser_file" / "quarantine").glob("bad-*.bin"))
            self.assertEqual(len(quarantined), 1)

    def test_raw_crash_event_fires_only_on_count_increase(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            run_dir = tmp_path / "runs" / "target" / "run"
            run_dir.mkdir(parents=True)
            snapshot = {"raw_crashes": 2, "raw_crash_files": ["runs/target/run/aflpp/h/crashes/id:000000"]}
            state = {"last_raw_crashes": 1, "alerted_keys": []}

            events = _raw_crash_events(tmp_path, run_dir, snapshot, state)

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].key, "raw-crash:run:2")
            self.assertEqual(
                _raw_crash_events(tmp_path, run_dir, snapshot, {"last_raw_crashes": 2, "alerted_keys": []}),
                [],
            )

    def test_dashboard_log_redacts_query_tokens(self) -> None:
        line = '127.0.0.1 - "GET /api/state?token=secret123&x=1 HTTP/1.1" 200 -'

        redacted = _redact_log_text(line)

        self.assertNotIn("secret123", redacted)
        self.assertIn("token=<redacted>", redacted)

    def test_raw_crash_event_marks_duplicate_only_growth_as_info(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            run_dir = tmp_path / "runs" / "target" / "run"
            run_dir.mkdir(parents=True)
            snapshot = {
                "raw_crashes": 3,
                "raw_crash_files": ["runs/target/run/aflpp/h/crashes/id:000002"],
                "unique_crash_count": 1,
                "duplicate_crashes": 2,
            }
            state = {
                "last_raw_crashes": 2,
                "last_unique_crashes": 1,
                "last_duplicate_crashes": 1,
                "alerted_keys": [],
            }

            events = _raw_crash_events(tmp_path, run_dir, snapshot, state)

            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].severity, "INFO")
            self.assertIn("duplicate", events[0].title)

    def test_worker_counts_cover_every_file_harness_before_extra_workers(self) -> None:
        harnesses = [
            Harness(name="a", type="file"),
            Harness(name="b", type="file"),
            Harness(name="c", type="file"),
            Harness(name="d", type="file"),
        ]

        self.assertEqual(_worker_counts(harnesses, 2), {"a": 1, "b": 1, "c": 1, "d": 1})
        self.assertEqual(_worker_counts(harnesses, 7), {"a": 2, "b": 2, "c": 2, "d": 1})

    def test_docker_run_command_sets_workspace_pythonpath(self) -> None:
        workspace = Path("/tmp/fuzz-pipeline")

        cmd = docker_run_command(workspace, ["status", "target"], image="image:test")

        self.assertIn(f"PYTHONPATH={workspace / 'src'}", cmd)
        self.assertIn(f"{workspace.parent}:{workspace.parent}", cmd)
        self.assertEqual(cmd[cmd.index("-w") + 1], str(workspace))
        self.assertIn("--runtime", cmd)
        self.assertIn("native", cmd)

    def test_leak_check_env_overrides_harness_leak_suppression(self) -> None:
        harness = Harness(
            name="parser",
            type="libfuzzer",
            env={"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=0"},
        )

        env = _merge_harness_env({"ASAN_OPTIONS": "detect_leaks=1"}, harness, detect_leaks=True)

        self.assertIn("detect_leaks=1", env["ASAN_OPTIONS"])
        self.assertNotIn("detect_leaks=0", env["ASAN_OPTIONS"])

    def test_afl_env_allows_more_workers_than_cores(self) -> None:
        self.assertEqual(_asan_env()["AFL_NO_AFFINITY"], "1")

    def test_harness_manifest_preserves_extra_build_flags(self) -> None:
        harness = Harness.from_dict(
            {
                "name": "parser",
                "type": "file",
                "compile_flags": ["-ffunction-sections"],
                "link_flags": ["-Wl,--gc-sections"],
            }
        )

        self.assertEqual(harness.compile_flags, ["-ffunction-sections"])
        self.assertEqual(harness.link_flags, ["-Wl,--gc-sections"])
        self.assertEqual(harness.to_dict()["link_flags"], ["-Wl,--gc-sections"])

    def test_symcc_profile_uses_system_libcxx_by_default(self) -> None:
        env = _profile_env("symcc")

        self.assertEqual(env["SYMCC_REGULAR_LIBCXX"], "1")
        self.assertNotIn("ASAN_OPTIONS", env)
        self.assertNotIn("UBSAN_OPTIONS", env)

    def test_context_flags_filter_generated_pch_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir()
            harness = source / "fuzzer.cc"
            harness.write_text("int main() { return 0; }\n", encoding="utf-8")
            context = workspace / "build" / "target" / "build-context" / "build-context.json"
            write_json(
                context,
                {
                    "include_dirs": [str(source / "include")],
                    "defines": ["-DFUZZING"],
                    "compile_flags": [
                        "-std=c++17",
                        "-include",
                        str(source / "cmake_pch.hxx"),
                        "-x",
                        "c++-header",
                        "-include-pch",
                        str(source / "cmake_pch.hxx.pch"),
                        "-Winvalid-pch",
                        "-fpch-instantiate-templates",
                        str(source / "bare-source-fragment.cc"),
                        "-Wno-unused",
                    ],
                    "link_artifacts": [],
                },
            )
            manifest = TargetManifest(
                name="target",
                language="c++",
                source_path=str(source),
                build_system="raw",
                build_context={"path": str(context)},
            )

            flags, _ = context_flags_for_source(workspace, manifest, harness)

            self.assertIn("-std=c++17", flags)
            self.assertIn("-Wno-unused", flags)
            self.assertNotIn("-include", flags)
            self.assertNotIn("-include-pch", flags)
            self.assertNotIn("-x", flags)
            self.assertFalse(any("cmake_pch" in flag for flag in flags))

    def test_harness_manifest_supports_fuzztest_profile(self) -> None:
        harness = Harness.from_dict(
            {
                "name": "parser_property",
                "type": "fuzztest",
                "source": "fuzz_harnesses/parser_property.cc",
                "profiles": ["fuzztest_asan_ubsan"],
            }
        )

        self.assertEqual(harness.type, "fuzztest")
        self.assertEqual(harness.profiles, ["fuzztest_asan_ubsan"])
        self.assertEqual(harness.to_dict()["profiles"], ["fuzztest_asan_ubsan"])

    def test_harness_review_requires_fuzztest_macro(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            harness_source = source / "fuzz_harnesses" / "parser_property.cc"
            harness_source.parent.mkdir(parents=True)
            harness_source.write_text("void ParserProperty(const char *) {}\n", encoding="utf-8")
            manifest = TargetManifest(
                name="target",
                language="c++",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_property", type="fuzztest", source="fuzz_harnesses/parser_property.cc")],
            )

            review = _review_data(workspace, manifest)

            self.assertIn("FuzzTest harness is missing FUZZ_TEST", [item["message"] for item in review["errors"]])

    def test_validate_accepts_fuzztest_harness_type(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            harness_source = source / "fuzz_harnesses" / "parser_property.cc"
            harness_source.parent.mkdir(parents=True)
            harness_source.write_text(
                '#include "fuzztest/fuzztest.h"\nvoid ParserProperty(const std::string&) {}\nFUZZ_TEST(ParserSuite, ParserProperty);\n',
                encoding="utf-8",
            )
            manifest = TargetManifest(
                name="target",
                language="c++",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_property", type="fuzztest", source="fuzz_harnesses/parser_property.cc")],
            )

            with contextlib.redirect_stdout(io.StringIO()):
                rc = validate_harnesses(workspace, manifest, build=False)

            self.assertEqual(rc, 0)

    def test_harness_qa_writes_four_principle_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "seeds").mkdir(parents=True)
            (source / "seeds" / "seed").write_bytes(b"abc")
            harness_source = source / "fuzz_harnesses" / "parser_file.c"
            harness_source.parent.mkdir(parents=True)
            harness_source.write_text(
                "#include <stdint.h>\n"
                "static void reset_state(void) {}\n"
                "static int target_parse(const uint8_t *data, unsigned long size) { return data && size > 0; }\n"
                "int main(int argc, char **argv) { reset_state(); return target_parse((const uint8_t *)argv[0], (unsigned long)argc); }\n",
                encoding="utf-8",
            )
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                seed_corpus="seeds",
                harnesses=[Harness(name="parser_file", type="file", argv=["@@"], source="fuzz_harnesses/parser_file.c")],
            )
            coverage = workspace / "runs" / "target" / "run" / "coverage"
            coverage.mkdir(parents=True)
            (coverage / "parser_file.report.txt").write_text(
                """Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover
src/parser.c 100 10 90.00% 10 0 100.00% 100 20 80.00% 0 0 -
TOTAL 100 10 90.00% 10 0 100.00% 100 20 80.00% 0 0 -
""",
                encoding="utf-8",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                result = harness_qa(workspace, manifest, run_id="run")

            self.assertEqual(result["four_principles"], [
                "logic_correctness",
                "api_protocol_compliance",
                "security_boundary_respect",
                "entry_point_adequacy",
            ])
            self.assertEqual(result["summary"]["passing"], 1)
            self.assertTrue(list((workspace / "workorders" / "target").glob("*-harness-qa/harness-qa.json")))

    def test_suspicious_points_prioritize_uncovered_parser_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "src").mkdir(parents=True)
            (source / "src" / "parser.c").write_text(
                "#include <stddef.h>\nint parse_record(const unsigned char *data, size_t size) { return data && size > 2; }\n",
                encoding="utf-8",
            )
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")
            coverage = workspace / "runs" / "target" / "run" / "coverage"
            coverage.mkdir(parents=True)
            (coverage / "other.report.txt").write_text(
                "Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover\n"
                "TOTAL 1 1 0.00% 1 1 0.00% 1 1 0.00% 0 0 -\n",
                encoding="utf-8",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                result = suspicious_points(workspace, manifest, run_id="run", limit=5)

            self.assertTrue(result["suspicious_points"])
            self.assertEqual(result["suspicious_points"][0]["function"], "parse_record")
            self.assertTrue((workspace / "runs" / "target" / "run" / "guidance" / "suspicious-points.json").exists())

    def test_post_cycle_records_partial_step_failures_without_stopping(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")
            run_dir = workspace / "runs" / "target" / "run"
            run_dir.mkdir(parents=True)
            write_json(run_dir / "run.json", {"status": "complete"})

            with contextlib.redirect_stdout(io.StringIO()):
                result = post_cycle_run(workspace, manifest, run_id="run", no_alerts=True)

            self.assertEqual(result["status"], "partial")
            self.assertIn("coverage", result["failed_steps"])
            self.assertTrue((run_dir / "post_cycle" / "post_cycle.json").exists())

    def test_advanced_tool_status_reports_optional_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            status = advanced_tool_status(Path(td))

            self.assertIn("symcc", status)
            self.assertIn("grammar_mutator_campaigns", status["ready"])
            self.assertTrue(status["ready"]["oss_fuzz_gen_workorders"])

    def test_symcc_hybrid_missing_tool_writes_skip_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_file", type="file", argv=["@@"], source="fuzzer.c")],
            )
            run_dir = workspace / "runs" / "target" / "run"
            (run_dir / "aflpp" / "parser_file" / "findings" / "sec1").mkdir(parents=True)
            write_json(run_dir / "run.json", {"status": "complete"})

            empty_bin = workspace / "empty-bin"
            empty_bin.mkdir()
            with mock.patch.dict(os.environ, {"PATH": str(empty_bin)}, clear=False):
                with contextlib.redirect_stdout(io.StringIO()):
                    result = symcc_hybrid_run(workspace, manifest, run_id="run", seconds=1)

            self.assertEqual(result["status"], "skipped")
            self.assertTrue((workspace / "workorders" / "target" / "hybrid" / "symcc-hybrid.json").exists())

    def test_symcc_hybrid_dry_run_reports_campaign_readiness_without_building(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[
                    Harness(
                        name="parser_file",
                        type="file",
                        argv=["@@"],
                        source="fuzzer.c",
                        profiles=["afl_asan_ubsan"],
                    ),
                    Harness(
                        name="coverage_only_file",
                        type="file",
                        argv=["@@"],
                        source="coverage.c",
                        profiles=["coverage"],
                    ),
                ],
            )
            run_dir = workspace / "runs" / "target" / "run"
            for role in ["main", "sec1"]:
                stats = run_dir / "aflpp" / "parser_file" / "findings" / role / "fuzzer_stats"
                stats.parent.mkdir(parents=True)
                stats.write_text("execs_done : 1\n", encoding="utf-8")
            write_json(run_dir / "run.json", {"status": "running"})

            fake_bin = workspace / "fake-bin"
            fake_bin.mkdir()
            for tool in ["symcc", "sym++", "symcc_fuzzing_helper"]:
                path = fake_bin / tool
                path.write_text("#!/bin/sh\necho fake symcc\n", encoding="utf-8")
                path.chmod(0o755)

            with mock.patch.dict(os.environ, {"PATH": str(fake_bin)}, clear=False):
                with mock.patch("fuzz_pipeline.hybrid.build_profile") as build_profile_mock:
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = symcc_hybrid_run(workspace, manifest, run_id="run", seconds=1, all_harnesses=True, dry_run=True)

            build_profile_mock.assert_not_called()
            self.assertEqual(result["mode"], "dry_run")
            self.assertEqual(result["status"], "ready_to_attempt")
            self.assertEqual([item["harness"] for item in result["results"]], ["parser_file"])
            self.assertEqual(result["results"][0]["afl_instance"], "sec1")
            self.assertTrue((run_dir / "hybrid" / "symcc" / "symcc-hybrid-plan.json").exists())

    def test_symcc_hybrid_records_build_failure_packet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[
                    Harness(
                        name="parser_file",
                        type="file",
                        argv=["@@"],
                        source="fuzzer.c",
                        profiles=["afl_asan_ubsan"],
                    )
                ],
            )
            run_dir = workspace / "runs" / "target" / "run"
            stats = run_dir / "aflpp" / "parser_file" / "findings" / "sec1" / "fuzzer_stats"
            stats.parent.mkdir(parents=True)
            stats.write_text("execs_done : 1\n", encoding="utf-8")
            write_json(run_dir / "run.json", {"status": "running"})
            build_log = workspace / "build" / "target" / "symcc" / "build.log"
            build_log.parent.mkdir(parents=True)
            build_log.write_text("compiler crashed while instrumenting target\n", encoding="utf-8")

            fake_bin = workspace / "fake-bin"
            fake_bin.mkdir()
            for tool in ["symcc", "sym++", "symcc_fuzzing_helper"]:
                path = fake_bin / tool
                path.write_text("#!/bin/sh\necho fake symcc\n", encoding="utf-8")
                path.chmod(0o755)

            with mock.patch.dict(os.environ, {"PATH": str(fake_bin)}, clear=False):
                with mock.patch("fuzz_pipeline.hybrid.build_profile", side_effect=FuzzCtlError("boom")):
                    with contextlib.redirect_stdout(io.StringIO()):
                        result = symcc_hybrid_run(workspace, manifest, run_id="run", seconds=1)

            self.assertEqual(result["status"], "build_failed")
            self.assertIn("compiler crashed", result["build_log_tail"])
            self.assertTrue((run_dir / "hybrid" / "symcc" / "symcc-hybrid.json").exists())

    def test_target_readiness_separates_core_ready_from_optional_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "seeds").mkdir(parents=True)
            (source / "seeds" / "seed").write_bytes(b"abc")
            (source / "fuzz_harnesses").mkdir()
            (source / "fuzz_harnesses" / "parser.c").write_text(
                "#include <stdint.h>\n"
                "int LLVMFuzzerTestOneInput(const uint8_t *data, unsigned long size) { return data && size; }\n"
                "int main(int argc, char **argv) { return LLVMFuzzerTestOneInput((const uint8_t *)argv[0], (unsigned long)argc); }\n",
                encoding="utf-8",
            )
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                seed_corpus="seeds",
                harnesses=[
                    Harness(name="parser_libfuzzer", type="libfuzzer", source="fuzz_harnesses/parser.c"),
                    Harness(
                        name="parser_file",
                        type="file",
                        argv=["@@"],
                        source="fuzz_harnesses/parser.c",
                        profiles=["afl_asan_ubsan", "coverage"],
                    ),
                ],
            )
            for profile, harnesses in {
                "afl_asan_ubsan": ["parser_file"],
                "libfuzzer_asan_ubsan": ["parser_libfuzzer"],
            }.items():
                build_dir = workspace / "build" / "target" / profile
                build_dir.mkdir(parents=True)
                write_json(
                    build_dir / "build.json",
                    {"artifacts": [{"harness": name, "profile": profile} for name in harnesses]},
                )
                for name in harnesses:
                    (build_dir / name).write_bytes(b"bin")
            run_dir = workspace / "runs" / "target" / "run"
            stats = run_dir / "aflpp" / "parser_file" / "findings" / "main" / "fuzzer_stats"
            stats.parent.mkdir(parents=True)
            stats.write_text("execs_done : 10\ncorpus_count : 2\nsaved_crashes : 0\nlast_update : 9999999999\n", encoding="utf-8")
            queue = stats.parent / "queue"
            queue.mkdir()
            (queue / "id:000000").write_bytes(b"abc")
            (run_dir / "coverage").mkdir(parents=True)
            (run_dir / "coverage" / "parser_file.report.txt").write_text(
                "Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover\n"
                "src/parser.c 100 1 99.00% 10 0 100.00% 100 5 95.00% 0 0 -\n"
                "TOTAL 100 1 99.00% 10 0 100.00% 100 5 95.00% 0 0 -\n",
                encoding="utf-8",
            )
            write_json(run_dir / "run.json", {"status": "running"})

            with contextlib.redirect_stdout(io.StringIO()):
                result = target_readiness(workspace, manifest, run_id="run")

            self.assertEqual(result["status"], "ready_with_warnings")
            self.assertFalse(any(gate["status"] == "fail" for gate in result["gates"] if gate["section"] == "core"))
            self.assertTrue(any(gate["name"] == "FuzzTest properties" and gate["status"] == "not_configured" for gate in result["gates"]))
            self.assertTrue((workspace / "workorders" / "target" / "readiness" / "target-readiness.json").exists())

    def test_grammar_configure_attaches_mutator_env(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            mutator = workspace / "libgrammarmutator-json.so"
            mutator.write_bytes(b"fake")
            trees = workspace / "trees"
            trees.mkdir()
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_file", type="file", argv=["@@"], source="fuzzer.c")],
            )

            with contextlib.redirect_stdout(io.StringIO()):
                grammar_configure(
                    workspace,
                    manifest,
                    harness_name="parser_file",
                    grammar_format="json",
                    mutator_library=mutator,
                    tree_dir=trees,
                    only=True,
                )

            self.assertEqual(manifest.harnesses[0].env["AFL_CUSTOM_MUTATOR_LIBRARY"], str(mutator))
            self.assertEqual(manifest.harnesses[0].env["AFL_CUSTOM_MUTATOR_ONLY"], "1")
            self.assertEqual(manifest.harnesses[0].env["AFL_GRAMMAR_TREE_DIR"], str(trees))

    def test_grammar_plan_writes_workorder_when_tool_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")

            with contextlib.redirect_stdout(io.StringIO()):
                result = grammar_plan(workspace, manifest, grammar_format="json")

            self.assertIn("commands", result)
            self.assertTrue((workspace / "workorders" / "target" / "grammar" / "json-plan.json").exists())

    def test_advanced_triage_writes_skipped_tool_state_without_tools(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir(parents=True)
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")
            run_dir = workspace / "runs" / "target" / "run"
            (run_dir / "triage").mkdir(parents=True)
            write_json(run_dir / "run.json", {"status": "complete"})
            write_json(run_dir / "triage" / "unique_crashes.json", {"crashes": []})

            with contextlib.redirect_stdout(io.StringIO()):
                result = advanced_triage_run(workspace, manifest, run_id="run")

            self.assertIn("casr", result)
            self.assertIn("exploitable", result)
            self.assertTrue((run_dir / "advanced_triage" / "advanced-triage.json").exists())

    def test_llm_gen_workorder_uses_candidate_packet_without_api_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "src").mkdir(parents=True)
            (source / "src" / "parser.c").write_text(
                "#include <stddef.h>\nint parse_record(const unsigned char *data, size_t size) { return data && size > 0; }\n",
                encoding="utf-8",
            )
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")

            with contextlib.redirect_stdout(io.StringIO()):
                out = write_llm_gen_workorder(
                    workspace,
                    manifest,
                    candidate_id="parse_record",
                    backend="codex",
                )

            self.assertTrue((out / "prompt.md").exists())
            self.assertTrue((out / "benchmark-skeleton.json").exists())
            self.assertIn("Codex", (out / "codex-task.md").read_text(encoding="utf-8"))

    def test_fuzztest_plan_and_template_stay_in_workorders(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "src").mkdir(parents=True)
            (source / "src" / "parser.cc").write_text(
                "#include <cstddef>\n#include <cstdint>\nbool ParseBlob(const uint8_t *data, size_t size) { return data && size > 0; }\n",
                encoding="utf-8",
            )
            manifest = TargetManifest(name="target", language="c++", source_path=str(source), build_system="raw")

            with contextlib.redirect_stdout(io.StringIO()):
                plan_dir = write_fuzztest_plan(workspace, manifest)
            plan = __import__("json").loads((plan_dir / "fuzztest-plan.json").read_text(encoding="utf-8"))
            candidate_id = plan["properties"][0]["id"]
            with contextlib.redirect_stdout(io.StringIO()):
                template_dir = write_fuzztest_template(workspace, manifest, candidate_id=candidate_id)

            self.assertTrue((template_dir / "manifest-entry.json").exists())
            generated_sources = list(template_dir.glob("*_fuzztest.cc"))
            self.assertEqual(len(generated_sources), 1)
            self.assertIn("FUZZ_TEST", generated_sources[0].read_text(encoding="utf-8"))
            self.assertFalse((source / "fuzz_harnesses").exists())

    def test_choose_harness_uses_libfuzzer_crash_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(workspace / "repo"),
                build_system="raw",
                harnesses=[
                    Harness(name="first_libfuzzer", type="libfuzzer"),
                    Harness(name="parser_libfuzzer", type="libfuzzer"),
                ],
            )
            binary = workspace / "build" / "target" / "libfuzzer_asan_ubsan" / "parser_libfuzzer"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            crash = workspace / "runs" / "target" / "run" / "libfuzzer" / "parser_libfuzzer" / "crashes" / "crash-x"
            crash.parent.mkdir(parents=True)
            crash.write_bytes(b"crash")

            harness, chosen_binary, profile = _choose_harness(workspace, manifest, crash)

            self.assertEqual(harness.name, "parser_libfuzzer")
            self.assertEqual(chosen_binary, binary)
            self.assertEqual(profile, "libfuzzer_asan_ubsan")

    def test_better_sanitizer_repro_keeps_libfuzzer_profile(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir()
            harness = Harness(name="parser_libfuzzer", type="libfuzzer")
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[harness],
            )
            binary = workspace / "build" / "target" / "libfuzzer_asan_ubsan" / "parser_libfuzzer"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            crash = workspace / "runs" / "target" / "run" / "libfuzzer" / "parser_libfuzzer" / "crashes" / "crash-x"
            crash.parent.mkdir(parents=True)
            crash.write_bytes(b"boom")

            class Result:
                output = "ERROR: AddressSanitizer: stack-buffer-overflow"
                returncode = 77

            _, chosen_binary, profile, cmd, _ = _better_sanitizer_repro(workspace, manifest, harness, crash, Result())

            self.assertEqual(chosen_binary, binary)
            self.assertEqual(profile, "libfuzzer_asan_ubsan")
            self.assertEqual(cmd, [str(binary), str(crash)])

    def test_triage_recognizes_libfuzzer_leak_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "runs" / "target" / "run"
            leak = run_dir / "libfuzzer" / "parser_libfuzzer" / "crashes" / "leak-deadbeef"
            leak.parent.mkdir(parents=True)
            leak.write_bytes(b"leak input")

            self.assertEqual(_crash_files(run_dir), [leak])
            self.assertEqual(_count_crash_artifacts(run_dir), 1)

    def test_triage_classifies_leaks_separately(self) -> None:
        output = "==1==ERROR: LeakSanitizer: detected memory leaks\nSUMMARY: AddressSanitizer: 10 byte(s) leaked"

        crash_type = _crash_type(output, 1)
        severity, impact = _severity(crash_type, "unknown", output)

        self.assertEqual(crash_type, "memory-leak")
        self.assertEqual(severity, "LOW")
        self.assertIn("resource exhaustion", impact)

    def test_triage_preserves_minimized_reproducer_metadata(self) -> None:
        item = {"id": "abc123", "type": "heap-buffer-overflow"}
        previous = {
            "id": "abc123",
            "minimized_path": "/tmp/abc123.bin",
            "minimized_size": 12,
            "reproducer_base64": "AAAA",
        }

        _preserve_reproducer_metadata(item, previous)

        self.assertEqual(item["minimized_path"], "/tmp/abc123.bin")
        self.assertEqual(item["minimized_size"], 12)
        self.assertEqual(item["reproducer_base64"], "AAAA")

    def test_latest_run_ignores_background_helper_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            root = workspace / "runs" / "target"
            (root / "20260607-010000-campaign-aflpp").mkdir(parents=True)
            (root / "background").mkdir()

            self.assertEqual(find_latest_run(workspace, "target").name, "20260607-010000-campaign-aflpp")

    def test_latest_fuzz_run_prefers_running_campaign_over_newer_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            root = workspace / "runs" / "target"
            campaign = root / "20260608-010000-campaign-aflpp"
            smoke = root / "20260608-010100-smoke-libfuzzer-leaks"
            campaign.mkdir(parents=True)
            smoke.mkdir()
            write_json(campaign / "run.json", {"status": "running"})
            write_json(smoke / "run.json", {"status": "complete"})
            (campaign / "aflpp").mkdir()
            (campaign / "coverage").mkdir()
            (campaign / "coverage" / "parser.report.txt").write_text(
                "TOTAL 10 1 90.00% 2 1 50.00% 20 2 90.00% 0 0 -\n",
                encoding="utf-8",
            )

            self.assertEqual(_latest_fuzz_run(workspace, "target"), campaign)

    def test_latest_fuzz_run_prefers_latest_coverage_over_stale_afl_stats(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            root = workspace / "runs" / "target"
            stale = root / "20260608-010000-campaign-aflpp"
            covered = root / "20260608-010100-smoke-libfuzzer"
            stats = stale / "aflpp" / "parser" / "findings" / "main"
            stats.mkdir(parents=True)
            covered.mkdir(parents=True)
            write_json(stale / "run.json", {"status": "complete"})
            write_json(covered / "run.json", {"status": "complete"})
            (stats / "fuzzer_stats").write_text("execs_done : 10\n", encoding="utf-8")
            (covered / "coverage").mkdir()
            (covered / "coverage" / "parser.report.txt").write_text(
                "TOTAL 10 1 90.00% 2 1 50.00% 20 2 90.00% 0 0 -\n",
                encoding="utf-8",
            )

            self.assertEqual(_latest_fuzz_run(workspace, "target"), covered)

    def test_target_findings_counts_only_reproducible_crashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            run_dir = workspace / "runs" / "target" / "20260607-010000-smoke-libfuzzer"
            (run_dir / "triage").mkdir(parents=True)
            (run_dir / "reports").mkdir()
            (run_dir / "reports" / "abc123.md").write_text("# report\n", encoding="utf-8")
            write_json(
                run_dir / "triage" / "unique_crashes.json",
                {
                    "crashes": [
                        {
                            "id": "abc123",
                            "type": "heap-buffer-overflow",
                            "harness": "parser_libfuzzer",
                            "severity": "HIGH",
                            "reproducible": True,
                        },
                        {
                            "id": "not-real",
                            "type": "unknown-crash",
                            "harness": "parser",
                            "severity": "LOW",
                            "reproducible": False,
                        },
                    ]
                },
            )

            findings = _target_findings(workspace, "target")

            self.assertEqual(findings["total"], 1)
            self.assertEqual(findings["triaged"], 2)
            self.assertEqual(findings["high_or_critical"], 1)
            self.assertEqual([item["id"] for item in findings["findings"]], ["abc123"])
            self.assertEqual(findings["findings"][0]["report"], "runs/target/20260607-010000-smoke-libfuzzer/reports/abc123.md")

    def test_target_findings_dedupes_same_state_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            run1 = workspace / "runs" / "target" / "20260607-010000-campaign-aflpp"
            run2 = workspace / "runs" / "target" / "20260607-020000-smoke-libfuzzer"
            (run1 / "triage").mkdir(parents=True)
            (run2 / "triage").mkdir(parents=True)
            (run2 / "reports").mkdir()
            (run2 / "reports" / "bbb222.md").write_text("# report\n", encoding="utf-8")
            shared_state = "heap-buffer-overflow:parse_record|decode_name|main"
            write_json(
                run1 / "triage" / "unique_crashes.json",
                {
                    "crashes": [
                        {
                            "id": "aaa111",
                            "state": shared_state,
                            "type": "heap-buffer-overflow",
                            "harness": "dns_wire_file",
                            "severity": "HIGH",
                            "reproducible": True,
                            "duplicates": 2,
                        }
                    ]
                },
            )
            write_json(
                run2 / "triage" / "unique_crashes.json",
                {
                    "crashes": [
                        {
                            "id": "bbb222",
                            "state": shared_state,
                            "type": "heap-buffer-overflow",
                            "harness": "dns_wire_libfuzzer",
                            "severity": "HIGH",
                            "reproducible": True,
                            "duplicates": 1,
                        }
                    ]
                },
            )

            findings = _target_findings(workspace, "target")

            self.assertEqual(findings["triaged"], 2)
            self.assertEqual(findings["triaged_artifacts"], 5)
            self.assertEqual(findings["reproducible"], 1)
            self.assertEqual(findings["cross_run_duplicates"], 1)
            self.assertEqual(findings["duplicate_artifacts"], 4)
            self.assertEqual(findings["findings"][0]["id"], "bbb222")
            self.assertEqual(findings["findings"][0]["raw_artifacts"], 5)
            self.assertEqual(findings["findings"][0]["run_duplicate_artifacts"], 3)
            self.assertEqual(findings["findings"][0]["run_ids"], [run1.name, run2.name])

    def test_crash_value_keeps_source_bug_valid_until_product_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repos" / "target"
            (source / "src").mkdir(parents=True)
            (source / "fuzz_harnesses").mkdir()
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_file", type="file", source="fuzz_harnesses/parser_fuzzer.c")],
            )
            run_dir = workspace / "runs" / "target" / "run"
            (run_dir / "triage" / "traces").mkdir(parents=True)
            (run_dir / "minimized").mkdir()
            trace = run_dir / "triage" / "traces" / "abc123.txt"
            trace.write_text(
                f"""ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in parse_record {source}/src/parser.c:142:26
    #1 0x2 in fuzz_parser {source}/fuzz_harnesses/parser_fuzzer.c:60:13
""",
                encoding="utf-8",
            )
            minimized = run_dir / "minimized" / "abc123.bin"
            minimized.write_bytes(b"abc")
            write_json(
                run_dir / "triage" / "unique_crashes.json",
                {
                    "crashes": [
                        {
                            "id": "abc123",
                            "state": "heap-buffer-overflow:parse_record",
                            "type": "heap-buffer-overflow",
                            "access": "read",
                            "harness": "parser_file",
                            "severity": "HIGH",
                            "reproducible": True,
                            "trace_path": str(trace),
                            "minimized_path": str(minimized),
                        }
                    ]
                },
            )

            result = analyze_target_crash_value(workspace, manifest, write=True)
            record = result["records"][0]

            self.assertEqual(record["tier"], "valid_target_bug")
            self.assertEqual(record["root_cause"]["file"], "src/parser.c")
            self.assertEqual(record["product_mapping"]["status"], "unmapped")
            self.assertTrue(crash_value_path(workspace, "target").exists())

    def test_crash_value_downgrades_harness_top_frame_to_noise(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            (source / "src").mkdir(parents=True)
            (source / "fuzz_harnesses").mkdir()
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")
            trace = workspace / "trace.txt"
            trace.write_text(
                f"""ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in dns_u16_parse {source}/fuzz_harnesses/parser_fuzzer.c:22:23
    #1 0x2 in parse_record {source}/src/parser.c:40:4
""",
                encoding="utf-8",
            )
            record = analyze_crash_item(
                workspace,
                manifest,
                {
                    "id": "abc123",
                    "type": "heap-buffer-overflow",
                    "access": "read",
                    "severity": "HIGH",
                    "reproducible": True,
                    "trace_path": str(trace),
                    "minimized_path": str(workspace / "min.bin"),
                },
            )

            self.assertEqual(record["tier"], "noise")
            self.assertTrue(record["harness_assessment"]["suspect"])

    def test_crash_value_keeps_unmapped_tooling_path_valid_not_product_plausible(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repos" / "target"
            (source / "tools").mkdir(parents=True)
            manifest = TargetManifest(name="target", language="c", source_path=str(source), build_system="raw")
            trace = workspace / "trace.txt"
            trace.write_text(
                f"""ERROR: AddressSanitizer: stack-buffer-overflow
    #0 0x1 in format_output {source}/tools/client.c:1100:12
    #1 0x2 in fuzz_parser {source}/fuzz_harnesses/parser_fuzzer.c:52:5
""",
                encoding="utf-8",
            )

            record = analyze_crash_item(
                workspace,
                manifest,
                {
                    "id": "def456",
                    "type": "stack-buffer-overflow",
                    "access": "read",
                    "severity": "HIGH",
                    "reproducible": True,
                    "trace_path": str(trace),
                    "minimized_path": str(workspace / "min.bin"),
                },
            )

            self.assertEqual(record["tier"], "valid_target_bug")
            self.assertEqual(record["product_mapping"]["status"], "unmapped")

    def test_snapshot_counts_triaged_duplicate_crashes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            run_dir = workspace / "runs" / "target" / "run"
            (run_dir / "triage").mkdir(parents=True)
            write_json(
                run_dir / "triage" / "unique_crashes.json",
                {
                    "crashes": [
                        {
                            "id": "abc123",
                            "type": "heap-buffer-overflow",
                            "severity": "HIGH",
                            "reproducible": True,
                            "duplicates": 2,
                        }
                    ]
                },
            )

            snapshot = _snapshot(workspace, run_dir)

            self.assertEqual(snapshot["unique_crash_count"], 1)
            self.assertEqual(snapshot["duplicate_crashes"], 2)
            self.assertEqual(snapshot["triaged_raw_crashes"], 3)

    def test_coverage_total_uses_weakest_harness_report(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "runs" / "target" / "run"
            coverage = run_dir / "coverage"
            coverage.mkdir(parents=True)
            template = """Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover
TOTAL 100 10 {region}% 20 2 {function}% 200 20 {line}% 0 0 -
"""
            (coverage / "strong.report.txt").write_text(template.format(region="90.00", function="90.00", line="90.00"), encoding="utf-8")
            (coverage / "weak.report.txt").write_text(template.format(region="30.00", function="20.00", line="10.00"), encoding="utf-8")

            total = _coverage_total(run_dir)

            self.assertEqual(total, {"region": 30.0, "function": 20.0, "line": 10.0, "reports": 2})

    def test_target_coverage_total_ignores_headers_and_harness_glue(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "runs" / "target" / "run"
            coverage = run_dir / "coverage"
            coverage.mkdir(parents=True)
            (coverage / "focused.report.txt").write_text(
                """Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover
fuzz_harnesses/parser_fuzzer.c 100 90 10.00% 10 9 10.00% 100 90 10.00% 0 0 -
include/parser.h 100 100 0.00% 10 10 0.00% 100 100 0.00% 0 0 -
src/parser.c 100 10 90.00% 10 0 100.00% 100 15 85.00% 0 0 -
TOTAL 300 200 33.33% 30 19 36.67% 300 205 31.67% 0 0 -
""",
                encoding="utf-8",
            )

            total = _coverage_target_total(run_dir)

            self.assertIsNotNone(total)
            self.assertEqual(total["line"], 85.0)
            self.assertEqual(total["function"], 100.0)
            self.assertEqual(total["mode"], "best_target_file_per_report")

    def test_best_file_rows_uses_strongest_harness_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            coverage = Path(td) / "coverage"
            coverage.mkdir()
            template = """Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover
src/parser.c 100 10 {region}% 20 2 {function}% 200 20 {line}% 0 0 -
TOTAL 100 10 {region}% 20 2 {function}% 200 20 {line}% 0 0 -
"""
            weak = coverage / "broad_file.report.txt"
            strong = coverage / "focused_file.report.txt"
            weak.write_text(template.format(region="10.00", function="10.00", line="10.00"), encoding="utf-8")
            strong.write_text(template.format(region="70.00", function="80.00", line="90.00"), encoding="utf-8")

            rows = _best_file_rows(
                [_parse_llvm_coverage_report(weak), _parse_llvm_coverage_report(strong)],
                Path(td),
            )

            self.assertEqual(rows["src/parser.c"]["line"], 90.0)
            self.assertEqual(rows["src/parser.c"]["harness"], "focused_file")

    def test_build_artifacts_counts_existing_manifest_binaries_when_metadata_is_stale(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            source.mkdir()
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[
                    Harness(name="a_file", type="file", source="a.c"),
                    Harness(name="b_file", type="file", source="b.c"),
                ],
            )
            build_dir = workspace / "build" / "target" / "afl_asan_ubsan"
            build_dir.mkdir(parents=True)
            (build_dir / "a_file").write_bytes(b"")
            (build_dir / "b_file").write_bytes(b"")
            write_json(build_dir / "build.json", {"artifacts": [{"harness": "a_file"}]})

            self.assertEqual(_build_artifacts(workspace, manifest)["afl_asan_ubsan"], 2)

    def test_harness_coverage_rows_are_identified_as_non_target_code(self) -> None:
        self.assertTrue(_is_harness_coverage_row({"file": "fuzz_harnesses/parser_fuzzer.c"}))
        self.assertTrue(_is_harness_coverage_row({"file": "/tmp/repo/fuzz_harnesses/parser_fuzzer.c"}))
        self.assertFalse(_is_harness_coverage_row({"file": "src/parser.c"}))

    def test_harness_candidates_do_not_become_target_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            harness_dir = source / "fuzz_harnesses"
            harness_dir.mkdir(parents=True)
            (harness_dir / "parser_fuzzer.c").write_text(
                "int fuzz_readline_bytes(const unsigned char *data, unsigned long size) { return size > 0 && data != 0; }\n",
                encoding="utf-8",
            )
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_file", type="file", source="fuzz_harnesses/parser_fuzzer.c")],
            )
            run_dir = workspace / "runs" / "target" / "run"
            coverage = run_dir / "coverage"
            coverage.mkdir(parents=True)
            (coverage / "parser_file.report.txt").write_text(
                """Filename Regions Missed Regions Cover Functions Missed Functions Executed Lines Missed Lines Cover Branches Missed Branches Cover
fuzz_harnesses/parser_fuzzer.c 10 1 90.00% 3 1 66.67% 11 7 36.36% 0 0 -
TOTAL 10 1 90.00% 3 1 66.67% 11 7 36.36% 0 0 -
""",
                encoding="utf-8",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                result = harness_blockers(workspace, manifest, run_id="run", as_json=True)

            self.assertEqual(result["summary"]["blockers"], 0)
            self.assertEqual(result["blockers"], [])

    def test_blocker_classifications_separate_documented_platform_gaps(self) -> None:
        blockers = [
            {
                "kind": "candidate_file_unreported",
                "candidate": "linux_parser_42",
                "file": "src/linux_parser.c",
                "function": "parse_linux",
            },
            {
                "kind": "candidate_file_unreported",
                "candidate": "bsd_parser_7",
                "file": "platform/bsd.c",
                "function": "parse_bsd",
            },
        ]
        classifications = [
            {
                "file": "platform/bsd.c",
                "function": "parse_bsd",
                "status": "platform-specific",
                "reason": "BSD-only backend is not built in the Linux native target",
            }
        ]

        unresolved, classified = _apply_blocker_classifications(blockers, classifications)

        self.assertEqual([item["candidate"] for item in unresolved], ["linux_parser_42"])
        self.assertEqual([item["candidate"] for item in classified], ["bsd_parser_7"])
        self.assertEqual(classified[0]["classification"]["status"], "platform-specific")

    def test_harness_review_accepts_multiline_main_signature(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            source = workspace / "repo"
            harness = source / "fuzzer.c"
            harness.parent.mkdir(parents=True)
            harness.write_text("int\nmain(int argc, char **argv) { return argc > 1 && argv != 0; }\n", encoding="utf-8")
            manifest = TargetManifest(
                name="target",
                language="c",
                source_path=str(source),
                build_system="raw",
                harnesses=[Harness(name="parser_file", type="file", argv=["@@"], source="fuzzer.c")],
            )

            review = _review_data(workspace, manifest)

            self.assertNotIn(
                "file/stdin harness does not define an obvious main()",
                [item["message"] for item in review["warnings"]],
            )

    def test_supervisor_classifies_only_real_campaign_processes(self) -> None:
        workspace = Path("/home/azanul/fuzz-pipeline")
        self.assertEqual(
            _classify_cmdline(
                [
                    "afl-fuzz",
                    "-o",
                    "/home/azanul/fuzz-pipeline/runs/target/20260607-010000-campaign-aflpp/aflpp/h/findings",
                ],
                workspace,
                "target",
            ),
            "afl-fuzz",
        )
        self.assertEqual(
            _classify_cmdline(
                ["python3", "-m", "fuzz_pipeline", "--runtime", "native", "run", "target", "--engine", "aflpp"],
                workspace,
                "target",
            ),
            "fuzzctl-run",
        )
        self.assertIsNone(
            _classify_cmdline(
                ["python3", "-m", "fuzz_pipeline", "--runtime", "native", "supervisor", "campaign-loop", "target"],
                workspace,
                "target",
            )
        )

    def test_supervisor_detects_mismatched_afl_worker_plan(self) -> None:
        manifest = TargetManifest(
            name="target",
            language="c",
            source_path="/repo",
            build_system="raw",
            harnesses=[
                Harness(name="dns_wire_file", type="file"),
                Harness(name="config_parse_file", type="file"),
                Harness(name="dns_rdata_file", type="file"),
                Harness(name="srp_filedata_file", type="file"),
            ],
        )
        active = [
            {"kind": "afl-fuzz", "harness": "dns_wire_file"},
            {"kind": "afl-fuzz", "harness": "dns_wire_file"},
            {"kind": "afl-fuzz", "harness": "dns_wire_file"},
            {"kind": "afl-fuzz", "harness": "dns_wire_file"},
        ]

        self.assertEqual(_active_afl_worker_counts(active), {"dns_wire_file": 4})
        self.assertIn(
            "does not match",
            _campaign_mismatch_reason(active, manifest, engine="aflpp", workers=8) or "",
        )


if __name__ == "__main__":
    unittest.main()
