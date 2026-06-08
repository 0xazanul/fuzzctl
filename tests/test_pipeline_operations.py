import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fuzz_pipeline.campaign import _count_crash_artifacts, _worker_counts
from fuzz_pipeline.coverage import collect_coverage_inputs
from fuzz_pipeline.dashboard import _target_findings
from fuzz_pipeline.harness import _coverage_total, _review_data
from fuzz_pipeline.manifest import Harness, TargetManifest
from fuzz_pipeline.monitor import _raw_crash_events
from fuzz_pipeline.supervisor import _classify_cmdline
from fuzz_pipeline.triage import _choose_harness, _crash_files, _crash_type, _preserve_reproducer_metadata, _severity
from fuzz_pipeline.util import write_json
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

    def test_worker_counts_are_total_budget_not_per_harness(self) -> None:
        harnesses = [
            Harness(name="a", type="file"),
            Harness(name="b", type="file"),
            Harness(name="c", type="file"),
            Harness(name="d", type="file"),
        ]

        self.assertEqual(_worker_counts(harnesses, 7), {"a": 2, "b": 2, "c": 2, "d": 1})

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
                    Harness(name="thread_netdata_libfuzzer", type="libfuzzer"),
                ],
            )
            binary = workspace / "build" / "target" / "libfuzzer_asan_ubsan" / "thread_netdata_libfuzzer"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            crash = workspace / "runs" / "target" / "run" / "libfuzzer" / "thread_netdata_libfuzzer" / "crashes" / "crash-x"
            crash.parent.mkdir(parents=True)
            crash.write_bytes(b"crash")

            harness, chosen_binary, profile = _choose_harness(workspace, manifest, crash)

            self.assertEqual(harness.name, "thread_netdata_libfuzzer")
            self.assertEqual(chosen_binary, binary)
            self.assertEqual(profile, "libfuzzer_asan_ubsan")

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
                            "harness": "thread_netdata_libfuzzer",
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


if __name__ == "__main__":
    unittest.main()
