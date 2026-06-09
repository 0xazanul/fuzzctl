# Agent Rules

This repository is a Python orchestration system for C/C++ memory-bug fuzzing.

Hard rules:

- Do not use or copy the old local fuzzing skill. This project stands alone.
- Keep the system Python-first: Python orchestrates setup, builds, fuzzing, monitoring, triage, reports, and dashboards.
- Do not implement a new fuzzer. Orchestrate proven tools: AFL++, libFuzzer, honggfuzz where supported, and sanitizer/coverage tooling.
- Keep advanced tooling modular. SymCC, OSS-Fuzz-Gen-style workorders, Grammar-Mutator, CASR, and exploitable are optional layers on top of the core loop, not replacements for good harnesses.
- Keep the current system focused on Linux source-available C/C++ targets.
- Do not report a bug from code review alone.
- Do not report a fuzzer crash unless it is reproducible and minimized.
- Treat "crash alone" as insufficient. Reports need attacker-controlled input, sanitizer evidence, minimized reproducer, and security impact.
- Prioritize critical memory corruption: OOB write, use-after-free write, double-free, invalid free, wild write, and exploitable integer-to-allocation paths.
- Classify null pointer dereferences as DoS/medium by default unless impact analysis proves a stronger boundary or exploitation path.
- Keep generated artifacts in `build/` and `runs/`; do not commit campaign output.
- Preserve target manifests as the source of truth. Avoid one-off shell commands that bypass `fuzzctl`.
- Use `fuzzctl monitor` for operational status and Discord alerts; do not paste webhook URLs into tracked files.
- Use `fuzzctl supervisor campaign-loop` for reboot-safe long campaigns. Do not start duplicate AFL++ campaigns manually when the supervisor is active.
- Use `research/fuzzer-matrix.json` to decide whether an external fuzzer is target-appropriate before installing it.
- Use `fuzzctl tools advanced` before relying on optional advanced tools. If a tool is absent, write a skipped packet or setup workorder instead of claiming that phase ran.
- Use AI/Codex for harness authoring, but require compile context, a candidate index or work order, review, sanitizer build, smoke run, coverage, blocker analysis, harness QA, and score before long campaigns.
- Treat generated draft harnesses as placeholders until they call the target API and coverage proves the intended parser/deserializer code is reached.
- Prefer SSH tunnel dashboard access. Do not expose the dashboard publicly without token auth and explicit network firewall intent.

When adding support for a new target:

1. Run `fuzzctl detect <path>`.
2. Create or update `targets/<name>/target.json`.
3. Run `fuzzctl build-context <name> --generate` and inspect whether compile units were found.
4. Run `fuzzctl harness ai-plan <path>` and `fuzzctl harness index <name>`.
5. Use `fuzzctl harness knowledge <name> --candidate <id>` or `fuzzctl harness work-order <name>` before asking Codex to write harness code.
6. Add at least one harness that accepts bytes from a file, stdin, or libFuzzer input.
7. Run `fuzzctl harness synthesize <name> --candidate <id> --source <harness>` for compile/repair feedback when useful.
8. Run `fuzzctl harness review <name>` after every harness edit.
9. Build ASan+UBSan profiles before fuzzing.
10. Run smoke before long campaigns.
11. Run coverage, `fuzzctl harness blockers <name>`, `fuzzctl harness suspicious-points <name>`, `fuzzctl harness qa <name>`, coverage guidance, and `fuzzctl harness score <name>` before deciding the harness is good enough.
12. After campaigns, run `fuzzctl post-cycle <name> --run <id>` instead of hand-running partial cleanup commands.
13. Triage, deduplicate, minimize, and report only reproducible crashes.
14. Only run `fuzzctl hybrid symcc` after an AFL++ run exists; it is a bounded deepening phase over AFL queue inputs, not a first-stage fuzzer.
15. Only attach Grammar-Mutator to file/stdin harnesses with matching seed/tree corpora and a real structured input format.
16. Use `fuzzctl advanced-triage` for CASR/exploitable evidence after normal triage, not before crash reproduction.
