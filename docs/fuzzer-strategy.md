# Fuzzer Strategy

The pipeline does not install every fuzzer listed in Awesome-AFL. Many entries are research prototypes, Windows-only, kernel/full-system tools, network/stateful tools, or ideas now represented inside AFL++.

Default operational stack:

- AFL++ for long-running campaigns.
- libFuzzer for in-process smoke, reproduction, and minimization.
- FuzzTest for optional C++ property/invariant harnesses.
- SymCC/QSYM as a bounded post-AFL++ hybrid deepening pass when the AFL queue has stalled on parser constraints.
- AFL++ Grammar-Mutator for structured inputs after dictionaries and seed minimization are in place.
- CASR and exploitable for secondary crash-severity evidence after sanitizer repro/deduplication.
- ASan+UBSan on every memory-bug build.
- LLVM coverage for harness quality.
- Harness QA for the four principles: logic correctness, API protocol compliance, security-boundary respect, and entry-point adequacy.
- Honggfuzz as an optional secondary engine.
- Radamsa as optional corpus enrichment when available.

Escalation rules:

- Hard magic bytes or deep comparisons: enable AFL++ CMPLOG and dictionaries first.
- Structured text/binary formats: add dictionaries, minimize the seed corpus, then attach AFL++ Grammar-Mutator or a target-specific custom mutator.
- C++ APIs with clear invariants: add FuzzTest properties for never-crashes, round trips, canonicalization, and state-machine contracts; keep AFL++ as the long-running campaign engine.
- Stalled coverage: minimize corpus, inspect uncovered parser code, split harnesses, add persistent mode where safe, then run a bounded SymCC hybrid pass against an existing AFL++ run.
- Coverage-guided harness expansion: run `fuzzctl harness suspicious-points <target> --run <id>` and target the top uncovered parser/decoder points before adding more campaign hours.
- Directed CVE/patch-diff hunt: consider AFLGo-style target locations.
- Stateful network protocol: future AFLNet/StateAFL adapter.
- Binary-only: future AFL++ QEMU/FRIDA/SymQEMU/Eclipser/Jackalope/TinyInst adapter.
- Windows/BSD/kernel: future platform-specific adapter, not this Linux C/C++ v1.

Reporting rule:

Never report crashes found only on transformed or emulated variants unless the same minimized input reproduces on the original target with sanitizer or product-build evidence.

Operational rule:

Run `fuzzctl post-cycle <target> --run <id>` after campaigns. It is the canonical cleanup path for raw crash alerts, reproducible crash triage, advanced triage when CASR/exploitable are installed, corpus sync, queue-derived coverage, coverage guidance, harness blockers, suspicious-point ranking, and harness QA.

Readiness rule:

Run `fuzzctl readiness <target> --run <id>` before calling a target production-ready. The readiness report is intentionally conservative: core harness/build/campaign gates must pass, while advanced tools are shown as configured, warning, or not configured instead of being treated as mandatory proof.

Advanced-tool rule:

Use `fuzzctl tools advanced` before enabling advanced phases. A missing optional tool must produce an explicit skipped packet, not a silent pass. SymCC, Grammar-Mutator, CASR, exploitable, and OSS-Fuzz-Gen reference repos live under ignored `state/external-tools/` and must not be committed.
For SymCC specifically, use the LLVM 17 build and run `fuzzctl tools symcc-self-test` after rebuilds or toolchain changes. A passing self-test is required before trusting a hybrid run for coverage-deepening decisions.
