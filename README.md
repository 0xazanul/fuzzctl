# fuzz-pipeline

Docker-first Python orchestration for Linux C/C++ memory-bug fuzzing.

The pipeline does not create a new fuzzer. It drives AFL++ for long-running campaigns, libFuzzer for harness validation, reproduction, and minimization when a libFuzzer harness exists, optional FuzzTest property harnesses for C++ API invariants, and optional advanced tools for deepening campaigns after the core loop is healthy. Harness generation is compile-aware and coverage-guided: the system builds a compile database, ranks parser/API candidates, writes AI work packets, validates sanitizer builds, then uses coverage reports to decide what to improve next.

## Quick Start

```bash
cd /home/azanul/fuzz-pipeline
bin/fuzzctl doctor
bin/fuzzctl detect fixtures/vuln_parser
bin/fuzzctl --runtime native build-context vuln_parser --generate
bin/fuzzctl --runtime native build vuln_parser --profile libfuzzer_asan_ubsan
bin/fuzzctl --runtime native smoke vuln_parser --seconds 30
```

Docker is the default runtime for build/fuzz commands:

```bash
bin/fuzzctl image-build
bin/fuzzctl smoke vuln_parser --seconds 300
```

Use `--runtime native` while developing on a host that already has clang, AFL++, and LLVM tools installed.

`doctor` checks Docker socket access. If it reports permission denied for `/var/run/docker.sock`, either fix Docker group/rootless access or run with `--runtime native` until Docker is available.

If `/proc/sys/kernel/core_pattern` is piped to an external crash handler, `doctor` will show it. AFL++ runs set `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` for non-root VPS compatibility, but the better long-running setup is still `echo core >/proc/sys/kernel/core_pattern` as root.

## Commands

- `doctor`: verify host tools, Docker, CPU, memory, disk, and fuzzing binaries.
- `tools doctor --deep`: verify the curated core toolchain and optional helpers.
- `tools install-core`: install apt-backed missing core tools and report manual tools.
- `tools advanced`: show advanced-tool readiness for SymCC, OSS-Fuzz-Gen workorders, AFL++ Grammar-Mutator, CASR, and exploitable.
- `tools install-advanced --tool <tool>`: clone or install optional advanced tools into ignored local state.
- `image-build`: build the local Docker image.
- `dashboard --host 127.0.0.1 --port 8088`: serve the browser dashboard; SSH tunnel access is recommended.
- `launch <repo-url-or-path>`: clone/onboard a repository and run the safe parts of the pipeline.
- `alerts test`: test or dry-run Discord webhook delivery.
- `detect <path>`: identify language and build system support.
- `init-target <path> --name <name>`: create a starter manifest.
- `build-context <name>`: discover or generate compile database context and link hints.
- `harness ai-plan/index/knowledge/prompt/synthesize/work-order/fuzztest-plan/fuzztest-generate/blockers/suspicious-points/qa/iterate/scan/scaffold/review/validate/score`: plan, create, review, build, score, and iterate harnesses.
- `build <name> --profile <profile>`: build an instrumented target.
- `smoke <name>`: run a short harness/sanitizer validation.
- `run <name>`: run AFL++ and/or libFuzzer campaigns.
- `fuzztest <name>`: run optional FuzzTest property harnesses.
- `status <name>`: summarize campaign stats.
- `monitor <name>`: monitor a run and emit actionable alerts.
- `triage <name>`: reproduce, classify, symbolize, and deduplicate crashes.
- `minimize <name>`: minimize unique reproducers.
- `report <name>`: emit Markdown reports with impact analysis.
- `crash-value <name>`: rank crashes by evidence, root cause, product reachability, and reportability.
- `readiness <name>`: audit target readiness without launching new fuzzing work.
- `advanced-triage <name>`: add CASR and exploitable evidence for already deduplicated crashes.
- `hybrid symcc <name>`: run bounded SymCC concolic sync against an existing AFL++ run.
- `corpus grammar-plan/grammar-enrich/grammar-configure <name>`: build and attach AFL++ grammar-mutator corpora/mutator state for structured targets.
- `post-cycle <name>`: run monitor, triage, minimization, crash-value, corpus sync, coverage, guidance, blockers, suspicious points, and harness QA for one run.
- `guide coverage <name>`: recommend next steps from coverage/campaign signals.

## Profiles

- `afl_asan_ubsan`: AFL++ compile with ASan+UBSan.
- `afl_lto_cmplog`: AFL++ LTO/CMPLOG build with ASan+UBSan.
- `libfuzzer_asan_ubsan`: clang/libFuzzer with ASan+UBSan.
- `fuzztest_asan_ubsan`: optional C++ FuzzTest property harness build with ASan+UBSan and sanitizer coverage.
- `symcc`: native SymCC/QSYM concolic companion build for AFL++ hybrid campaigns.
- `coverage`: LLVM source coverage build.

## Scope

Current scope is intentionally narrow:

- Linux C/C++ source targets only.
- Docker-first, native override supported.
- AFL++ and libFuzzer are core; FuzzTest, SymCC, Grammar-Mutator, CASR, exploitable, and OSS-Fuzz-Gen-style workorders are optional layers.
- Binary-only fuzzing, Jackalope, TinyInst, and framework-specific harnesses are future modules.

## Reporting Standard

A finding report must include:

- Reproduction command.
- Minimized input.
- Symbolized sanitizer trace.
- Crash type and severity.
- Attacker control and security impact.
- Why it is more than "program crashed."

Null dereference reports default to DoS/medium unless the analysis proves a stronger impact.

## Monitoring And Alerts

Set a Discord webhook only through the environment:

```bash
export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'
bin/fuzzctl --runtime native alerts test
bin/fuzzctl --runtime native monitor vuln_parser --once
```

Alerts are actionable-only: new reproducible unique crashes, high/critical severity findings, campaign failures, disk danger, and stalled campaigns. Without `DISCORD_WEBHOOK_URL`, monitor still writes `runs/<target>/<run>/monitor/state.json` and prints events locally.

Crash value analysis is intentionally conservative:

```bash
bin/fuzzctl --runtime native crash-value <target-name>
```

It separates raw crash noise from useful security work: noise, valid target bugs, product-plausible bugs, and report candidates. A crash is not treated as product-impacting until the root cause is mapped to a shipped product path and verified outside the fuzz harness.

For deeper crash evidence after normal triage/minimization:

```bash
bin/fuzzctl --runtime native advanced-triage <target-name> --run <run-id>
```

This runs CASR when available and the GDB exploitable plugin when installed. It never replaces sanitizer evidence or minimization; it adds severity and clustering context for crashes that already reproduce.

## Dashboard

Run this from the VPS:

```bash
bin/fuzzctl --runtime native dashboard --host 127.0.0.1 --port 8088
```

From your laptop or desktop, tunnel the port:

```bash
ssh -L 8088:127.0.0.1:8088 azanul@<vps-public-ip>
```

Then open `http://127.0.0.1:8088/`. The dashboard shows tool readiness, connectivity diagnostics, targets, runs, reports, logs, coverage, launch reports, and a repo onboarding form.

Direct `http://10.x.x.x:8088/` access only works from the same private VNet/VPN. If public exposure is intentionally needed, set `FUZZ_DASHBOARD_TOKEN` or pass `--token` and open the cloud firewall rule deliberately.

For public HTTPS access without opening inbound VPS firewall rules, install `cloudflared` and enable:

```bash
systemctl --user enable --now fuzz-dashboard-tunnel.service
journalctl --user -u fuzz-dashboard-tunnel.service -n 80 --no-pager | grep -o 'https://[^ ]*trycloudflare.com' | tail -1
```

The public URL still requires the dashboard token.

## Post-Cycle Cleanup

After any campaign, run the full cleanup once:

```bash
bin/fuzzctl --runtime native post-cycle <target-name> --run <run-id>
```

This is what the reboot-safe supervisor uses after each campaign. It sends monitor alerts when configured, deduplicates crashes, minimizes real reproducers, ranks crash value, syncs queue-derived corpora, generates coverage from AFL queue inputs, writes coverage guidance, writes harness blockers, writes suspicious-point workorders, and writes a harness QA packet. The dashboard run page shows this step-by-step status.

## One-Command Onboarding

```bash
bin/fuzzctl --runtime native launch https://github.com/org/repo.git --name repo
```

The launch flow clones into `repos/<name>`, detects language/build system, creates a manifest, scans harness candidates, and writes a launch report. If a real harness is already configured, it can also run smoke/campaign with `--smoke-seconds` and `--campaign-hours`. If no real harness exists, it stops honestly with the exact harness work needed.

## Harness Flow

```bash
bin/fuzzctl --runtime native harness scan /path/to/repo
bin/fuzzctl --runtime native harness ai-plan /path/to/repo
bin/fuzzctl --runtime native build-context target_name --generate
bin/fuzzctl --runtime native harness index target_name
bin/fuzzctl --runtime native harness knowledge target_name --candidate <candidate-id>
bin/fuzzctl --runtime native harness work-order target_name
bin/fuzzctl --runtime native harness prompt target_name
bin/fuzzctl --runtime native harness prompt target_name --candidate <candidate-id>
bin/fuzzctl --runtime native harness synthesize target_name --candidate <candidate-id>
bin/fuzzctl --runtime native harness scaffold target_name --type libfuzzer --harness-name parser --function parse_api
bin/fuzzctl --runtime native harness review target_name
bin/fuzzctl --runtime native harness validate target_name --build
bin/fuzzctl --runtime native coverage target_name
bin/fuzzctl --runtime native harness blockers target_name
bin/fuzzctl --runtime native harness suspicious-points target_name
bin/fuzzctl --runtime native harness qa target_name
bin/fuzzctl --runtime native harness iterate target_name --candidate <candidate-id>
bin/fuzzctl --runtime native harness score target_name
bin/fuzzctl --runtime native readiness target_name
```

`build-context` finds or creates `compile_commands.json`, extracts include dirs, defines, standards, compile flags, and link artifacts, then stores the summary in the target manifest. This is the first gate for serious harness authoring because AI prompts and build attempts need the same compile reality as the target. Use `--refresh` when an old generated compile database should be replaced.

`harness index` writes `workorders/<target>/indexes/latest-index.json` with compile-aware candidate ranking. `harness knowledge` writes a single-candidate packet for Codex/Claude. `harness synthesize` creates a draft harness, compiles either that draft or a supplied harness source with libFuzzer+ASan+UBSan, stores the build log, and writes a repair prompt. A generated draft that compiles is still marked `draft_ready_for_ai` until the real target API call is wired.

`harness work-order` writes `workorders/<target>/<timestamp>-harness-work-order/` with candidate-specific prompts, source excerpts, call-site hints, compile context, seed/dictionary ideas, and validation commands. Give one prompt at a time to Codex/Claude, write one narrow harness, then run review/build/smoke/coverage/blockers/qa/score before moving to the next candidate.

`harness qa` is the local quality gate for the four production harness principles: logic correctness, API protocol compliance, security-boundary respect, and entry-point adequacy. It does not trust an LLM claim; it checks source shape, banned behavior, seeds, build artifacts, and coverage evidence. `harness suspicious-points` ranks uncovered parser/decoder functions for the next harness, using compile-aware candidates and LLVM coverage.

`readiness` is the target-level truth check. It combines harness review, sanitizer build artifacts, seed count, live campaign liveness, queue growth, coverage evidence, triage state, and optional advanced-tool integration into one gate report under `workorders/<target>/readiness/`. Use it before claiming a target is fully ready.

Scaffolded harnesses are templates. Wire the real parser/API call before treating coverage or crash results as meaningful. A good harness is deterministic, fast, sanitizer-clean on seeds, tolerant of malformed input, and deep enough to reach parser/deserializer logic under coverage.

FuzzTest is an optional harness framework layer, not a replacement for AFL++. Use it when the target exposes C++ APIs with useful properties: parser never-crashes, serializer/deserializer round trips, canonicalization, state-machine invariants, or equivalence against a reference implementation.

```bash
bin/fuzzctl --runtime native harness fuzztest-plan target_name
bin/fuzzctl --runtime native harness fuzztest-generate target_name --candidate <candidate-id>
bin/fuzzctl --runtime native build target_name --profile fuzztest_asan_ubsan
bin/fuzzctl --runtime native fuzztest target_name --seconds 300
```

`harness fuzztest-generate` writes a non-applied template under `workorders/`. Do not add it to the manifest until the include path, target call, FuzzTest/GoogleTest link flags, and property assertion are real. Prefer `build_commands.fuzztest_asan_ubsan` for projects that already use CMake or Bazel FuzzTest integration.

## Advanced Tools

The advanced layer is intentionally separate from the core orchestration. Check readiness first:

```bash
bin/fuzzctl --runtime native tools advanced
```

Current advanced modules:

- SymCC/QSYM: builds a `symcc` companion binary and uses `symcc_fuzzing_helper` to feed new constraint-solved inputs into an existing AFL++ output directory.
- OSS-Fuzz-Gen style workorders: `harness llm-gen` writes Codex-ready harness packets without storing LLM API credentials or requiring a cloud model.
- AFL++ Grammar-Mutator: `corpus grammar-enrich` generates structured seed/tree corpora, and `corpus grammar-configure` attaches `AFL_CUSTOM_MUTATOR_LIBRARY` plus tree state to a file/stdin harness.
- CASR/exploitable: `advanced-triage` writes CASR reports and exploitable GDB logs for deduplicated crashes.

Typical commands:

```bash
bin/fuzzctl --runtime native tools install-advanced --tool casr
bin/fuzzctl --runtime native tools install-advanced --tool grammar-mutator
bin/fuzzctl --runtime native tools install-advanced --tool symcc
bin/fuzzctl --runtime native tools install-advanced --tool exploitable
bin/fuzzctl --runtime native tools symcc-self-test

bin/fuzzctl --runtime native harness llm-gen target_name --candidate <candidate-id>
bin/fuzzctl --runtime native corpus grammar-plan target_name --format json
bin/fuzzctl --runtime native corpus grammar-enrich target_name --harness <file-harness> --format json
bin/fuzzctl --runtime native corpus grammar-configure target_name --harness <file-harness> --format json --only
bin/fuzzctl --runtime native hybrid symcc target_name --run <afl-run-id> --dry-run --all-harnesses
bin/fuzzctl --runtime native hybrid symcc target_name --run <afl-run-id> --seconds 1800
bin/fuzzctl --runtime native advanced-triage target_name --run <run-id>
```

Do not run advanced tools as a substitute for better harnesses. Add them after the target has sanitizer-clean builds, meaningful coverage, minimized corpora, and deduplicated crashes.

For SymCC, prefer the LLVM 17 build on this VPS. `tools symcc-self-test` compiles a tiny branchy program with `symcc`, runs it with `SYMCC_INPUT_FILE`, and verifies that the QSYM backend generates new inputs. If that self-test fails, treat SymCC hybrid as unavailable until the toolchain is fixed.

## Research Matrix

`research/fuzzer-matrix.json` records the Awesome-AFL ecosystem and requested related repos. It is a strategy database, not an install list. The default install remains curated and operational: AFL++, libFuzzer/LLVM, sanitizers, Honggfuzz, coverage tools, debuggers, and corpus helpers.
