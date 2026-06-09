# fuzz-pipeline Onboarding and Customer Delivery Guide

## 1. Executive Summary

`fuzz-pipeline` is a Docker-first Python orchestration system for Linux C/C++ memory-bug fuzzing. It is not a new fuzzer; it drives and coordinates existing proven tools such as AFL++, libFuzzer, and optional FuzzTest harnesses to create a practical, scalable, coverage-aware, and reportable fuzzing pipeline.

This document is intended as a complete onboarding guide for customers, security teams, engineering partners, and operations staff. It covers architecture, workflows, supported capabilities, target manifest shape, command reference, deployment recommendations, alerting, reporting practices, and operational rules.

---

## 2. Purpose and Scope

### 2.1 Purpose

The goal of `fuzz-pipeline` is to:

- onboard C/C++ source targets quickly
- discover and validate harnesses for parser-like and API-based inputs
- build instrumented binaries with sanitizer coverage
- run long-lived AFL++ campaigns and smoke-test libFuzzer harnesses
- triage, minimize, and score crashes for actionable reporting
- provide structured guidance for harness quality and coverage improvements
- optionally use C++ FuzzTest properties when appropriate

### 2.2 Scope

The pipeline is intentionally narrow and production-ready for:

- Linux C and C++ user-space applications
- compile-aware harness generation and validation
- AFL++ long-running campaigns as the primary crash discovery engine
- libFuzzer for harness validation, reproduction, minimization, and lightweight campaign work
- FuzzTest as an optional property/exemplar harness layer, not a replacement for crash discovery
- Docker-first orchestration, with a native runtime override for host development

Not yet in scope for this version:

- Windows, BSD, kernel, or embedded fuzzing
- binary-only QEMU/FRIDA instrumentation adapters
- direct support for other engines such as Honggfuzz beyond optional future use
- network protocol state machines beyond handwritten harnesses
- framework-specific harness generators like Jackalope or TinyInst

---

## 3. Repository and Workspace Layout

### 3.1 Top-level structure

- `README.md`: high-level overview and quick start steps
- `pyproject.toml`: Python package metadata and CLI entrypoint
- `bin/fuzzctl`: local wrapper to execute the toolchain
- `docs/`: pipeline documentation and strategy documents
- `src/fuzz_pipeline/`: core Python implementation
- `targets/`: onboarded target manifests and metadata
- `workorders/`: harness creation, AI work orders, and candidate artifacts
- `runs/`: active or historical fuzz campaigns and triage results
- `build/`: build context, compile databases, and build artifacts
- `state/`: pipeline runtime state and lock tracking
- `systemd/`: optional user service definitions for dashboard and campaign supervision
- `fixtures/`: sample or test target sources used for development
- `tests/`: pipeline unit tests and validation logic
- `corpora/`: sample corpora and support files

### 3.2 Important directories

- `targets/<name>/target.json`: the canonical target manifest
- `workorders/<target>/`: generated harness work orders, AI prompts, and candidate builds
- `runs/<target>/<run>/`: fuzz run artifacts, triage, crash dedupe, coverage, and reports
- `build/<target>/build-context/`: compile database and build context files
- `systemd/fuzz-*.service`: user-level systemd services for dashboard, monitor, and campaign loops

---

## 4. Runtime and Deployment Model

### 4.1 Docker-first design

`fuzz-pipeline` is built to run inside Docker by default. The wrapper command `bin/fuzzctl` uses `--runtime docker` unless the environment variable `FUZZ_PIPELINE_INSIDE_DOCKER` is set.

Docker mode is suitable for:

- consistent toolchain execution across hosts
- isolating fuzzing dependencies and runtime environment
- supporting Linux targets on shared deployment infrastructure

### 4.2 Native mode

`--runtime native` is available for developer-hosted execution when the host already provides:

- clang/LLVM toolchain
- AFL++
- libFuzzer and sanitizer build tooling
- Docker socket access is not required

Native mode is valuable for local development, quick debugging, and when Docker is unavailable.

### 4.3 Environment and shell behavior

- `bin/fuzzctl` exports `PYTHONPATH` to include `src`
- `fuzz-pipeline` commands may read environment variables such as `FUZZ_DASHBOARD_TOKEN`, `DISCORD_WEBHOOK_URL`, and `FUZZ_PIPELINE_INSIDE_DOCKER`
- Container runtime commands are automatically executed in Docker for build/fuzz commands unless native mode is explicitly requested

### 4.4 Systemd supervisor services

`systemd` user services are provided to support recovery and long-running campaigns:

- `fuzz-dashboard.service`: dashboard bound to `127.0.0.1:8088`
- `fuzz-dashboard-lan.service`: dashboard on `0.0.0.0:8089` with token protection
- `fuzz-dashboard-tunnel.service`: Cloudflare quick tunnel for remote dashboard access
- `fuzz-monitor@<target-name>.service`: monitor loop for one target
- `fuzz-campaign@<target-name>.service`: supervised campaign loop with crash triage and post-cycle actions

These services should be installed under `~/.config/systemd/user` with user-level systemd, and `loginctl enable-linger $USER` should be configured for service persistence across logouts.

---

## 5. Tooling and Dependencies

### 5.1 Core tools supported

`fuzz-pipeline` expects a curated Linux fuzzing toolchain such as:

- `clang` / `clang++`
- `AFL++`
- `libFuzzer` / `LLVM` sanitizer libraries
- `ASan` and `UBSan`
- `LLVM source coverage`
- Optional: `Honggfuzz`, `Radamsa`

### 5.2 Toolchain inventory commands

- `bin/fuzzctl doctor`: verify host tooling, Docker access, CPU, memory, disk, and available fuzzing binaries
- `bin/fuzzctl tools doctor --deep`: verify curated core fuzzing tools and optional helpers
- `bin/fuzzctl tools install-core`: install apt-backed missing core tools when supported

### 5.3 Recommended host tuning

- Set `kernel.core_pattern=core` for sanitizer crash handling
- Ensure enough memory for instrumented builds and fuzz campaigns
- Keep available disk for run artifacts, corpora, and reports
- Run `doctor` early and address any container or toolchain issues before onboarding targets

---

## 6. Operational Workflow

### 6.1 Quick start example

```bash
cd /home/azanul/fuzz-pipeline
bin/fuzzctl doctor
bin/fuzzctl detect fixtures/vuln_parser
bin/fuzzctl --runtime native build-context vuln_parser --generate
bin/fuzzctl --runtime native build vuln_parser --profile libfuzzer_asan_ubsan
bin/fuzzctl --runtime native smoke vuln_parser --seconds 30
```

### 6.2 One-command repo onboarding

```bash
bin/fuzzctl --runtime native launch https://github.com/org/repo.git --name repo
```

The launch flow:

- clones or updates the repository under `repos/<name>`
- detects language and build system
- creates or updates a `targets/<name>/target.json` manifest
- scans harness candidates
- writes a launch report
- runs safe actions such as smoke checks if configured
- stops honestly when a real harness build is not available

### 6.3 Target creation and manifest initialization

Create a starter manifest for a local source tree:

```bash
bin/fuzzctl init-target /path/to/source --name my_target
```

This creates `targets/my_target/target.json` with:

- detected language and build system
- default harness definition for file-mode AFL++
- default seed corpus path `seeds`
- default memory, timeout, and input limits

### 6.4 Build context discovery

`build-context` is the first serious gate for harness authoring. It discovers or generates:

- `compile_commands.json`
- include directories
- defines
- compiler flags and standards
- link artifacts
- build-system hints

Run:

```bash
bin/fuzzctl build-context my_target --generate
```

Use `--method auto|cmake|bear|synthetic` to control discovery. Use `--refresh` to regenerate an existing context.

### 6.5 Build profiles

Supported build profiles:

- `afl_asan_ubsan`: AFL++ instrumentation with ASan and UBSan
- `afl_lto_cmplog`: AFL++ LTO build with CMPLOG, ASan and UBSan
- `libfuzzer_asan_ubsan`: libFuzzer build with ASan and UBSan
- `fuzztest_asan_ubsan`: optional FuzzTest property harness build with ASan and UBSan
- `coverage`: LLVM source coverage build

Build a target:

```bash
bin/fuzzctl build my_target --profile afl_asan_ubsan
```

### 6.6 Smoke validation

Run quick validation to ensure harnesses compile and execute under sanitizer builds:

```bash
bin/fuzzctl smoke my_target --seconds 300
```

For libFuzzer harnesses, add `--leak-check` when leak detection is required.

### 6.7 Campaign execution

Start a fuzzing campaign:

```bash
bin/fuzzctl run my_target --engine aflpp --hours 24 --workers 8
```

Engine options:

- `aflpp`: long-running AFL++ campaigns
- `libfuzzer`: libFuzzer campaigns, useful for seed validation and reproductions
- `fuzztest`: optional property-based FuzzTest harness runs
- `all`: run both AFL++ and libFuzzer when both are available

### 6.8 Monitoring and alerts

Monitor a run and emit actionable alerts:

```bash
bin/fuzzctl monitor my_target --interval 60 --webhook-url "$DISCORD_WEBHOOK_URL"
```

Options include:

- `--once`: run a single monitor iteration
- `--max-loops`: stop after a fixed number of checks
- `--no-alerts`: disable webhook delivery, but still record monitor state
- `--no-triage`: skip automatic triage during monitoring

Alerts are designed to surface:

- new unique reproducible crashes
- high/critical severity findings
- campaign failures or stalls
- disk space danger
- mismatched worker plans

A Discord webhook may be configured via:

```bash
export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'
```

### 6.9 Triage and deduplication

Process crashes to confirm and classify:

```bash
bin/fuzzctl triage my_target --run <run_id>
```

This step:

- identifies sanitizer-reproducible crashes
- deduplicates unique crashes
- records triage state under `runs/<target>/<run>/triage`

### 6.10 Minimization

Minimize unique crash artifacts:

```bash
bin/fuzzctl minimize my_target --run <run_id>
```

Minimization produces smaller, easier-to-review reproducers and helps prioritize real issues over noisy, large inputs.

### 6.11 Reporting

Generate Markdown reports:

```bash
bin/fuzzctl report my_target --run <run_id>
```

A reporting standard is enforced by the pipeline:

- reproduction command
- minimized input
- symbolized sanitizer trace
- crash type and severity
- attacker control and security impact
- evidence that this is more than “program crashed”

Null dereferences default to DoS/medium unless analysis proves higher impact.

### 6.12 Crash value analysis

Rank crashes by crash value:

```bash
bin/fuzzctl crash-value my_target --run <run_id>
```

This analysis separates:

- raw crash noise
- valid harness crashes
- product-plausible bugs
- report candidates

It is intentionally conservative: a crash is only product-impacting after root-cause mapping to shipped product logic.

### 6.13 Coverage analysis

Generate LLVM coverage for seeds, queue inputs, libFuzzer corpus, and reproducers:

```bash
bin/fuzzctl coverage my_target --run <run_id> --max-inputs 5000
```

### 6.14 Corpus management

Corpus commands support corpus hygiene and enrichment:

- `bin/fuzzctl corpus sync my_target --run <run_id> --max-inputs 20000`
- `bin/fuzzctl corpus enrich my_target --mutations-per-input 10 --overwrite --prune-crashers`
- `bin/fuzzctl corpus prune-crashers my_target --harness parser_file --timeout 2.0`

Corpus sync deduplicates and minimizes collected inputs. Enrich can generate deterministic seeds and optional Radamsa mutations. Pruning quarantines seeds that crash ASan/UBSan harnesses.

### 6.15 Supervisor loop

Supervisor commands maintain reboot-safe campaigns:

```bash
bin/fuzzctl supervisor campaign-loop my_target --engine aflpp --hours 24 --workers 8
```

The supervisor:

- waits for existing fuzzing to finish or adopt a live campaign
- runs continuous 24-hour campaign cycles
- runs post-cycle triage, reporting, and corpus sync
- can replace stale or mismatched AFL++ worker plans

Check status with:

```bash
bin/fuzzctl supervisor status my_target
```

### 6.16 Coverage guidance

Get harness and coverage improvement recommendations:

```bash
bin/fuzzctl guide coverage my_target --run <run_id>
```

This command inspects coverage artifacts and helps prioritize the next harness or corpus improvements.

---

## 7. Harness Lifecycle

Harness creation and maintenance is a core differentiator of the pipeline. This section explains the harness workflow.

### 7.1 Candidate discovery and scanning

The pipeline can scan a repo for likely parser/decoder entry points:

```bash
bin/fuzzctl harness scan /path/to/repo
```

The candidate scanner looks for:

- functions matching parser or decode names
- file-based API call sites
- likely input buffer and length parameters
- recommended harness type (`file`, `libfuzzer`, or `stdin`)

### 7.2 AI harness planning

Produce an AI-ready harness plan for authoring:

```bash
bin/fuzzctl harness ai-plan /path/to/repo
```

The plan includes:

- candidate list with function signatures
- compile context
- harness strategy
- prompt-quality guidance for AI-assisted harness writing

### 7.3 Candidate indexing

Write a compile-aware harness candidate index:

```bash
bin/fuzzctl harness index my_target
```

This command builds an index of candidate harness points using the target’s compile context.

### 7.4 Knowledge packet generation

Generate a single-candidate packet for AI authoring:

```bash
bin/fuzzctl harness knowledge my_target --candidate <candidate-id>
```

The generated packet contains everything needed for one narrow harness.

### 7.5 Prompt generation

Print a Codex-ready harness prompt:

```bash
bin/fuzzctl harness prompt my_target --candidate <candidate-id>
```

Use this prompt to author or review produced harness code.

### 7.6 AI harness synthesis

Create and compile an AI-generated harness attempt:

```bash
bin/fuzzctl harness synthesize my_target --candidate <candidate-id> --attempts 5
```

This step may produce:

- a draft harness source file
- a compiled candidate binary
- a build log for debugging and tuning
- a status marker such as `draft_ready_for_ai`

### 7.7 Work-order packets

Generate a full AI harness work-order packet:

```bash
bin/fuzzctl harness work-order my_target --limit 8
```

A work-order includes:

- compile context
- source excerpts and call hints
- seed/dictionary ideas
- validation commands
- exact instructions for one narrow harness at a time

Work orders are stored under `workorders/<target>/<timestamp>-harness-work-order/`.

### 7.8 Harness scaffolding

Create a reviewed harness template when a candidate is known:

```bash
bin/fuzzctl harness scaffold my_target --type libfuzzer --harness-name parser --function parse_api
```

Scaffolded harnesses are templates that should be wired to the real target API before campaign use.

### 7.9 Harness review and validation

Review harness code for fuzz-loop safety:

```bash
bin/fuzzctl harness review my_target
```

Validate manifest shape and build readiness:

```bash
bin/fuzzctl harness validate my_target --build
```

A target is not campaign-ready until:

- harness review passes
- ASan+UBSan builds succeed
- smoke runs pass cleanly on seeds
- coverage reaches parser logic and code paths of interest

### 7.10 Coverage blockers and iterations

Derive harness blockers from coverage:

```bash
bin/fuzzctl harness blockers my_target --run <run_id>
```

Iterate harnesses with coverage guidance:

```bash
bin/fuzzctl harness iterate my_target --candidate <candidate-id> --run <run_id>
```

This flow helps identify why the harness is not exploring deeper logic and what to improve.

### 7.11 Harness scoring

Score harness readiness based on review, build, seeds, and coverage:

```bash
bin/fuzzctl harness score my_target --run <run_id>
```

Scoring provides a stability gate before long campaigns.

---

## 8. Target Manifest and Harness Schema

### 8.1 Manifest overview

A target manifest is the central contract for a fuzz target. It is stored in `targets/<target-name>/target.json` and contains:

- `name`: target identifier
- `language`: `c` or `c++`
- `source_path`: relative or absolute path to the source tree
- `build_system`: detected build system such as `raw`, `cmake`, or others
- `seed_corpus`: directory name for seed files
- `dictionary`: path to a dictionary file, if used
- `max_len`: maximum input size in bytes
- `timeout_ms`: harness execution timeout
- `memory_mb`: memory limit for fuzzing
- `afl_cmplog`: whether AFL++ CMPLOG is enabled
- `harnesses`: harness definitions
- `build_commands`: custom build commands per profile
- `build_context`: compile database and build metadata
- `harness_attempts`: historical AI harness attempt records
- `coverage_goals`: coverage improvement goals
- `blocker_classifications`: coverage blocker records

### 8.2 Harness definition fields

Each harness object in `harnesses` includes:

- `name`: harness name
- `type`: `file`, `libfuzzer`, or `fuzztest`
- `source`: path to harness source relative to the target source directory
- `argv`: command-line arguments when running a file-mode harness
- `input_mode`: `file`, `libfuzzer`, or other harness input style
- `profiles`: build profiles that should include this harness
- `env`: environment variables to set for this harness
- `compile_flags`: extra flags for building this harness
- `link_flags`: extra linker flags for this harness

### 8.3 Example manifest excerpt

```json
{
  "name": "vuln_parser",
  "language": "c",
  "source_path": "fixtures/vuln_parser",
  "build_system": "raw",
  "seed_corpus": "seeds",
  "max_len": 4096,
  "timeout_ms": 1000,
  "memory_mb": 4096,
  "afl_cmplog": true,
  "harnesses": [
    {
      "name": "parser_file",
      "type": "file",
      "source": "vuln_parser.c",
      "argv": ["@@"],
      "input_mode": "file",
      "profiles": ["afl_asan_ubsan", "afl_lto_cmplog", "coverage"]
    },
    {
      "name": "parser_libfuzzer",
      "type": "libfuzzer",
      "source": "vuln_parser.c",
      "input_mode": "libfuzzer",
      "profiles": ["libfuzzer_asan_ubsan"]
    }
  ]
}
```

### 8.4 Custom build commands

`build_commands` can provide explicit build sequences for a profile when automatic build logic is insufficient. This is useful for projects with complex or nonstandard build systems.

---

## 9. Build and Harness Safety Rules

The pipeline enforces safety and quality rules in harness creation.

### 9.1 Harness requirements

Good harnesses should:

- be narrow and focused on a single parser or API entrypoint
- accept bytes and length instead of broad file paths when possible
- run deterministically under sanitizer builds
- be tolerant of malformed input
- avoid shell invocation and subprocess spawning inside the fuzz loop
- expose `LLVMFuzzerTestOneInput` for libFuzzer when appropriate
- use `@@` for AFL++ file-mode harnesses

### 9.2 AI harness generation guidance

When AI is used to author harnesses, the pipeline:

- generates candidate-specific prompts
- includes compile context and source snippets
- writes work-order artifacts for each harness candidate
- marks draft builds as `draft_ready_for_ai` until real wiring is complete

### 9.3 Coverage as a harness gate

A harness is not campaign-ready only because it compiles. It must also:

- execute seed corpus inputs cleanly
- reach parser or decoder logic under coverage
- not stop early before meaningful code paths

Coverage blockers help determine what is missing.

---

## 10. Campaign and Crash Management

### 10.1 Campaign run storage

Campaigns are stored under `runs/<target>/<run-id>/` and contain:

- `aflpp/` or libFuzzer run artifacts
- `triage/` deduplicated crash data
- `coverage/` instrumentation reports
- `monitor/` state snapshots
- `report/` generated Markdown outputs

### 10.2 Crash triage flow

Crash triage validates whether AFL++ or libFuzzer crash artifacts are reproducible and sanitizer-backed. The pipeline captures:

- sanitizer type
- symbolized stack trace
- crash uniqueness
- evidence of control and exploitability

### 10.3 Crash value and reportability

Crash value is computed conservatively. The pipeline distinguishes:

- noise: non-actionable harness crashes or crashes from instrumentation issues
- valid bugs: sanitizer-supported crashes in the target code
- product-relevant bugs: crashes mapped to real product paths
- report candidates: confirmed security-impacting findings

### 10.4 Reporting standard

Every report should include:

- reproduction command
- minimized input
- trace and code context
- crash type and severity
- impact analysis
- why this is a real security issue, not just a crash

---

## 11. Dashboard and Visibility

`fuzz-pipeline` includes a built-in dashboard server for observability.

### 11.1 Launch dashboard

```bash
bin/fuzzctl dashboard --host 127.0.0.1 --port 8088
```

### 11.2 Remote access

Tunnel from a laptop:

```bash
ssh -L 8088:127.0.0.1:8088 user@vps
```

Then open `http://127.0.0.1:8088/`.

### 11.3 Token protection and tunneling

For LAN/public access, use `FUZZ_DASHBOARD_TOKEN` or direct token arguments. For remote HTTPS without firewall changes, use `fuzz-dashboard-tunnel.service` and Cloudflare quick tunnels.

### 11.4 Dashboard content

The dashboard exposes:

- tool readiness and diagnostics
- targets and run status
- logs and reports
- coverage summaries
- launch and harness onboarding artifacts

---

## 12. Target Onboarding Checklist

Use this checklist to onboard a new customer target.

1. Run `bin/fuzzctl doctor` and resolve host/tool issues.
2. Clone or receive the target source tree.
3. Run `bin/fuzzctl detect /path/to/source`.
4. Create a manifest with `bin/fuzzctl init-target /path/to/source --name <target>`.
5. Inspect and edit `targets/<target>/target.json`.
6. Run `bin/fuzzctl build-context <target> --generate`.
7. Review compile context and fix include/build issues.
8. Create or tune harnesses:
   - `bin/fuzzctl harness scan /path/to/source`
   - `bin/fuzzctl harness ai-plan /path/to/source`
   - `bin/fuzzctl harness index <target>`
   - `bin/fuzzctl harness work-order <target>`
   - `bin/fuzzctl harness synthesize <target> --candidate <id>`
   - `bin/fuzzctl harness review <target>`
   - `bin/fuzzctl harness validate <target> --build`
9. Build sanitizer profiles: `bin/fuzzctl build <target> --profile afl_asan_ubsan` and `libfuzzer_asan_ubsan` as needed.
10. Run smoke validation: `bin/fuzzctl smoke <target> --seconds 300`.
11. Start campaigns: `bin/fuzzctl run <target> --engine aflpp --hours 24 --workers 8`.
12. Enable monitoring: `bin/fuzzctl monitor <target> --interval 60 --webhook-url "$DISCORD_WEBHOOK_URL"`.
13. Triage, minimize, and report crashes.
14. Keep coverage and harness blockers under review.

---

## 13. Glossary

- `target`: an onboarded C/C++ source project configured in `targets/<name>`.
- `manifest`: the JSON file defining harnesses, build context, and target metadata.
- `harness`: a fuzz harness definition or source file used for AFL++/libFuzzer/FuzzTest.
- `run`: a fuzzing campaign execution under `runs/<target>/<run-id>`.
- `workorder`: generated AI harness packet and candidate metadata in `workorders/<target>/`.
- `build-context`: compile database and environment metadata used for harness builds.
- `coverage blockers`: missing coverage or harness quality issues discovered by instrumentation.
- `crash value`: the severity and reportability ranking for a crash.

---

## 14. Future and Optional Capabilities

This pipeline is built to evolve. Future or optional enhancements include:

- support for additional engines such as Honggfuzz, Jackalope, and TinyInst
- binary-only QEMU/FRIDA instrumentation adapters
- network/stateful fuzzing adapters such as AFLNet/StateAFL
- deeper grammar-driven harness tooling
- more automated patch-diff / directed fuzzing support
- richer dashboard telemetry and reporting formats

Optional components in this release:

- FuzzTest property harnesses for C++ APIs
- Radamsa-based corpus enrichment
- Cloudflare quick tunnel dashboard access
- systemd supervisor services for persistence and campaign recovery

---

## 15. Reference Command Summary

### Setup and health

- `bin/fuzzctl doctor`
- `bin/fuzzctl tools doctor --deep`
- `bin/fuzzctl tools install-core`
- `bin/fuzzctl image-build`

### Target handling

- `bin/fuzzctl launch <repo> --name <name>`
- `bin/fuzzctl detect <path>`
- `bin/fuzzctl init-target <path> --name <name>`
- `bin/fuzzctl build-context <name> --generate`

### Build and validation

- `bin/fuzzctl build <name> --profile <profile>`
- `bin/fuzzctl smoke <name> --seconds <n>`
- `bin/fuzzctl coverage <name> --run <run_id>`

### Fuzzing and supervision

- `bin/fuzzctl run <name> --engine aflpp --hours <h> --workers <w>`
- `bin/fuzzctl fuzztest <name> --seconds <n>`
- `bin/fuzzctl supervisor campaign-loop <name> --engine aflpp --hours <h> --workers <w>`
- `bin/fuzzctl supervisor status <name>`

### Monitoring and alerts

- `bin/fuzzctl monitor <name> --once`
- `bin/fuzzctl monitor <name> --interval 60 --webhook-url "$DISCORD_WEBHOOK_URL"`
- `bin/fuzzctl alerts test --webhook-url "$DISCORD_WEBHOOK_URL"`

### Triage and reporting

- `bin/fuzzctl triage <name> --run <run_id>`
- `bin/fuzzctl minimize <name> --run <run_id>`
- `bin/fuzzctl report <name> --run <run_id>`
- `bin/fuzzctl crash-value <name> --run <run_id>`

### Harness operations

- `bin/fuzzctl harness scan <path>`
- `bin/fuzzctl harness ai-plan <path>`
- `bin/fuzzctl harness index <target>`
- `bin/fuzzctl harness knowledge <target> --candidate <id>`
- `bin/fuzzctl harness prompt <target> --candidate <id>`
- `bin/fuzzctl harness synthesize <target> --candidate <id> --attempts 5`
- `bin/fuzzctl harness work-order <target>`
- `bin/fuzzctl harness review <target>`
- `bin/fuzzctl harness validate <target> --build`
- `bin/fuzzctl harness blockers <target> --run <run_id>`
- `bin/fuzzctl harness iterate <target> --candidate <id> --run <run_id>`
- `bin/fuzzctl harness score <target> --run <run_id>`
- `bin/fuzzctl harness scaffold <target> --type <libfuzzer|file|stdin> --harness-name <name> --function <fn>`

### Corpus management

- `bin/fuzzctl corpus sync <target> --run <run_id>`
- `bin/fuzzctl corpus enrich <target> --mutations-per-input <n>`
- `bin/fuzzctl corpus prune-crashers <target> --harness <name>`

---

## 16. Contact and Support

For customers using `fuzz-pipeline`, support should include:

- the expected pipeline owner or operations contact
- a documented process for reporting failures and blocked harnesses
- escalation paths for toolchain issues and infrastructure problems
- replay instructions for reproducing crashes on supported build profiles

Keep the pipeline documentation versioned alongside the codebase so customers always receive an accurate operational contract.
