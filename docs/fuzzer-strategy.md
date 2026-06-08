# Fuzzer Strategy

The pipeline does not install every fuzzer listed in Awesome-AFL. Many entries are research prototypes, Windows-only, kernel/full-system tools, network/stateful tools, or ideas now represented inside AFL++.

Default operational stack:

- AFL++ for long-running campaigns.
- libFuzzer for in-process smoke, reproduction, and minimization.
- ASan+UBSan on every memory-bug build.
- LLVM coverage for harness quality.
- Honggfuzz as an optional secondary engine.
- Radamsa as optional corpus enrichment when available.

Escalation rules:

- Hard magic bytes or deep comparisons: enable AFL++ CMPLOG and dictionaries first.
- Structured text/binary formats: add dictionaries, then AFL++ custom mutator, then consider grammar tools such as Nautilus/Grimoire/Weizz concepts.
- Stalled coverage: minimize corpus, inspect uncovered parser code, split harnesses, and add persistent mode.
- Directed CVE/patch-diff hunt: consider AFLGo-style target locations.
- Stateful network protocol: future AFLNet/StateAFL adapter.
- Binary-only: future AFL++ QEMU/FRIDA/SymQEMU/Eclipser/Jackalope/TinyInst adapter.
- Windows/macOS/kernel: future platform-specific adapter, not this Linux C/C++ v1.

Reporting rule:

Never report crashes found only on transformed or emulated variants unless the same minimized input reproduces on the original target with sanitizer or product-build evidence.

