from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .advanced_tools import advanced_tool_status, grammar_mutator_dir
from .manifest import TargetManifest, save_manifest
from .util import FuzzCtlError, ensure_dir, rel_to, run_cmd, write_json


FORMAT_GRAMMARS = {
    "json": "grammars/json.json",
    "http": "grammars/http.json",
    "ruby": "grammars/ruby.json",
}


def _harness_by_name(manifest: TargetManifest, name: str):
    for harness in manifest.harnesses:
        if harness.name == name:
            return harness
    raise FuzzCtlError(f"harness not found: {name}")


def _generator_for(workspace: Path, grammar_format: str) -> Path | None:
    root = grammar_mutator_dir(workspace)
    for direct in [root / f"grammar_generator-{grammar_format}", root / "src" / f"grammar_generator-{grammar_format}"]:
        if direct.exists():
            return direct
    matches = sorted([*root.glob(f"grammar_generator-{grammar_format}*"), *root.glob(f"src/grammar_generator-{grammar_format}*")])
    return matches[0] if matches else None


def _mutator_for(workspace: Path, grammar_format: str) -> Path | None:
    root = grammar_mutator_dir(workspace)
    for direct in [root / f"libgrammarmutator-{grammar_format}.so", root / "src" / f"libgrammarmutator-{grammar_format}.so"]:
        if direct.exists():
            return direct
    matches = sorted([*root.glob(f"libgrammarmutator-{grammar_format}*.so"), *root.glob(f"src/libgrammarmutator-{grammar_format}*.so")])
    return matches[0] if matches else None


def grammar_plan(workspace: Path, manifest: TargetManifest, *, grammar_format: str = "json", as_json: bool = False) -> dict[str, Any]:
    status = advanced_tool_status(workspace)
    grammar_root = grammar_mutator_dir(workspace)
    grammar_file = FORMAT_GRAMMARS.get(grammar_format, grammar_format)
    result = {
        "target": manifest.name,
        "format": grammar_format,
        "grammar_mutator": status["grammar_mutator"],
        "grammar_file": str(grammar_root / grammar_file) if not Path(grammar_file).is_absolute() else grammar_file,
        "mutator_library": str(_mutator_for(workspace, grammar_format)) if _mutator_for(workspace, grammar_format) else None,
        "generator": str(_generator_for(workspace, grammar_format)) if _generator_for(workspace, grammar_format) else None,
        "commands": [
            f"git clone https://github.com/AFLplusplus/Grammar-Mutator {grammar_root}",
            f"cd {grammar_root} && make GRAMMAR_FILE={grammar_file}",
            f"bin/fuzzctl --runtime native corpus grammar-enrich {manifest.name} --format {grammar_format} --harness <file-harness>",
            f"bin/fuzzctl --runtime native corpus grammar-configure {manifest.name} --format {grammar_format} --harness <file-harness> --only",
        ],
    }
    out = ensure_dir(workspace / "workorders" / manifest.name / "grammar")
    write_json(out / f"{grammar_format}-plan.json", result)
    md = [f"# Grammar Mutator Plan: {manifest.name}/{grammar_format}", ""]
    for command in result["commands"]:
        md.append(f"- `{command}`")
    (out / f"{grammar_format}-plan.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if as_json:
        print(__import__("json").dumps(result, indent=2, sort_keys=True))
    else:
        print(f"grammar plan: {rel_to(out / f'{grammar_format}-plan.md', workspace)}")
    return result


def grammar_enrich(
    workspace: Path,
    manifest: TargetManifest,
    *,
    harness_name: str,
    grammar_format: str = "json",
    count: int = 128,
    max_size: int = 512,
) -> Path:
    harness = _harness_by_name(manifest, harness_name)
    if harness.type not in {"file", "stdin"}:
        raise FuzzCtlError("grammar mutator AFL++ campaigns require a file/stdin harness")
    generator = _generator_for(workspace, grammar_format)
    if generator is None:
        grammar_plan(workspace, manifest, grammar_format=grammar_format)
        raise FuzzCtlError(f"grammar generator for {grammar_format!r} not found; build Grammar-Mutator first")
    out = ensure_dir(workspace / "corpora" / manifest.name / harness.name / f"grammar-{grammar_format}")
    seeds = ensure_dir(out / "seeds")
    trees = ensure_dir(out / "trees")
    if seeds.exists():
        shutil.rmtree(seeds)
        seeds.mkdir()
    if trees.exists():
        shutil.rmtree(trees)
        trees.mkdir()
    run_cmd([str(generator), str(count), str(max_size), str(seeds), str(trees)], check=True, print_cmd=True)
    current = ensure_dir(workspace / "corpora" / manifest.name / harness.name / "current")
    for seed in seeds.iterdir():
        if seed.is_file():
            shutil.copy2(seed, current / f"grammar-{grammar_format}-{seed.name}")
    write_json(
        out / "grammar-enrich.json",
        {
            "target": manifest.name,
            "harness": harness.name,
            "format": grammar_format,
            "generator": str(generator),
            "seed_count": len([p for p in seeds.iterdir() if p.is_file()]),
            "tree_dir": str(trees),
            "current": str(current),
        },
    )
    print(f"grammar corpus: {rel_to(out, workspace)}")
    return out


def grammar_configure(
    workspace: Path,
    manifest: TargetManifest,
    *,
    harness_name: str,
    grammar_format: str = "json",
    mutator_library: Path | None = None,
    tree_dir: Path | None = None,
    only: bool = False,
) -> Path:
    harness = _harness_by_name(manifest, harness_name)
    if harness.type not in {"file", "stdin"}:
        raise FuzzCtlError("grammar mutator AFL++ campaigns require a file/stdin harness")
    mutator = mutator_library.expanduser().resolve() if mutator_library else _mutator_for(workspace, grammar_format)
    if mutator is None or not mutator.exists():
        grammar_plan(workspace, manifest, grammar_format=grammar_format)
        raise FuzzCtlError(f"grammar mutator library for {grammar_format!r} not found")
    trees = tree_dir.expanduser().resolve() if tree_dir else workspace / "corpora" / manifest.name / harness.name / f"grammar-{grammar_format}" / "trees"
    harness.env["AFL_CUSTOM_MUTATOR_LIBRARY"] = str(mutator)
    if only:
        harness.env["AFL_CUSTOM_MUTATOR_ONLY"] = "1"
    elif "AFL_CUSTOM_MUTATOR_ONLY" in harness.env:
        del harness.env["AFL_CUSTOM_MUTATOR_ONLY"]
    if trees.exists():
        harness.env["AFL_GRAMMAR_TREE_DIR"] = str(trees)
    saved = save_manifest(workspace, manifest)
    print(f"configured grammar mutator for {manifest.name}/{harness.name}: {rel_to(saved, workspace)}")
    return saved
