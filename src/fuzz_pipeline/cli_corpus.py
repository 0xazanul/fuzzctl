from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from .corpus import corpus_enrich, corpus_prune_crashers, corpus_sync
from .grammar import grammar_configure, grammar_enrich, grammar_plan
from .manifest import load_manifest


def dispatch_corpus_command(args: Namespace, workspace: Path) -> int:
    if args.corpus_command == "sync":
        manifest = load_manifest(workspace, args.name)
        corpus_sync(workspace, manifest, args.run, max_inputs=args.max_inputs)
        return 0
    if args.corpus_command == "enrich":
        manifest = load_manifest(workspace, args.name)
        corpus_enrich(
            workspace,
            manifest,
            mutations_per_input=args.mutations_per_input,
            overwrite=args.overwrite,
        )
        if args.prune_crashers:
            corpus_prune_crashers(workspace, manifest, timeout_seconds=args.prune_timeout)
        return 0
    if args.corpus_command == "prune-crashers":
        manifest = load_manifest(workspace, args.name)
        corpus_prune_crashers(workspace, manifest, harness_names=args.harnesses, timeout_seconds=args.timeout)
        return 0
    if args.corpus_command == "grammar-plan":
        manifest = load_manifest(workspace, args.name)
        grammar_plan(workspace, manifest, grammar_format=args.format, as_json=args.json)
        return 0
    if args.corpus_command == "grammar-enrich":
        manifest = load_manifest(workspace, args.name)
        grammar_enrich(
            workspace,
            manifest,
            harness_name=args.harness,
            grammar_format=args.format,
            count=args.count,
            max_size=args.max_size,
        )
        return 0
    if args.corpus_command == "grammar-configure":
        manifest = load_manifest(workspace, args.name)
        grammar_configure(
            workspace,
            manifest,
            harness_name=args.harness,
            grammar_format=args.format,
            mutator_library=Path(args.mutator_library) if args.mutator_library else None,
            tree_dir=Path(args.tree_dir) if args.tree_dir else None,
            only=args.only,
        )
        return 0
    return 0
