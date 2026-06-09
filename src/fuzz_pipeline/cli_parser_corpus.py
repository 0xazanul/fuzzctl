from __future__ import annotations

import argparse


def add_corpus_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("corpus", help="corpus collection, minimization, and promotion")
    corpus_sub = p.add_subparsers(dest="corpus_command", required=True)

    p_corpus = corpus_sub.add_parser("sync", help="dedupe and minimize seed/queue/libFuzzer corpora")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--run")
    p_corpus.add_argument("--max-inputs", type=int, default=20000)

    p_corpus = corpus_sub.add_parser(
        "enrich",
        help="write per-harness deterministic seeds and optional Radamsa mutations",
    )
    p_corpus.add_argument("name")
    p_corpus.add_argument("--mutations-per-input", type=int, default=0)
    p_corpus.add_argument("--overwrite", action="store_true")
    p_corpus.add_argument(
        "--prune-crashers",
        action="store_true",
        help="quarantine seeds that crash ASan/UBSan file harnesses",
    )
    p_corpus.add_argument(
        "--prune-timeout",
        type=float,
        default=2.0,
        help="seconds allowed per seed when pruning crashers",
    )

    p_corpus = corpus_sub.add_parser(
        "prune-crashers",
        help="quarantine curated seeds that crash ASan/UBSan file harnesses",
    )
    p_corpus.add_argument("name")
    p_corpus.add_argument(
        "--harness",
        action="append",
        dest="harnesses",
        help="file harness name to check; may be repeated",
    )
    p_corpus.add_argument("--timeout", type=float, default=2.0, help="seconds allowed per seed")

    p_corpus = corpus_sub.add_parser("grammar-plan", help="write an AFL++ Grammar-Mutator setup plan")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--format", default="json")
    p_corpus.add_argument("--json", action="store_true")

    p_corpus = corpus_sub.add_parser("grammar-enrich", help="generate grammar seeds and trees for one harness")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--harness", required=True)
    p_corpus.add_argument("--format", default="json")
    p_corpus.add_argument("--count", type=int, default=128)
    p_corpus.add_argument("--max-size", type=int, default=512)

    p_corpus = corpus_sub.add_parser("grammar-configure", help="attach a built grammar mutator library to a harness")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--harness", required=True)
    p_corpus.add_argument("--format", default="json")
    p_corpus.add_argument("--mutator-library")
    p_corpus.add_argument("--tree-dir")
    p_corpus.add_argument("--only", action="store_true")
