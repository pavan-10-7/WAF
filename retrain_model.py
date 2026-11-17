"""Append explicitly verified labels, then retrain the model offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from train_model import DATA, ROOT, train

ALLOWED = {"benign", "sqli", "xss", "traversal"}


def append_verified(jsonl_path: Path, csv_path: Path = DATA) -> int:
    """Import JSONL entries only when they contain text and an explicit label."""
    import csv

    examples: list[tuple[str, str]] = []
    with jsonl_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            item = json.loads(line)
            label, text = item.get("label"), item.get("text")
            if label not in ALLOWED or not isinstance(text, str) or not text.strip():
                raise ValueError(f"Line {line_number}: expected explicit label and non-empty text")
            examples.append((label, text.strip()))
    if not examples:
        return 0
    with csv_path.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerows(examples)
    return len(examples)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("labelled_jsonl", type=Path,
                        help='JSONL rows: {"label":"benign|sqli|xss|traversal","text":"..."}')
    args = parser.parse_args()
    count = append_verified(args.labelled_jsonl)
    result = train()
    print(f"Imported {count} explicitly labelled examples; saved updated model under {ROOT / 'models'}")
    print(f"Holdout accuracy: {result['accuracy']:.3f}")
