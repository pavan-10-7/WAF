"""Train/evaluate the character n-gram classifier and persist it."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "training_data.csv"
MODEL = ROOT / "models" / "detector.joblib"
LABELS = ["benign", "sqli", "xss", "traversal"]


def load_rows(path: Path) -> tuple[list[str], list[str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows or any(row.get("label") not in LABELS or not row.get("text") for row in rows):
        raise ValueError("Training CSV needs non-empty text and labels: " + ", ".join(LABELS))
    return [row["text"] for row in rows], [row["label"] for row in rows]


def build_model() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1,
                                  sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1500, class_weight="balanced",
                                           random_state=42)),
    ])


def train(data_path: Path = DATA, model_path: Path = MODEL) -> dict[str, object]:
    texts, labels = load_rows(data_path)
    x_train, x_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.25, random_state=42, stratify=labels)
    evaluation_model = build_model().fit(x_train, y_train)
    predicted = evaluation_model.predict(x_test)
    metrics = {
        "accuracy": accuracy_score(y_test, predicted),
        "classification_report": classification_report(y_test, predicted, labels=LABELS,
                                                       zero_division=0, output_dict=True),
        "confusion_matrix_labels": LABELS,
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=LABELS).tolist(),
        "test_samples": len(y_test),
    }
    final_model = build_model().fit(texts, labels)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, model_path)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=DATA)
    parser.add_argument("--model", type=Path, default=MODEL)
    args = parser.parse_args()
    results = train(args.data, args.model)
    print(f"Saved model to {args.model}")
    print(f"Accuracy: {results['accuracy']:.3f} ({results['test_samples']} test samples)")
    print("Confusion matrix labels:", results["confusion_matrix_labels"])
    print(results["confusion_matrix"])
    print("Per-class precision, recall, and F1:")
    for label in LABELS:
        row = results["classification_report"][label]
        print(f"{label}: precision={row['precision']:.3f}, "
              f"recall={row['recall']:.3f}, f1={row['f1-score']:.3f}")
