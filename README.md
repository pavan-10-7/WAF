# Hybrid WAF — Member 2 Detection Engine

This branch contains the standalone hybrid detection engine for SQL injection,
cross-site scripting (XSS), and path traversal.

## Install and train

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python train_model.py
python -m unittest discover -s tests -v
```

Training writes `models/detector.joblib`. The checked-in model is included so
the detector can be imported immediately. The small CSV dataset is for project
demonstration and does not establish real-world detection performance.

## Proxy integration

From the repository root, Member 1 can import:

```python
from detector import detect

result = detect({
    "method": "GET",
    "path": "/search",
    "query": "id=1 OR 1=1",
    "body": "",
    "headers": {},
})
```

The returned dictionary follows the agreed contract: `verdict` (`block` or
`allow`), `attack_type` (`sqli`, `xss`, `traversal`, or `none`), `score` from
0.0 to 1.0, and a short `reason`.

## Explicitly labelled retraining

Create a JSONL file with verified labels, one object per line:

```json
{"label":"sqli","text":"id=1 OR 1=1"}
```

Then run `python retrain_model.py verified_examples.jsonl`. The tool rejects
missing or unsupported labels. Detection predictions are never automatically
used as training labels.
