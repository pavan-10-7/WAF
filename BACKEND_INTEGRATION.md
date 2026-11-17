# Backend Integration Contract (frontend's view)

> The frontend was built from scratch, so these formats are the **proposed** contract.
> Confirm each one with the owning team member. If a field name differs, add it to the
> `*_ALIASES` dictionaries at the top of `data_access.py` - no dashboard changes needed.

## Data folder
`WAF_DATA_DIR` env var -> `./data/` -> `./samples/` (bundled preview data, shown with a "SAMPLE data" banner).

## events.jsonl (production) - one JSON object per line
| field | example |
|---|---|
| timestamp | `2026-11-17T10:15:02Z` (ISO-8601) |
| source_ip | `203.0.113.7` |
| method | `POST` |
| endpoint | `/login` |
| attack_type | `SQL Injection` / `XSS` / `Path Traversal` / `None` (`sqli`, `xss`, `path_traversal` also accepted) |
| verdict | `BLOCK` / `ALLOW` |
| score | `0.97` (0-1 detection score) |

`events.json` (JSON array, or `{"events": [...]}`) is also accepted. Bad lines are skipped and reported.

## triage_results.json - array (or `{"results": [...]}`)
`vuln_id, title, endpoint, attack_type, cvss, asset_criticality, observed_attacks, risk_score, priority (CRITICAL|HIGH|MEDIUM|LOW), virtual_patch`

## system_status.json
```json
{"waf_status":"ONLINE","detection_engine":"RUNNING","ml_model":"LOADED","last_updated":"ISO-8601",
 "components":{"rule_engine":"ONLINE"},
 "model":{"algorithm":"Logistic Regression","feature_extraction":"TF-IDF Character N-grams",
          "training_status":"TRAINED","version":"1.0","trained_at":"ISO-8601"}}
```

## Retraining
The **Retrain Model** button calls a Python function named by `WAF_RETRAIN_ENTRYPOINT`
(default `model_service:retrain`, i.e. `retrain()` inside `model_service.py`).
It takes no arguments; its return value (dict/str) is shown in the UI. Exceptions are shown as errors.
If the module does not exist yet, the dashboard says so - it never fakes a retrain.
**Agree this name with the ML owner.**

## Definitions
* Attack Detection Rate = events with an attack type != None / total events.
