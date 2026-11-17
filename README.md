# Hybrid AI WAF - SOC Dashboard

Streamlit dashboard: Overview, Live Traffic, Attack Analytics, Vulnerability Triage, Model Management.

## Run
```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
streamlit run dashboard.py     # http://localhost:8501
```

## Real data vs sample data
Put `events.jsonl`, `triage_results.json`, `system_status.json` in a `data/` folder
(or set `WAF_DATA_DIR`). Without them, the dashboard shows the bundled `samples/` with a
"SAMPLE data" banner. Missing data shows empty states - never invented numbers.

## Files
* `dashboard.py` - UI (pages, theme, charts)
* `data_access.py` - all file reading + backend retrain call
* `BACKEND_INTEGRATION.md` - data formats and retrain interface
* `tests/` - `python -m unittest discover -s tests -v`
