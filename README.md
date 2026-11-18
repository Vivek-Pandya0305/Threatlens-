# ThreatLens

A small, local web app that helps analysts organise and triage threat indicators (IOCs). It imports CSV/JSON lists, cleans and de-duplicates them, keeps the evidence trail, gives each item a cautious score, and lets a human decide. Built with Python, FastAPI and SQLite.

## Scope

**Included**
- Import of CSV/JSON indicator files (max 2 MB)
- Cleaning and validation of IPv4, IPv6, domain, URL, MD5, SHA1 and SHA256
- De-duplication with per-source evidence (provenance)
- Transparent score: highest source confidence + 7 per extra source (bonus capped at 15)
- Allowlist and expiry handling
- Analyst triage, plain-English summaries, search and filters
- Export to CSV, JSON and STIX 2.1
- 20 synthetic practice records, loaded automatically

**Not included:** live reputation lookups, STIX/TAXII import, user login, multi-user use.

## Architecture

Three layers:

1. **Dashboard** (`static/index.html`): HTML, CSS and JavaScript in the browser.
2. **API server** (`app/main.py`): FastAPI, started by `run.py`. Handles cleaning, merging, scoring, triage and export.
3. **Database** (`threatlens.db`): SQLite with three tables: `iocs` (unique indicators), `observations` (each report and its evidence) and `allowlist`.

Flow: upload file → clean and validate → merge duplicates → save evidence → score → apply allowlist/expiry → show status → analyst triage → export.

```
ThreatLens/
  run.py  setup.bat  setup.sh  start.bat  requirements.txt
  app/main.py        server logic
  static/            dashboard and sample files
  data/              practice data and starter allowlist
  tests/             unit tests
```

## Assumptions

- All sample data is synthetic: documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and `.test` domains.
- Runs on one computer for one user, on `127.0.0.1:8000`.
- Python 3.10 or newer is installed; internet is needed only for the first package install.
- The score is a guide, not proof. Only a human can set "Confirmed malicious".
- Input files include at least an `indicator` column; `type`, `source`, `source_confidence`, `evidence` and `expires_at` are recommended.

## Test Environment

- Linux, Python 3.12.3
- FastAPI 0.163.1, Uvicorn 0.54.0, Pytest 9.2.0, SQLite
- Dashboard checked in headless Chromium (Playwright)
- Results: 4 unit tests and 26 functional checks, all passing. The Windows scripts (`setup.bat`, `start.bat`) were reviewed but not run on Windows.

## Limitations

- Expiry and status are recalculated only when data changes (import, allowlist edit), not continuously. An indicator that expires later keeps its old status until then.
- Re-importing an indicator recalculates its status and can overwrite an earlier analyst status.
- Allowlist matches exact values only (no subnets or wildcards).
- Search covers the cleaned indicator and category only; there is no pagination.
- No authentication, so do not expose the app to a network.
- SQLite suits small, single-user use. "Reset demo data" deletes all local records.
- FastAPI's `on_event` startup hook used in `app/main.py` is deprecated and should move to lifespan handlers.

## Quick Start

```
git clone LINK
cd ThreatLens
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:8000 (API help at `/docs`). On Windows, `setup.bat` does all of this. Run tests with `pip install pytest` then `python -m pytest tests -v`.

## License

MIT. See `LICENSE.txt`.
