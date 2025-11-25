# Firefox Forensics Extraction Tool - Documentation Index

## Quick Start
- **[README.md](README.md)** - Full documentation and usage
- **[SETUP.md](SETUP.md)** - Installation and quick start
- **[FIREFOX_FORENSICS.md](FIREFOX_FORENSICS.md)** - Forensic reference guide

## Source Files
- **[main.py](main.py)** - CLI entry point
- **[extractor.py](extractor.py)** - Database extraction core
- **[formatters.py](formatters.py)** - Report generation
- **[queries.py](queries.py)** - Forensic SQL queries
- **[utils.py](utils.py)** - Utility functions

## Quick Usage

```bash
# Basic extraction
python main.py ~/.mozilla/firefox/profile.default

# Custom output directory
python main.py /path/to/profile --output my_analysis

# List available queries
python main.py --list-queries
```

## Forensic Queries

**places.sqlite**: browsing_history, bookmarks, top_sites, recent_24h, downloads, search_queries, referrer_chains  
**cookies.sqlite**: all_cookies, auth_tokens, persistent_sessions, cookies_by_domain  
**formhistory.sqlite**: all_form_history, sensitive_fields, search_queries, email_addresses  
**permissions.sqlite**: all_permissions, granted_permissions, geolocation, media_devices, notifications  
**storage.sqlite**: localstorage, sessionstorage  
**favicons.sqlite**: favicon_mapping

## Output Structure

```
firefox_forensics_output/
├── databases/       # Raw SQLite table exports (CSV)
├── forensics/       # Forensic query results (CSV)
├── reports/         # Database summaries (Markdown)
├── artifacts/       # Processed JSON files
└── master_report.md # Comprehensive report
```

## Key Features

- ✓ Automatic database detection and table enumeration
- ✓ 20+ forensic SQL queries (history, cookies, forms, permissions)
- ✓ CSV exports and Markdown reports
- ✓ JSON artifact parsing (extensions, sessions)
- ✓ Zero external dependencies (Python stdlib only)

## Common Tasks

```bash
# View browsing history
cat firefox_forensics_output/forensics/places_browsing_history.csv

# View auth tokens
cat firefox_forensics_output/forensics/cookies_auth_tokens.csv

# View form inputs
cat firefox_forensics_output/forensics/formhistory_sensitive_fields.csv
```

## Programmatic Usage

```python
from extractor import FirefoxDatabaseExtractor
from pathlib import Path

profile = Path.home() / ".mozilla/firefox/profile.default"
extractor = FirefoxDatabaseExtractor(profile)

for db in extractor.find_databases():
    tables = extractor.get_tables(db)
    print(f"{db.name}: {', '.join(tables)}")
```

---

**Python 3.9+ | No Dependencies | CSV/Markdown Output**
