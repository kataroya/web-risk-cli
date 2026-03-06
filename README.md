# Web Risk API Client

A Python client that uses the [Google Cloud Web Risk API](https://cloud.google.com/web-risk/docs) to maintain a local threat hash database, check URLs for threats, and submit suspicious URLs for review.

## Overview

This client implements two workflows:

### Update API — Threat Detection

1. **Sync** — Periodically fetches threat list diffs via `ComputeThreatListDiff` and stores hash prefixes in a local SQLite database.
2. **Check** — For a given URL, computes SHA-256 hashes, matches them against the local DB, and verifies matches via the `SearchHashes` API.

```
[Sync Flow]
  ComputeThreatListDiff API
    → RESET (full snapshot) or DIFF (incremental)
    → Store hash prefixes in local SQLite
    → Save version_token for next sync

[Check Flow]
  URL → Canonicalize → SHA-256 hashes
    → Local prefix matching (fast, no network)
    → If matched: SearchHashes API (full hash verification)
    → Return threat result
```

### Submit URI API — Threat Reporting

3. **Submit** — Submits suspicious URLs to Google's Safe Browsing blocklist for review via the `SubmitUri` API.

```
[Submit Flow]
  Suspicious URL + threat metadata
    → SubmitUri API (Long Running Operation)
    → Google reviews and adds to blocklist
    → Poll operation status (optional)
```

> **Note**: The Submit URI API requires your GCP project to be allowlisted.
> Contact your Google Cloud sales representative or Customer Engineer.

### Supported Threat Types

| Threat Type          | Description                        |
|----------------------|------------------------------------|
| `MALWARE`            | Malicious software distribution    |
| `SOCIAL_ENGINEERING` | Phishing and deceptive sites       |
| `UNWANTED_SOFTWARE`  | Unwanted software distribution     |

## Prerequisites

### 1. GCP Project Setup

- Create or select a [Google Cloud project](https://console.cloud.google.com/).
- Enable the **Web Risk API**:
  ```bash
  gcloud services enable webrisk.googleapis.com
  ```

### 2. Authentication

Choose one of the following:

**Option A: Service Account (recommended for production)**
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
```

**Option B: Application Default Credentials (for development)**
```bash
gcloud auth application-default login
```

### 3. Python Dependencies

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install google-cloud-webrisk
```

## Usage

### Sync Threat Lists

Run this first to populate the local database:

```bash
# Sync only lists that need updating (based on recommended_next_diff)
python webrisk_cli.py sync

# Force sync all lists regardless of timing
python webrisk_cli.py sync -f
```

### Check a URL

```bash
python webrisk_cli.py check "http://example.com"
```

Output:
```
Checking: http://example.com

  Safe - no threats detected.
```

If a threat is detected:
```
Checking: http://malicious-site.example

  Threat detected!
    - MALWARE (expires: 2026-02-25T00:00:00+00:00)
```

### Submit a Suspicious URL

```bash
# Basic submission
python webrisk_cli.py submit "http://phishing.example/login" \
    --project my-project-123 \
    --type SOCIAL_ENGINEERING

# Full options with wait
python webrisk_cli.py submit "http://malware.example/payload" \
    --project my-project-123 \
    --type MALWARE \
    --confidence HIGH \
    --justification "MANUAL_VERIFICATION" \
    --comment "Confirmed malware dropper" \
    --platform WINDOWS \
    --region "US,KR" \
    --wait -v
```

### View Local DB Status

```bash
python webrisk_cli.py status
```

Output:
```
=== Local DB Status ===

  MALWARE:
    hash prefixes  : 9,839
    version_token  : a1b2c3d4e5f6...
    next diff time : 2026-02-24T12:30:00+00:00

  SOCIAL_ENGINEERING:
    hash prefixes  : 65,536
    version_token  : f6e5d4c3b2a1...
    next diff time : 2026-02-24T12:30:00+00:00

  UNWANTED_SOFTWARE:
    hash prefixes  : 32,880
    version_token  : 1a2b3c4d5e6f...
    next diff time : 2026-02-24T12:30:00+00:00
```

## Project Structure

| File                        | Description                                               |
|-----------------------------|-----------------------------------------------------------|
| `webrisk_cli.py`            | CLI entry point (`sync`, `check`, `status`, `submit`, `cache-clear`) |
| `threat_list_syncer.py`     | Fetches diffs via `ComputeThreatListDiff` and applies them |
| `url_threat_checker.py`     | Local prefix matching + `SearchHashes` API verification   |
| `url_canonicalizer.py`      | URL canonicalization and SHA-256 hashing                  |
| `url_submitter.py`          | Submit suspicious URLs via `SubmitUri` API + LRO polling  |
| `threat_hash_store.py`      | SQLite storage for hash prefixes and metadata             |
| `WORKFLOW_GUIDE.md`         | Detailed workflow documentation with Mermaid diagrams     |
| `webrisk_local.db`          | Auto-generated local SQLite database (gitignore this)     |

## References

- [Web Risk API Documentation](https://cloud.google.com/web-risk/docs)
- [Update API Guide](https://cloud.google.com/web-risk/docs/update-api)
- [Submit URI Guide](https://cloud.google.com/web-risk/docs/submit-uri)
- [URLs and Hashing](https://cloud.google.com/web-risk/docs/urls-hashing)
- [ComputeThreatListDiff RPC](https://cloud.google.com/web-risk/docs/reference/rpc/google.cloud.webrisk.v1#computethreatlistdiffrequest)
- [SearchHashes RPC](https://cloud.google.com/web-risk/docs/reference/rpc/google.cloud.webrisk.v1#searchhashesrequest)
- [SubmitUri RPC](https://cloud.google.com/web-risk/docs/reference/rpc/google.cloud.webrisk.v1#submituriRequest)
