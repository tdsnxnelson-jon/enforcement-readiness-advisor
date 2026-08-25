# Enforcement Readiness Advisor

Analyzes a Carbon Black App Control environment and produces a readiness score and actionable recommendations for moving toward High Enforcement mode.

## Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- CB App Control server with API access

### 2. Install

```bash
git clone https://github.com/<your-org>/enforcement-readiness-advisor.git
cd enforcement-readiness-advisor
pip install -r requirements.txt
```

### 3. Run

```bash
python main.py --server https://your-cbserver.example.com --token <api_token>
```

### 4. View the report

Open `enforcement_readiness_report.html` in a browser, or inspect `enforcement_readiness_report.json` directly.

## Requirements

- Python 3.8+
- CB App Control server with API access

## Usage

```bash
python main.py --server <cb_server_url> --token <api_token> [options]
```

Or use a JSON config file:

```bash
python main.py --config advisor_config.json
```

Config precedence is:

1. CLI arguments
2. Config file values
3. Built-in defaults

### Required Arguments

| Argument | Description |
|---|---|
| `--server` | CB App Control server URL (for example `https://server.example.com`) |
| `--token` | API token for authentication |

### Optional Arguments

| Argument | Default | Description |
|---|---|---|
| `--config` | `None` | Optional JSON config path (CLI overrides config) |
| `--output` | `enforcement_readiness_report.json` | Output JSON file path |
| `--html-output` | `<output>.html` | Output HTML file path |
| `--no-html` | `false` | Skip HTML report generation |
| `--html` | `false` | Force HTML report generation (overrides config) |
| `--acceleration-mode` | `conservative` | `conservative` (stricter thresholds) or `accelerated` (faster readiness lift) |
| `--max-rows` | `0` (no cap, fetch full dataset) | Set a positive value to cap collection at a partial sample |
| `--max-workers` | `4` | Concurrent requests when paginating large endpoints; raise for faster collection, lower to reduce load on the App Control server |
| `--verify-ssl` | `false` | Verify SSL certificates |
| `--insecure` | `false` | Disable SSL verification (overrides config) |

### Examples

```bash
python main.py --server https://cbserver.example.com --token abc123
```

```bash
python main.py --server https://cbserver.example.com --token abc123 --acceleration-mode accelerated --output my_report.json
```

```bash
python main.py --server https://cbserver.example.com --token abc123 --html-output readiness.html
```

```bash
python main.py --config advisor_config.json
```

```bash
python main.py --config advisor_config.json --max-rows 8000 --verify-ssl
```

### Config File

Use [advisor_config.example.json](advisor_config.example.json) as a template and create your own `advisor_config.json`.

`advisor_config.json` can include:

- `server`
- `token`
- `verify_ssl`
- `output`
- `html_output`
- `no_html`
- `acceleration_mode`
- `max_rows`
- `rapid_config`
- `endpoint_readiness`

`rapid_config` supports:

- `excluded_configs` (list of names/IDs/patterns to remove from Rapid Config scoring)

`excluded_configs` matching supports:

- Exact name (for example `"Office Script Control"`)
- Exact ID using `id:` prefix (for example `"id:12345"`)
- Exact name using `name:` prefix (for example `"name:Linux Baseline"`)
- Wildcards via glob syntax (for example `"*Linux*"`)

Excluded Rapid Config entries are marked as not relevant in analysis views and omitted from `rapid_config_readiness` scoring. They are listed in report output under `rapid_config_analysis.excluded_configs`.

`endpoint_readiness` supports:

- `lookback_days`
- `min_ready_score`
- `near_ready_score`
- `max_block_events`
- `max_unapproved_events`
- `unapproved_penalty`
- `block_penalty`
- `recent_penalty`
- `max_unapproved_penalty`
- `max_block_penalty`
- `max_recent_penalty`

## Output

The tool writes a JSON report (default: `enforcement_readiness_report.json`) and an HTML report (default: `enforcement_readiness_report.html`) containing:

- Readiness score and recommendation
- Score breakdown and score audit checks
- Environment baseline metrics
- Approval workflow guidance and per-file decisions
- Rule suggestions and acceleration candidates
- Guardrail checks and rollout workflow guidance
- Strategic recommendations, certificate portfolio, policy scope simulation, and recurring event analysis

## Report UI Notes

The HTML report includes:

- Tabbed navigation across major sections
- Automatic scroll to the top when changing tabs
- Search, sorting, filtering, and pagination for report tables
- Pager status text (for example: `Page 1 of 1 (8 matching rows)`) on managed tables

## Data Pulled from App Control

The script pulls multiple datasets from the CB App Control REST API (base path: `/api/bit9platform/v1`) and computes readiness metrics locally.

### Core API Data Sources

| API Endpoint | What Is Pulled | Why It Is Used |
|---|---|---|
| `fileCatalog` | Unknown (`approvalState:NOT_APPROVED`) and approved (`approvalState:APPROVED`) binaries | Main inventory for scoring and candidate generation |
| `companyName` | Trusted and blocked publishers (`reputation:TRUSTED/BLOCKED`) | Publisher trust analysis |
| `certificate` | Valid signatures, invalid signatures, and full certificate list | Certificate trust scoring |
| `fileInstance` | File-to-computer occurrences (`fileCatalogId`, `computerId`) | Prevalence analysis |
| `computer` | Active computers (`status:Active`) | Endpoint coverage metric |
| `event` | New unapproved file events (with fallback filters) | Approval workflow and rule suggestions |
| Rule endpoints (multiple) | Existing rules from available endpoints | Safer recommendation generation |

### Count-Only Summary Calls

For readiness summaries, the script also requests count-only totals (`rows=0`) for:

- Unknown binaries
- Approved binaries
- Trusted publishers
- Blocked publishers
- Valid certificates
- Active computers

## Troubleshooting

### SSL Certificate Warnings

If you see `InsecureRequestWarning` messages from urllib3, this means SSL verification is disabled (default behavior). These warnings are informational and do not stop report generation.

To enforce certificate validation:

```bash
python main.py --server https://server.example.com --token <token> --verify-ssl
```

## Project Structure

```text
enforcement_readiness_advisor/
├── config/
│   └── api_endpoints.py
├── data_collection/
│   ├── api_client.py
│   └── collectors.py
├── analysis/
│   ├── trust_signals.py
│   ├── path_analysis.py
│   ├── approval_workflow.py
│   └── strategic_recommendations.py
├── report/
│   └── html_report.py
├── main.py
├── requirements.txt
└── README.md
```
