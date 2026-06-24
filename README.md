# Enforcement Readiness Advisor

Analyzes a Carbon Black App Control environment and produces a readiness score and recommendations for moving to High Enforcement mode.

> **Privacy:** All data stays on your machine. No information is sent to the cloud. The optional LLM feature uses [Ollama](https://ollama.ai), which runs entirely locally.

## Quick Start

### 1. Prerequisites

- Python 3.8 or higher
- CB App Control server with API access
- (Optional) [Ollama](https://ollama.ai) for AI-generated explanations — see [LLM Setup](#llm-setup-optional) below

### 2. Install

```bash
git clone https://github.com/<your-org>/enforcement-readiness-advisor.git
cd enforcement-readiness-advisor
pip install -r requirements.txt
```

### 3. Run (without LLM)

```bash
python main.py --server https://your-cbserver.example.com --token <api_token> --no-llm
```

### 4. View the report

Open `enforcement_readiness_report.html` in a browser, or inspect `enforcement_readiness_report.json` directly.

---

## LLM Setup (Optional)

The LLM feature generates a human-readable narrative summary of your environment. It requires [Ollama](https://ollama.ai) running locally — no data leaves your machine.

**Install Ollama:**

- Windows / macOS: Download from [https://ollama.ai/download](https://ollama.ai/download)
- Linux: `curl -fsSL https://ollama.ai/install.sh | sh`

**Pull a model (Mistral is recommended — fast, fits in 8 GB RAM):**

```bash
ollama pull mistral
```

Other supported models: `llama3`, `phi3`, `gemma2`. Larger models produce better analysis but require more RAM.

**Verify Ollama is running:**

```bash
ollama list
```

Once Ollama is running, omit `--no-llm` from the command:

```bash
python main.py --server https://your-cbserver.example.com --token <api_token>
```

---

## Requirements

- Python 3.8+
- CB App Control server with API access
- (Optional) [Ollama](https://ollama.ai) running locally for LLM-generated explanations

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py --server <cb_server_url> --token <api_token> [options]
```

### Required Arguments

| Argument | Description |
|---|---|
| `--server` | CB App Control server URL (e.g., `https://server.example.com`) |
| `--token` | API token for authentication |

### Optional Arguments

| Argument | Default | Description |
|---|---|---|
| `--model` | `mistral` | Local LLM model name (requires Ollama) |
| `--output` | `enforcement_readiness_report.json` | Output file path |
| `--acceleration-mode` | `conservative` | `conservative` (strict thresholds) or `accelerated` (lower thresholds for faster enforcement) |
| `--no-llm` | `false` | Skip LLM explanation generation |
| `--verify-ssl` | `false` | Verify SSL certificates |

### Examples

**Basic run:**
```bash
python main.py --server https://cbserver.example.com --token abc123
```

**Accelerated mode, custom output file, skip LLM:**
```bash
python main.py --server https://cbserver.example.com --token abc123 \
  --acceleration-mode accelerated \
  --output my_report.json \
  --no-llm
```

**With a specific Ollama model:**
```bash
python main.py --server https://cbserver.example.com --token abc123 --model llama3
```

## Output

The tool writes a JSON report to the specified output file (default: `enforcement_readiness_report.json`) containing:

- **Readiness score** — Overall percentage score and whether the environment is ready for High Enforcement
- **Summary** — Counts of unknown binaries, trusted publishers, certificates, etc.
- **Path filter results** — Binaries excluded from auto-approval because they reside in user-writable paths
- **Approval workflow guidance** — Broadcom-aligned event console setup, per-file decisions, and custom-rule recommendations
- **Auto-approval candidates** — Top binaries recommended for automatic approval
- **Acceleration candidates** — Binaries that would most improve the readiness score if approved
- **Acceleration plan** — Steps to reach the 80% readiness target
- **LLM explanation** — Human-readable narrative (if LLM is available)

### Approval Workflow Coverage

The report now includes an `approval_workflow` section with:

- `console_setup_guidance`: Event view setup guidance from the Broadcom workflow (filters, columns, grouping)
- `file_evaluation`: Per-file decision outcomes from the "Evaluating Each File" flowchart
- `custom_rule_considerations`: Event-description-based recommendations from the "Consider a Custom Rule" flowchart
- `rule_suggestions`: Broadcom-guided candidate rules to accelerate toward High Enforcement, including:
  - Prioritized `recommended_rules` (File Creation Control, Execution Control, and selective Performance Optimization)
  - `rule_anti_patterns_detected` warnings for known risky rule patterns
  - `strategy_notes` and summary counts to support implementation planning

### Readiness Score Breakdown

The total score is a weighted average of six components. Each component is scored 0–100%, then multiplied by its weight to produce the total score.

#### Score Components

| Component | Weight | Description |
|---|---|---|
| **Unknown Binaries** | 25% | Percentage of binaries that are **recognized or approved**. Unknown binaries are the primary blocker to enforcement readiness. Score = (1 − unknown%) × 100 |
| **Publisher Trust** | 20% | Percentage of binaries with **trusted publishers** among all binaries analyzed. Trusted publishers indicate legitimate software that can be safely approved. |
| **Certificate Trust** | 15% | Percentage of files signed with **valid certificates**. Valid certificates indicate authentic software from legitimate authors. |
| **Prevalence** | 15% | Distribution of **file prevalence** across the organization. Higher score for files seen across many computers (high prevalence) vs. single-endpoint files. Patterns: high=1.0, medium=0.7, low=0.3, single-endpoint=0.1 |
| **Approval Requests** | 15% | Status of pending **approval requests**. Currently a placeholder metric (static 50%) pending implementation. |
| **Computer Coverage** | 10% | **Percentage of computers** in the organization with analyzed data. Currently a placeholder metric (static 50%) pending implementation. |

#### Recommendation Thresholds

The total score determines readiness for enforcement mode changes:

| Score Range | Status | Recommendation |
|---|---|---|
| ≥ 80% | Ready | `READY_FOR_HIGH_ENFORCEMENT` — Environment is prepared for high enforcement mode |
| 60–79% | Near Ready | `NEAR_READY` — Address remaining unknowns before high enforcement |
| 40–59% | Medium Risk | `MEDIUM_ENFORCEMENT_RECOMMENDED` — Move to medium enforcement; continue reducing unknowns |
| < 40% | High Risk | `MAINTAIN_LOW_ENFORCEMENT` — Focus on identifying and approving common binaries first |

#### Example Score Breakdown

```json
{
  "total_score": 34.1,
  "breakdown": {
    "unknown_binaries": 50.0,
    "publisher_trust": 0.0,
    "certificate_trust": 50.0,
    "prevalence": 10.7,
    "approval_requests": 50.0,
    "computer_coverage": 50.0
  },
  "weights": {
    "unknown_binaries": 0.25,
    "publisher_trust": 0.2,
    "certificate_trust": 0.15,
    "prevalence": 0.15,
    "approval_requests": 0.15,
    "computer_coverage": 0.1
  },
  "ready_for_high_enforcement": false,
  "recommendation": "MAINTAIN_LOW_ENFORCEMENT"
}
```

**Calculation:** (50.0 × 0.25) + (0.0 × 0.2) + (50.0 × 0.15) + (10.7 × 0.15) + (50.0 × 0.15) + (50.0 × 0.1) = **34.1%**

## Troubleshooting

### SSL Certificate Warnings

If you see `InsecureRequestWarning` messages from urllib3:

```
urllib3.exceptions.InsecureRequestWarning: Unverified HTTPS request is being made to host...
```

This occurs when running without SSL verification (default behavior). These are **informational warnings, not errors** — the script runs successfully. The warnings are automatically suppressed as of v1.1. If you still see them, they're safe to ignore.

**To eliminate warnings entirely:** If your CB App Control server has a valid SSL certificate, use:

```bash
python main.py --server https://server.example.com --token <token> --verify-ssl
```

## Data Flow

1. **API Collection** → Query pre-aggregated endpoints (fileCatalog, certificate, etc.)
2. **Aggregation** → Extract trust signals from API responses
3. **Analysis** → Calculate trust scores and readiness metrics
4. **LLM Explanation** → Generate human-readable explanations (optional)
5. **Output** → Produce JSON report and recommendations

## Key Design Principles

- **Filter at source**: Use API facets and filters to minimize data transfer
- **Aggregate early**: Pre-aggregate in SQL/API, not in Python
- **Small LLM input**: Only pass distilled signals to LLM (< 10MB)
- **Local only**: All processing stays on customer premises

## Project Structure

```
enforcement_readiness_advisor/
├── config/
│   └── api_endpoints.py      # CB App Control API endpoint definitions
├── data_collection/
│   ├── api_client.py         # CB API client
│   └── collectors.py         # Data collectors for each endpoint
├── analysis/
│   ├── trust_signals.py      # Trust signal extraction and scoring
│   └── path_analysis.py      # Path classification and installer lineage
├── llm/
│   ├── prompt_templates.py   # LLM prompt templates
│   └── local_llm.py          # Local LLM (Ollama) integration
├── main.py                   # Main entry point
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```