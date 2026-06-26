# HTML Report Generator for Enforcement Readiness Advisor
# Produces a self-contained single-file HTML report — no server, no Docker required.

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Score metadata — human labels and explanations, hidden from raw JSON output
# ---------------------------------------------------------------------------

_SCORE_META = {
    "unknown_binaries": {
        "label": "Unknown File Reduction",
        "explain": (
            "Measures how much of the file catalog has been reviewed. "
            "A higher score means fewer unapproved files remain, which directly "
            "reduces the risk of disruption when switching to High Enforcement."
        ),
    },
    "publisher_trust": {
        "label": "Publisher Trust Coverage",
        "explain": (
            "Measures how many files come from publishers your organisation has "
            "explicitly trusted. Bulk-trusting a publisher approves all current and "
            "future files from that vendor in one action — the highest-leverage step "
            "available before enforcement."
        ),
    },
    "certificate_trust": {
        "label": "Certificate Validity",
        "explain": (
            "Measures how many files carry digitally signed certificates that are "
            "currently valid. Signed files are lower risk and are strong candidates "
            "for auto-approval."
        ),
    },
    "prevalence": {
        "label": "File Prevalence Pattern",
        "explain": (
            "Measures how widely each file is seen across endpoints. A file observed "
            "on many machines is more likely to be legitimate infrastructure than one "
            "seen only on a single endpoint."
        ),
    },
    "computer_coverage": {
        "label": "Endpoint Coverage",
        "explain": (
            "Measures how many active endpoints contributed data to this assessment. "
            "More endpoints means more reliable trust signals — decisions based on "
            "a single machine are less confident."
        ),
    },
}

_DECISION_LABELS = {
    "FOLLOW_COMPANY_POLICY":        ("Do Not Approve",             "danger"),
    "EXISTING_RULE_PRESENT":        ("Existing Rule Covers This",  "success"),
    "CONSIDER_APPROVING_PUBLISHER": ("Trust the Publisher",        "success"),
    "CONSIDER_LOCAL_APPROVAL":      ("Approve on This Endpoint",   "warning"),
    "CONSIDER_GLOBAL_APPROVAL":     ("Approve Globally",           "success"),
    "PROCEED_TO_CUSTOM_RULE":       ("Create a Custom Rule",       "info"),
}


def _score_colour(score: float) -> str:
    if score >= 70:
        return "#28a745"
    if score >= 40:
        return "#fd7e14"
    return "#dc3545"


def _e(value: Any) -> str:
    """HTML-escape a value for safe inline use."""
    return html.escape(str(value) if value is not None else "")


def _pct_bar(value: float, colour: str) -> str:
    clamped = max(0.0, min(100.0, value))
    return (
        f'<div class="bar-track">'
        f'<div class="bar-fill" style="width:{clamped:.1f}%;background:{colour}"></div>'
        f'</div>'
    )


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{_e(kind)}">{_e(text)}</span>'


def _decision_badge(raw_decision: str) -> str:
    label, kind = _DECISION_LABELS.get(raw_decision, (raw_decision, "secondary"))
    return _badge(label, kind)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_sampling_banner(data: Dict) -> str:
    meta = data.get("collection_metadata", {})
    if not meta.get("catalog_sampled"):
        return ""
    total = meta.get("catalog_total", "?")
    cap = meta.get("max_rows", "?")
    return f"""
    <div class="banner banner-warning">
        &#9888; <strong>Partial Sample:</strong> The file catalog contains
        <strong>{_e(total):,}</strong> unknown files but this report analysed only
        the first <strong>{_e(cap):,}</strong>. Scores may not reflect the full
        environment. Re-run with a higher <code>--max-rows</code> value for a
        complete assessment.
    </div>"""


def _render_hero(data: Dict) -> str:
    rs = data.get("readiness_score", {})
    score = rs.get("total_score", 0)
    ready = rs.get("ready_for_high_enforcement", False)
    recommendation = rs.get("recommendation", "")
    colour = _score_colour(score)

    status_text = "Ready for High Enforcement" if ready else "Not Yet Ready for High Enforcement"
    status_class = "status-ready" if ready else "status-not-ready"

    rec_map = {
        "READY_FOR_HIGH_ENFORCEMENT":     "You can proceed to High Enforcement mode.",
        "NEAR_READY - ADDRESS REMAINING UNKNOWNS":
            "You are close. Resolve the remaining unknown files before switching.",
        "MEDIUM ENFORCEMENT RECOMMENDED": "Move to Medium Enforcement first and continue reducing unknowns.",
        "MAINTAIN LOW ENFORCEMENT":       "Stay in Low Enforcement and work through the action plan below.",
    }
    rec_text = rec_map.get(recommendation, recommendation)

    server = data.get("server", "")
    ts = data.get("timestamp", "")
    try:
        ts_fmt = datetime.fromisoformat(ts).strftime("%d %B %Y %H:%M")
    except Exception:
        ts_fmt = ts

    return f"""
    <div class="hero">
        <div class="hero-score" style="color:{colour}">{score:.0f}<span class="hero-pct">%</span></div>
        <div class="hero-label">Enforcement Readiness Score</div>
        <div class="hero-status {status_class}">{_e(status_text)}</div>
        <p class="hero-rec">{_e(rec_text)}</p>
        <div class="hero-meta">
            Assessed: <strong>{_e(ts_fmt)}</strong> &nbsp;|&nbsp;
            Server: <strong>{_e(server)}</strong>
        </div>
    </div>"""


def _render_score_breakdown(data: Dict) -> str:
    rs = data.get("readiness_score", {})
    breakdown = rs.get("breakdown", {})

    cards = []
    for key, meta in _SCORE_META.items():
        value = breakdown.get(key, 0)
        colour = _score_colour(value)
        cards.append(f"""
        <div class="score-card">
            <div class="score-card-label">{_e(meta['label'])}</div>
            {_pct_bar(value, colour)}
            <div class="score-card-value" style="color:{colour}">{value:.0f}%</div>
            <p class="score-card-explain">{_e(meta['explain'])}</p>
        </div>""")

    return f"""
    <section>
        <h2>Score Breakdown
            <button class="toggle-btn" onclick="toggle('score-detail')">Show detail &#9660;</button>
        </h2>
        <div id="score-detail" class="collapsible">
            <div class="score-grid">{''.join(cards)}</div>
        </div>
    </section>"""


def _render_llm_section(data: Dict) -> str:
    llm = data.get("llm_explanation")
    if not llm:
        return ""

    source = llm.get("source", "unknown")
    if source == "disabled":
        return ""

    status = llm.get("overall_readiness_status", "")
    strengths = llm.get("strengths", [])
    improvements = llm.get("areas_for_improvement", [])
    next_steps = llm.get("next_steps", [])
    limits = llm.get("confidence_and_limits", "")

    source_note = {
        "llm":         "",
        "fallback":    '<div class="banner banner-info">&#8505; AI narrative was unavailable; this summary was generated automatically from collected signals.</div>',
        "unavailable": '<div class="banner banner-info">&#8505; Configured Ollama service was not reachable. Start the service or correct the endpoint and re-run to include an AI-generated narrative.</div>',
    }.get(source, "")

    def _list(items: List[str]) -> str:
        return "<ul>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"

    steps_html = "".join(
        f'<div class="step"><span class="step-num">{i+1}</span>{_e(s)}</div>'
        for i, s in enumerate(next_steps)
    )

    return f"""
    <section>
        <h2>Assessment Summary</h2>
        {source_note}
        <p class="summary-status">{_e(status)}</p>
        <div class="two-col">
            <div>
                <h3>&#10003; Strengths</h3>
                {_list(strengths)}
            </div>
            <div>
                <h3>&#9888; Areas to Improve</h3>
                {_list(improvements)}
            </div>
        </div>
        {'<h3>Recommended Next Steps</h3><div class="steps">' + steps_html + '</div>' if steps_html else ''}
        {'<p class="confidence-note"><em>' + _e(limits) + '</em></p>' if limits else ''}
    </section>"""


def _render_key_metrics(data: Dict) -> str:
    summary = data.get("summary", {})
    pf = data.get("path_filter", {})
    ap = data.get("acceleration_plan", {})

    metrics = [
        ("Unknown Files",         summary.get("unknown_count", 0),          "Files not yet reviewed or approved"),
        ("Trusted Publishers",    summary.get("trusted_publisher_count", 0), "Publishers your org has explicitly trusted"),
        ("Valid Certificates",    summary.get("valid_certificate_count", 0), "Files with valid digital signatures"),
        ("Active Endpoints",      summary.get("active_computer_count", 0),   "Machines that contributed data"),
        ("Safe Path Candidates",  pf.get("safe_binaries", 0),               "Files in system paths (not user-writable)"),
        ("Excluded (User Paths)", pf.get("excluded_user_writable", 0),       "Files in user-writable locations — excluded from auto-approval"),
    ]

    cards = "".join(f"""
        <div class="metric-card">
            <div class="metric-value">{v:,}</div>
            <div class="metric-label">{_e(l)}</div>
            <div class="metric-desc">{_e(d)}</div>
        </div>""" for l, v, d in metrics)

    gap = ap.get("gap_to_target")
    gap_html = ""
    if gap is not None:
        if gap <= 0:
            gap_html = '<p class="goal-met">&#10003; Readiness target of 80% has been met.</p>'
        else:
            total_cands = ap.get("total_acceleration_candidates", 0)
            gap_html = f"""
            <div class="goal-banner">
                <strong>{gap:.1f}% gap</strong> to the 80% High Enforcement target &mdash;
                <strong>{_e(total_cands)}</strong> acceleration candidates identified to close it.
            </div>"""

    return f"""
    <section>
        <h2>Environment at a Glance</h2>
        {gap_html}
        <div class="metric-grid">{cards}</div>
    </section>"""


def _render_decisions_table(data: Dict) -> str:
    fe = data.get("approval_workflow", {}).get("file_evaluation", {})
    decisions = fe.get("all_decisions", fe.get("sample_decisions", []))
    counts = fe.get("decision_counts", {})
    total = fe.get("total_files_evaluated", 0)

    if not decisions:
        return ""

    # Summary pills
    pills = "".join(
        f'<button class="filter-pill" data-decision="{_e(k)}" onclick="filterTable(\'{_e(k)}\')">'
        f'{_e(_DECISION_LABELS.get(k, (k, "secondary"))[0])}: <strong>{_e(v)}</strong>'
        f'</button>'
        for k, v in counts.items() if v > 0
    )

    rows = "".join(f"""
        <tr data-decision="{_e(d.get('decision',''))}">
            <td>{_e(d.get('file_name',''))}</td>
            <td class="path-cell">{_e(d.get('file_path',''))}</td>
            <td>{_decision_badge(d.get('decision',''))}</td>
            <td>{_e(d.get('rationale',''))}</td>
            <td>{_e(d.get('recommended_next_step',''))}</td>
        </tr>""" for d in decisions)

    shown = len(decisions)
    note = f"Showing all {shown:,} evaluated files." if total == shown else f"Showing {shown:,} of {total:,} evaluated files."

    return f"""
    <section>
        <h2>File Review Decisions
            <button class="toggle-btn" onclick="toggle('decisions-detail')">Show detail &#9660;</button>
        </h2>
        <p>{_e(note)} Use the filters, search, sorting, and pagination controls to review the full set.</p>
        <div id="decisions-detail" class="collapsible">
            <div class="filter-bar">
                <button class="filter-pill active" data-decision="ALL" onclick="filterTable('ALL')">All</button>
                {pills}
            </div>
            <div class="table-toolbar">
                <div class="search-row">
                    <input id="decision-search" class="search-input" type="search" placeholder="Search file, path, rationale, or next step..." oninput="searchDecisions(this.value)">
                </div>
                <div class="pager-row">
                    <label class="pager-label" for="decision-page-size">Rows per page</label>
                    <select id="decision-page-size" class="pager-select" onchange="setDecisionPageSize(this.value)">
                        <option value="10">10</option>
                        <option value="25" selected>25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                    <button class="pager-button" data-action="previous" onclick="previousDecisionPage()">Previous</button>
                    <button class="pager-button" data-action="next" onclick="nextDecisionPage()">Next</button>
                    <span class="pager-info" data-role="page-info"></span>
                </div>
            </div>
            <div class="table-wrap">
                <table id="decisions-table">
                    <thead>
                        <tr>
                            <th class="sortable-th" onclick="sortTable('decisions-table', 0, 'text')">File Name <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('decisions-table', 1, 'text')">Path <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('decisions-table', 2, 'text')">Recommendation <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('decisions-table', 3, 'text')">Rationale <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('decisions-table', 4, 'text')">Next Step <span class="sort-indicator"></span></th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            <div class="table-toolbar table-toolbar-bottom">
                <div class="pager-row pager-row-bottom">
                    <button class="pager-button" data-action="previous" onclick="previousDecisionPage()">Previous</button>
                    <button class="pager-button" data-action="next" onclick="nextDecisionPage()">Next</button>
                    <span class="pager-info" data-role="page-info"></span>
                </div>
            </div>
        </div>
    </section>"""


def _render_candidates(data: Dict) -> str:
    candidates = data.get("acceleration_candidates", [])
    if not candidates:
        return ""

    rows = "".join(f"""
        <tr>
            <td>{_e(c.get('target',''))}</td>
            <td>{_e(c.get('type','').replace('_', ' ').title())}</td>
            <td>{_e(c.get('files_to_approve', '—'))}</td>
            <td>{_e(c.get('readiness_improvement_percent', '—'))}%</td>
            <td>{_e(c.get('confidence_percent', '—'))}%</td>
            <td>{_badge(c.get('priority','').title(), 'success' if c.get('priority') == 'high' else 'warning')}</td>
            <td class="path-cell">{_e(c.get('rationale',''))}</td>
        </tr>""" for c in candidates)

    return f"""
    <section>
        <h2>Top Acceleration Candidates</h2>
        <p>Approving these certificates or publishers will have the largest immediate impact on your readiness score.
           Confidence is a heuristic based on available signals (risk score, signature validity, issuer trust, prevalence) — not a guarantee.</p>
        <div class="table-wrap">
            <table id="candidates-table">
                <thead>
                    <tr>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 0, 'text')">Target <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 1, 'text')">Action Type <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 2, 'number')">Files Approved <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 3, 'number')">Score Gain <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 4, 'number')">Confidence <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 5, 'text')">Priority <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 6, 'text')">Rationale <span class="sort-indicator"></span></th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </section>"""


def _render_rule_suggestions(data: Dict) -> str:
    """Render rule suggestions to approve unapproved files."""
    rule_sugg = data.get("approval_workflow", {}).get("rule_suggestions", {})
    candidates = rule_sugg.get("recommended_rules", rule_sugg.get("candidates", []))
    summary = rule_sugg.get("summary", {})
    
    if not candidates:
        return f"""
    <section>
        <h2>Recommended Rules for Unapproved Files</h2>
        <p>No rule suggestions generated. Check File Review Decisions for files that may need custom rules.</p>
    </section>"""
    
    # Build rows for the suggestions table
    rows = "".join(f"""
        <tr>
            <td>{_e(c.get('rule_type', ''))}</td>
            <td>{_e(c.get('rule_name', ''))}</td>
            <td>{_e(c.get('process_pattern', ''))}</td>
            <td class="path-cell">{_e(c.get('file_pattern', ''))}</td>
            <td>{_e(c.get('operation', ''))}</td>
            <td>{_badge(c.get('action', 'Approve').title(), 'info')}</td>
            <td>{int(c.get('confidence', 0) * 100)}%</td>
            <td>{_e(c.get('source_event_count', 0))} events</td>
            <td><span class="expand-btn" onclick="toggleSafetyChecks(this)">+</span></td>
        </tr>
        <tr class="safety-checks-row" style="display: none;">
            <td colspan="9">
                <div class="safety-checks">
                    <strong>Safety Checks:</strong>
                    <ul>
                        {"".join(f"<li>{_e(check)}</li>" for check in c.get('safety_checks', []))}
                    </ul>
                    <strong>Rationale:</strong>
                    <p>{_e(c.get('rationale', ''))}</p>
                    <strong>Expected Impact:</strong>
                    <p>{_e(c.get('expected_enforcement_impact', ''))}</p>
                </div>
            </td>
        </tr>""" for c in candidates)
    
    return f"""
    <section>
        <h2>Recommended Rules for Unapproved Files
            <button class="toggle-btn" onclick="toggle('rules-detail')">Show detail &#9660;</button>
        </h2>
        <p>These rules are derived from kernel discovery events and file approval patterns. Use them to approve recurring unapproved files.</p>
        <div id="rules-detail" class="collapsible">
            <div class="table-wrap">
                <table id="rules-table">
                    <thead>
                        <tr>
                            <th class="sortable-th" onclick="sortTable('rules-table', 0, 'text')">Rule Type <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 1, 'text')">Rule Name <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 2, 'text')">Process <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 3, 'text')">File Pattern <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 4, 'text')">Operation <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 5, 'text')">Action <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 6, 'number')">Confidence <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 7, 'number')">Events <span class="sort-indicator"></span></th>
                            <th style="width: 50px;">Details</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </section>"""


def _render_risks(data: Dict) -> str:
    risks = data.get("risks_requiring_review", [])
    if not risks:
        return ""

    cards = "".join(f"""
        <div class="risk-card">
            <div class="risk-title">{_e(r.get('category',''))}</div>
            <p>{_e(r.get('description',''))}</p>
            <p><strong>Impact:</strong> {_e(r.get('impact',''))}</p>
            <p><strong>Action:</strong> {_e(r.get('recommended_action',''))}</p>
        </div>""" for r in risks)

    return f"""
    <section>
        <h2>Risks Requiring Manual Review</h2>
        <div class="risk-grid">{cards}</div>
    </section>"""


# ---------------------------------------------------------------------------
# CSS and JS
# ---------------------------------------------------------------------------

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    font-size: 15px; line-height: 1.6;
    background: #f4f6f9; color: #2c3e50;
}

.page-wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }

/* Header */
.page-header { background: #1a2b45; color: #fff; padding: 18px 24px; border-radius: 8px; margin-bottom: 24px; }
.page-header h1 { font-size: 1.4rem; font-weight: 600; }
.page-header .subtitle { font-size: 0.85rem; opacity: 0.7; margin-top: 2px; }

/* Banners */
.banner { padding: 12px 16px; border-radius: 6px; margin-bottom: 20px; font-size: 0.9rem; }
.banner-warning { background: #fff3cd; border-left: 4px solid #fd7e14; color: #7a4f00; }
.banner-info    { background: #d1ecf1; border-left: 4px solid #17a2b8; color: #0c5460; }

/* Hero */
.hero { text-align: center; background: #fff; border-radius: 10px; padding: 36px 24px 28px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
.hero-score { font-size: 6rem; font-weight: 700; line-height: 1; }
.hero-pct { font-size: 2.5rem; vertical-align: super; }
.hero-label { font-size: 1rem; color: #6c757d; margin-top: 4px; }
.hero-status { display: inline-block; margin-top: 12px; padding: 6px 18px; border-radius: 20px; font-weight: 600; font-size: 0.95rem; }
.status-ready     { background: #d4edda; color: #155724; }
.status-not-ready { background: #f8d7da; color: #721c24; }
.hero-rec  { margin-top: 12px; font-size: 0.95rem; color: #495057; }
.hero-meta { margin-top: 14px; font-size: 0.8rem; color: #adb5bd; }

/* Sections */
section { background: #fff; border-radius: 10px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
section h2 { font-size: 1.15rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; }
section h3 { font-size: 1rem; font-weight: 600; margin: 16px 0 8px; }

/* Toggle button */
.toggle-btn { margin-left: auto; font-size: 0.8rem; padding: 4px 10px; border: 1px solid #ced4da; border-radius: 4px; background: #f8f9fa; cursor: pointer; }
.collapsible { display: none; margin-top: 12px; }

/* Score grid */
.score-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; }
.score-card { border: 1px solid #e9ecef; border-radius: 8px; padding: 14px; }
.score-card-label { font-weight: 600; font-size: 0.9rem; margin-bottom: 10px; }
.score-card-value { font-size: 1.4rem; font-weight: 700; margin: 6px 0; }
.score-card-explain { font-size: 0.78rem; color: #6c757d; margin-top: 8px; line-height: 1.4; }

/* Bar */
.bar-track { background: #e9ecef; border-radius: 4px; height: 8px; overflow: hidden; }
.bar-fill  { height: 100%; border-radius: 4px; transition: width .4s; }

/* Summary status */
.summary-status { font-size: 1.05rem; font-style: italic; margin-bottom: 16px; padding: 12px; background: #f8f9fa; border-radius: 6px; }
.confidence-note { margin-top: 16px; font-size: 0.82rem; color: #868e96; }
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
@media (max-width: 640px) { .two-col { grid-template-columns: 1fr; } }
ul { padding-left: 20px; } li { margin: 4px 0; }

/* Steps */
.steps { display: flex; flex-direction: column; gap: 10px; margin-top: 12px; }
.step { display: flex; align-items: flex-start; gap: 12px; padding: 10px 14px; background: #f0f7ff; border-radius: 6px; font-size: 0.9rem; }
.step-num { background: #1a2b45; color: #fff; border-radius: 50%; min-width: 24px; height: 24px; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 700; }

/* Metric grid */
.metric-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 14px; }
.metric-card { border: 1px solid #e9ecef; border-radius: 8px; padding: 16px 14px; text-align: center; }
.metric-value { font-size: 2rem; font-weight: 700; color: #1a2b45; }
.metric-label { font-weight: 600; font-size: 0.85rem; margin-top: 4px; }
.metric-desc  { font-size: 0.75rem; color: #6c757d; margin-top: 4px; line-height: 1.3; }
.goal-banner { background: #fff3cd; border-left: 4px solid #fd7e14; padding: 10px 14px; border-radius: 4px; margin-bottom: 16px; font-size: 0.9rem; }
.goal-met    { color: #155724; font-weight: 600; margin-bottom: 12px; }

/* Badges */
.badge { display: inline-block; padding: 3px 9px; border-radius: 12px; font-size: 0.78rem; font-weight: 600; white-space: nowrap; }
.badge-success   { background: #d4edda; color: #155724; }
.badge-warning   { background: #fff3cd; color: #856404; }
.badge-danger    { background: #f8d7da; color: #721c24; }
.badge-info      { background: #d1ecf1; color: #0c5460; }
.badge-secondary { background: #e9ecef; color: #495057; }

/* Filter bar */
.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.filter-pill { padding: 4px 12px; border: 1px solid #ced4da; border-radius: 16px; background: #f8f9fa; cursor: pointer; font-size: 0.82rem; }
.filter-pill.active { background: #1a2b45; color: #fff; border-color: #1a2b45; }

/* Search */
.search-row { margin-bottom: 12px; }
.search-input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #ced4da;
    border-radius: 8px;
    font-size: 0.9rem;
}

/* Pagination */
.table-toolbar { display: flex; flex-direction: column; gap: 10px; margin-bottom: 12px; }
.table-toolbar-bottom { margin-top: 12px; margin-bottom: 0; }
.pager-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.pager-row-bottom { justify-content: flex-end; }
.pager-label { font-size: 0.84rem; color: #495057; }
.pager-select, .pager-button {
    border: 1px solid #ced4da;
    border-radius: 6px;
    background: #fff;
    padding: 8px 10px;
    font-size: 0.85rem;
}
.pager-button { cursor: pointer; background: #f8f9fa; }
.pager-button:disabled { cursor: not-allowed; opacity: 0.5; }
.pager-info { font-size: 0.84rem; color: #495057; margin-left: auto; }

/* Tables */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.87rem; }
th { background: #f0f2f5; text-align: left; padding: 9px 12px; border-bottom: 2px solid #dee2e6; font-weight: 600; white-space: nowrap; }
td { padding: 8px 12px; border-bottom: 1px solid #f0f2f5; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.path-cell { font-family: monospace; font-size: 0.8rem; color: #495057; word-break: break-all; }
.sortable-th { cursor: pointer; user-select: none; }
.sort-indicator { display: inline-block; width: 0.9em; color: #6c757d; margin-left: 4px; }

/* Risks */
.risk-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
.risk-card { border: 1px solid #f8d7da; border-left: 4px solid #dc3545; border-radius: 8px; padding: 16px; }
.risk-title { font-weight: 700; color: #dc3545; margin-bottom: 8px; }
.risk-card p { font-size: 0.87rem; margin-top: 6px; }

/* Rule Suggestions */
.expand-btn { display: inline-block; width: 28px; height: 28px; background: #007bff; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; text-align: center; line-height: 28px; font-size: 1.2rem; transition: background 0.2s; }
.expand-btn:hover { background: #0056b3; }
.safety-checks-row { background: #f8f9fa; border-top: 1px solid #dee2e6; }
.safety-checks { padding: 12px 0; }
.safety-checks strong { display: block; margin-top: 10px; margin-bottom: 6px; color: #2c3e50; }
.safety-checks ul { margin: 0 0 8px 20px; padding: 0; }
.safety-checks li { margin-bottom: 4px; font-size: 0.9rem; color: #495057; }
.safety-checks p { margin: 6px 0; font-size: 0.9rem; color: #495057; }
"""

_JS = """
var currentDecisionFilter = 'ALL';
var currentDecisionSearch = '';
var currentDecisionPage = 1;
var currentDecisionPageSize = 25;
var tableSortState = {};

function toggle(id) {
    var el = document.getElementById(id);
    var btn = el.previousElementSibling.querySelector('.toggle-btn');
    if (el.style.display === 'block') {
        el.style.display = 'none';
        btn.innerHTML = 'Show detail &#9660;';
    } else {
        el.style.display = 'block';
        btn.innerHTML = 'Hide detail &#9650;';
    }
}

function filterTable(decision) {
    currentDecisionFilter = decision;
    document.querySelectorAll('.filter-pill').forEach(function(pill) {
        pill.classList.toggle('active', pill.getAttribute('data-decision') === decision || decision === 'ALL');
    });
    currentDecisionPage = 1;
    applyDecisionTableState();
}

function searchDecisions(term) {
    currentDecisionSearch = term || '';
    currentDecisionPage = 1;
    applyDecisionTableState();
}

function setDecisionPageSize(value) {
    currentDecisionPageSize = parseInt(value, 10) || 25;
    currentDecisionPage = 1;
    applyDecisionTableState();
}

function previousDecisionPage() {
    if (currentDecisionPage > 1) {
        currentDecisionPage -= 1;
        applyDecisionTableState(false);
    }
}

function nextDecisionPage() {
    var totalPages = getDecisionTotalPages();
    if (currentDecisionPage < totalPages) {
        currentDecisionPage += 1;
        applyDecisionTableState(false);
    }
}

function getDecisionFilteredRows() {
    var rows = Array.from(document.querySelectorAll('#decisions-table tbody tr'));
    return rows.filter(function(row) {
        var matchesDecision = (currentDecisionFilter === 'ALL' || row.dataset.decision === currentDecisionFilter);
        var matchesSearch = !currentDecisionSearch || row.textContent.toLowerCase().indexOf(currentDecisionSearch.toLowerCase()) >= 0;
        return matchesDecision && matchesSearch;
    });
}

function getDecisionTotalPages() {
    return Math.max(1, Math.ceil(getDecisionFilteredRows().length / currentDecisionPageSize));
}

function applyDecisionTableState(resetPage) {
    var table = document.getElementById('decisions-table');
    if (!table) {
        return;
    }

    if (resetPage === true) {
        currentDecisionPage = 1;
    }

    var rows = Array.from(document.querySelectorAll('#decisions-table tbody tr'));
    var filtered = rows.filter(function(row) {
        var matchesDecision = (currentDecisionFilter === 'ALL' || row.dataset.decision === currentDecisionFilter);
        var matchesSearch = !currentDecisionSearch || row.textContent.toLowerCase().indexOf(currentDecisionSearch.toLowerCase()) >= 0;
        return matchesDecision && matchesSearch;
    });

    var totalPages = Math.max(1, Math.ceil(filtered.length / currentDecisionPageSize));
    if (currentDecisionPage > totalPages) {
        currentDecisionPage = totalPages;
    }

    var start = (currentDecisionPage - 1) * currentDecisionPageSize;
    var end = start + currentDecisionPageSize;

    rows.forEach(function(row) {
        row.style.display = 'none';
    });

    filtered.slice(start, end).forEach(function(row) {
        row.style.display = '';
    });

    var infoText = (filtered.length === 0)
        ? 'No matching files'
        : 'Page ' + currentDecisionPage + ' of ' + totalPages + ' (' + filtered.length + ' matching files)';

    document.querySelectorAll('[data-role="page-info"]').forEach(function(info) {
        info.textContent = infoText;
    });

    document.querySelectorAll('.pager-button[data-action="previous"]').forEach(function(button) {
        button.disabled = currentDecisionPage <= 1 || filtered.length === 0;
    });
    document.querySelectorAll('.pager-button[data-action="next"]').forEach(function(button) {
        button.disabled = currentDecisionPage >= totalPages || filtered.length === 0;
    });
}

function sortTable(tableId, columnIndex, sortType) {
    var table = document.getElementById(tableId);
    if (!table) {
        return;
    }

    var tbody = table.querySelector('tbody');
    var rows = Array.from(tbody.querySelectorAll('tr'));
    var state = tableSortState[tableId] || { column: -1, direction: 'asc' };
    var direction = (state.column === columnIndex && state.direction === 'asc') ? 'desc' : 'asc';

    rows.sort(function(leftRow, rightRow) {
        var leftValue = (leftRow.cells[columnIndex] || {}).textContent || '';
        var rightValue = (rightRow.cells[columnIndex] || {}).textContent || '';

        if (sortType === 'number') {
            leftValue = parseFloat(leftValue.replace(/[^0-9.-]/g, ''));
            rightValue = parseFloat(rightValue.replace(/[^0-9.-]/g, ''));
            leftValue = Number.isNaN(leftValue) ? -Infinity : leftValue;
            rightValue = Number.isNaN(rightValue) ? -Infinity : rightValue;
            return direction === 'asc' ? leftValue - rightValue : rightValue - leftValue;
        }

        leftValue = leftValue.trim().toLowerCase();
        rightValue = rightValue.trim().toLowerCase();
        if (leftValue < rightValue) return direction === 'asc' ? -1 : 1;
        if (leftValue > rightValue) return direction === 'asc' ? 1 : -1;
        return 0;
    });

    rows.forEach(function(row) {
        tbody.appendChild(row);
    });

    tableSortState[tableId] = { column: columnIndex, direction: direction, type: sortType };
    updateSortIndicators(tableId);

    if (tableId === 'decisions-table') {
        applyDecisionTableState(true);
    }
}

function updateSortIndicators(tableId) {
    var table = document.getElementById(tableId);
    if (!table) {
        return;
    }

    var state = tableSortState[tableId] || { column: -1, direction: 'asc' };
    table.querySelectorAll('th.sortable-th').forEach(function(header, index) {
        var indicator = header.querySelector('.sort-indicator');
        if (!indicator) {
            return;
        }
        if (index === state.column) {
            indicator.textContent = state.direction === 'asc' ? '▲' : '▼';
        } else {
            indicator.textContent = '';
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    sortTable('decisions-table', 0, 'text');
    sortTable('candidates-table', 0, 'text');
    sortTable('rules-table', 6, 'number');
    applyDecisionTableState(true);
});

function toggleSafetyChecks(btn) {
    var row = btn.closest('tr');
    var nextRow = row.nextElementSibling;
    
    if (nextRow && nextRow.classList.contains('safety-checks-row')) {
        if (nextRow.style.display === 'none') {
            nextRow.style.display = '';
            btn.textContent = '-';
        } else {
            nextRow.style.display = 'none';
            btn.textContent = '+';
        }
    }
}

function showApprovalTab(tabName) {
    var tabs = document.querySelectorAll('.approval-tab-content');
    var buttons = document.querySelectorAll('.approval-tab-btn');

    tabs.forEach(function(tab) {
        tab.classList.remove('active');
        tab.style.display = 'none';
    });
    buttons.forEach(function(btn) {
        btn.classList.remove('active');
    });

    var tabMap = {
        'pending': 'approval-pending-tab',
        'approved': 'approval-approved-tab',
        'denied': 'approval-denied-tab'
    };

    var activeTab = document.getElementById(tabMap[tabName]);
    if (activeTab) {
        activeTab.classList.add('active');
        activeTab.style.display = 'block';
    }

    event.target.classList.add('active');
}
"""


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_html_report(data: Dict, output_path: str) -> None:
    """
    Generate a self-contained HTML report from the analysis data dict.

    Args:
        data:        The full report dictionary (as written to the JSON file).
        output_path: File path to write the HTML file to.
    """
    server = data.get("server", "")
    ts = data.get("timestamp", "")
    try:
        ts_fmt = datetime.fromisoformat(ts).strftime("%d %B %Y %H:%M")
    except Exception:
        ts_fmt = ts

    body = "\n".join([
        _render_sampling_banner(data),
        _render_hero(data),
        _render_key_metrics(data),
        _render_llm_section(data),
        _render_score_breakdown(data),
        _render_decisions_table(data),
        _render_rule_suggestions(data),
        _render_candidates(data),
        _render_risks(data),
    ])

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enforcement Readiness Report &mdash; {_e(server)}</title>
    <style>{_CSS}</style>
</head>
<body>
<div class="page-wrap">
    <div class="page-header">
        <h1>Carbon Black App Control &mdash; Enforcement Readiness Report</h1>
        <div class="subtitle">{_e(server)} &nbsp;|&nbsp; {_e(ts_fmt)}</div>
    </div>
    {body}
</div>
<script>{_JS}</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
