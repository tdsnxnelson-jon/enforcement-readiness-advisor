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
        <div class="hero-label">Enforcement Readiness Score <span class="tip" data-tooltip="Weighted composite of five dimensions: Unknown File Reduction, Publisher Trust Coverage, Certificate Validity, File Prevalence Pattern, and Endpoint Coverage. Each dimension contributes equally to the 0–100 total.">i</span></div>
        <div class="hero-status {status_class}">{_e(status_text)}</div>
        <p class="hero-rec">{_e(rec_text)}</p>
        <p class="section-help">
            <strong>Purpose:</strong> quick status of enforcement readiness. &nbsp;
            <strong>How to use:</strong> treat this as a summary signal, then use the optimized plan and guardrails to decide actions.
        </p>
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
        <p class="section-help">
            <strong>Purpose:</strong> shows which scoring dimensions are limiting readiness. &nbsp;
            <strong>How to use:</strong> prioritize remediation work on the lowest weighted contributors first.
        </p>
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
        <p class="section-help">
            <strong>Purpose:</strong> narrative explanation of readiness posture. &nbsp;
            <strong>How to use:</strong> use for communication context; treat tabular sections as the source of truth for change decisions.
        </p>
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
        <p class="section-help">
            <strong>Purpose:</strong> baseline inventory snapshot for this run. &nbsp;
            <strong>How to use:</strong> use these counts to validate data quality and identify immediate bottlenecks before approvals.
        </p>
        {gap_html}
        <div class="metric-grid">{cards}</div>
    </section>"""


def _render_score_audit(data: Dict) -> str:
    audit = data.get("score_audit", {})
    if not audit:
        return ""

    inputs = audit.get("inputs", {})
    publisher_counts = audit.get("publisher_analysis_counts", {})
    warnings = audit.get("warnings", [])

    def _value_state(value: Any) -> str:
        if isinstance(value, (int, float)):
            return "nonzero" if value != 0 else "zero"
        return "nonzero" if str(value).strip() else "zero"

    rows = "".join(
        f"<tr data-value-state=\"{_e(_value_state(v))}\"><td>{_e(k.replace('_', ' ').title())}</td><td>{_e(v)}</td></tr>"
        for k, v in inputs.items()
    )
    pub_rows = "".join(
        f"<tr data-value-state=\"{_e(_value_state(v))}\"><td>{_e(k.replace('_', ' ').title())}</td><td>{_e(v)}</td></tr>"
        for k, v in publisher_counts.items()
    )

    warning_html = ""
    if warnings:
        warning_html = """
        <div class="banner banner-warning">
            <strong>Scoring Consistency Warnings</strong>
            <ul>{}</ul>
        </div>""".format("".join(f"<li>{_e(w)}</li>" for w in warnings))

    return f"""
    <section>
        <h2>Score Audit
            <button class="toggle-btn" onclick="toggle('score-audit-detail')">Show detail &#9660;</button>
        </h2>
        <p class="section-help">
            <strong>Purpose:</strong> verifies scoring inputs and consistency checks. &nbsp;
            <strong>How to use:</strong> resolve warnings here before trusting projected gains in downstream sections.
        </p>
        {warning_html}
        <div id="score-audit-detail" class="collapsible">
            <div class="two-col">
                <div>
                    <h3>Score Inputs</h3>
                    <div class="filter-bar">
                        <button class="filter-pill active" data-table-id="audit-inputs-table" data-filter-value="ALL" onclick="filterManagedTable('audit-inputs-table','ALL')">All</button>
                        <button class="filter-pill" data-table-id="audit-inputs-table" data-filter-value="nonzero" onclick="filterManagedTable('audit-inputs-table','nonzero')">Non-zero</button>
                        <button class="filter-pill" data-table-id="audit-inputs-table" data-filter-value="zero" onclick="filterManagedTable('audit-inputs-table','zero')">Zero</button>
                    </div>
                    <div class="table-toolbar">
                        <div class="search-row">
                            <input id="audit-inputs-search" class="search-input" type="search" placeholder="Search score input metrics..." oninput="setManagedTableSearch('audit-inputs-table', this.value)">
                        </div>
                        <div class="pager-row">
                            <label class="pager-label" for="audit-inputs-page-size">Rows per page</label>
                            <select id="audit-inputs-page-size" class="pager-select" onchange="setManagedTablePageSize('audit-inputs-table', this.value)">
                                <option value="5" selected>5</option>
                                <option value="10">10</option>
                                <option value="25">25</option>
                            </select>
                            <button id="audit-inputs-prev" class="pager-button" onclick="previousManagedTablePage('audit-inputs-table')">Previous</button>
                            <button id="audit-inputs-next" class="pager-button" onclick="nextManagedTablePage('audit-inputs-table')">Next</button>
                            <span id="audit-inputs-pager" class="pager-info"></span>
                        </div>
                    </div>
                    <div class="table-wrap">
                        <table id="audit-inputs-table">
                            <thead><tr><th class="sortable-th" onclick="sortTable('audit-inputs-table', 0, 'text')">Metric <span class="sort-indicator"></span></th><th class="sortable-th" onclick="sortTable('audit-inputs-table', 1, 'number')">Value <span class="sort-indicator"></span></th></tr></thead>
                            <tbody>{rows}</tbody>
                        </table>
                    </div>
                </div>
                <div>
                    <h3>Publisher Analysis Counts</h3>
                    <div class="filter-bar">
                        <button class="filter-pill active" data-table-id="audit-publisher-table" data-filter-value="ALL" onclick="filterManagedTable('audit-publisher-table','ALL')">All</button>
                        <button class="filter-pill" data-table-id="audit-publisher-table" data-filter-value="nonzero" onclick="filterManagedTable('audit-publisher-table','nonzero')">Non-zero</button>
                        <button class="filter-pill" data-table-id="audit-publisher-table" data-filter-value="zero" onclick="filterManagedTable('audit-publisher-table','zero')">Zero</button>
                    </div>
                    <div class="table-toolbar">
                        <div class="search-row">
                            <input id="audit-publisher-search" class="search-input" type="search" placeholder="Search publisher count metrics..." oninput="setManagedTableSearch('audit-publisher-table', this.value)">
                        </div>
                        <div class="pager-row">
                            <label class="pager-label" for="audit-publisher-page-size">Rows per page</label>
                            <select id="audit-publisher-page-size" class="pager-select" onchange="setManagedTablePageSize('audit-publisher-table', this.value)">
                                <option value="5" selected>5</option>
                                <option value="10">10</option>
                                <option value="25">25</option>
                            </select>
                            <button id="audit-publisher-prev" class="pager-button" onclick="previousManagedTablePage('audit-publisher-table')">Previous</button>
                            <button id="audit-publisher-next" class="pager-button" onclick="nextManagedTablePage('audit-publisher-table')">Next</button>
                            <span id="audit-publisher-pager" class="pager-info"></span>
                        </div>
                    </div>
                    <div class="table-wrap">
                        <table id="audit-publisher-table">
                            <thead><tr><th class="sortable-th" onclick="sortTable('audit-publisher-table', 0, 'text')">Metric <span class="sort-indicator"></span></th><th class="sortable-th" onclick="sortTable('audit-publisher-table', 1, 'number')">Value <span class="sort-indicator"></span></th></tr></thead>
                            <tbody>{pub_rows}</tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </section>"""


def _render_optimized_plan(data: Dict) -> str:
    plan = data.get("optimized_acceleration_plan", {})
    if not plan:
        return ""

    actions = plan.get("actions", [])
    action_types = sorted({str(a.get('type', '')).replace('_', ' ').title() for a in actions if a.get('type')})

    if actions:
        action_rows = "".join(
            f"""
            <tr data-action-type=\"{_e(str(a.get('type', '')).replace('_', ' ').title())}\">
                <td>{_e(a.get('target', ''))}</td>
                <td>{_e(str(a.get('type', '')).replace('_', ' ').title())}</td>
                <td>{_e(a.get('net_new_files', a.get('files_to_approve', '—')))}</td>
                <td>{_e(a.get('overlap_percent', '—'))}%</td>
                <td>{_e(a.get('marginal_gain_percent', '—'))}%</td>
                <td>{_e(a.get('projected_readiness_score', '—'))}%</td>
            </tr>"""
            for a in actions
        )
    else:
        action_rows = '<tr><td colspan="6">No positive-gain optimized actions were found.</td></tr>'

    return f"""
    <section>
        <h2>Optimized Acceleration Plan</h2>
        <p class="section-help">
            <strong>Purpose:</strong> overlap-aware sequence of the highest marginal-gain actions. &nbsp;
            <strong>How to use:</strong> execute in order, re-run after each batch, and compare projected vs actual movement.
        </p>
        <p>
            Current: <strong>{_e(plan.get('current_readiness', 0))}%</strong> &nbsp;|&nbsp;
            Projected: <strong>{_e(plan.get('projected_readiness', 0))}%</strong> &nbsp;|&nbsp;
            Gain: <strong>{_e(plan.get('projected_gain', 0))}%</strong> &nbsp;|&nbsp;
            Target: <strong>{_e(plan.get('target_readiness', 80))}%</strong>
        </p>
        <div class="filter-bar">
            <button class="filter-pill active" data-table-id="optimized-table" data-filter-value="ALL" onclick="filterManagedTable('optimized-table','ALL')">All</button>
            {''.join(f'<button class="filter-pill" data-table-id="optimized-table" data-filter-value="{_e(t)}" onclick="filterManagedTable(\'optimized-table\',\'{_e(t)}\')">{_e(t)}</button>' for t in action_types)}
        </div>
        <div class="table-toolbar">
            <div class="search-row">
                <input id="optimized-table-search" class="search-input" type="search" placeholder="Search optimized actions..." oninput="setManagedTableSearch('optimized-table', this.value)">
            </div>
            <div class="pager-row">
                <label class="pager-label" for="optimized-table-page-size">Rows per page</label>
                <select id="optimized-table-page-size" class="pager-select" onchange="setManagedTablePageSize('optimized-table', this.value)">
                    <option value="5" selected>5</option>
                    <option value="10">10</option>
                    <option value="25">25</option>
                </select>
                <button id="optimized-table-prev" class="pager-button" onclick="previousManagedTablePage('optimized-table')">Previous</button>
                <button id="optimized-table-next" class="pager-button" onclick="nextManagedTablePage('optimized-table')">Next</button>
                <span id="optimized-table-pager" class="pager-info"></span>
            </div>
        </div>
        <div class="table-wrap">
            <table id="optimized-table">
                <thead>
                    <tr>
                        <th class="sortable-th" onclick="sortTable('optimized-table', 0, 'text')">Target <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('optimized-table', 1, 'text')">Action Type <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('optimized-table', 2, 'number')">Net New Files <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('optimized-table', 3, 'number')">Overlap <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('optimized-table', 4, 'number')">Marginal Gain <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('optimized-table', 5, 'number')">Projected Score <span class="sort-indicator"></span></th>
                    </tr>
                </thead>
                <tbody>{action_rows}</tbody>
            </table>
        </div>
    </section>"""


def _render_guardrails(data: Dict) -> str:
    guardrails = data.get("guardrail_checks", {})
    if not guardrails:
        return ""

    findings = guardrails.get("findings", [])
    finding_rows = "".join(
        f"""
        <tr data-severity=\"{_e(str(f.get('severity', '')).title())}\">
            <td>{_badge(str(f.get('severity', '')).title(), 'danger' if f.get('severity') == 'high' else 'warning')}</td>
            <td>{_e(f.get('category', ''))}</td>
            <td>{_e(f.get('target', ''))}</td>
            <td>{_e(f.get('message', ''))}</td>
        </tr>"""
        for f in findings
    )
    if not finding_rows:
        finding_rows = '<tr><td colspan="4">No guardrail findings.</td></tr>'

    return f"""
    <section>
        <h2>Guardrail Checks</h2>
        <p class="section-help">
            <strong>Purpose:</strong> identifies risky recommendations that can inflate score while increasing policy risk. &nbsp;
            <strong>How to use:</strong> treat high severity findings as blockers and tighten scope before rollout.
        </p>
        <p>
            Total findings: <strong>{_e(guardrails.get('total_findings', 0))}</strong> &nbsp;|&nbsp;
            High severity: <strong>{_e(guardrails.get('high_severity', 0))}</strong> &nbsp;|&nbsp;
            Medium severity: <strong>{_e(guardrails.get('medium_severity', 0))}</strong>
        </p>
        <div class="filter-bar">
            <button class="filter-pill active" data-table-id="guardrails-table" data-filter-value="ALL" onclick="filterManagedTable('guardrails-table','ALL')">All</button>
            <button class="filter-pill" data-table-id="guardrails-table" data-filter-value="High" onclick="filterManagedTable('guardrails-table','High')">High</button>
            <button class="filter-pill" data-table-id="guardrails-table" data-filter-value="Medium" onclick="filterManagedTable('guardrails-table','Medium')">Medium</button>
        </div>
        <div class="table-toolbar">
            <div class="search-row">
                <input id="guardrails-table-search" class="search-input" type="search" placeholder="Search guardrail findings..." oninput="setManagedTableSearch('guardrails-table', this.value)">
            </div>
            <div class="pager-row">
                <label class="pager-label" for="guardrails-table-page-size">Rows per page</label>
                <select id="guardrails-table-page-size" class="pager-select" onchange="setManagedTablePageSize('guardrails-table', this.value)">
                    <option value="10" selected>10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                </select>
                <button id="guardrails-table-prev" class="pager-button" onclick="previousManagedTablePage('guardrails-table')">Previous</button>
                <button id="guardrails-table-next" class="pager-button" onclick="nextManagedTablePage('guardrails-table')">Next</button>
                <span id="guardrails-table-pager" class="pager-info"></span>
            </div>
        </div>
        <div class="table-wrap">
            <table id="guardrails-table">
                <thead>
                    <tr>
                        <th class="sortable-th" onclick="sortTable('guardrails-table', 0, 'text')">Severity <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('guardrails-table', 1, 'text')">Category <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('guardrails-table', 2, 'text')">Target <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('guardrails-table', 3, 'text')">Message <span class="sort-indicator"></span></th>
                    </tr>
                </thead>
                <tbody>{finding_rows}</tbody>
            </table>
        </div>
    </section>"""


def _render_backlog_dashboard(data: Dict) -> str:
    dashboard = data.get("backlog_delta_dashboard", {})
    if not dashboard:
        return ""

    buckets = dashboard.get("buckets", [])
    bucket_cards = "".join(
        f"""
        <div class="metric-card">
            <div class="metric-label">{_e(b.get('bucket', ''))}</div>
            <div class="metric-value">+{_e(b.get('projected_gain_percent', 0))}%</div>
            <div class="metric-desc">Projected Score: {_e(b.get('projected_score', 0))}%</div>
            <div class="metric-desc">{_e(b.get('description', ''))}</div>
        </div>"""
        for b in buckets
    )
    if not bucket_cards:
        bucket_cards = '<p>No backlog buckets available.</p>'

    return f"""
    <section>
        <h2>Backlog Delta Dashboard</h2>
        <p class="section-help">
            <strong>Purpose:</strong> bucket-level what-if impact for planning. &nbsp;
            <strong>How to use:</strong> choose the safest high-gain bucket to prioritize next sprint actions.
        </p>
        <p>Current score: <strong>{_e(dashboard.get('current_score', 0))}%</strong></p>
        <div class="metric-grid">{bucket_cards}</div>
    </section>"""


def _render_staged_workflow(data: Dict) -> str:
    workflow = data.get("staged_remediation_workflow", {})
    if not workflow:
        return ""

    def _render_text_list(items: List[Any]) -> str:
        if not items:
            return "<li>None</li>"
        return "".join(f"<li>{_e(item)}</li>" for item in items)

    canary = workflow.get("phase_1_canary", {})
    broad = workflow.get("phase_2_broad_rollout", {})
    validate = workflow.get("phase_3_validation_and_rollback", {})

    canary_actions = canary.get("actions", [])
    canary_html = "".join(
        f"<li>{_e(a.get('type', '')).replace('_', ' ').title()} - {_e(a.get('target', ''))}</li>"
        for a in canary_actions
    ) or "<li>No canary actions.</li>"

    broad_actions = broad.get("actions", [])
    broad_html = "".join(
        f"<li>{_e(a.get('type', '')).replace('_', ' ').title()} - {_e(a.get('target', ''))}</li>"
        for a in broad_actions
    ) or "<li>No broad-rollout actions.</li>"

    return f"""
    <section>
        <h2>Staged Remediation Workflow
            <button class="toggle-btn" onclick="toggle('staged-workflow-detail')">Show detail &#9660;</button>
        </h2>
        <p class="section-help">
            <strong>Purpose:</strong> operational rollout model with canary, broad deployment, and rollback logic. &nbsp;
            <strong>How to use:</strong> do not skip phase gates; pause rollout when rollback triggers are met.
        </p>
        <div id="staged-workflow-detail" class="collapsible">
            <div class="two-col">
                <div>
                    <h3>Phase 1: Canary</h3>
                    <p><strong>Scope:</strong> {_e(canary.get('policy_scope', ''))}</p>
                    <p><strong>Actions</strong></p>
                    <ul>{canary_html}</ul>
                    <p><strong>Exit Criteria</strong></p>
                    <ul>{_render_text_list(canary.get('exit_criteria', []))}</ul>
                </div>
                <div>
                    <h3>Phase 2: Broad Rollout</h3>
                    <p><strong>Scope:</strong> {_e(broad.get('policy_scope', ''))}</p>
                    <p><strong>Actions</strong></p>
                    <ul>{broad_html}</ul>
                    <p><strong>Gates</strong></p>
                    <ul>{_render_text_list(broad.get('gates', []))}</ul>
                </div>
            </div>
            <h3>Phase 3: Validation and Rollback</h3>
            <p><strong>Current High Severity Guardrails:</strong> {_e(validate.get('current_guardrail_high_severity', 0))}</p>
            <p><strong>Monitoring</strong></p>
            <ul>{_render_text_list(validate.get('monitoring', []))}</ul>
            <p><strong>Rollback Triggers</strong></p>
            <ul>{_render_text_list(validate.get('rollback_triggers', []))}</ul>
        </div>
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
        <p class="section-help">
            <strong>Purpose:</strong> file-level recommendations and rationale for manual triage. &nbsp;
            <strong>How to use:</strong> filter by decision type, resolve high-risk files first, and feed outcomes back into policy updates.
        </p>
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
                        <option value="10" selected>10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                    <button id="decision-prev-top" class="pager-button" onclick="previousDecisionPage()">Previous</button>
                    <button id="decision-next-top" class="pager-button" onclick="nextDecisionPage()">Next</button>
                    <span id="decision-pager-top" class="pager-info"></span>
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
                    <button id="decision-prev-bottom" class="pager-button" onclick="previousDecisionPage()">Previous</button>
                    <button id="decision-next-bottom" class="pager-button" onclick="nextDecisionPage()">Next</button>
                    <span id="decision-pager-bottom" class="pager-info"></span>
                </div>
            </div>
        </div>
    </section>"""


def _render_candidates(data: Dict) -> str:
    candidates = data.get("acceleration_candidates", [])
    if not candidates:
        return ""

    candidate_types = sorted({str(c.get('type', '')).replace('_', ' ').title() for c in candidates if c.get('type')})

    rows = "".join(f"""
        <tr data-candidate-type="{_e(str(c.get('type','').replace('_', ' ').title()))}">
            <td>{_e(c.get('target',''))}</td>
            <td>{_e(c.get('type','').replace('_', ' ').title())}</td>
            <td>{_e(c.get('files_to_approve', '—'))}</td>
            <td>{_e(c.get('readiness_gain_percent', '—'))}%</td>
            <td>{_e(c.get('confidence_percent', '—'))}%</td>
            <td>{_badge(c.get('priority','').title(), 'success' if c.get('priority') == 'high' else 'warning')}</td>
            <td class="path-cell">{_e(c.get('rationale',''))}</td>
        </tr>""" for c in candidates)

    return f"""
    <section>
        <h2>Top Acceleration Candidates</h2>
        <p class="section-help">
            <strong>Purpose:</strong> one-at-a-time approval simulations. &nbsp;
            <strong>How to use:</strong> compare candidates, but do not add gains across rows; use optimized plan for combined execution order.
        </p>
        <p>Each row simulates approving that candidate on its own, then recalculates readiness using the current scoring model.
           Gain values are independent per-row results and must not be added together. Confidence is still heuristic.</p>
        <div class="filter-bar">
            <button class="filter-pill active" data-table-id="candidates-table" data-filter-value="ALL" onclick="filterManagedTable('candidates-table','ALL')">All</button>
            {''.join(f'<button class="filter-pill" data-table-id="candidates-table" data-filter-value="{_e(t)}" onclick="filterManagedTable(\'candidates-table\',\'{_e(t)}\')">{_e(t)}</button>' for t in candidate_types)}
        </div>
        <div class="table-toolbar">
            <div class="search-row">
                <input id="candidates-table-search" class="search-input" type="search" placeholder="Search candidates..." oninput="setManagedTableSearch('candidates-table', this.value)">
            </div>
            <div class="pager-row">
                <label class="pager-label" for="candidates-table-page-size">Rows per page</label>
                <select id="candidates-table-page-size" class="pager-select" onchange="setManagedTablePageSize('candidates-table', this.value)">
                    <option value="10" selected>10</option>
                    <option value="25">25</option>
                    <option value="50">50</option>
                </select>
                <button id="candidates-table-prev" class="pager-button" onclick="previousManagedTablePage('candidates-table')">Previous</button>
                <button id="candidates-table-next" class="pager-button" onclick="nextManagedTablePage('candidates-table')">Next</button>
                <span id="candidates-table-pager" class="pager-info"></span>
            </div>
        </div>
        <div class="table-wrap">
            <table id="candidates-table">
                <thead>
                    <tr>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 0, 'text')">Target <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 1, 'text')">Action Type <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 2, 'number')">Files Approved <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 3, 'number')">Gain <span class="tip tip-below" data-tooltip="Actual percentage-point increase from the current readiness score after approving this candidate by itself. Gains are not additive across rows.">i</span> <span class="sort-indicator"></span></th>
                        <th class="sortable-th" onclick="sortTable('candidates-table', 4, 'number')">Confidence <span class="tip tip-below" data-tooltip="Heuristic confidence based on risk score, digital signature validity, certificate issuer trust, and file prevalence across endpoints. Not a guarantee of safety.">i</span> <span class="sort-indicator"></span></th>
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
    # Collect distinct rule types for filter pills
    rule_types = sorted({c.get('rule_type', '') for c in candidates if c.get('rule_type')})
    type_counts = {rt: sum(1 for c in candidates if c.get('rule_type') == rt) for rt in rule_types}
    total = len(candidates)

    pills = "".join(
        f'<button class="filter-pill" data-rule-type="{_e(rt)}" onclick="filterRules(\'{_e(rt)}\')">'
        f'{_e(rt)}: <strong>{type_counts[rt]}</strong></button>'
        for rt in rule_types
    )

    rows = "".join(f"""
        <tr data-rule-type="{_e(c.get('rule_type', ''))}" data-expanded="false">
            <td class="expand-cell"><button class="expand-btn" onclick="toggleSafetyChecks(this)" aria-expanded="false" title="Toggle recommendation details">&gt;</button></td>
            <td>{_e(c.get('rule_type', ''))}</td>
            <td>{_e(c.get('rule_name', ''))}</td>
            <td>{_e(c.get('process_pattern', ''))}</td>
            <td class="path-cell">{_e(c.get('file_pattern', ''))}</td>
            <td>{_e(c.get('operation', ''))}</td>
            <td>{_badge(c.get('action', 'Approve').title(), 'info')}</td>
            <td>{int(c.get('confidence', 0) * 100)}%</td>
            <td>{_e(c.get('readiness_gain_percent', '—'))}%</td>
            <td>{_e(c.get('source_event_count', 0))} files</td>
        </tr>
        <tr class="safety-checks-row" style="display: none;">
            <td colspan="10">
                <div class="safety-checks">
                    <strong>Safety Checks:</strong>
                    <ul>{"".join(f"<li>{_e(check)}</li>" for check in c.get('safety_checks', []))}</ul>
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
        <p class="section-help">
            <strong>Purpose:</strong> recurring rule candidates derived from event patterns. &nbsp;
            <strong>How to use:</strong> start with narrow rules and validate process, path, and user scope before expansion.
        </p>
        <p>{total:,} rule recommendations derived from unapproved file patterns. Sorted by files covered (highest first).</p>
        <div id="rules-detail" class="collapsible">
            <div class="filter-bar">
                <button class="filter-pill active" data-rule-type="ALL" onclick="filterRules('ALL')">All: <strong>{total}</strong></button>
                {pills}
            </div>
            <div class="table-toolbar">
                <div class="search-row">
                    <input id="rules-search" class="search-input" type="search" placeholder="Search rule name, file pattern, process..." oninput="searchRules(this.value)">
                </div>
                <div class="pager-row">
                    <label class="pager-label" for="rules-page-size">Rows per page</label>
                    <select id="rules-page-size" class="pager-select" onchange="setRulesPageSize(this.value)">
                        <option value="10" selected>10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                    <button id="rules-prev-top" class="pager-button" onclick="previousRulesPage()">Previous</button>
                    <button id="rules-next-top" class="pager-button" onclick="nextRulesPage()">Next</button>
                    <span id="rules-pager-top" class="pager-info"></span>
                </div>
            </div>
            <div class="table-wrap">
                <table id="rules-table">
                    <thead>
                        <tr>
                            <th style="width: 42px;"></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 1, 'text')">Rule Type <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 2, 'text')">Rule Name <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 3, 'text')">Process <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 4, 'text')">File Pattern <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 5, 'text')">Operation <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 6, 'text')">Action <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 7, 'number')">Confidence <span class="tip tip-below" data-tooltip="Rule confidence based on pattern consistency, digital signature data, and frequency of matched events. Higher values indicate stronger evidence the rule is safe to apply.">i</span> <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 8, 'number')">Gain <span class="tip tip-below" data-tooltip="Estimated percentage-point readiness gain if this rule reduces recurring unapproved activity. Based on source event count as a proxy for impacted files.">i</span> <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable('rules-table', 9, 'number')">Files <span class="sort-indicator"></span></th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            <div class="table-toolbar table-toolbar-bottom">
                <div class="pager-row pager-row-bottom">
                    <button id="rules-prev-bottom" class="pager-button" onclick="previousRulesPage()">Previous</button>
                    <button id="rules-next-bottom" class="pager-button" onclick="nextRulesPage()">Next</button>
                    <span id="rules-pager-bottom" class="pager-info"></span>
                </div>
            </div>
        </div>
    </section>"""


def _render_strategic_recommendations(data: Dict) -> str:
    strategic_recs = data.get("strategic_recommendations", {})
    if not strategic_recs:
        return ""

    rule_recommendations = strategic_recs.get("rule_recommendations", [])
    publisher_recommendations = strategic_recs.get("publisher_recommendations", [])
    strategic_roadmap = strategic_recs.get("strategic_roadmap", {})

    # Render rules table
    rule_rows = "".join(f"""
        <tr>
            <td>{_e(r.get('rule_type', ''))}</td>
            <td>{_e(r.get('rule_name', ''))}</td>
            <td class="path-cell">{_e(r.get('file_pattern', ''))}</td>
            <td>{r.get('estimated_files_covered', 0)}</td>
            <td>{_badge(r.get('priority', 'MEDIUM'), 'info')}</td>
            <td>{r.get('estimated_score_gain', 0):.1f}%</td>
            <td><details style="cursor:pointer"><summary>View</summary><p><strong>Rationale:</strong> {_e(r.get('rationale', ''))}</p><p><strong>Safety Checks:</strong></p><ul>{"".join(f"<li>{_e(check)}</li>" for check in r.get('safety_checks', []))}</ul><p><strong>Console Action:</strong></p><p><code>{_e(r.get('console_action', ''))}</code></p></details></td>
        </tr>""" for r in rule_recommendations)

    rule_total_gain = sum(r.get('estimated_score_gain', 0) for r in rule_recommendations)

    # Render publishers table
    pub_rows = "".join(f"""
        <tr>
            <td>{_e(p.get('publisher_name', ''))}</td>
            <td>{p.get('files_signed', 0)}</td>
            <td>{_badge(p.get('risk_level', 'MEDIUM'), 'warning')}</td>
            <td>{p.get('estimated_score_gain', 0):.1f}%</td>
            <td><details style="cursor:pointer"><summary>View</summary><p><strong>Rationale:</strong> {_e(p.get('rationale', ''))}</p><p><strong>Recommendation:</strong> {_e(p.get('recommendation', ''))}</p></details></td>
        </tr>""" for p in publisher_recommendations)

    pub_total_gain = sum(p.get('estimated_score_gain', 0) for p in publisher_recommendations)

    # Render roadmap steps
    roadmap_steps = ""
    for step in strategic_roadmap.get('steps', []):
        priority = step.get('priority', 0)
        action = _e(step.get('action', ''))
        details = _e(step.get('details', ''))
        gain = step.get('estimated_gain', 0)
        estimated_score = step.get('estimated_score', 0)
        effort = _e(step.get('effort', ''))
        risk = _e(step.get('risk', ''))
        console_steps = step.get('console_steps', [])
        
        console_html = "".join(f"<li><code>{_e(cs)}</code></li>" for cs in console_steps)
        
        roadmap_steps += f"""
        <div class="roadmap-step" style="margin-bottom: 25px; padding: 15px 15px 15px 20px; margin-left: 15px; border-left: 4px solid #0066cc; background: #f9f9f9;">
            <h4 style="margin: 0 0 10px 0;">Step {priority}: {action}</h4>
            <p><strong>Details:</strong> {details}</p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin: 10px 0;">
                <div><strong>Estimated Gain:</strong> {gain:.1f}%</div>
                <div><strong>Projected Score:</strong> {estimated_score:.1f}%</div>
                <div><strong>Effort:</strong> {effort}</div>
                <div><strong>Risk:</strong> {risk}</div>
            </div>
            <strong>Console Steps:</strong>
            <ol style="margin-left: 20px; margin-top: 8px;">{"".join(console_html)}</ol>
        </div>"""

    current_score = strategic_roadmap.get('current_score_pct', 0)
    target = strategic_roadmap.get('target_score', 80)
    gap = strategic_roadmap.get('gap', 0)
    achievable = strategic_roadmap.get('achievable_without_approvals', '')
    total_effort = strategic_roadmap.get('total_estimated_effort', '')
    success_criteria = strategic_roadmap.get('success_criteria', '')

    # Build recommendations tables
    rule_section = ""
    if rule_recommendations:
        rule_section = f"""
        <h3 style="margin-top: 40px; margin-bottom: 15px;">Trusted Path Rule Recommendations</h3>
        <p style="margin-bottom: 15px;">Create these batch-approval rules to significantly improve readiness. Total estimated gain: <strong>{rule_total_gain:.1f}%</strong></p>
        <div class="table-wrap">
            <table id="rules-recommendations-table">
                <thead>
                    <tr>
                        <th>Rule Type</th>
                        <th>Rule Name</th>
                        <th>File Pattern</th>
                        <th>Files Covered</th>
                        <th>Priority</th>
                        <th>Score Gain</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {rule_rows}
                </tbody>
            </table>
        </div>"""

    pub_section = ""
    if publisher_recommendations:
        pub_section = f"""
        <h3 style="margin-top: 40px; margin-bottom: 15px;">Publisher Trust Recommendations</h3>
        <p style="margin-bottom: 15px;">Trust these publishers to bulk-approve all their current and future files. Total estimated gain: <strong>{pub_total_gain:.1f}%</strong></p>
        <div class="table-wrap">
            <table id="publishers-recommendations-table">
                <thead>
                    <tr>
                        <th>Publisher</th>
                        <th>Files Signed</th>
                        <th>Risk Level</th>
                        <th>Score Gain</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    {pub_rows}
                </tbody>
            </table>
        </div>"""

    return f"""
    <section>
        <h2>Strategic Recommendations
            <button class="toggle-btn" onclick="toggle('strategic-recs-detail')">Show detail &#9660;</button>
        </h2>
        <p class="section-help">
            <strong>Purpose:</strong> prioritized roadmap and specific actions to reach enforcement readiness targets. &nbsp;
            <strong>How to use:</strong> execute steps in order, starting with high-impact rules and publisher approvals.
        </p>
        
        <div class="roadmap-summary" style="padding: 15px; background: #f0f8ff; border-radius: 4px; margin-bottom: 30px;">
            <h3 style="margin-top: 0; margin-bottom: 15px;">Readiness Roadmap</h3>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                <div><strong>Current Score:</strong> {current_score:.1f}%</div>
                <div><strong>Target Score:</strong> {target:.0f}%</div>
                <div><strong>Gap:</strong> {gap:.1f}%</div>
            </div>
            <div style="background: white; padding: 10px; border-radius: 3px; margin-bottom: 10px;">
                <strong>Achievable with Rules + Publisher Actions:</strong> {_e(achievable)}
            </div>
            <div style="background: white; padding: 10px; border-radius: 3px;">
                <strong>Total Estimated Effort:</strong> {_e(total_effort)}<br>
                <strong>Success Criteria:</strong> {_e(success_criteria)}
            </div>
        </div>

        <div id="strategic-recs-detail" class="collapsible">
        <h3 style="margin-bottom: 20px;">Step-by-Step Roadmap</h3>
        {roadmap_steps}

        {rule_section}
        {pub_section}
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
        <p class="section-help">
            <strong>Purpose:</strong> backlog of items where automation should not decide approval. &nbsp;
            <strong>How to use:</strong> treat this as a mandatory analyst queue before increasing enforcement mode.
        </p>
        <div class="risk-grid">{cards}</div>
    </section>"""


def _render_tabbed_report(groups: List[Dict[str, Any]]) -> str:
    available_groups = []
    for group in groups:
        sections = [section for section in group.get("sections", []) if section]
        if not sections:
            continue
        available_groups.append({
            "id": group["id"],
            "title": group["title"],
            "description": group["description"],
            "sections": sections,
        })

    if not available_groups:
        return ""

    buttons = []
    panels = []
    for index, group in enumerate(available_groups):
        panel_id = f"report-tab-{group['id']}"
        button_id = f"report-tab-btn-{group['id']}"
        is_active = index == 0
        active_class = " is-active" if is_active else ""
        selected = "true" if is_active else "false"
        hidden = "" if is_active else " hidden"

        buttons.append(f"""
        <button
            id="{button_id}"
            class="report-tab-btn{active_class}"
            type="button"
            role="tab"
            aria-selected="{selected}"
            aria-controls="{panel_id}"
            data-tab-target="{panel_id}"
            onclick="showReportTab('{panel_id}', this)">
            <span class="report-tab-btn-title">{_e(group['title'])}</span>
            <span class="report-tab-btn-meta">{len(group['sections'])} sections</span>
        </button>""")

        panels.append(f"""
        <div
            id="{panel_id}"
            class="report-tab-panel{active_class}"
            role="tabpanel"
            aria-labelledby="{button_id}"{hidden}>
            {''.join(group['sections'])}
        </div>""")

    return f"""
    <div class="report-shell">
        <aside class="report-nav">
            <div class="report-tab-list" role="tablist" aria-label="Report views">
                {''.join(buttons)}
            </div>
        </aside>
        <div class="report-tab-panels">
            {''.join(panels)}
        </div>
    </div>"""


# ---------------------------------------------------------------------------
# CSS and JS
# ---------------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: #f4f6f9; color: #2c3e50; margin: 0; padding: 0; }
.page-wrap { max-width: none; margin: 0; padding: 16px 14px 24px; }
.page-header { background: #1a2b45; color: #fff; border-radius: 10px; padding: 24px 28px; margin-bottom: 24px; }
.page-header h1 { margin: 0 0 6px; font-size: 1.35rem; font-weight: 700; }
.page-header .subtitle { font-size: 0.9rem; opacity: 0.8; }
.hero {
    background: linear-gradient(135deg, #ffffff 0%, #f4f7fb 100%);
    border: 1px solid #dbe4ee;
    border-radius: 16px;
    padding: 20px 22px;
    margin-bottom: 18px;
    box-shadow: 0 4px 18px rgba(26, 43, 69, 0.06);
}
.hero-score { font-size: 3.2rem; font-weight: 800; line-height: 1; letter-spacing: -0.04em; margin-bottom: 6px; }
.hero-pct { font-size: 2.5rem; vertical-align: super; }
.hero-label { display: flex; align-items: center; gap: 8px; font-size: 0.98rem; font-weight: 400; margin-bottom: 8px; }
.hero-status {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 7px 12px;
    font-size: 0.88rem;
    font-weight: 700;
    margin-bottom: 14px;
}
.status-not-ready { background: #fdeaea; color: #9b2c2c; }
.status-ready     { background: #d4edda; color: #155724; }
.hero-rec { font-size: 0.98rem; margin: 0 0 14px; line-height: 1.45; }
.hero-meta { font-size: 0.92rem; color: #415266; margin-top: 12px; }

/* Report tabs */
.report-shell { display: grid; grid-template-columns: 210px minmax(0, 1fr); gap: 16px; align-items: start; }
.report-nav {
    position: sticky;
    top: 16px;
    background: linear-gradient(180deg, #eef3f8 0%, #e6edf5 100%);
    border: 1px solid #d7e1ec;
    border-radius: 12px;
    padding: 12px;
}
.report-nav-header h2 { margin: 0 0 6px; font-size: 1rem; }
.report-nav-header p { margin: 0; color: #52606d; font-size: 0.82rem; line-height: 1.35; }
.report-nav-kicker, .report-tab-kicker {
    margin: 0 0 6px;
    color: #6b7785;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}
.report-tab-list { display: flex; flex-direction: column; gap: 8px; margin-top: 12px; }
.report-tab-btn {
    width: 100%;
    border: 1px solid #d5dee8;
    border-radius: 10px;
    background: #fff;
    color: #1f2d3d;
    cursor: pointer;
    text-align: left;
    padding: 10px 11px 9px;
    transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}
.report-tab-btn:hover { transform: translateY(-1px); box-shadow: 0 6px 18px rgba(26, 43, 69, 0.08); }
.report-tab-btn.is-active {
    background: #1a2b45;
    color: #fff;
    border-color: #1a2b45;
    box-shadow: 0 8px 18px rgba(26, 43, 69, 0.15);
}
.report-tab-btn-title { display: block; font-size: 0.86rem; font-weight: 700; margin-bottom: 2px; }
.report-tab-btn-meta { display: block; font-size: 0.72rem; opacity: 0.78; }
.report-tab-panels { min-width: 0; }
.report-tab-panel { display: none; }
.report-tab-panel.is-active { display: block; }

/* Sections */
section { background: #fff; border-radius: 10px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
section h2 { font-size: 1.15rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 12px; }
section h3 { font-size: 1rem; font-weight: 600; margin: 16px 0 8px; }
.section-help {
    font-size: 0.86rem;
    color: #495057;
    background: #f8f9fa;
    border-left: 4px solid #1a2b45;
    border-radius: 4px;
    padding: 8px 12px;
    margin: 0 0 12px 0;
}

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

/* Tooltips */
.tip {
    display: inline-flex; align-items: center; justify-content: center;
    width: 15px; height: 15px; border-radius: 50%;
    background: #6c757d; color: #fff;
    font-size: 0.65rem; font-weight: 700; font-style: normal;
    cursor: help; vertical-align: middle; position: relative;
    margin-left: 5px; flex-shrink: 0;
}
.tip::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: calc(100% + 7px);
    left: 50%; transform: translateX(-50%);
    background: #2c3e50; color: #fff;
    padding: 8px 12px; border-radius: 6px;
    font-size: 0.78rem; font-weight: 400; line-height: 1.45;
    white-space: normal; width: 260px;
    pointer-events: none; opacity: 0;
    transition: opacity 0.15s; z-index: 200; text-align: left;
}
.tip::before {
    content: '';
    position: absolute;
    bottom: calc(100% + 2px);
    left: 50%; transform: translateX(-50%);
    border: 5px solid transparent;
    border-top-color: #2c3e50;
    pointer-events: none; opacity: 0;
    transition: opacity 0.15s; z-index: 200;
}
.tip:hover::after, .tip:hover::before { opacity: 1; }
/* Tooltip pointing downward — use in table headers to avoid being clipped by elements above */
.tip-below::after {
    bottom: auto;
    top: calc(100% + 7px);
}
.tip-below::before {
    bottom: auto;
    top: calc(100% + 2px);
    border-top-color: transparent;
    border-bottom-color: #2c3e50;
}

/* Rule Suggestions */
.expand-cell { width: 42px; text-align: center; }
.expand-btn {
    display: inline-block;
    width: 24px;
    height: 24px;
    border: 1px solid #ced4da;
    border-radius: 4px;
    background: #fff;
    color: #1a2b45;
    cursor: pointer;
    font-weight: 700;
    font-size: 0.95rem;
    line-height: 22px;
    padding: 0;
}
.expand-btn:hover { background: #f0f2f5; }
.safety-checks-row { background: #f8f9fa; border-top: 1px solid #dee2e6; }
.safety-checks { padding: 12px 0; }
.safety-checks strong { display: block; margin-top: 10px; margin-bottom: 6px; color: #2c3e50; }
.safety-checks ul { margin: 0 0 8px 20px; padding: 0; }
.safety-checks li { margin-bottom: 4px; font-size: 0.9rem; color: #495057; }
.safety-checks p { margin: 6px 0; font-size: 0.9rem; color: #495057; }

@media (max-width: 900px) {
    .report-shell { grid-template-columns: 1fr; }
    .report-nav { position: static; }
    .report-tab-list { flex-direction: row; overflow-x: auto; padding-bottom: 4px; }
    .report-tab-btn { min-width: 170px; flex: 0 0 auto; }
}
"""

_JS = """
var currentDecisionFilter = 'ALL';
var currentDecisionSearch = '';
var currentDecisionPage = 1;
var currentDecisionPageSize = 10;
var tableSortState = {};
var managedTables = {};

function registerManagedTable(tableId, options) {
    managedTables[tableId] = {
        filterAttr: options.filterAttr || '',
        filter: 'ALL',
        search: '',
        page: 1,
        pageSize: options.pageSize || 10,
        pagerInfoId: options.pagerInfoId || '',
        prevButtonId: options.prevButtonId || '',
        nextButtonId: options.nextButtonId || ''
    };
}

function setManagedTableSearch(tableId, term) {
    if (!managedTables[tableId]) {
        return;
    }
    managedTables[tableId].search = term || '';
    managedTables[tableId].page = 1;
    applyManagedTableState(tableId);
}

function setManagedTablePageSize(tableId, value) {
    if (!managedTables[tableId]) {
        return;
    }
    managedTables[tableId].pageSize = parseInt(value, 10) || 10;
    managedTables[tableId].page = 1;
    applyManagedTableState(tableId);
}

function filterManagedTable(tableId, filterValue) {
    if (!managedTables[tableId]) {
        return;
    }
    managedTables[tableId].filter = filterValue;
    managedTables[tableId].page = 1;

    document.querySelectorAll('.filter-pill[data-table-id="' + tableId + '"]').forEach(function(pill) {
        pill.classList.toggle('active', pill.getAttribute('data-filter-value') === filterValue);
    });

    applyManagedTableState(tableId);
}

function previousManagedTablePage(tableId) {
    if (!managedTables[tableId]) {
        return;
    }
    if (managedTables[tableId].page > 1) {
        managedTables[tableId].page -= 1;
        applyManagedTableState(tableId);
    }
}

function nextManagedTablePage(tableId) {
    if (!managedTables[tableId]) {
        return;
    }
    var state = managedTables[tableId];
    var totalPages = getManagedTableTotalPages(tableId);
    if (state.page < totalPages) {
        state.page += 1;
        applyManagedTableState(tableId);
    }
}

function getManagedFilteredRows(tableId) {
    var state = managedTables[tableId];
    if (!state) {
        return [];
    }

    var rows = Array.from(document.querySelectorAll('#' + tableId + ' tbody tr'));
    return rows.filter(function(row) {
        var matchesFilter = true;
        if (state.filter !== 'ALL' && state.filterAttr) {
            matchesFilter = row.dataset[state.filterAttr] === state.filter;
        }
        var matchesSearch = !state.search || row.textContent.toLowerCase().indexOf(state.search.toLowerCase()) >= 0;
        return matchesFilter && matchesSearch;
    });
}

function getManagedTableTotalPages(tableId) {
    var state = managedTables[tableId];
    if (!state) {
        return 1;
    }
    var count = getManagedFilteredRows(tableId).length;
    return Math.max(1, Math.ceil(count / state.pageSize));
}

function applyManagedTableState(tableId, resetPage) {
    var state = managedTables[tableId];
    if (!state) {
        return;
    }

    if (resetPage === true) {
        state.page = 1;
    }

    var rows = Array.from(document.querySelectorAll('#' + tableId + ' tbody tr'));
    var filtered = getManagedFilteredRows(tableId);
    var totalPages = Math.max(1, Math.ceil(filtered.length / state.pageSize));
    if (state.page > totalPages) {
        state.page = totalPages;
    }

    var start = (state.page - 1) * state.pageSize;
    var end = start + state.pageSize;

    rows.forEach(function(row) {
        row.style.display = 'none';
    });

    filtered.slice(start, end).forEach(function(row) {
        row.style.display = '';
    });

    var infoText = filtered.length === 0
        ? 'No matching rows'
        : 'Page ' + state.page + ' of ' + totalPages + ' (' + filtered.length + ' matching rows)';

    var infoEl = document.getElementById(state.pagerInfoId);
    if (infoEl) {
        infoEl.textContent = infoText;
    }

    var prevEl = document.getElementById(state.prevButtonId);
    if (prevEl) {
        prevEl.disabled = state.page <= 1 || filtered.length === 0;
    }
    var nextEl = document.getElementById(state.nextButtonId);
    if (nextEl) {
        nextEl.disabled = state.page >= totalPages || filtered.length === 0;
    }
}

function toggle(id) {
    var el = document.getElementById(id);
    if (!el) {
        return;
    }
    var section = el.closest('section');
    var btn = section ? section.querySelector('.toggle-btn') : null;
    if (el.style.display === 'block') {
        el.style.display = 'none';
        if (btn) {
            btn.innerHTML = 'Show detail &#9660;';
        }
    } else {
        el.style.display = 'block';
        if (btn) {
            btn.innerHTML = 'Hide detail &#9650;';
        }
    }
}

function showReportTab(tabId, buttonEl) {
    var buttons = document.querySelectorAll('.report-tab-btn');
    var panels = document.querySelectorAll('.report-tab-panel');

    buttons.forEach(function(button) {
        var isActive = button.dataset.tabTarget === tabId;
        button.classList.toggle('is-active', isActive);
        button.setAttribute('aria-selected', isActive ? 'true' : 'false');
    });

    panels.forEach(function(panel) {
        var isActive = panel.id === tabId;
        panel.classList.toggle('is-active', isActive);
        panel.hidden = !isActive;
    });

    if (window.location.hash !== '#' + tabId) {
        history.replaceState(null, '', '#' + tabId);
    }
}

function filterTable(decision) {
    currentDecisionFilter = decision;
    document.querySelectorAll('.filter-pill[data-decision]').forEach(function(pill) {
        pill.classList.toggle('active', pill.getAttribute('data-decision') === decision);
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

    ['decision-pager-top', 'decision-pager-bottom'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.textContent = infoText;
    });
    ['decision-prev-top', 'decision-prev-bottom'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.disabled = currentDecisionPage <= 1 || filtered.length === 0;
    });
    ['decision-next-top', 'decision-next-bottom'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.disabled = currentDecisionPage >= totalPages || filtered.length === 0;
    });
}

function sortTable(tableId, columnIndex, sortType) {
    var table = document.getElementById(tableId);
    if (!table) {
        return;
    }

    var tbody = table.querySelector('tbody');
    var state = tableSortState[tableId] || { column: -1, direction: 'asc' };
    var direction = (state.column === columnIndex && state.direction === 'asc') ? 'desc' : 'asc';

    var sortByValue = function(leftValue, rightValue) {

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
    };

    if (tableId === 'rules-table') {
        var dataRows = Array.from(tbody.querySelectorAll('tr:not(.safety-checks-row)'));
        var pairs = dataRows.map(function(row) {
            var detailRow = row.nextElementSibling;
            if (!detailRow || !detailRow.classList.contains('safety-checks-row')) {
                detailRow = null;
            }
            return { data: row, detail: detailRow };
        });

        pairs.sort(function(leftPair, rightPair) {
            var leftValue = (leftPair.data.cells[columnIndex] || {}).textContent || '';
            var rightValue = (rightPair.data.cells[columnIndex] || {}).textContent || '';
            return sortByValue(leftValue, rightValue);
        });

        pairs.forEach(function(pair) {
            tbody.appendChild(pair.data);
            if (pair.detail) {
                tbody.appendChild(pair.detail);
            }
        });
    } else {
        var rows = Array.from(tbody.querySelectorAll('tr'));
        rows.sort(function(leftRow, rightRow) {
            var leftValue = (leftRow.cells[columnIndex] || {}).textContent || '';
            var rightValue = (rightRow.cells[columnIndex] || {}).textContent || '';
            return sortByValue(leftValue, rightValue);
        });

        rows.forEach(function(row) {
            tbody.appendChild(row);
        });
    }

    tableSortState[tableId] = { column: columnIndex, direction: direction, type: sortType };
    updateSortIndicators(tableId);

    if (tableId === 'decisions-table') {
        applyDecisionTableState(true);
    }
    if (tableId === 'rules-table') {
        applyRulesTableState(true);
    }
    if (managedTables[tableId]) {
        applyManagedTableState(tableId);
    }
}

function updateSortIndicators(tableId) {
    var table = document.getElementById(tableId);
    if (!table) {
        return;
    }

    var state = tableSortState[tableId] || { column: -1, direction: 'asc' };
    table.querySelectorAll('th.sortable-th').forEach(function(header) {
        var indicator = header.querySelector('.sort-indicator');
        if (!indicator) {
            return;
        }
        var columnIndex = Array.from(header.parentElement.children).indexOf(header);
        if (columnIndex === state.column) {
            indicator.textContent = state.direction === 'asc' ? '▲' : '▼';
        } else {
            indicator.textContent = '';
        }
    });
}

document.addEventListener('DOMContentLoaded', function() {
    sortTable('decisions-table', 0, 'text');
    sortTable('candidates-table', 0, 'text');
    sortTable('rules-table', 9, 'number');
    sortTable('optimized-table', 4, 'number');
    sortTable('guardrails-table', 0, 'text');
    sortTable('audit-inputs-table', 0, 'text');
    sortTable('audit-publisher-table', 0, 'text');

    registerManagedTable('candidates-table', {
        filterAttr: 'candidateType',
        pageSize: 10,
        pagerInfoId: 'candidates-table-pager',
        prevButtonId: 'candidates-table-prev',
        nextButtonId: 'candidates-table-next'
    });
    registerManagedTable('optimized-table', {
        filterAttr: 'actionType',
        pageSize: 5,
        pagerInfoId: 'optimized-table-pager',
        prevButtonId: 'optimized-table-prev',
        nextButtonId: 'optimized-table-next'
    });
    registerManagedTable('guardrails-table', {
        filterAttr: 'severity',
        pageSize: 10,
        pagerInfoId: 'guardrails-table-pager',
        prevButtonId: 'guardrails-table-prev',
        nextButtonId: 'guardrails-table-next'
    });
    registerManagedTable('audit-inputs-table', {
        filterAttr: 'valueState',
        pageSize: 5,
        pagerInfoId: 'audit-inputs-pager',
        prevButtonId: 'audit-inputs-prev',
        nextButtonId: 'audit-inputs-next'
    });
    registerManagedTable('audit-publisher-table', {
        filterAttr: 'valueState',
        pageSize: 5,
        pagerInfoId: 'audit-publisher-pager',
        prevButtonId: 'audit-publisher-prev',
        nextButtonId: 'audit-publisher-next'
    });

    applyDecisionTableState(true);
    applyRulesTableState(true);

    var requestedTab = window.location.hash ? window.location.hash.slice(1) : '';
    var firstTab = document.querySelector('.report-tab-btn');
    if (requestedTab && !document.getElementById(requestedTab)) {
        requestedTab = '';
    }
    if (!requestedTab && firstTab) {
        requestedTab = firstTab.dataset.tabTarget || '';
    }
    if (requestedTab) {
        showReportTab(requestedTab);
    }
});

// ---- Rules table state ----
var currentRulesFilter = 'ALL';
var currentRulesSearch = '';
var currentRulesPage = 1;
var currentRulesPageSize = 10;

function filterRules(ruleType) {
    currentRulesFilter = ruleType;
    document.querySelectorAll('.filter-pill[data-rule-type]').forEach(function(pill) {
        pill.classList.toggle('active', pill.getAttribute('data-rule-type') === ruleType || ruleType === 'ALL');
    });
    currentRulesPage = 1;
    applyRulesTableState();
}

function searchRules(term) {
    currentRulesSearch = term || '';
    currentRulesPage = 1;
    applyRulesTableState();
}

function setRulesPageSize(value) {
    currentRulesPageSize = parseInt(value, 10) || 25;
    currentRulesPage = 1;
    applyRulesTableState();
}

function previousRulesPage() {
    if (currentRulesPage > 1) {
        currentRulesPage -= 1;
        applyRulesTableState(false);
    }
}

function nextRulesPage() {
    var totalPages = Math.max(1, Math.ceil(getRulesFilteredRows().length / currentRulesPageSize));
    if (currentRulesPage < totalPages) {
        currentRulesPage += 1;
        applyRulesTableState(false);
    }
}

function getRulesFilteredRows() {
    // Only data rows (not expansion rows)
    return Array.from(document.querySelectorAll('#rules-table tbody tr:not(.safety-checks-row)')).filter(function(row) {
        var matchesType = currentRulesFilter === 'ALL' || row.dataset.ruleType === currentRulesFilter;
        var matchesSearch = !currentRulesSearch || row.textContent.toLowerCase().indexOf(currentRulesSearch.toLowerCase()) >= 0;
        return matchesType && matchesSearch;
    });
}

function applyRulesTableState(resetPage) {
    var table = document.getElementById('rules-table');
    if (!table) return;
    if (resetPage === true) currentRulesPage = 1;

    var allDataRows = Array.from(document.querySelectorAll('#rules-table tbody tr:not(.safety-checks-row)'));

    allDataRows.forEach(function(row) {
        row.style.display = 'none';
        var safetyRow = row.nextElementSibling;
        if (safetyRow && safetyRow.classList.contains('safety-checks-row')) {
            safetyRow.style.display = 'none';
        }
    });

    var filtered = getRulesFilteredRows();
    var totalPages = Math.max(1, Math.ceil(filtered.length / currentRulesPageSize));
    if (currentRulesPage > totalPages) currentRulesPage = totalPages;

    var start = (currentRulesPage - 1) * currentRulesPageSize;
    filtered.slice(start, start + currentRulesPageSize).forEach(function(row) {
        row.style.display = '';
        var safetyRow = row.nextElementSibling;
        var btn = row.querySelector('.expand-btn');
        var expanded = row.dataset.expanded === 'true';

        if (btn) {
            btn.textContent = expanded ? 'v' : '>';
            btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        }
        if (safetyRow && safetyRow.classList.contains('safety-checks-row')) {
            safetyRow.style.display = expanded ? 'table-row' : 'none';
        }
    });

    var infoText = filtered.length === 0
        ? 'No matching rules'
        : 'Page ' + currentRulesPage + ' of ' + totalPages + ' (' + filtered.length + ' matching rules)';

    ['rules-pager-top', 'rules-pager-bottom'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.textContent = infoText;
    });
    ['rules-prev-top', 'rules-prev-bottom'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.disabled = currentRulesPage <= 1 || filtered.length === 0;
    });
    ['rules-next-top', 'rules-next-bottom'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.disabled = currentRulesPage >= totalPages || filtered.length === 0;
    });
}

function toggleSafetyChecks(btn) {
    var row = btn.closest('tr');
    if (!row) {
        return;
    }

    var safetyRow = row.nextElementSibling;
    if (!safetyRow || !safetyRow.classList.contains('safety-checks-row')) {
        return;
    }

    var isExpanded = row.dataset.expanded === 'true';
    var nextExpanded = !isExpanded;
    row.dataset.expanded = nextExpanded ? 'true' : 'false';

    btn.textContent = nextExpanded ? 'v' : '>';
    btn.setAttribute('aria-expanded', nextExpanded ? 'true' : 'false');

    if (row.style.display !== 'none') {
        safetyRow.style.display = nextExpanded ? 'table-row' : 'none';
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


def _render_certificate_portfolio(data: Dict) -> str:
    """Render certificate portfolio optimization section."""
    cert_analysis = data.get('certificate_portfolio_analysis', {})
    if not cert_analysis or not cert_analysis.get('top_certificates'):
        return ""
    
    certs = cert_analysis.get('top_certificates', [])
    rows = "".join(f"""
        <tr>
            <td>{_e(c.get('certificate_id', ''))}</td>
            <td class="path-cell">{_e(c.get('issuer', 'Unknown')[:60])}</td>
            <td>{_e(c.get('files_covered', '0'))}</td>
            <td>{_e(c.get('affected_computers', '0'))}</td>
            <td>{_badge('Valid' if c.get('valid_signature') else 'Invalid', 'success' if c.get('valid_signature') else 'danger')}</td>
            <td>{_e(c.get('projected_score_gain', '0'))}%</td>
            <td>{_badge('No Flags' if not c.get('risk_flags') else 'Review', 'info')}</td>
        </tr>""" for c in certs)
    
    return f"""
    <section>
        <h2>Certificate Portfolio Optimizer
            <button class="toggle-btn" onclick="toggle('cert-portfolio-detail')">Show detail &#9660;</button>
        </h2>
        <p class="section-help">
            <strong>Purpose:</strong> identify top certificates to whitelist for maximum file coverage with minimal scope risk. &nbsp;
            <strong>How to use:</strong> review top certificates, apply guardrails, and add safe ones to policy.
        </p>
        <div id="cert-portfolio-detail" class="collapsible">
            <p><strong>Potential Score Gain:</strong> {_e(cert_analysis.get('total_potential_gain', '0'))}% | <strong>Guardrail Violations Detected:</strong> {_e(cert_analysis.get('violations_detected', '0'))}</p>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 0, 'number')">Certificate ID <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 1, 'text')">Issuer <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 2, 'number')">Files Covered <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 3, 'number')">Affected Computers <span class="sort-indicator"></span></th>
                            <th>Valid Signature</th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 5, 'number')">Score Gain <span class="sort-indicator"></span></th>
                            <th>Risk Assessment</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </section>"""


def _render_policy_scope(data: Dict) -> str:
    """Render policy scope simulation section."""
    scope_analysis = data.get('policy_scope_analysis', {})
    if not scope_analysis or not scope_analysis.get('scoped_candidates'):
        return ""
    
    candidates = scope_analysis.get('scoped_candidates', [])
    rows = "".join(f"""
        <tr>
            <td>{_e(c.get('rule_id', ''))}</td>
            <td>{_e(c.get('affected_files', '0'))}</td>
            <td>{_e(c.get('affected_computers', '0'))}</td>
            <td>{_badge(c.get('risk_reduction', '0%'), 'success')}</td>
            <td>{_e(c.get('projected_score_gain', '0'))}%</td>
        </tr>""" for c in candidates)
    
    return f"""
    <section>
        <h2>Policy Scope Simulation
            <button class="toggle-btn" onclick="toggle('policy-scope-detail')">Show detail &#9660;</button>
        </h2>
        <p class="section-help">
            <strong>Purpose:</strong> unlock high-impact approvals by scoping them to pilot computers instead of global. &nbsp;
            <strong>How to use:</strong> test scoped rules on pilot fleet before broad deployment.
        </p>
        <div id="policy-scope-detail" class="collapsible">
            <p><strong>Unlock Potential:</strong> {_e(scope_analysis.get('unlock_potential', '0'))}% additional score gain</p>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Rule ID</th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 1, 'number')">Files Affected <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 2, 'number')">Pilot Computers <span class="sort-indicator"></span></th>
                            <th>Risk Reduction</th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 4, 'number')">Score Gain <span class="sort-indicator"></span></th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </section>"""


def _render_recurring_events(data: Dict) -> str:
    """Render recurring event auto-packaging section."""
    event_analysis = data.get('recurring_event_analysis', {})
    if not event_analysis or not event_analysis.get('suggested_rules'):
        return ""
    
    rules = event_analysis.get('suggested_rules', [])
    rows = "".join(f"""
        <tr>
            <td>{_e(r.get('process_name', 'unknown')[:40])}</td>
            <td class="path-cell">{_e(r.get('file_path', 'N/A')[:60])}</td>
            <td>{_e(r.get('occurrences', '0'))}</td>
            <td>{_e(r.get('coverage_percent', '0'))}%</td>
            <td>{_e(r.get('estimated_reduction', '0'))}</td>
        </tr>""" for r in rules)
    
    return f"""
    <section>
        <h2>Recurring Event Auto-Packaging
            <button class="toggle-btn" onclick="toggle('recurring-events-detail')">Show detail &#9660;</button>
        </h2>
        <p class="section-help">
            <strong>Purpose:</strong> pre-approve high-frequency process/path clusters to cut unknown churn. &nbsp;
            <strong>How to use:</strong> convert suggested rules into file-creation control policies for next scoring cycle.
        </p>
        <div id="recurring-events-detail" class="collapsible">
            <p><strong>Estimated Unknown Reduction:</strong> {_e(event_analysis.get('unknown_reduction', '0'))} files</p>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 0, 'text')">Process <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 1, 'text')">File Path <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 2, 'number')">Occurrences <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 3, 'number')">Coverage <span class="sort-indicator"></span></th>
                            <th class="sortable-th" onclick="sortTable(this.parentElement.parentElement.parentElement, 4, 'number')">Reduction <span class="sort-indicator"></span></th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
        </div>
    </section>"""


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

    sampling_banner = _render_sampling_banner(data)
    hero = _render_hero(data)
    key_metrics = _render_key_metrics(data)
    score_audit = _render_score_audit(data)
    llm_section = _render_llm_section(data)
    score_breakdown = _render_score_breakdown(data)
    optimized_plan = _render_optimized_plan(data)
    guardrails = _render_guardrails(data)
    strategic_recommendations = _render_strategic_recommendations(data)
    backlog_dashboard = _render_backlog_dashboard(data)
    staged_workflow = _render_staged_workflow(data)
    certificate_portfolio = _render_certificate_portfolio(data)
    policy_scope = _render_policy_scope(data)
    recurring_events = _render_recurring_events(data)
    decisions_table = _render_decisions_table(data)
    rule_suggestions = _render_rule_suggestions(data)
    candidates = _render_candidates(data)
    risks = _render_risks(data)

    tabbed_report = _render_tabbed_report([
        {
            "id": "overview",
            "title": "Overview",
            "description": "Current posture, inventory baseline, scoring inputs, and the high-level narrative for this run.",
            "sections": [key_metrics, llm_section, score_breakdown, score_audit],
        },
        {
            "id": "action-plan",
            "title": "Action Plan",
            "description": "Prioritized rollout guidance to move the score with the least waste and the clearest operational sequence.",
            "sections": [optimized_plan, strategic_recommendations, backlog_dashboard, staged_workflow],
        },
        {
            "id": "approvals",
            "title": "Approvals",
            "description": "Execution views for file decisions, recurring rule creation, and approval candidates.",
            "sections": [decisions_table, rule_suggestions, candidates],
        },
        {
            "id": "controls",
            "title": "Controls and Risk",
            "description": "Guardrails, manual review backlog, and scope-tuning tools to keep readiness gains from creating policy debt.",
            "sections": [guardrails, certificate_portfolio, policy_scope, recurring_events, risks],
        },
    ])

    body = "\n".join([
        sampling_banner,
        hero,
        tabbed_report,
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
