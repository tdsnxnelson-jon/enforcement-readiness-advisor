# Enforcement Readiness Advisor - Main Entry Point
"""
Main entry point for the Enforcement Readiness Advisor.

Usage:
    python main.py --server <cb_server> --token <api_token>
"""

import argparse
import json
import logging
import sys
import fnmatch
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

# Add project root to path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_collection.api_client import CBApiClient
from data_collection.collectors import EnforcementReadinessCollector
from analysis.trust_signals import TrustSignalAnalyzer, EnforcementReadinessScorer
from analysis.path_analysis import PathClassifier, InstallerLineageAnalyzer
from analysis.approval_workflow import ApprovalWorkflowAnalyzer
from analysis.strategic_recommendations import StrategicRecommendationEngine
from report.html_report import generate_html_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


DEFAULT_ENDPOINT_READINESS_CONFIG: Dict[str, Any] = {
    'lookback_days': 7,
    'min_ready_score': 80.0,
    'near_ready_score': 60.0,
    'max_block_events': 0,
    'max_unapproved_events': 3,
    'unapproved_penalty': 3.0,
    'block_penalty': 5.0,
    'recent_penalty': 4.0,
    'max_unapproved_penalty': 60.0,
    'max_block_penalty': 25.0,
    'max_recent_penalty': 20.0,
}


def build_score_audit(summary: Dict[str, Any], readiness: Dict[str, Any], publisher_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Capture scoring inputs and detect contradictory readiness signals."""
    warnings: List[str] = []
    publisher_score = readiness.get('breakdown', {}).get('publisher_trust', 0.0)
    trusted_total = int(summary.get('trusted_publisher_count', 0) or 0)
    blocked_total = int(summary.get('blocked_publisher_count', 0) or 0)
    unknown_count = int(summary.get('unknown_count', 0) or 0)
    approved_count = int(summary.get('approved_count', 0) or 0)

    # Check file catalog consistency
    if unknown_count == approved_count and unknown_count > 0:
        warnings.append(
            f'CRITICAL: unknown_count ({unknown_count}) equals approved_count ({approved_count}). '
            'These should be separate totals. API may be returning duplicate or incorrect data.'
        )

    # Check publisher reputation counts
    if trusted_total == blocked_total and trusted_total > 0:
        warnings.append(
            f'CRITICAL: trusted_publisher_count ({trusted_total}) equals blocked_publisher_count ({blocked_total}). '
            'These should be separate. API blocked_publishers endpoint may be returning wrong data.'
        )

    # Check publisher analysis vs summary mismatch
    pub_counts = publisher_analysis.get('summary_counts', {})
    pub_trusted = int(pub_counts.get('trusted', 0) or 0)
    pub_blocked = int(pub_counts.get('blocked', 0) or 0)
    pub_trusted_total = int(pub_counts.get('trusted_total', 0) or 0)
    pub_blocked_total = int(pub_counts.get('blocked_total', 0) or 0)

    if pub_blocked_total > 0 and pub_blocked == 0:
        warnings.append(
            f'DATA MISMATCH: Publisher analysis found {pub_blocked} blocked publishers but summary reports blocked_total={pub_blocked_total}. '
            'The blocked_publishers API endpoint may be returning data that cannot be parsed as blocked reputation.'
        )

    if pub_trusted_total != trusted_total:
        warnings.append(
            f'MISMATCH: Publisher analysis trusted_total={pub_trusted_total} but summary trusted_publisher_count={trusted_total}. '
            'Data collection counts may differ from analysis counts.'
        )

    if trusted_total > 0 and publisher_score == 0.0:
        warnings.append(
            'Trusted publishers were detected in summary counts but publisher trust scored 0.0. '
            'Verify reputation parsing and publisher data completeness.'
        )

    if trusted_total > 0 and not publisher_analysis.get('trusted'):
        warnings.append(
            'Trusted publisher summary count is non-zero, but trusted publisher rows are empty. '
            'Workflow decisions may under-use trusted publisher guidance.'
        )

    if unknown_count > 0 and readiness.get('breakdown', {}).get('unknown_binaries', 0.0) >= 95.0:
        warnings.append(
            'Unknown binaries exist but unknown binary score is near-perfect. Validate summary count consistency.'
        )

    return {
        'inputs': {
            'unknown_count': int(summary.get('unknown_count', 0) or 0),
            'approved_count': int(summary.get('approved_count', 0) or 0),
            'trusted_publisher_count': trusted_total,
            'blocked_publisher_count': int(summary.get('blocked_publisher_count', 0) or 0),
            'active_computer_count': int(summary.get('active_computer_count', 0) or 0),
        },
        'publisher_analysis_counts': publisher_analysis.get('summary_counts', {}),
        'warnings': warnings,
    }


def build_guardrail_checks(acceleration_candidates: List[Dict[str, Any]], rule_suggestions: Dict[str, Any]) -> Dict[str, Any]:
    """Detect risky recommendation patterns that could inflate score at security cost."""
    findings: List[Dict[str, Any]] = []

    for candidate in acceleration_candidates:
        candidate_type = candidate.get('type', 'unknown')
        target = str(candidate.get('target', ''))
        files_to_approve = int(candidate.get('files_to_approve', 0) or 0)
        confidence = float(candidate.get('confidence_percent', 0.0) or 0.0)

        if files_to_approve >= 250:
            findings.append({
                'severity': 'high',
                'category': 'broad_approval_scope',
                'target': target,
                'message': f'{candidate_type} affects {files_to_approve} files; apply to pilot policy first.'
            })

        if confidence < 70.0:
            findings.append({
                'severity': 'medium',
                'category': 'low_confidence',
                'target': target,
                'message': f'{candidate_type} confidence is {confidence}%; require manual review before approval.'
            })

        if '*' in target or target.lower().startswith('any '):
            findings.append({
                'severity': 'high',
                'category': 'wildcard_target',
                'target': target,
                'message': 'Wildcard approval target detected; narrow scope to known signer or publisher.'
            })

    for rule in rule_suggestions.get('recommended_rules', rule_suggestions.get('candidates', [])):
        file_pattern = str(rule.get('file_pattern', ''))
        process_pattern = str(rule.get('process_pattern', ''))
        user_scope = str(rule.get('user_scope', ''))

        if ('*' in file_pattern and ('\\' not in file_pattern and '/' not in file_pattern)) or file_pattern.lower() in {'*', 'any path'}:
            findings.append({
                'severity': 'high',
                'category': 'broad_rule_pattern',
                'target': rule.get('rule_name', 'unnamed_rule'),
                'message': 'Rule file pattern is too broad; scope to specific directories or extensions.'
            })

        if process_pattern.lower() in {'*', 'any process'} and user_scope.lower() in {'any user', '*'}:
            findings.append({
                'severity': 'high',
                'category': 'any_process_any_user',
                'target': rule.get('rule_name', 'unnamed_rule'),
                'message': 'Any Process + Any User rule detected; convert to least-privilege scope.'
            })

    return {
        'total_findings': len(findings),
        'high_severity': len([f for f in findings if f['severity'] == 'high']),
        'medium_severity': len([f for f in findings if f['severity'] == 'medium']),
        'findings': findings[:25],
    }


def build_backlog_delta_dashboard(
    readiness: Dict[str, Any],
    acceleration_candidates: List[Dict[str, Any]],
    summary: Dict[str, Any],
    rapid_config_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """Summarize projected score lift from practical backlog buckets."""
    current = float(readiness.get('total_score', 0.0) or 0.0)

    top_publisher = next((c for c in acceleration_candidates if c.get('type') == 'publisher_approval'), None)
    cert_candidates = [c for c in acceleration_candidates if c.get('type') == 'certificate_approval']
    top_three_certs = cert_candidates[:3]

    cert_gain = round(sum(float(c.get('readiness_gain_percent', 0.0) or 0.0) for c in top_three_certs), 1)
    publisher_gain = round(float(top_publisher.get('readiness_gain_percent', 0.0) or 0.0), 1) if top_publisher else 0.0

    active = int(summary.get('active_computer_count', 0) or 0)
    target_active = 10
    coverage_gain = 0.0
    if active < 6:
        coverage_gain = 2.0
    elif active < 10:
        coverage_gain = 1.0

    rapid_summary = rapid_config_analysis.get('summary', {}) if isinstance(rapid_config_analysis, dict) else {}
    # Backlog gain: how much can be captured by promoting report-mode configs to enforcement.
    configured_total = max(1, int(rapid_summary.get('configured_rapid_configs', 0) or 0))
    report_count = int(rapid_summary.get('report_mode_configs', 0) or 0)
    not_configured_count_local = int(rapid_summary.get('not_configured_configs', 0) or 0)
    # Heuristic: each report-mode and unconfigured priority config represents a readiness gap.
    # Moving report-mode configs to enforcement closes a meaningful but bounded gap (~4% max total contribution).
    rapid_promotion_ratio = report_count / configured_total if configured_total else 0.0
    rapid_projected_gain = round(min(4.0, rapid_promotion_ratio * 4.0), 1)

    buckets = [
        {
            'bucket': 'Top Publisher Approval',
            'projected_gain_percent': publisher_gain,
            'projected_score': round(current + publisher_gain, 1),
            'description': top_publisher.get('rationale') if top_publisher else 'No publisher candidate available.'
        },
        {
            'bucket': 'Top 3 Certificate Approvals',
            'projected_gain_percent': cert_gain,
            'projected_score': round(current + cert_gain, 1),
            'description': f'{len(top_three_certs)} certificate recommendations combined.'
        },
        {
            'bucket': f'Increase Endpoint Coverage to {target_active}',
            'projected_gain_percent': coverage_gain,
            'projected_score': round(current + coverage_gain, 1),
            'description': f'Current active endpoints: {active}. Improve data confidence and readiness weighting.'
        },
        {
            'bucket': 'Rapid Config Relevance and Staging',
            'projected_gain_percent': rapid_projected_gain,
            'projected_score': round(current + rapid_projected_gain, 1),
            'description': (
                f'{report_count} Rapid Config(s) are configured but in report/monitor mode only. '
                'Prioritize named controls in report-only mode, add exceptions from observed would-block behavior, '
                'then promote stable controls to enforcement.'
            )
        },
    ]

    return {
        'current_score': current,
        'buckets': buckets,
    }


def build_staged_remediation_workflow(
    optimized_plan: Dict[str, Any],
    guardrails: Dict[str, Any],
    rapid_config_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """Create a practical staged rollout plan users can execute in production."""
    actions = optimized_plan.get('actions', [])
    rapid_names = rapid_config_analysis.get('action_needed_config_names', rapid_config_analysis.get('prioritized_config_names', [])) if isinstance(rapid_config_analysis, dict) else []
    rapid_canary_actions = [
        {
            'type': 'rapid_config_report_pilot',
            'target': name,
        }
        for name in rapid_names[:3]
    ]
    rapid_broad_actions = [
        {
            'type': 'rapid_config_enforcement_promotion',
            'target': name,
        }
        for name in rapid_names[3:6]
    ]

    canary_actions = rapid_canary_actions + actions[:3]
    broad_actions = rapid_broad_actions + actions[3:]

    return {
        'phase_1_canary': {
            'policy_scope': 'Pilot policy / small endpoint ring',
            'actions': canary_actions,
            'exit_criteria': [
                'No unexpected block spikes for 24 hours',
                'No high-severity guardrail violations introduced',
                'Projected score change aligns with observed unknown reduction',
                'Rapid Config report-only telemetry reviewed and exception candidates documented'
            ]
        },
        'phase_2_broad_rollout': {
            'policy_scope': 'Production policies by business unit',
            'actions': broad_actions,
            'gates': [
                'Apply changes in batches of 2-3 actions',
                'Re-run readiness report between batches',
                'Pause rollout if new high-severity findings appear',
                'Promote only Rapid Configs with low-noise report history and explicit exception handling'
            ]
        },
        'phase_3_validation_and_rollback': {
            'monitoring': [
                'Track new unapproved event volume by process and path',
                'Compare projected vs actual readiness gain after each batch',
                'Review high-risk or low-confidence approvals weekly'
            ],
            'rollback_triggers': [
                'Unexpected executable approvals in user-writable paths',
                'Sustained block increase after deployment window',
                'Any guardrail finding classified as high severity'
            ],
            'current_guardrail_high_severity': guardrails.get('high_severity', 0),
        }
    }


def build_publisher_analysis_input(trust_signals: Dict[str, Any]) -> Dict[str, Any]:
    """Merge trusted/blocked/all publisher responses into a single normalized dataset."""
    merged: Dict[str, Dict[str, Any]] = {}

    def _rows(payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict):
            rows = payload.get('results', payload.get('rows', []))
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return []

    def _upsert(row: Dict[str, Any], forced_reputation: str = '') -> None:
        pub_id = row.get('id')
        name = (row.get('name') or '').strip()
        key = f"{pub_id}|{name.lower()}"
        if not name:
            return

        normalized = dict(row)
        if forced_reputation:
            normalized['reputation'] = forced_reputation

        existing = merged.get(key)
        if not existing:
            merged[key] = normalized
            return

        # Preserve strongest known reputation when merging records.
        order = {'TRUSTED': 3, 'BLOCKED': 2, 'UNKNOWN': 1, '': 0}
        existing_rep = str(existing.get('reputation', '')).upper()
        incoming_rep = str(normalized.get('reputation', '')).upper()
        if order.get(incoming_rep, 0) > order.get(existing_rep, 0):
            merged[key] = normalized

    for row in _rows(trust_signals.get('all_publishers', {})):
        _upsert(row)

    for row in _rows(trust_signals.get('trusted_publishers', {})):
        _upsert(row, 'TRUSTED')

    for row in _rows(trust_signals.get('blocked_publishers', {})):
        _upsert(row, 'BLOCKED')

    return {'results': list(merged.values())}


def build_certificate_portfolio_analysis(cert_portfolio: Dict[str, Any]) -> Dict[str, Any]:
    """Format certificate portfolio optimizer results for report."""
    if not cert_portfolio or not cert_portfolio.get('top_by_coverage'):
        return {'certificates': [], 'recommendations': []}
    
    recommendations = []
    for cert in cert_portfolio.get('top_by_coverage', [])[:10]:
        recommendations.append({
            'certificate_id': cert.get('id'),
            'issuer': cert.get('issuer'),
            'files_covered': cert.get('file_count'),
            'affected_computers': cert.get('affected_computers'),
            'valid_signature': cert.get('has_valid_signature'),
            'projected_score_gain': round(cert.get('score_gain_if_trusted', 0) * 100, 1),
            'risk_flags': [v for v in cert_portfolio.get('guardrail_violations', []) if str(cert.get('id')) in v],
        })
    
    return {
        'top_certificates': recommendations,
        'total_potential_gain': round(cert_portfolio.get('total_potential_gain', 0) * 100, 1),
        'violations_detected': len(cert_portfolio.get('guardrail_violations', [])),
    }


def build_policy_scope_analysis(scope_simulation: Dict[str, Any]) -> Dict[str, Any]:
    """Format policy scope simulation results for report."""
    if not scope_simulation or not scope_simulation.get('scoped_approvals'):
        return {'scoped_candidates': [], 'unlock_gain': 0.0}
    
    candidates = []
    for approval in scope_simulation.get('scoped_approvals', [])[:5]:
        candidates.append({
            'rule_id': approval.get('rule_id'),
            'affected_files': approval.get('affected_files'),
            'affected_computers': approval.get('proposed_computers'),
            'risk_reduction': f"{(approval.get('current_risk_score', 0) - approval.get('proposed_risk_score', 0)) * 100:.0f}%",
            'projected_score_gain': round(approval.get('score_gain', 0) * 100, 1),
        })
    
    return {
        'scoped_candidates': candidates,
        'unlock_potential': round(scope_simulation.get('unlock_potential', 0) * 100, 1),
    }


def build_recurring_event_rules(event_rules: Dict[str, Any]) -> Dict[str, Any]:
    """Format recurring event auto-packaging results for report."""
    if not event_rules or not event_rules.get('rules'):
        return {'suggested_rules': [], 'unknown_reduction': 0}
    
    rules = []
    for rule in event_rules.get('rules', [])[:10]:
        rules.append({
            'process_name': rule.get('process'),
            'file_path': rule.get('path'),
            'occurrences': rule.get('occurrences'),
            'coverage_percent': round(rule.get('coverage_percent', 0), 1),
            'estimated_reduction': rule.get('estimated_unknown_reduction'),
        })
    
    return {
        'suggested_rules': rules,
        'unknown_reduction': event_rules.get('unknown_reduction', 0),
    }


def _extract_rows(payload: Any) -> List[Dict[str, Any]]:
    """Normalize API payloads that may be list- or dict-shaped."""
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows = payload.get('results', payload.get('rows', []))
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _contains_token(value: Any, candidates: List[str]) -> bool:
    text = str(value or '').lower()
    return any(token in text for token in candidates)


def _normalize_os_family(value: Any) -> str:
    text = str(value or '').strip().lower()
    if not text:
        return 'unknown'
    if any(token in text for token in ['win', 'windows', 'server 20']):
        return 'windows'
    if any(token in text for token in ['mac', 'os x', 'darwin']):
        return 'macos'
    if any(token in text for token in ['linux', 'ubuntu', 'rhel', 'centos', 'debian', 'suse']):
        return 'linux'
    return 'unknown'


def _extract_environment_os_families(active_computers: Any) -> List[str]:
    rows = _extract_rows(active_computers)
    families = set()
    for row in rows:
        for key in ['osName', 'osShortName', 'operatingSystem', 'platform', 'agentOs', 'os']:
            family = _normalize_os_family(row.get(key))
            if family != 'unknown':
                families.add(family)

        # Fallback when explicit OS fields are unavailable.
        if not families:
            family = _normalize_os_family(row.get('name'))
            if family != 'unknown':
                families.add(family)

    # Current deployment is App Control on Windows-first endpoints; keep practical default.
    if not families:
        families.add('windows')

    return sorted(families)


def _infer_config_os_from_name(name: str) -> List[str]:
    """Infer supported OS families from Rapid Config name when API provides no metadata."""
    name_lower = str(name or '').lower()
    if any(token in name_lower for token in ['linux', 'unix', 'rhel', 'ubuntu', 'debian', 'suse', 'centos']):
        return ['linux']
    if any(token in name_lower for token in ['windows', 'win32', 'winrm', 'wmi', 'powershell']):
        return ['windows']
    if any(token in name_lower for token in ['mac', 'macos', 'darwin', 'osx']):
        return ['macos']
    # Default: assume all OSs when name gives no hint (conservative).
    return []


def _extract_supported_os_families(row: Dict[str, Any]) -> List[str]:
    values: List[Any] = []
    for key in ['supportedOperatingSystems', 'supportedOs', 'os', 'platform', 'targetOs']:
        raw = row.get(key)
        if isinstance(raw, list):
            values.extend(raw)
        elif raw is not None:
            values.append(raw)

    families = {f for f in (_normalize_os_family(v) for v in values) if f != 'unknown'}
    
    # If API provided no OS metadata, infer from config name.
    if not families:
        families = set(_infer_config_os_from_name(row.get('name', '')))
    
    return sorted(families)


def _parse_event_time(value: Any) -> Any:
    """Best-effort parser for multiple timestamp formats from CB event rows."""
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None

    # Handle common UTC ISO format ending with Z.
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'

    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        pass

    known_formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%m/%d/%Y %H:%M:%S',
    ]
    for fmt in known_formats:
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return parsed
        except Exception:
            continue
    return None


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {'true', '1', 'yes', 'y', 'on'}:
            return True
        if lowered in {'false', '0', 'no', 'n', 'off'}:
            return False
    return default


def _as_string_list(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _load_config_file(path: str) -> Dict[str, Any]:
    """Load optional JSON config file for runtime settings."""
    if not path:
        return {}
    if not os.path.exists(path):
        logger.warning(f"Config file not found: {path}. Continuing with CLI/default settings.")
        return {}

    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.error(f"Failed to load config file {path}: {exc}")
        sys.exit(1)

    if not isinstance(data, dict):
        logger.error(f"Config file {path} must contain a top-level JSON object.")
        sys.exit(1)
    return data


def _resolve_value(cli_value: Any, config_value: Any, default: Any) -> Any:
    if cli_value is not None:
        return cli_value
    if config_value is not None:
        return config_value
    return default


def resolve_runtime_settings(args: argparse.Namespace) -> Dict[str, Any]:
    """Resolve runtime settings with precedence: CLI > config file > defaults."""
    cfg = _load_config_file(args.config)

    endpoint_cfg = dict(DEFAULT_ENDPOINT_READINESS_CONFIG)
    cfg_endpoint = cfg.get('endpoint_readiness', {})
    if isinstance(cfg_endpoint, dict):
        endpoint_cfg.update(cfg_endpoint)

    rapid_config_cfg = cfg.get('rapid_config', {})
    rapid_exclusions = []
    if isinstance(rapid_config_cfg, dict):
        rapid_exclusions = _as_string_list(rapid_config_cfg.get('excluded_configs', []))

    resolved = {
        'server': _resolve_value(args.server, cfg.get('server'), None),
        'token': _resolve_value(args.token, cfg.get('token'), None),
        'output': _resolve_value(args.output, cfg.get('output'), 'enforcement_readiness_report.json'),
        'html_output': _resolve_value(args.html_output, cfg.get('html_output'), None),
        'no_html': _as_bool(_resolve_value(args.no_html, cfg.get('no_html'), False), False),
        'acceleration_mode': _resolve_value(args.acceleration_mode, cfg.get('acceleration_mode'), 'conservative'),
        'max_rows': _as_int(_resolve_value(args.max_rows, cfg.get('max_rows'), 5000), 5000),
        'verify_ssl': _as_bool(_resolve_value(args.verify_ssl, cfg.get('verify_ssl'), False), False),
        'config_path': args.config,
        'rapid_config': {
            'excluded_configs': rapid_exclusions,
        },
        'endpoint_readiness': {
            'lookback_days': _as_int(endpoint_cfg.get('lookback_days'), 7),
            'min_ready_score': _as_float(endpoint_cfg.get('min_ready_score'), 80.0),
            'near_ready_score': _as_float(endpoint_cfg.get('near_ready_score'), 60.0),
            'max_block_events': _as_int(endpoint_cfg.get('max_block_events'), 0),
            'max_unapproved_events': _as_int(endpoint_cfg.get('max_unapproved_events'), 3),
            'unapproved_penalty': _as_float(endpoint_cfg.get('unapproved_penalty'), 3.0),
            'block_penalty': _as_float(endpoint_cfg.get('block_penalty'), 5.0),
            'recent_penalty': _as_float(endpoint_cfg.get('recent_penalty'), 4.0),
            'max_unapproved_penalty': _as_float(endpoint_cfg.get('max_unapproved_penalty'), 60.0),
            'max_block_penalty': _as_float(endpoint_cfg.get('max_block_penalty'), 25.0),
            'max_recent_penalty': _as_float(endpoint_cfg.get('max_recent_penalty'), 20.0),
        },
    }

    if not resolved['server'] or not resolved['token']:
        logger.error('Server and token are required. Provide via CLI (--server/--token) or config file.')
        sys.exit(2)

    if resolved['acceleration_mode'] not in {'conservative', 'accelerated'}:
        logger.error('Invalid acceleration_mode. Use conservative or accelerated.')
        sys.exit(2)

    return resolved


def _is_excluded_rapid_config(name: str, config_id: str, exclusions: List[str]) -> bool:
    name_lower = str(name or '').strip().lower()
    id_lower = str(config_id or '').strip().lower()

    for raw in exclusions:
        pattern = str(raw or '').strip().lower()
        if not pattern:
            continue

        # Support name: and id: exact match selectors plus glob patterns.
        if pattern.startswith('name:'):
            if name_lower == pattern[5:].strip():
                return True
            continue
        if pattern.startswith('id:'):
            if id_lower == pattern[3:].strip():
                return True
            continue

        if '*' in pattern or '?' in pattern:
            if fnmatch.fnmatch(name_lower, pattern) or fnmatch.fnmatch(id_lower, pattern):
                return True
            continue

        if name_lower == pattern or id_lower == pattern:
            return True

    return False


def build_rapid_config_analysis(
    software_rules: Dict[str, Any],
    event_data: Any,
    active_computers: Any,
    excluded_configs: List[str],
) -> Dict[str, Any]:
    """Summarize Rapid Config posture and produce read-only rollout recommendations."""
    all_rules = _extract_rows(software_rules)
    rapid_configs_all = [
        row for row in all_rules
        if str(row.get('_ruleSourceEndpoint', '')).lower().endswith('/rapidconfig')
    ]
    excluded_details: List[Dict[str, Any]] = []
    scored_config_ids: set = set()

    event_rows = _extract_rows(event_data)
    environment_os = _extract_environment_os_families(active_computers)

    def _mode_of(row: Dict[str, Any]) -> str:
        mode_raw = ' '.join(
            str(row.get(key, ''))
            for key in ['mode', 'operationMode', 'enforcementMode', 'state', 'action']
        ).lower()
        if any(token in mode_raw for token in ['report', 'monitor', 'observe', 'audit']):
            return 'report'
        if any(token in mode_raw for token in ['block', 'deny', 'enforce', 'prevent']):
            return 'block'
        return 'unknown'

    def _enabled_of(row: Dict[str, Any]) -> bool:
        enabled_raw = row.get('enabled', row.get('isEnabled', row.get('active', False)))
        if isinstance(enabled_raw, bool):
            return enabled_raw
        return str(enabled_raw).strip().lower() not in {'false', '0', 'disabled', 'no'}

    def _configured_of(row: Dict[str, Any]) -> bool:
        configured_raw = row.get('configured', row.get('isConfigured', True))
        if isinstance(configured_raw, bool):
            return configured_raw
        return str(configured_raw).strip().lower() not in {'false', '0', 'no', 'not configured'}

    def _infer_mode_from_purpose(row: Dict[str, Any]) -> str:
        purpose_text = str(row.get('purpose', '') or '').lower()
        if any(token in purpose_text for token in ['look for', 'watch', 'suspicious behavior', 'detect', 'reconnaissance and exfiltration']):
            return 'report'
        return 'block'

    risky_process_tokens = [
        'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32',
        'winword', 'excel', 'powerpnt', 'outlook',
    ]
    noisy_unapproved = [
        row for row in event_rows
        if _contains_token(row.get('processName') or row.get('process') or row.get('source'), risky_process_tokens)
    ]

    analyzed_configs: List[Dict[str, Any]] = []
    report_mode_count = 0
    block_mode_count = 0
    not_configured_count = 0
    configured_count = 0
    broad_scope_count = 0
    prioritized_count = 0
    prioritized_report_mode_count = 0
    relevant_config_count = 0
    enabled_relevant_count = 0

    for row in rapid_configs_all:
        mode = _mode_of(row)
        raw_configured = _configured_of(row)
        operational_configured = _enabled_of(row)

        if mode == 'unknown' and operational_configured:
            mode = _infer_mode_from_purpose(row)

        if not operational_configured:
            mode = 'not_configured'
        elif mode == 'unknown':
            mode = 'configured'

        # "Enabled" is treated as enforcement-enabled (block mode) for rollout planning.
        enabled = operational_configured and mode == 'block'
        name = row.get('name') or row.get('displayName') or f"RapidConfig-{row.get('id', 'unknown')}"
        config_id = str(row.get('id', ''))
        name_lower = str(name).strip().lower()
        priority_candidate = name_lower.endswith('protection') or name_lower.endswith('hardening')
        supported_os = _extract_supported_os_families(row)
        environment_relevant = True if not supported_os else bool(set(supported_os).intersection(set(environment_os)))
        excluded_by_config = _is_excluded_rapid_config(name, config_id, excluded_configs)
        relevant_to_environment = environment_relevant and not excluded_by_config
        relevance_reason = 'Relevant'
        if excluded_by_config:
            relevance_reason = 'Excluded by config'
        elif not environment_relevant:
            relevance_reason = 'OS mismatch'

        if excluded_by_config:
            excluded_details.append({'id': config_id, 'name': name, 'reason': 'excluded_by_config'})
        else:
            if mode == 'report':
                report_mode_count += 1
                configured_count += 1
            elif mode == 'block':
                block_mode_count += 1
                configured_count += 1
            elif mode == 'not_configured':
                not_configured_count += 1
            else:
                configured_count += 1

            if priority_candidate:
                prioritized_count += 1
                if mode == 'report':
                    prioritized_report_mode_count += 1

            if relevant_to_environment:
                relevant_config_count += 1
                if enabled:
                    enabled_relevant_count += 1

            scored_config_ids.add(config_id)

        path_text = ' '.join(str(row.get(k, '')) for k in ['path', 'pathName', 'filePattern', 'target'])
        process_text = ' '.join(str(row.get(k, '')) for k in ['process', 'processName', 'processPattern'])
        user_text = str(row.get('user', row.get('userScope', '')))

        broad_scope = (
            _contains_token(path_text, ['*', 'any'])
            or _contains_token(process_text, ['*', 'any process'])
            or _contains_token(user_text, ['*', 'any user'])
        )
        if broad_scope:
            broad_scope_count += 1

        analyzed_configs.append({
            'id': config_id,
            'name': name,
            'enabled': enabled,
            'configured': operational_configured,
            'raw_configured': raw_configured,
            'mode': mode,
            'policy_name': row.get('policyName', row.get('policy', 'Unspecified')),
            'path_pattern': path_text.strip() or 'Unspecified',
            'process_pattern': process_text.strip() or 'Unspecified',
            'user_scope': user_text or 'Unspecified',
            'broad_scope': broad_scope,
            'supported_os': supported_os,
            'relevant_to_environment': relevant_to_environment,
            'relevance_reason': relevance_reason,
            'excluded_by_config': excluded_by_config,
            'environment_relevant': environment_relevant,
            'priority_candidate': priority_candidate,
        })

    prioritized_names = [
        c['name'] for c in analyzed_configs
        if c.get('priority_candidate') and c.get('relevant_to_environment') and not c.get('excluded_by_config')
    ]
    # Configs needing attention: relevant, prioritized, and NOT yet in enforcement (block) mode.
    action_needed_names = [
        c['name'] for c in analyzed_configs
        if c.get('priority_candidate')
        and c.get('relevant_to_environment')
        and c.get('mode') != 'block'
        and not c.get('excluded_by_config')
    ]
    
    # Metric: of all configured/operational configs, what percent are BOTH relevant AND in block mode?
    # This shows enforcement readiness of the Rapid Config strategy.
    enabled_count = len([c for c in analyzed_configs if c['enabled'] and not c.get('excluded_by_config')])
    enabled_relevant_percent = round((enabled_relevant_count / max(1, configured_count)) * 100.0, 1) if configured_count else 0.0

    recommendations: List[Dict[str, str]] = []
    if not scored_config_ids:
        recommendations.append({
            'priority': 'high',
            'title': 'No score-relevant Rapid Config coverage detected',
            'recommendation': (
                'Create pilot Rapid Configs in report mode for high-risk execution vectors '
                '(PowerShell, script hosts, Office child-process behaviors) before broad enforcement.'
            ),
        })
    else:
        if report_mode_count == 0:
            recommendations.append({
                'priority': 'medium',
                'title': 'No report-mode Rapid Configs',
                'recommendation': 'Keep at least one report-mode pilot Rapid Config active to capture new breakpoints safely.',
            })

        if prioritized_names:
            recommendations.append({
                'priority': 'high',
                'title': 'Prioritize named Rapid Configs first',
                'recommendation': (
                    f"Prioritize these Rapid Configs first: {', '.join(prioritized_names[:8])}. "
                    'Start them in report-only mode, then add targeted exceptions where block behavior is observed before moving to enforcement.'
                ),
            })

        if noisy_unapproved and report_mode_count > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Promote stable report-mode configs to enforcement',
                'recommendation': (
                    f'{len(noisy_unapproved)} unapproved events involve risky interpreters. '
                    'Promote only low-noise report-mode configs to block mode with explicit exceptions.'
                ),
            })
        if broad_scope_count > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Narrow broad Rapid Config scope',
                'recommendation': (
                    f'{broad_scope_count} Rapid Config entries appear broad. Restrict path/process/user scope before expansion.'
                ),
            })

        if enabled_relevant_percent < 70.0:
            recommendations.append({
                'priority': 'medium',
                'title': 'Increase environment-relevant Rapid Config coverage',
                'recommendation': (
                    f'Only {enabled_relevant_percent:.1f}% of enabled Rapid Configs appear relevant to detected endpoint OS families. '
                    'Focus enablement on configs that match deployed platforms.'
                ),
            })

    return {
        'summary': {
            'total_rapid_configs': len(rapid_configs_all),
            'scored_rapid_configs': len(scored_config_ids),
            'excluded_rapid_configs': len(excluded_details),
            'total_rapid_configs_before_exclusions': len(rapid_configs_all),
            'enabled_rapid_configs': enabled_count,
            'configured_rapid_configs': configured_count,
            'report_mode_configs': report_mode_count,
            'block_mode_configs': block_mode_count,
            'not_configured_configs': not_configured_count,
            'broad_scope_configs': broad_scope_count,
            'risky_process_unapproved_events': len(noisy_unapproved),
            'environment_os_families': environment_os,
            'relevant_rapid_configs': relevant_config_count,
            'enabled_relevant_rapid_configs': enabled_relevant_count,
            'enabled_relevant_percent': enabled_relevant_percent,
            'prioritized_configs': prioritized_count,
            'prioritized_report_mode_configs': prioritized_report_mode_count,
        },
        'rapid_configs': analyzed_configs,
        'excluded_configs': excluded_details,
        'applied_exclusions': excluded_configs,
        'prioritized_config_names': prioritized_names,
        'action_needed_config_names': action_needed_names,
        'recommendations': recommendations,
    }


def build_rapid_config_readiness_score(rapid_config_analysis: Dict[str, Any]) -> float:
    """Calculate a 0-100 readiness sub-score from Rapid Config posture."""
    summary = rapid_config_analysis.get('summary', {})
    total = int(summary.get('scored_rapid_configs', summary.get('total_rapid_configs', 0)) or 0)
    if total <= 0:
        return 0.0

    enabled_relevant_pct = float(summary.get('enabled_relevant_percent', 0.0) or 0.0)
    report_mode_ratio = (float(summary.get('report_mode_configs', 0) or 0.0) / float(total)) * 100.0
    broad_scope = int(summary.get('broad_scope_configs', 0) or 0)
    broad_scope_score = max(0.0, 100.0 - min(100.0, float(broad_scope * 10)))

    prioritized_total = int(summary.get('prioritized_configs', 0) or 0)
    prioritized_report = int(summary.get('prioritized_report_mode_configs', 0) or 0)
    if prioritized_total > 0:
        prioritized_score = (float(prioritized_report) / float(prioritized_total)) * 100.0
    else:
        prioritized_score = 50.0

    score = (
        (enabled_relevant_pct * 0.50)
        + (report_mode_ratio * 0.25)
        + (prioritized_score * 0.15)
        + (broad_scope_score * 0.10)
    )
    return round(max(0.0, min(100.0, score)), 1)


def _recommendation_from_percent(score_percent: float) -> str:
    if score_percent >= 80.0:
        return 'READY_FOR_HIGH_ENFORCEMENT'
    if score_percent >= 60.0:
        return 'NEAR_READY - ADDRESS REMAINING UNKNOWNS'
    if score_percent >= 40.0:
        return 'MEDIUM ENFORCEMENT RECOMMENDED'
    return 'MAINTAIN LOW ENFORCEMENT'


def apply_rapid_config_score_to_readiness(readiness: Dict[str, Any], rapid_config_score: float) -> Dict[str, Any]:
    """Inject Rapid Config posture into the top-level readiness score."""
    updated = dict(readiness)
    breakdown = dict(updated.get('breakdown', {}))
    existing_dimensions = max(1, len(breakdown))
    current_total = float(updated.get('total_score', 0.0) or 0.0)

    new_total = round(((current_total * existing_dimensions) + rapid_config_score) / float(existing_dimensions + 1), 1)
    breakdown['rapid_config_readiness'] = rapid_config_score

    weight = round(1.0 / float(existing_dimensions + 1), 4)
    weights = {key: weight for key in breakdown.keys()}

    updated['total_score'] = new_total
    updated['breakdown'] = breakdown
    updated['weights'] = weights
    updated['ready_for_high_enforcement'] = new_total >= 70.0
    updated['recommendation'] = _recommendation_from_percent(new_total)
    return updated


def build_endpoint_readiness_analysis(active_computers: Any, event_data: Any, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Identify endpoint candidates that are likely ready for high-enforcement pilot."""
    computers = _extract_rows(active_computers)
    events = _extract_rows(event_data)

    by_id: Dict[str, Dict[str, Any]] = {}
    for comp in computers:
        comp_id = str(comp.get('id', ''))
        if not comp_id:
            continue
        by_id[comp_id] = {
            'computer_id': comp_id,
            'computer_name': comp.get('name', f'endpoint-{comp_id}'),
            'policy_id': comp.get('policyId', 'unknown'),
            'policy_name': comp.get('policyName', comp.get('policy', 'Unassigned')),
            'unapproved_events': 0,
            'block_events': 0,
            'recent_unapproved_7d': 0,
        }

    lookback_days = max(1, int(settings.get('lookback_days', 7)))
    min_ready_score = float(settings.get('min_ready_score', 80.0))
    near_ready_score = float(settings.get('near_ready_score', 60.0))
    max_block_events = max(0, int(settings.get('max_block_events', 0)))
    max_unapproved_events = max(0, int(settings.get('max_unapproved_events', 3)))
    unapproved_penalty = max(0.0, float(settings.get('unapproved_penalty', 3.0)))
    block_penalty = max(0.0, float(settings.get('block_penalty', 5.0)))
    recent_penalty = max(0.0, float(settings.get('recent_penalty', 4.0)))
    max_unapproved_penalty = max(0.0, float(settings.get('max_unapproved_penalty', 60.0)))
    max_block_penalty = max(0.0, float(settings.get('max_block_penalty', 25.0)))
    max_recent_penalty = max(0.0, float(settings.get('max_recent_penalty', 20.0)))

    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=lookback_days)

    for event in events:
        comp_id = str(event.get('computerId', ''))
        if not comp_id:
            continue
        if comp_id not in by_id:
            by_id[comp_id] = {
                'computer_id': comp_id,
                'computer_name': event.get('computerName', f'endpoint-{comp_id}'),
                'policy_id': event.get('policyId', 'unknown'),
                'policy_name': event.get('policyName', 'Unassigned'),
                'unapproved_events': 0,
                'block_events': 0,
                'recent_unapproved_7d': 0,
            }

        subtype = str(event.get('subtype', event.get('eventType', ''))).lower()
        description = str(event.get('description', '')).lower()
        is_block = ('block' in subtype) or ('blocked' in description)

        by_id[comp_id]['unapproved_events'] += 1
        if is_block:
            by_id[comp_id]['block_events'] += 1

        event_time = _parse_event_time(
            event.get('eventTime') or event.get('timestamp') or event.get('date') or event.get('createdTime')
        )
        if event_time and event_time >= seven_days_ago:
            by_id[comp_id]['recent_unapproved_7d'] += 1

    endpoint_rows: List[Dict[str, Any]] = []
    for endpoint in by_id.values():
        unapproved = int(endpoint.get('unapproved_events', 0) or 0)
        blocked = int(endpoint.get('block_events', 0) or 0)
        recent = int(endpoint.get('recent_unapproved_7d', 0) or 0)

        # Conservative readiness scoring for pilot candidacy.
        readiness_score = 100.0
        readiness_score -= min(max_unapproved_penalty, float(unapproved * unapproved_penalty))
        readiness_score -= min(max_block_penalty, float(blocked * block_penalty))
        readiness_score -= min(max_recent_penalty, float(recent * recent_penalty))
        readiness_score = max(0.0, round(readiness_score, 1))

        is_ready = (
            readiness_score >= min_ready_score
            and blocked <= max_block_events
            and unapproved <= max_unapproved_events
        )
        if is_ready:
            recommendation = 'Pilot candidate for high enforcement.'
        elif readiness_score >= near_ready_score:
            recommendation = 'Near-ready; clear recurring unapproved events before pilot.'
        else:
            recommendation = 'Not ready; keep in report or lower enforcement while triaging.'

        endpoint_rows.append({
            **endpoint,
            'readiness_score': readiness_score,
            'ready_for_high_enforcement': is_ready,
            'recommendation': recommendation,
        })

    endpoint_rows.sort(
        key=lambda item: (
            item.get('ready_for_high_enforcement', False),
            item.get('readiness_score', 0.0),
            -item.get('unapproved_events', 0),
        ),
        reverse=True,
    )

    ready = [row for row in endpoint_rows if row.get('ready_for_high_enforcement')]
    policy_buckets: Dict[str, int] = {}
    for row in ready:
        policy_name = str(row.get('policy_name', 'Unassigned'))
        policy_buckets[policy_name] = policy_buckets.get(policy_name, 0) + 1

    recommendations = []
    if not ready:
        recommendations.append(
            f'No endpoints currently meet high-enforcement pilot criteria (score >= {min_ready_score:.1f}, '
            f'block events <= {max_block_events}, unapproved events <= {max_unapproved_events}).'
        )
        recommendations.append(
            'Reduce per-endpoint unapproved event churn first, then re-run to identify pilot candidates.'
        )
    else:
        recommendations.append(
            f'{len(ready)} endpoint(s) are ready for high-enforcement pilot based on current event profile.'
        )
        recommendations.append(
            'Start with one policy-aligned pilot ring, validate for 24-48 hours, then expand incrementally.'
        )

    return {
        'summary': {
            'total_endpoints_evaluated': len(endpoint_rows),
            'ready_endpoints': len(ready),
            'near_ready_endpoints': len([r for r in endpoint_rows if near_ready_score <= r.get('readiness_score', 0.0) < min_ready_score]),
            'not_ready_endpoints': len([r for r in endpoint_rows if r.get('readiness_score', 0.0) < near_ready_score]),
        },
        'settings_used': {
            'lookback_days': lookback_days,
            'min_ready_score': min_ready_score,
            'near_ready_score': near_ready_score,
            'max_block_events': max_block_events,
            'max_unapproved_events': max_unapproved_events,
            'unapproved_penalty': unapproved_penalty,
            'block_penalty': block_penalty,
            'recent_penalty': recent_penalty,
            'max_unapproved_penalty': max_unapproved_penalty,
            'max_block_penalty': max_block_penalty,
            'max_recent_penalty': max_recent_penalty,
        },
        'policy_ready_buckets': policy_buckets,
        'recommendations': recommendations,
        'top_ready_endpoints': ready[:25],
        'endpoint_scores': endpoint_rows[:100],
    }


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Carbon Black App Control Enforcement Readiness Advisor'
    )
    parser.add_argument(
        '--config',
        default=None,
        help='Optional JSON config path (CLI args override config values).'
    )
    parser.add_argument(
        '--server', 
        required=False,
        help='CB App Control server URL (e.g., https://server.example.com)'
    )
    parser.add_argument(
        '--token', 
        required=False,
        help='API token for authentication'
    )
    parser.add_argument(
        '--output',
        default=None,
        help='Output file path (default: enforcement_readiness_report.json)'
    )
    parser.add_argument(
        '--acceleration-mode',
        choices=['conservative', 'accelerated'],
        default=None,
        help='Auto-approval mode: conservative (strict thresholds) or accelerated (lower thresholds for faster enforcement)'
    )
    parser.add_argument(
        '--verify-ssl',
        dest='verify_ssl',
        action='store_true',
        default=None,
        help='Verify SSL certificates (overrides config).'
    )
    parser.add_argument(
        '--insecure',
        dest='verify_ssl',
        action='store_false',
        help='Disable SSL certificate verification (overrides config).'
    )
    parser.add_argument(
        '--html-output',
        default=None,
        help='Path for the self-contained HTML report (e.g. report.html). '
             'If omitted, defaults to the JSON output path with a .html extension.'
    )
    parser.add_argument(
        '--no-html',
        dest='no_html',
        action='store_true',
        default=None,
        help='Skip HTML report generation (overrides config).'
    )
    parser.add_argument(
        '--html',
        dest='no_html',
        action='store_false',
        help='Force HTML report generation (overrides config).'
    )
    parser.add_argument(
        '--max-rows',
        type=int,
        default=None,
        help='Maximum rows to fetch per collection (default: 5000). '
             'Increase for large environments to avoid partial-sample analysis.'
    )
    return parser.parse_args()


def main():
    """Main execution function."""
    args = parse_args()
    settings = resolve_runtime_settings(args)
    
    logger.info("=" * 60)
    logger.info("Enforcement Readiness Advisor")
    logger.info("=" * 60)
    
    # Step 1: Initialize API client
    logger.info("\n[1/4] Connecting to CB App Control server...")
    api_client = CBApiClient(settings['server'], settings['token'], settings['verify_ssl'])
    
    if not api_client.test_connection():
        logger.error("Failed to connect to CB App Control server")
        sys.exit(1)
    
    logger.info("Connected successfully")
    
    # Step 2: Collect trust signal data
    logger.info("\n[2/4] Collecting trust signal data...")
    collector = EnforcementReadinessCollector(api_client, max_rows=settings['max_rows'])
    
    try:
        trust_signals = collector.collect_all_trust_signals()
        summary = collector.collect_summary()
    except Exception as e:
        logger.error(f"Data collection failed: {e}")
        sys.exit(1)
    
    logger.info(f"Collected data from {len(trust_signals)} sources")
    
    # Step 3: Analyze trust signals
    logger.info("\n[3/4] Analyzing trust signals...")
    analyzer = TrustSignalAnalyzer(acceleration_mode=settings['acceleration_mode'])
    scorer = EnforcementReadinessScorer()
    path_classifier = PathClassifier()
    installer_analyzer = InstallerLineageAnalyzer()
    workflow_analyzer = ApprovalWorkflowAnalyzer()
    
    # Analyze unknown binaries
    unknown_analysis = analyzer.analyze_unknown_binaries(
        trust_signals.get('unknown_binaries', {}),
        trust_signals.get('file_prevalence', {}),
        trust_signals.get('all_certificates', trust_signals.get('valid_certificates', {})),
        trust_signals.get('active_computers', {})
    )
    
    # Apply path classification filter (CRITICAL - exclude user-writable paths)
    logger.info("Applying path classification filter...")
    safe_binaries = []
    excluded_user_writable = []
    
    for binary in unknown_analysis:
        classification = path_classifier.classify_path(binary.file_path)
        if classification.is_user_writable:
            excluded_user_writable.append({
                'file_name': binary.file_name,
                'file_path': binary.file_path,
                'category': classification.category.value,
                'reason': classification.reason
            })
        else:
            safe_binaries.append(binary)
    
    logger.info(f"Path filter: {len(safe_binaries)} safe, {len(excluded_user_writable)} user-writable excluded")
    
    # Analyze installer lineage for safe binaries
    installer_analysis = installer_analyzer.analyze_installer_lineage([
        {'filePath': b.file_path} for b in safe_binaries
    ])
    
    # Analyze publisher trust
    publisher_analysis = analyzer.analyze_publisher_trust(
        build_publisher_analysis_input(trust_signals),
        summary
    )
    
    # Analyze certificate trust
    certificate_analysis = analyzer.analyze_certificate_trust(
        trust_signals.get('valid_certificates', {}),
        trust_signals.get('invalid_certificates', {})
    )
    
    # Analyze prevalence
    prevalence_analysis = analyzer.analyze_prevalence(
        trust_signals.get('file_prevalence', {})
    )
    
    # Calculate readiness score
    detailed_analysis = {
        'publisher_analysis': publisher_analysis,
        'certificate_analysis': certificate_analysis,
        'prevalence_analysis': prevalence_analysis
    }

    # Evaluate Broadcom approval workflow decisions
    workflow_file_decisions = workflow_analyzer.evaluate_each_file(
        unknown_analysis,
        publisher_analysis,
        trust_signals.get('new_unapproved_events', {}),
        trust_signals.get('software_rules', {})
    )
    workflow_custom_rule_decisions = workflow_analyzer.consider_custom_rule(
        trust_signals.get('new_unapproved_events', {})
    )
    workflow_rule_suggestions = workflow_analyzer.suggest_rules_for_high_enforcement(
        workflow_file_decisions,
        trust_signals.get('new_unapproved_events', {}),
        trust_signals.get('software_rules', {})
    )

    readiness = scorer.calculate_readiness_score(summary, detailed_analysis)
    rapid_config_analysis = build_rapid_config_analysis(
        trust_signals.get('software_rules', {}),
        trust_signals.get('new_unapproved_events', {}),
        trust_signals.get('active_computers', {}),
        settings.get('rapid_config', {}).get('excluded_configs', []),
    )
    rapid_config_readiness_score = build_rapid_config_readiness_score(rapid_config_analysis)
    readiness = apply_rapid_config_score_to_readiness(readiness, rapid_config_readiness_score)

    # Add estimated readiness gain for each suggested rule using source event count
    # as a proxy for impacted unknown files.
    base_unknown = summary.get('unknown_count', 0)
    base_approved = summary.get('approved_count', 0)
    rule_candidates = workflow_rule_suggestions.get('recommended_rules', workflow_rule_suggestions.get('candidates', []))
    enriched_rule_candidates = []
    for candidate in rule_candidates:
        covered = int(candidate.get('source_event_count', 0) or 0)
        covered = max(0, min(covered, base_unknown))

        simulated_summary = dict(summary)
        simulated_summary['unknown_count'] = max(0, base_unknown - covered)
        simulated_summary['approved_count'] = base_approved + covered

        projected = scorer.calculate_readiness_score(simulated_summary, detailed_analysis)['total_score']
        enriched = dict(candidate)
        enriched['readiness_gain_percent'] = round(projected - readiness['total_score'], 1)
        enriched_rule_candidates.append(enriched)

    if 'recommended_rules' in workflow_rule_suggestions:
        workflow_rule_suggestions['recommended_rules'] = enriched_rule_candidates
    elif 'candidates' in workflow_rule_suggestions:
        workflow_rule_suggestions['candidates'] = enriched_rule_candidates

    all_acceleration_candidates = scorer.annotate_acceleration_candidates(
        analyzer.get_acceleration_candidates(
            safe_binaries,
            trust_signals.get('all_certificates', trust_signals.get('valid_certificates', {})),
            100
        ),
        summary,
        detailed_analysis,
        safe_binaries,
        readiness['total_score'],
    )

    optimized_acceleration_plan = scorer.build_optimized_acceleration_plan(
        all_acceleration_candidates,
        safe_binaries,
        summary,
        detailed_analysis,
        target_readiness=80.0,
        max_steps=8,
    )
    # Patch current_readiness to reflect the final score including Rapid Config dimension.
    optimized_acceleration_plan['current_readiness'] = readiness['total_score']

    guardrail_checks = build_guardrail_checks(all_acceleration_candidates, workflow_rule_suggestions)
    backlog_delta_dashboard = build_backlog_delta_dashboard(readiness, all_acceleration_candidates, summary, rapid_config_analysis)
    score_audit = build_score_audit(summary, readiness, publisher_analysis)
    staged_remediation_workflow = build_staged_remediation_workflow(optimized_acceleration_plan, guardrail_checks, rapid_config_analysis)
    
    # Run the 3 new optimizers
    cert_portfolio = analyzer.analyze_certificate_portfolio(
        trust_signals.get('all_certificates', {}),
        trust_signals.get('unknown_binaries', []),
        active_computers=summary.get('active_computer_count', 0)
    )
    certificate_portfolio_analysis = build_certificate_portfolio_analysis(cert_portfolio)
    
    policy_scope = analyzer.simulate_policy_scope_impact(
        workflow_rule_suggestions,
        active_computers=summary.get('active_computer_count', 0)
    )
    policy_scope_analysis = build_policy_scope_analysis(policy_scope)
    
    file_events = trust_signals.get('new_unapproved_events', {}).get('results', []) if isinstance(trust_signals.get('new_unapproved_events'), dict) else []
    event_rules = analyzer.generate_recurring_event_rules(file_events)
    recurring_event_analysis = build_recurring_event_rules(event_rules)
    endpoint_readiness_analysis = build_endpoint_readiness_analysis(
        trust_signals.get('active_computers', {}),
        trust_signals.get('new_unapproved_events', {}),
        settings['endpoint_readiness'],
    )
    
    logger.info(f"Readiness Score: {readiness['total_score']}%")
    logger.info(f"Ready for High Enforcement: {readiness['ready_for_high_enforcement']}")
    
    # Generate strategic recommendations
    rec_engine = StrategicRecommendationEngine()
    rule_recommendations = rec_engine.generate_rule_recommendations(
        workflow_file_decisions,
        readiness['breakdown'],
        summary,
        {
            'publisher_analysis': publisher_analysis,
            'certificate_analysis': certificate_analysis,
            'prevalence_analysis': prevalence_analysis
        }
    )
    publisher_recommendations = rec_engine.generate_publisher_recommendations(
        publisher_analysis,
        workflow_file_decisions,
        readiness['breakdown']
    )
    strategic_roadmap = rec_engine.generate_strategic_roadmap(
        readiness['total_score'] / 100.0,  # Convert to decimal
        {k: v/100.0 for k, v in readiness['breakdown'].items()},  # Convert to decimal
        workflow_file_decisions,
        rule_recommendations,
        publisher_recommendations,
        summary
    )
    
    # Step 4: Generate output
    logger.info("\n[4/4] Generating output...")
    
    output = {
        'timestamp': datetime.now().isoformat(),
        'server': settings['server'],
        'collection_metadata': {
            'max_rows': settings['max_rows'],
            'catalog_total': trust_signals.get('catalog_total', 'unknown'),
            'catalog_sampled': trust_signals.get('catalog_sampled', False),
            'read_only_analysis': True,
            'api_write_operations': 0,
            'config_path': settings.get('config_path'),
        },
        'readiness_score': readiness,
        'summary': summary,
        'rapid_config_summary': {
            'enabled_relevant_percent': rapid_config_analysis.get('summary', {}).get('enabled_relevant_percent', 0.0),
            'enabled_relevant_rapid_configs': rapid_config_analysis.get('summary', {}).get('enabled_relevant_rapid_configs', 0),
            'enabled_rapid_configs': rapid_config_analysis.get('summary', {}).get('enabled_rapid_configs', 0),
            'configured_rapid_configs': rapid_config_analysis.get('summary', {}).get('configured_rapid_configs', 0),
            'environment_os_families': rapid_config_analysis.get('summary', {}).get('environment_os_families', []),
        },
        'score_audit': score_audit,
        'path_filter': {
            'safe_binaries': len(safe_binaries),
            'excluded_user_writable': len(excluded_user_writable),
            'excluded_samples': excluded_user_writable[:5]
        },
        'approval_workflow': {
            'api_diagnostics': {
                'rule_endpoint': trust_signals.get('software_rules', {}).get('resolved_rule_endpoint'),
                'rule_endpoint_error_type': trust_signals.get('software_rules', {}).get('error_type'),
                'rule_endpoint_hint': trust_signals.get('software_rules', {}).get('hint'),
                'rule_endpoints_accessible': trust_signals.get('software_rules', {}).get('rule_endpoints_accessible', []),
                'rule_endpoints_forbidden': trust_signals.get('software_rules', {}).get('rule_endpoints_forbidden', []),
                'rule_endpoints_missing': trust_signals.get('software_rules', {}).get('rule_endpoints_missing', [])
            },
            'console_setup_guidance': workflow_analyzer.get_console_setup_guidance(),
            'file_evaluation': {
                'total_files_evaluated': len(workflow_file_decisions),
                'decision_counts': {
                    'FOLLOW_COMPANY_POLICY': len([d for d in workflow_file_decisions if d['decision'] == 'FOLLOW_COMPANY_POLICY']),
                    'EXISTING_RULE_PRESENT': len([d for d in workflow_file_decisions if d['decision'] == 'EXISTING_RULE_PRESENT']),
                    'CONSIDER_APPROVING_PUBLISHER': len([d for d in workflow_file_decisions if d['decision'] == 'CONSIDER_APPROVING_PUBLISHER']),
                    'CONSIDER_LOCAL_APPROVAL': len([d for d in workflow_file_decisions if d['decision'] == 'CONSIDER_LOCAL_APPROVAL']),
                    'CONSIDER_GLOBAL_APPROVAL': len([d for d in workflow_file_decisions if d['decision'] == 'CONSIDER_GLOBAL_APPROVAL']),
                    'PROCEED_TO_CUSTOM_RULE': len([d for d in workflow_file_decisions if d['decision'] == 'PROCEED_TO_CUSTOM_RULE'])
                },
                'all_decisions': workflow_file_decisions,
                'sample_decisions': workflow_file_decisions[:30]
            },
            'custom_rule_considerations': {
                'total_events_evaluated': len(workflow_custom_rule_decisions),
                'sample_recommendations': workflow_custom_rule_decisions[:30]
            },
            'rule_suggestions': workflow_rule_suggestions
        },
        'installer_lineage': installer_analysis,
        'auto_approval_candidates': [
            {
                'file_name': b.file_name,
                'file_path': b.file_path,
                'publisher': b.publisher,
                'signer': b.signer,
                'risk_score': b.risk_score,
                'recommendation': b.recommendation
            }
            for b in safe_binaries[:20]  # Top 20 candidates from safe binaries only
            if b.recommendation == 'AUTO_APPROVE_CANDIDATE'
        ],
        'acceleration_candidates': all_acceleration_candidates[:10],
        'optimized_acceleration_plan': optimized_acceleration_plan,
        'guardrail_checks': guardrail_checks,
        'backlog_delta_dashboard': backlog_delta_dashboard,
        'staged_remediation_workflow': staged_remediation_workflow,
        'strategic_recommendations': {
            'rule_recommendations': rule_recommendations,
            'publisher_recommendations': publisher_recommendations,
            'strategic_roadmap': strategic_roadmap,
            'rapid_config_recommendations': rapid_config_analysis.get('recommendations', []),
            'prioritized_rapid_config_names': rapid_config_analysis.get('action_needed_config_names', []),
        },
        'acceleration_plan': {
            'current_readiness': readiness['total_score'],
            'target_readiness': 80.0,  # Target for high enforcement
            'gap_to_target': round(80.0 - readiness['total_score'], 1),
            'acceleration_mode': settings['acceleration_mode'],
            'total_acceleration_candidates': len(all_acceleration_candidates),
            'optimized_projected_readiness': optimized_acceleration_plan.get('projected_readiness', readiness['total_score']),
            'optimized_projected_gain': optimized_acceleration_plan.get('projected_gain', 0.0),
            'priority_actions': [
                f"Use {settings['acceleration_mode']} mode for {'faster' if settings['acceleration_mode'] == 'accelerated' else 'conservative'} approval thresholds",
                "Focus on publisher approvals for bulk file approvals",
                "Consider adding trusted installers for application deployment",
                "Review high-confidence recommendations first (70%+ confidence)",
                "Apply optimized overlap-aware action sequence before lower-impact approvals",
                "Run canary rollout gates before broad deployment"
            ]
        },
        'risks_requiring_review': [
            {
                'category': 'Low Prevalence',
                'description': f"{len(prevalence_analysis.get('single_endpoint', []))} files on single endpoint",
                'impact': 'May be legitimate but require manual review',
                'recommended_action': 'Review each file before approval'
            },
            {
                'category': 'User Writable Paths',
                'description': f"{len(excluded_user_writable)} binaries in user-writable paths",
                'impact': 'Excluded from auto-approval per security policy',
                'recommended_action': 'Review manually if approval needed'
            }
        ],
        'certificate_portfolio_analysis': certificate_portfolio_analysis,
        'policy_scope_analysis': policy_scope_analysis,
        'recurring_event_analysis': recurring_event_analysis,
        'rapid_config_analysis': rapid_config_analysis,
        'endpoint_readiness_analysis': endpoint_readiness_analysis,
    }
    
    # Write JSON output
    with open(settings['output'], 'w') as f:
        json.dump(output, f, indent=2)

    logger.info(f"Report saved to: {settings['output']}")

    # Write HTML report
    if not settings['no_html']:
        html_path = settings['html_output'] or os.path.splitext(settings['output'])[0] + '.html'
        try:
            generate_html_report(output, html_path)
            logger.info(f"HTML report saved to: {html_path}")
        except Exception as e:
            logger.warning(f"HTML report generation failed: {e}")

    # Print summary
    print("\n" + "=" * 60)
    print("ENFORCEMENT READINESS SUMMARY")
    print("=" * 60)
    print(f"Readiness Score: {readiness['total_score']}%")
    print(f"Ready for High Enforcement: {readiness['ready_for_high_enforcement']}")
    print(f"Recommendation: {readiness['recommendation']}")
    print(f"\nAuto-Approval Candidates: {len(output['auto_approval_candidates'])}")
    print(f"Risks Requiring Review: {len(output['risks_requiring_review'])}")
    print("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())