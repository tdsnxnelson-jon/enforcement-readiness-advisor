# Enforcement Readiness Advisor - Main Entry Point
"""
Main entry point for the Enforcement Readiness Advisor.

Usage:
    python main.py --server <cb_server> --token <api_token> [--model <model_name>]
"""

import argparse
import json
import logging
import sys
from datetime import datetime
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
from llm.local_llm import LocalLLM, ExplanationGenerator
from report.html_report import generate_html_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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


def build_backlog_delta_dashboard(readiness: Dict[str, Any], acceleration_candidates: List[Dict[str, Any]], summary: Dict[str, Any]) -> Dict[str, Any]:
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
    ]

    return {
        'current_score': current,
        'buckets': buckets,
    }


def build_staged_remediation_workflow(optimized_plan: Dict[str, Any], guardrails: Dict[str, Any]) -> Dict[str, Any]:
    """Create a practical staged rollout plan users can execute in production."""
    actions = optimized_plan.get('actions', [])
    canary_actions = actions[:3]
    broad_actions = actions[3:]

    return {
        'phase_1_canary': {
            'policy_scope': 'Pilot policy / small endpoint ring',
            'actions': canary_actions,
            'exit_criteria': [
                'No unexpected block spikes for 24 hours',
                'No high-severity guardrail violations introduced',
                'Projected score change aligns with observed unknown reduction'
            ]
        },
        'phase_2_broad_rollout': {
            'policy_scope': 'Production policies by business unit',
            'actions': broad_actions,
            'gates': [
                'Apply changes in batches of 2-3 actions',
                'Re-run readiness report between batches',
                'Pause rollout if new high-severity findings appear'
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


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Carbon Black App Control Enforcement Readiness Advisor'
    )
    parser.add_argument(
        '--server', 
        required=True,
        help='CB App Control server URL (e.g., https://server.example.com)'
    )
    parser.add_argument(
        '--token', 
        required=True,
        help='API token for authentication'
    )
    parser.add_argument(
        '--model',
        default='mistral',
        help='Ollama model name (default: mistral)'
    )
    parser.add_argument(
        '--ollama-url',
        default=None,
        help='Ollama base URL (for example http://localhost:11434 or https://ollama.internal:11434). '
             'Defaults to OLLAMA_HOST/OLLAMA_BASE_URL if set, otherwise http://localhost:11434.'
    )
    parser.add_argument(
        '--output',
        default='enforcement_readiness_report.json',
        help='Output file path (default: enforcement_readiness_report.json)'
    )
    parser.add_argument(
        '--acceleration-mode',
        choices=['conservative', 'accelerated'],
        default='conservative',
        help='Auto-approval mode: conservative (strict thresholds) or accelerated (lower thresholds for faster enforcement)'
    )
    parser.add_argument(
        '--no-llm',
        action='store_true',
        help='Skip LLM explanation generation'
    )
    parser.add_argument(
        '--verify-ssl',
        action='store_true',
        default=False,
        help='Verify SSL certificates (default: False)'
    )
    parser.add_argument(
        '--html-output',
        default=None,
        help='Path for the self-contained HTML report (e.g. report.html). '
             'If omitted, defaults to the JSON output path with a .html extension.'
    )
    parser.add_argument(
        '--no-html',
        action='store_true',
        help='Skip HTML report generation.'
    )
    parser.add_argument(
        '--max-rows',
        type=int,
        default=5000,
        help='Maximum rows to fetch per collection (default: 5000). '
             'Increase for large environments to avoid partial-sample analysis.'
    )
    return parser.parse_args()


def main():
    """Main execution function."""
    args = parse_args()
    
    logger.info("=" * 60)
    logger.info("Enforcement Readiness Advisor")
    logger.info("=" * 60)
    
    # Step 1: Initialize API client
    logger.info("\n[1/5] Connecting to CB App Control server...")
    api_client = CBApiClient(args.server, args.token, args.verify_ssl)
    
    if not api_client.test_connection():
        logger.error("Failed to connect to CB App Control server")
        sys.exit(1)
    
    logger.info("Connected successfully")
    
    # Step 2: Collect trust signal data
    logger.info("\n[2/5] Collecting trust signal data...")
    collector = EnforcementReadinessCollector(api_client, max_rows=args.max_rows)
    
    try:
        trust_signals = collector.collect_all_trust_signals()
        summary = collector.collect_summary()
    except Exception as e:
        logger.error(f"Data collection failed: {e}")
        sys.exit(1)
    
    logger.info(f"Collected data from {len(trust_signals)} sources")
    
    # Step 3: Analyze trust signals
    logger.info("\n[3/5] Analyzing trust signals...")
    analyzer = TrustSignalAnalyzer(acceleration_mode=args.acceleration_mode)
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

    guardrail_checks = build_guardrail_checks(all_acceleration_candidates, workflow_rule_suggestions)
    backlog_delta_dashboard = build_backlog_delta_dashboard(readiness, all_acceleration_candidates, summary)
    score_audit = build_score_audit(summary, readiness, publisher_analysis)
    staged_remediation_workflow = build_staged_remediation_workflow(optimized_acceleration_plan, guardrail_checks)
    
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
    
    # Step 4: Generate LLM explanations (optional)
    llm_explanation = None
    if not args.no_llm:
        logger.info("\n[4/5] Generating LLM explanations...")
        llm = LocalLLM(model=args.model, base_url=args.ollama_url)
        
        if llm.is_available():
            generator = ExplanationGenerator(llm)
            
            # Prepare analysis data for LLM
            analysis_data = {
                'unknown_binaries': unknown_analysis,
                'publisher_analysis': publisher_analysis,
                'certificate_analysis': certificate_analysis,
                'prevalence_analysis': prevalence_analysis,
                'workflow_file_decisions': len(workflow_file_decisions),
                'workflow_custom_rule_decisions': len(workflow_custom_rule_decisions),
                'workflow_rule_suggestions': workflow_rule_suggestions.get('summary', {})
            }
            
            try:
                llm_explanation = generator.generate_enforcement_readiness_explanation(
                    analysis_data,
                    readiness['total_score']
                )
                logger.info("LLM explanation generated successfully")
            except Exception as e:
                logger.warning(f"LLM explanation failed: {e}")
                llm_explanation = generator.generate_enforcement_readiness_fallback(
                    analysis_data,
                    readiness['total_score'],
                    str(e)
                )
        else:
            logger.warning(f"LLM not available at {llm.base_url} - skipping explanations")
            llm_explanation = {
                'source': 'unavailable',
                'overall_readiness_status': f'Configured Ollama service not available at {llm.base_url}. Report generated without model narrative.',
                'next_steps': [
                    f'Start Ollama at {llm.base_url} and ensure the selected model is available.',
                    'Re-run without --no-llm to include model-generated narrative.'
                ]
            }
    else:
        logger.info("\n[4/5] Skipping LLM explanations (--no-llm flag)")
        llm_explanation = {
            'source': 'disabled',
            'overall_readiness_status': 'LLM narrative generation was skipped by user request (--no-llm).',
            'next_steps': [
                'Run again without --no-llm to include a model-generated explanation.'
            ]
        }
    
    # Step 5: Generate output
    logger.info("\n[5/5] Generating output...")
    
    output = {
        'timestamp': datetime.now().isoformat(),
        'server': args.server,
        'collection_metadata': {
            'max_rows': args.max_rows,
            'catalog_total': trust_signals.get('catalog_total', 'unknown'),
            'catalog_sampled': trust_signals.get('catalog_sampled', False),
        },
        'readiness_score': readiness,
        'summary': summary,
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
            'strategic_roadmap': strategic_roadmap
        },
        'acceleration_plan': {
            'current_readiness': readiness['total_score'],
            'target_readiness': 80.0,  # Target for high enforcement
            'gap_to_target': round(80.0 - readiness['total_score'], 1),
            'acceleration_mode': args.acceleration_mode,
            'total_acceleration_candidates': len(all_acceleration_candidates),
            'optimized_projected_readiness': optimized_acceleration_plan.get('projected_readiness', readiness['total_score']),
            'optimized_projected_gain': optimized_acceleration_plan.get('projected_gain', 0.0),
            'priority_actions': [
                f"Use {args.acceleration_mode} mode for {'faster' if args.acceleration_mode == 'accelerated' else 'conservative'} approval thresholds",
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
        'llm_explanation': llm_explanation
    }
    
    # Write JSON output
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)

    logger.info(f"Report saved to: {args.output}")

    # Write HTML report
    if not args.no_html:
        html_path = args.html_output or os.path.splitext(args.output)[0] + '.html'
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