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

# Add project root to path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_collection.api_client import CBApiClient
from data_collection.collectors import EnforcementReadinessCollector
from analysis.trust_signals import TrustSignalAnalyzer, EnforcementReadinessScorer
from analysis.path_analysis import PathClassifier, InstallerLineageAnalyzer
from analysis.approval_workflow import ApprovalWorkflowAnalyzer
from llm.local_llm import LocalLLM, ExplanationGenerator
from report.html_report import generate_html_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
        trust_signals.get('trusted_publishers', {})
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
    
    logger.info(f"Readiness Score: {readiness['total_score']}%")
    logger.info(f"Ready for High Enforcement: {readiness['ready_for_high_enforcement']}")
    
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
        'acceleration_candidates': analyzer.get_acceleration_candidates(
            safe_binaries,
            trust_signals.get('all_certificates', trust_signals.get('valid_certificates', {})),
            10
        ),
        'acceleration_plan': {
            'current_readiness': readiness['total_score'],
            'target_readiness': 80.0,  # Target for high enforcement
            'gap_to_target': round(80.0 - readiness['total_score'], 1),
            'acceleration_mode': args.acceleration_mode,
            'total_acceleration_candidates': len(
                analyzer.get_acceleration_candidates(
                    safe_binaries,
                    trust_signals.get('all_certificates', trust_signals.get('valid_certificates', {})),
                    100
                )
            ),
            'priority_actions': [
                f"Use {args.acceleration_mode} mode for {'faster' if args.acceleration_mode == 'accelerated' else 'conservative'} approval thresholds",
                "Focus on publisher approvals for bulk file approvals",
                "Consider adding trusted installers for application deployment",
                "Review high-confidence recommendations first (70%+ confidence)",
                "Monitor readiness score improvements after each approval batch"
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