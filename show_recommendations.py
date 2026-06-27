#!/usr/bin/env python3
import json

data = json.load(open('enforcement_readiness_report.json'))
recs = data.get('strategic_recommendations', {})

print('\n' + '=' * 70)
print('STRATEGIC RECOMMENDATIONS GENERATED')
print('=' * 70)

# Rule recommendations
rules = recs.get('rule_recommendations', [])
print(f'\n1. RULE RECOMMENDATIONS: {len(rules)} rules to create')
for i, rule in enumerate(rules, 1):
    print(f'\n   Rule {i}: {rule.get("rule_name")}')
    print(f'   Type: {rule.get("rule_type")}')
    print(f'   Pattern: {rule.get("file_pattern")}')
    print(f'   Files Covered: {rule.get("estimated_files_covered")}')
    print(f'   Score Gain: +{rule.get("estimated_score_gain")}%')
    print(f'   Priority: {rule.get("priority")}')
    print(f'   Action: {rule.get("console_action")}')

# Publisher recommendations
pubs = recs.get('publisher_recommendations', [])
print(f'\n2. PUBLISHER RECOMMENDATIONS: {len(pubs)} publishers to trust')
for i, pub in enumerate(pubs[:3], 1):  # Show first 3
    print(f'\n   Publisher {i}: {pub.get("publisher_name")}')
    print(f'   Files Signed: {pub.get("files_signed")}')
    print(f'   Score Gain: +{pub.get("estimated_score_gain")}%')
    print(f'   Rationale: {pub.get("rationale")}')

# Strategic roadmap
roadmap = recs.get('strategic_roadmap', {})
print(f'\n3. STRATEGIC ROADMAP TO 80%:')
print(f'   Current Score: {roadmap.get("current_score") * 100:.1f}%')
print(f'   Target Score: {roadmap.get("target_score")}%')
print(f'   Gap: {roadmap.get("gap"):.1f}%')
print(f'   Estimated Final Score: {roadmap.get("estimated_final_score")}%')
print(f'   Total Effort: {roadmap.get("total_estimated_effort")}')

steps = roadmap.get('steps', [])
print(f'\n   Steps ({len(steps)} total):')
for step in steps:
    priority = step.get('priority')
    action = step.get('action')
    gain = step.get('estimated_gain')
    score = step.get('estimated_score')
    effort = step.get('effort')
    risk = step.get('risk')
    print(f'\n     Step {priority}: {action}')
    print(f'       Gain: +{gain}% → {score}%')
    print(f'       Effort: {effort}')
    print(f'       Risk: {risk}')
    print(f'       Details: {step.get("details")}')

print('\n' + '=' * 70)
