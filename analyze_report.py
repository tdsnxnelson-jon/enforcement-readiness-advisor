#!/usr/bin/env python3
import json

data = json.load(open('enforcement_readiness_report.json'))

print("=" * 60)
print("READINESS SCORE BREAKDOWN")
print("=" * 60)
breakdown = data['readiness_score']['breakdown']
for key, val in breakdown.items():
    print(f"{key:25} {val:6.1f}%")

print("\n" + "=" * 60)
print("CERTIFICATE ANALYSIS")
print("=" * 60)
cert = data.get('certificate_portfolio_analysis', {})
violations = cert.get('violations_detected')
if isinstance(violations, dict):
    print(f"Violations:")
    for key, val in violations.items():
        print(f"  {key:30} {val:6}")
else:
    print(f"Violations Detected: {violations}")
    
print(f"Potential Gain: {cert.get('total_potential_gain', 0):.1f}%")

print("\n" + "=" * 60)
print("APPROVAL WORKFLOW DECISIONS")
print("=" * 60)
workflow = data['approval_workflow']['file_evaluation']
counts = workflow.get('decision_counts', {})
for key, val in counts.items():
    print(f"{key:40} {val:6}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
summary = data['summary']
for key, val in summary.items():
    print(f"{key:30} {val:6}")
