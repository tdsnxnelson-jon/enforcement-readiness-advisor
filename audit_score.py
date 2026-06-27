#!/usr/bin/env python3
"""Verify if the 65.5% score is legitimate or manipulated."""
import json

data = json.load(open('enforcement_readiness_report.json'))
summary = data['summary']
scores = data['readiness_score']['breakdown']
weights = data['readiness_score']['weights']

print("=" * 70)
print("SCORE LEGITIMACY AUDIT")
print("=" * 70)

print("\n1. RAW API DATA (from server):")
print(f"   Unknown binaries:     {summary['unknown_count']:6}")
print(f"   Approved binaries:    {summary['approved_count']:6}")
print(f"   Active computers:     {summary['active_computer_count']:6}")

print("\n2. SCORE BREAKDOWN:")
for component in ['unknown_binaries', 'publisher_trust', 'certificate_trust', 'prevalence', 'computer_coverage']:
    score = scores[component]
    weight = weights[component]
    print(f"   {component:25} {score:6.1f}% × {weight:.2f} weight")

print("\n3. WEIGHTED TOTAL CALCULATION:")
total = 0
for component in scores.keys():
    contribution = (scores[component] / 100) * weights[component]
    total += contribution
    print(f"   {component:25} ({scores[component]:.1f}% × {weights[component]}) = {contribution*100:.2f}%")
    
total_pct = total * 100
print(f"\n   CALCULATED TOTAL: {total_pct:.1f}%")
print(f"   REPORTED TOTAL:   {data['readiness_score']['total_score']:.1f}%")
print(f"   MATCH: {'✓ YES' if abs(total_pct - data['readiness_score']['total_score']) < 0.1 else '✗ NO - DISCREPANCY'}")

print("\n4. LEGITIMACY QUESTIONS:")
# Unknown binaries score
total_files = summary['unknown_count'] + summary['approved_count']
if total_files > 0:
    unknown_ratio = summary['unknown_count'] / total_files
    expected_unknown_score = (1 - unknown_ratio) * 100
    print(f"\n   ✓ Unknown binaries score:")
    print(f"     {summary['unknown_count']} unknown / {total_files} total = {unknown_ratio*100:.1f}% unknown")
    print(f"     Expected score: {expected_unknown_score:.1f}%")
    print(f"     Actual score:   {scores['unknown_binaries']:.1f}%")
    if abs(expected_unknown_score - scores['unknown_binaries']) > 1:
        print(f"     ⚠️  POSSIBLE MANIPULATION - scores don't match")
    else:
        print(f"     ✓ LEGITIMATE")

# Publisher trust
trusted = summary.get('trusted_publisher_count', 0)
blocked = summary.get('blocked_publisher_count', 0)
print(f"\n   ✓ Publisher trust score:")
print(f"     {trusted} trusted publishers, {blocked} blocked")
print(f"     Score: {scores['publisher_trust']:.1f}%")
if scores['publisher_trust'] == 100 and (trusted == 0 or blocked > 0):
    print(f"     ⚠️  SUSPICIOUS - maxed at 100% despite low/blocked data")

# Certificate trust
print(f"\n   ✓ Certificate trust score: {scores['certificate_trust']:.1f}%")
certs = data.get('certificate_portfolio_analysis', {})
violations = certs.get('violations_detected', 0)
print(f"     Violations detected: {violations}")
if violations > 0 and scores['certificate_trust'] == 100:
    print(f"     ⚠️  SUSPICIOUS - 100% despite {violations} violations")

# Prevalence  
computers = summary.get('active_computer_count', 0)
print(f"\n   ✓ Prevalence score: {scores['prevalence']:.1f}%")
print(f"     Only {computers} computers in environment")
if computers <= 10:
    print(f"     ⚠️  SMALL LAB - prevalence score may not be reliable")

# Computer coverage
print(f"\n   ✓ Computer coverage score: {scores['computer_coverage']:.1f}%")
print(f"     {computers} computers detected")

print("\n" + "=" * 70)
