"""Strategic recommendations for reaching enforcement readiness targets."""

from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
from collections import defaultdict


@dataclass
class RuleRecommendation:
    """Recommended rule to create for batch approval."""
    rule_type: str
    rule_name: str
    file_pattern: str
    rationale: str
    estimated_files_covered: int
    estimated_score_gain: float
    safety_checks: List[str]
    console_action: str
    priority: str


@dataclass
class PublisherRecommendation:
    """Recommended publisher to trust."""
    publisher_name: str
    current_status: str
    files_signed: int
    rationale: str
    risk_level: str
    estimated_score_gain: float
    recommendation: str


class StrategicRecommendationEngine:
    """Generates strategic recommendations for enforcement readiness."""

    def __init__(self):
        pass

    def _extract_path_patterns(self, file_decisions: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """Extract and group files by path patterns."""
        patterns = defaultdict(list)
        
        for decision in file_decisions:
            path = str(decision.get("file_path", "")).lower()
            
            # Categorize by path pattern
            if "\\windows\\system32\\" in path:
                patterns["system32"].append(decision)
            elif "\\windows\\system32\\drivers" in path:
                patterns["drivers"].append(decision)
            elif "\\windows\\uus\\" in path:
                patterns["windows_update"].append(decision)
            elif any(virt in path for virt in ["qemu", "virtio", "spice", "balloon", "vioser"]):
                patterns["hypervisor"].append(decision)
            elif "\\program files\\" in path:
                patterns["program_files"].append(decision)
            elif "\\windows\\" in path:
                patterns["windows_other"].append(decision)
            else:
                patterns["other"].append(decision)
        
        return patterns

    def generate_rule_recommendations(
        self,
        file_decisions: List[Dict[str, Any]],
        readiness_breakdown: Dict[str, float],
        summary: Dict[str, Any],
        detailed_analysis: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Generate rule creation recommendations based on file patterns."""
        recommendations = []
        
        patterns = self._extract_path_patterns(file_decisions)
        
        # Rule 1: System32 binaries (include FOLLOW_COMPANY_POLICY, CONSIDER_LOCAL_APPROVAL, etc.)
        if patterns.get("system32"):
            files = patterns["system32"]
            recommendations.append(asdict(RuleRecommendation(
                rule_type="Trusted Path Rule",
                rule_name="Windows System32 Binaries Trust Rule",
                file_pattern="C:\\Windows\\System32\\*.exe, C:\\Windows\\System32\\*.dll",
                rationale=f"Trust {len(files)} legitimate Windows binaries in System32. These are core OS files required for system operation and third-party software compatibility.",
                estimated_files_covered=len(files),
                estimated_score_gain=2.5,
                safety_checks=[
                    "Limit scope to C:\\Windows\\System32 only",
                    "Require Windows/Microsoft publisher",
                    "Enable audit logging for all executions",
                    "Exclude any unsigned binaries"
                ],
                console_action="Policy > Rules > New > Trusted Path Rule > Path: C:\\Windows\\System32 > Filter: Publisher contains 'Microsoft'",
                priority="HIGH"
            )))
        
        # Rule 2: System drivers
        if patterns.get("drivers"):
            files = patterns["drivers"]
            recommendations.append(asdict(RuleRecommendation(
                rule_type="Trusted Path Rule",
                rule_name="System Drivers Trust Rule",
                file_pattern="C:\\Windows\\System32\\drivers\\*.sys, C:\\Windows\\System32\\driverstore\\*",
                rationale=f"Trust {len(files)} system driver files. These are required for hardware compatibility and system stability.",
                estimated_files_covered=len(files),
                estimated_score_gain=1.8,
                safety_checks=[
                    "Restrict to drivers subdirectories only",
                    "Require Windows driver signature",
                    "Exclude user-writable locations",
                    "Monitor for unsigned drivers"
                ],
                console_action="Policy > Rules > New > Trusted Path Rule > Path: C:\\Windows\\System32\\drivers > Filter: Requires valid signature",
                priority="HIGH"
            )))
        
        # Rule 3: Windows Update staging
        if patterns.get("windows_update"):
            files = patterns["windows_update"]
            recommendations.append(asdict(RuleRecommendation(
                rule_type="Trusted Path Rule",
                rule_name="Windows Update Staging Trust Rule",
                file_pattern="C:\\Windows\\UUS\\*",
                rationale=f"Trust {len(files)} Windows Update staging files. Required for Windows Update for Business feature deployment.",
                estimated_files_covered=len(files),
                estimated_score_gain=0.8,
                safety_checks=[
                    "Limit to C:\\Windows\\UUS only",
                    "Verify Microsoft signature",
                    "Enable detailed audit logging"
                ],
                console_action="Policy > Rules > New > Trusted Path Rule > Path: C:\\Windows\\UUS > Filter: Microsoft Publisher",
                priority="MEDIUM"
            )))
        
        # Rule 4: Hypervisor/VM drivers
        if patterns.get("hypervisor"):
            files = patterns["hypervisor"]
            recommendations.append(asdict(RuleRecommendation(
                rule_type="Trusted Path Rule",
                rule_name="Hypervisor Guest Drivers Trust Rule",
                file_pattern="C:\\Program Files\\QEMU\\*, C:\\Program Files\\Spice Agent\\*, C:\\Program Files\\VirtIO-Win\\*",
                rationale=f"Trust {len(files)} guest drivers (QEMU, VirtIO, Spice). Required for VM operation in virtualized environments.",
                estimated_files_covered=len(files),
                estimated_score_gain=1.2,
                safety_checks=[
                    "Limit to official hypervisor vendor directories only",
                    "Verify vendor certificate authenticity",
                    "Log installations and updates"
                ],
                console_action="Policy > Rules > New > Trusted Path Rule > Add VM driver vendor directories",
                priority="MEDIUM"
            )))
        
        # Rule 5: Other Windows directories
        if patterns.get("windows_other"):
            files = patterns["windows_other"]
            if len(files) >= 5:
                recommendations.append(asdict(RuleRecommendation(
                    rule_type="Trusted Directory Rule",
                    rule_name="Windows Directory Trust Rule",
                    file_pattern="C:\\Windows\\*",
                    rationale=f"Trust {len(files)} additional legitimate Windows binaries. These are in protected system directories.",
                    estimated_files_covered=len(files),
                    estimated_score_gain=1.0,
                    safety_checks=[
                        "Verify Windows directory permissions are properly restricted",
                        "Require administrator privileges for file modifications",
                        "Enable change tracking and alerting"
                    ],
                    console_action="Policy > Rules > New > Trusted Directory Rule > Path: C:\\Windows",
                    priority="MEDIUM"
                )))
        
        return recommendations

    def generate_publisher_recommendations(
        self,
        publisher_analysis: Dict[str, Any],
        file_decisions: List[Dict[str, Any]],
        readiness_breakdown: Dict[str, float],
    ) -> List[Dict[str, Any]]:
        """Generate publisher trust recommendations."""
        recommendations = []
        
        # Count files per publisher
        publisher_counts: Dict[str, int] = defaultdict(int)
        for decision in file_decisions:
            if decision.get("decision") in ["CONSIDER_LOCAL_APPROVAL", "CONSIDER_GLOBAL_APPROVAL", "CONSIDER_APPROVING_PUBLISHER"]:
                pub = decision.get("publisher", "Unknown")
                if pub and pub not in ["Unknown", ""]:
                    publisher_counts[pub] += 1
        
        # Create recommendations for top publishers
        sorted_pubs = sorted(publisher_counts.items(), key=lambda x: x[1], reverse=True)
        for publisher, count in sorted_pubs[:5]:
            recommendations.append(asdict(PublisherRecommendation(
                publisher_name=publisher,
                current_status="unknown",
                files_signed=count,
                rationale=f"Publisher '{publisher}' is the source of {count} files in your environment. Trusting this publisher would improve readiness.",
                risk_level="MEDIUM",
                estimated_score_gain=0.5,
                recommendation=f"Research '{publisher}' online. If reputable, trust via Policy > Publishers > Trust. ~0.5% improvement per publisher."
            )))
        
        return recommendations

    def generate_strategic_roadmap(
        self,
        current_score: float,
        readiness_breakdown: Dict[str, float],
        file_decisions: List[Dict[str, Any]],
        rule_recommendations: List[Dict[str, Any]],
        publisher_recommendations: List[Dict[str, Any]],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a prioritized roadmap to reach 80% readiness."""
        target = 80.0
        current_pct = current_score * 100
        gap = target - current_pct
        
        steps = []
        
        # Step 1: Create batch-approval rules
        rule_gains = sum(r.get("estimated_score_gain", 0) for r in rule_recommendations)
        score_after_rules = current_pct + rule_gains
        
        steps.append({
            "priority": 1,
            "action": "Create Batch-Approval Rules",
            "details": f"Create {len(rule_recommendations)} trusted path/directory rules for system files, drivers, and VM components",
            "estimated_gain": round(rule_gains, 1),
            "estimated_score": round(min(score_after_rules, 100), 1),
            "effort": "Medium (5-10 minutes per rule in console)",
            "risk": "Low - restricted to known safe paths",
            "console_steps": [r.get("console_action") for r in rule_recommendations],
            "recommendations": [
                {
                    "name": r.get("rule_name"),
                    "type": r.get("rule_type"),
                    "pattern": r.get("file_pattern"),
                    "files_covered": r.get("estimated_files_covered"),
                    "priority": r.get("priority"),
                    "rationale": r.get("rationale"),
                }
                for r in rule_recommendations
            ]
        })
        
        # Step 2: Trust additional publishers
        pub_gains = sum(p.get("estimated_score_gain", 0) for p in publisher_recommendations)
        score_after_pubs = score_after_rules + pub_gains
        
        # Always include Step 2 for continuity, even if no publishers identified
        step2_details = f"Trust {len(publisher_recommendations)} publishers with files in your environment" if publisher_recommendations else "No additional publishers identified from current file decisions"
        step2_effort = "Low (2-3 minutes per publisher reputation check)" if publisher_recommendations else "N/A - No candidates identified"
        step2_console = [
            f"Policy > Publishers > Search '{p.get('publisher_name')}' > Review > Trust if reputable"
            for p in publisher_recommendations
        ] if publisher_recommendations else ["Check Policy > Publishers for any reputable publishers already in your environment"]
        
        steps.append({
            "priority": 2,
            "action": "Trust Additional Publishers",
            "details": step2_details,
            "estimated_gain": round(pub_gains, 1),
            "estimated_score": round(min(score_after_pubs, 100), 1),
            "effort": step2_effort,
            "risk": "Medium - requires reputation research" if publisher_recommendations else "N/A",
            "console_steps": step2_console,
            "recommendations": [
                {
                    "name": p.get("publisher_name"),
                    "files_signed": p.get("files_signed"),
                    "recommendation": p.get("recommendation"),
                }
                for p in publisher_recommendations
            ] if publisher_recommendations else []
        })
        
        # Step 3: Address remaining gap
        remaining_gap = target - score_after_pubs
        
        steps.append({
            "priority": 3,
            "action": "Close Remaining Gap",
            "details": f"Remaining gap: {remaining_gap:.1f}%",
            "estimated_gain": 0,  # Informational only
            "estimated_score": round(score_after_pubs, 1),
            "effort": "Ongoing - operational feedback required",
            "risk": "Variable",
            "console_steps": [
                "Monitor event logs for recurring file execution patterns",
                "Build case-by-case approvals or rules as evidence accumulates",
                "Trust publishers incrementally as organizational confidence grows",
            ],
            "recommendations": [
                f"Remaining {remaining_gap:.1f}% requires additional operational context",
                "Focus on legitimate rules and publisher approvals, not score manipulation",
                "Let prevalence scores improve naturally through operational use",
                "These decisions should be driven by real security needs, not metrics"
            ]
        })
        
        return {
            "current_score": current_score,
            "current_score_pct": round(current_pct, 1),
            "target_score": target,
            "gap": round(gap, 1),
            "achievable_without_approvals": f"With rules and publishers → ~{round(min(score_after_pubs, 100), 1)}%",
            "steps": steps,
            "total_estimated_effort": "20-40 minutes for core rule and publisher recommendations",
            "success_criteria": f"Reach {target}% readiness for high enforcement capability"
        }
