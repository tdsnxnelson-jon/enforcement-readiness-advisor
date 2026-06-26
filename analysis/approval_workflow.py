"""Approval workflow analysis aligned to Broadcom App Control best practices.

Implements:
1) File-level approval workflow decisions
2) Custom-rule consideration from event descriptions
3) Rule suggestions for moving toward High Enforcement
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from .trust_signals import BinaryAnalysis


@dataclass
class FileWorkflowDecision:
    """Decision outcome for one unapproved file."""

    file_name: str
    file_path: str
    file_id: str
    decision: str
    rationale: str
    recommended_next_step: str
    rule_exists: bool
    recurring_event_likelihood: str


@dataclass
class CustomRuleDecision:
    """Custom-rule decision based on event description patterns."""

    event_id: str
    file_path: str
    description: str
    signal_type: str
    recommendation: str
    rule_type: Optional[str]
    action: Optional[str]
    rationale: str


@dataclass
class RuleSuggestion:
    """Suggested rule candidate to reduce recurring approvals safely."""

    rule_name: str
    rule_type: str
    operation: str
    action: str
    process_pattern: str
    file_pattern: str
    user_scope: str
    source_event_count: int
    confidence: float
    expected_enforcement_impact: str
    rationale: str
    safety_checks: List[str]


class ApprovalWorkflowAnalyzer:
    """Analyzes App Control workflow decisions for unapproved files and rules."""

    CONSOLE_SETUP = {
        "report": "Reports > Events",
        "filters": [
            "Subtype = New Unapproved File to Computer",
            "First Execution Date is specified",
            "File State = Unapproved",
        ],
        "columns": [
            "Timestamp",
            "File First Execution Date",
            "Subtype",
            "Source",
            "Description",
            "User",
            "Process Name",
            "File Prevalence",
            "File Trust",
        ],
        "group_by": "Process Descending by Count",
        "subgroup_by": "File Path Descending by Count",
    }

    RULE_SOURCE_TIERS = {
        "high": {
            "/api/bit9platform/v1/executionControlRule",
            "/api/bit9platform/v1/fileCreationControlRule",
            "/api/bit9platform/v1/trustedPathRule",
            "/api/bit9platform/v1/advancedRule",
            "/api/bit9platform/v1/expertRule",
        },
        "medium": {
            "/api/bit9platform/v1/trustedDirectory",
            "/api/bit9platform/v1/trustedUser",
            "/api/bit9platform/v1/rapidConfig",
            "/api/bit9platform/v1/updater",
        },
        "low": {
            "/api/bit9platform/v1/scriptRule",
        },
    }

    def __init__(self, high_prevalence_threshold: int = 10, recurring_event_threshold: int = 3):
        self.high_prevalence_threshold = high_prevalence_threshold
        self.recurring_event_threshold = recurring_event_threshold

    def get_console_setup_guidance(self) -> Dict[str, Any]:
        return self.CONSOLE_SETUP

    def evaluate_each_file(
        self,
        binaries: List[BinaryAnalysis],
        publisher_analysis: Dict[str, Any],
        event_data: Optional[Dict[str, Any]] = None,
        software_rules: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        trusted_publishers = {
            (p.get("name") or "").strip().lower()
            for p in publisher_analysis.get("trusted", [])
            if (p.get("name") or "").strip()
        }

        rules_text = self._flatten_rules_text(software_rules)
        recurring_counts = self._build_event_counts(event_data)

        decisions: List[Dict[str, Any]] = []
        for binary in binaries:
            decision = self._evaluate_single_file(binary, trusted_publishers, recurring_counts, rules_text)
            decisions.append(asdict(decision))

        return decisions

    def consider_custom_rule(self, event_data: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        events = self._extract_rows(event_data)
        recommendations: List[Dict[str, Any]] = []

        for event in events:
            description = str(event.get("description") or "")
            desc_upper = description.upper()

            if any(
                marker in desc_upper
                for marker in [
                    "DISCOVEREDBY: KERNEL: WRITE",
                    "DISCOVEREDBY: KERNEL: CREATE",
                    "DISCOVEREDBY: KERNEL: RENAME",
                ]
            ):
                recommendations.append(
                    asdict(
                        CustomRuleDecision(
                            event_id=str(event.get("id") or ""),
                            file_path=str(event.get("filePath") or event.get("pathName") or ""),
                            description=description,
                            signal_type="file_creation",
                            recommendation="Consider File Creation Control rule for recurring writes",
                            rule_type="File Creation Control",
                            action="Approve",
                            rationale=(
                                "Write/create/rename discovery indicates a better fit for local approval via "
                                "File Creation Control than broad execution bypasses."
                            ),
                        )
                    )
                )
                continue

            if any(
                marker in desc_upper
                for marker in [
                    "DISCOVEREDBY: KERNEL: SCRIPT EXECUTE",
                    "DISCOVEREDBY: KERNEL: EXECUTE",
                ]
            ):
                recommendations.append(
                    asdict(
                        CustomRuleDecision(
                            event_id=str(event.get("id") or ""),
                            file_path=str(event.get("filePath") or event.get("pathName") or ""),
                            description=description,
                            signal_type="execution",
                            recommendation="Consider Execution Control only if write-based local approval is not viable",
                            rule_type="Execution Control",
                            action="Allow",
                            rationale="Execution-only discovery should be treated as an exception path and tightly constrained.",
                        )
                    )
                )

        return recommendations

    def suggest_rules_for_high_enforcement(
        self,
        file_decisions: List[Dict[str, Any]],
        event_data: Optional[Dict[str, Any]] = None,
        software_rules: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        source_quality = self._build_rule_source_quality(software_rules)
        events = self._extract_rows(event_data)
        eligible_paths = {
            str(d.get("file_path") or "").strip().lower()
            for d in file_decisions
            if d.get("decision")
            in {
                "CONSIDER_LOCAL_APPROVAL",
                "CONSIDER_GLOBAL_APPROVAL",
                "PROCEED_TO_CUSTOM_RULE",
                "CONSIDER_APPROVING_PUBLISHER",
                "EXISTING_RULE_PRESENT",
            }
        }

        grouped: Dict[str, Dict[str, Any]] = {}
        execute_groups: Dict[str, int] = {}

        for event in events:
            discovery = self._discovery_signal(str(event.get("description") or ""))
            if not discovery:
                continue

            process = self._normalize_process(
                event.get("processName") or event.get("process") or event.get("source") or event.get("parent")
            )
            raw_path = str(event.get("filePath") or event.get("pathName") or "")
            event_path = raw_path.strip().lower()

            if eligible_paths and not self._path_matches_allowed(event_path, eligible_paths):
                continue

            pattern = self._to_file_pattern(raw_path)
            extension = self._extract_extension(raw_path)
            user_scope = str(event.get("user") or event.get("userName") or "Any User")

            key = "|".join([discovery, process, pattern, user_scope])
            if key not in grouped:
                grouped[key] = {
                    "discovery": discovery,
                    "process": process,
                    "pattern": pattern,
                    "user_scope": user_scope,
                    "count": 0,
                    "extension": extension,
                }
            grouped[key]["count"] += 1

            if discovery in {"kernel_execute", "kernel_script_execute"}:
                execute_key = "|".join([process, pattern, extension])
                execute_groups[execute_key] = execute_groups.get(execute_key, 0) + 1

        suggestions: List[Dict[str, Any]] = []
        for group in grouped.values():
            count = group["count"]
            if count < self.recurring_event_threshold:
                continue

            discovery = group["discovery"]
            process = group["process"]
            pattern = group["pattern"]
            user_scope = self._normalize_user_scope(group["user_scope"])
            ext = group["extension"]

            if discovery in {"kernel_write", "kernel_create", "kernel_rename"}:
                suggestions.append(
                    asdict(
                        RuleSuggestion(
                            rule_name=f"Auto - Local Approval - {process} -> {pattern}",
                            rule_type="File Creation Control",
                            operation="Write/Modify",
                            action="Approve",
                            process_pattern=process,
                            file_pattern=pattern,
                            user_scope=user_scope,
                            source_event_count=count,
                            confidence=self._confidence_from_count(count, base=0.62),
                            expected_enforcement_impact="Reduces repeat New Unapproved File events by locally approving recurring write paths.",
                            rationale=(
                                "Broadcom guidance prioritizes local approvals for Kernel:Write/Create/Rename "
                                "because later execution uses file hash approval."
                            ),
                            safety_checks=[
                                "Derive from New Unapproved File to Computer events, not block events.",
                                "Start narrow, then expand wildcard scope only with evidence.",
                                "Apply in policy scope first when app usage is department-specific.",
                            ],
                        )
                    )
                )

                exec_key = "|".join([process, pattern, ext])
                if ext in {".tmp", ".log", ".etl", ".obj", ".pch", ".ilk"} and execute_groups.get(exec_key, 0) == 0 and count >= 10:
                    suggestions.append(
                        asdict(
                            RuleSuggestion(
                                rule_name=f"Auto - Performance Optimization - {process} {ext or '*'}",
                                rule_type="Performance Optimization",
                                operation="Write Ignore",
                                action="Ignore",
                                process_pattern=process,
                                file_pattern=pattern,
                                user_scope=user_scope,
                                source_event_count=count,
                                confidence=self._confidence_from_count(count, base=0.55),
                                expected_enforcement_impact="Lowers event and analysis load for non-executed, high-churn file writes.",
                                rationale="Use Write Ignore only for heavy write activity where those files do not execute.",
                                safety_checks=[
                                    "Validate that ignored files are non-executable/transient.",
                                    "Avoid broad Any Path patterns for processes that can write executable files.",
                                    "Re-check for new execute events after rollout.",
                                ],
                            )
                        )
                    )

            if discovery in {"kernel_execute", "kernel_script_execute"}:
                is_unc = pattern.startswith("\\\\")
                suggestions.append(
                    asdict(
                        RuleSuggestion(
                            rule_name=f"Auto - Execution Allow - {process} -> {pattern}",
                            rule_type="Execution Control",
                            operation="Execute",
                            action="Allow",
                            process_pattern=process,
                            file_pattern=pattern,
                            user_scope=user_scope,
                            source_event_count=count,
                            confidence=self._confidence_from_count(count, base=0.58 if is_unc else 0.48),
                            expected_enforcement_impact="Allows recurring execution-only discoveries where local approval is unavailable.",
                            rationale="Execution Control should be sparing and bounded, mainly for UNC/network paths or explicit runtime constraints.",
                            safety_checks=[
                                "For local paths, check for over-broad Performance Optimization or Kernel Exclusion first.",
                                "Do not pair Execute with Approve due to performance impact.",
                                "Keep process/path/user constraints narrow.",
                            ],
                        )
                    )
                )

        # When event-based suggestions are insufficient, derive rules directly from
        # file decisions using path/publisher/extension grouping. This covers the
        # common case where the App Control server does not populate detailed kernel
        # discovery markers in event descriptions.
        if len(suggestions) < 3:
            suggestions.extend(self._suggest_rules_from_file_decisions(file_decisions))

        anti_patterns = self._detect_rule_antipatterns(software_rules)
        weighted_suggestions = self._apply_source_quality_weighting(suggestions, source_quality)
        ranked = self._dedupe_and_rank_suggestions(weighted_suggestions)

        return {
            "strategy_notes": [
                "Prioritize File Creation Control Approve for Kernel write/create/rename discovery.",
                "Use Execution Control Allow sparingly, mainly for UNC/network paths or strict runtime constraints.",
                "Do not build custom rules from execute block events.",
                "Manage expansion by minimizing Path x Process x User combinations.",
            ],
            "recommended_rules": ranked[:50],
            "rule_anti_patterns_detected": anti_patterns,
            "summary": {
                "total_candidates": len(ranked),
                "high_confidence_candidates": len([s for s in ranked if s.get("weighted_confidence", s.get("confidence", 0)) >= 0.75]),
                "anti_pattern_count": len(anti_patterns),
                "source_quality": source_quality,
            },
        }

    def _evaluate_single_file(
        self,
        binary: BinaryAnalysis,
        trusted_publishers: set,
        recurring_counts: Dict[str, int],
        rules_text: str,
    ) -> FileWorkflowDecision:
        publisher = (binary.publisher or "").strip().lower()
        file_key = (binary.file_path or binary.file_name or "").strip().lower()

        if not self._is_trustworthy_and_allowed(binary, trusted_publishers):
            return FileWorkflowDecision(
                file_name=binary.file_name,
                file_path=binary.file_path,
                file_id=binary.file_id,
                decision="FOLLOW_COMPANY_POLICY",
                rationale="File is not sufficiently trustworthy based on trust/threat signals and reputation.",
                recommended_next_step="Do not auto-approve; follow policy and manual investigation process.",
                rule_exists=False,
                recurring_event_likelihood="low",
            )

        if file_key and file_key in rules_text:
            return FileWorkflowDecision(
                file_name=binary.file_name,
                file_path=binary.file_path,
                file_id=binary.file_id,
                decision="EXISTING_RULE_PRESENT",
                rationale="Application appears to already have a rule entry.",
                recommended_next_step="Review existing Software Rule/Rapid Config before creating a new rule.",
                rule_exists=True,
                recurring_event_likelihood=self._recurrence_label(recurring_counts.get(file_key, 0)),
            )

        if bool(binary.signer) and publisher in trusted_publishers:
            return FileWorkflowDecision(
                file_name=binary.file_name,
                file_path=binary.file_path,
                file_id=binary.file_id,
                decision="CONSIDER_APPROVING_PUBLISHER",
                rationale="Binary is signed and publisher is currently trusted.",
                recommended_next_step="Evaluate publisher-level approval to reduce repetitive approvals.",
                rule_exists=False,
                recurring_event_likelihood=self._recurrence_label(recurring_counts.get(file_key, 0)),
            )

        if binary.prevalence < self.high_prevalence_threshold:
            return FileWorkflowDecision(
                file_name=binary.file_name,
                file_path=binary.file_path,
                file_id=binary.file_id,
                decision="CONSIDER_LOCAL_APPROVAL",
                rationale="Prevalence is low; broad approval could introduce unnecessary risk.",
                recommended_next_step="Consider approving this file locally on affected endpoints.",
                rule_exists=False,
                recurring_event_likelihood=self._recurrence_label(recurring_counts.get(file_key, 0)),
            )

        recurring_count = recurring_counts.get(file_key, 0)
        if self._is_common_application(binary) and recurring_count >= self.recurring_event_threshold:
            return FileWorkflowDecision(
                file_name=binary.file_name,
                file_path=binary.file_path,
                file_id=binary.file_id,
                decision="PROCEED_TO_CUSTOM_RULE",
                rationale="File has high prevalence and recurring unapproved activity that is likely operational.",
                recommended_next_step="Proceed to custom-rule workflow to reduce repeat manual approvals.",
                rule_exists=False,
                recurring_event_likelihood=self._recurrence_label(recurring_count),
            )

        return FileWorkflowDecision(
            file_name=binary.file_name,
            file_path=binary.file_path,
            file_id=binary.file_id,
            decision="CONSIDER_GLOBAL_APPROVAL",
            rationale="File is prevalent but recurring behavior does not strongly justify a custom rule yet.",
            recommended_next_step="Consider global approval for this file after policy review.",
            rule_exists=False,
            recurring_event_likelihood=self._recurrence_label(recurring_count),
        )

    def _suggest_rules_from_file_decisions(
        self, file_decisions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Generate rule suggestions by grouping unapproved file decisions by directory,
        extension, and publisher. Used when kernel discovery event data is unavailable.
        """
        from collections import defaultdict

        # Group CONSIDER_LOCAL_APPROVAL files by (parent_dir, extension)
        dir_ext_groups: Dict[tuple, List[Dict]] = defaultdict(list)
        # Group CONSIDER_APPROVING_PUBLISHER files by publisher
        publisher_groups: Dict[str, List[Dict]] = defaultdict(list)
        # Group CONSIDER_GLOBAL_APPROVAL / PROCEED_TO_CUSTOM_RULE by dir
        global_dir_groups: Dict[str, List[Dict]] = defaultdict(list)

        for d in file_decisions:
            decision = d.get("decision", "")
            file_path = str(d.get("file_path") or "").strip().lower().replace("/", "\\")
            file_name = str(d.get("file_name") or "").strip().lower()

            # Determine parent dir and extension from file_path + file_name
            # file_path may already be directory-only (no extension in last segment)
            if file_name and "." in file_name:
                ext = "." + file_name.rsplit(".", 1)[-1]
                parent_dir = file_path if file_path else "<unknown>"
            elif "." in file_path.split("\\")[-1]:
                last = file_path.split("\\")[-1]
                ext = "." + last.rsplit(".", 1)[-1]
                parent_dir = file_path[: file_path.rfind("\\")] if "\\" in file_path else file_path
            else:
                ext = ""
                parent_dir = file_path if file_path else "<unknown>"

            if decision == "CONSIDER_LOCAL_APPROVAL":
                dir_ext_groups[(parent_dir, ext)].append(d)
            elif decision == "CONSIDER_APPROVING_PUBLISHER":
                publisher = str(d.get("file_name") or "unknown_publisher")
                publisher_groups[publisher].append(d)
            elif decision in {"CONSIDER_GLOBAL_APPROVAL", "PROCEED_TO_CUSTOM_RULE"}:
                global_dir_groups[parent_dir].append(d)

        suggestions: List[Dict[str, Any]] = []

        # File Creation Control per (dir, ext) group
        for (parent_dir, ext), files in sorted(dir_ext_groups.items(), key=lambda x: -len(x[1])):
            count = len(files)
            pattern = f"{parent_dir}\\*{ext}" if ext else f"{parent_dir}\\*"
            label = ext if ext else "any"
            suggestions.append(
                asdict(
                    RuleSuggestion(
                        rule_name=f"Local Approval - {parent_dir}\\*{ext}",
                        rule_type="File Creation Control",
                        operation="Write/Modify",
                        action="Approve",
                        process_pattern="Any Process",
                        file_pattern=pattern,
                        user_scope="Any User",
                        source_event_count=count,
                        confidence=self._confidence_from_count(count, base=0.55),
                        expected_enforcement_impact=(
                            f"Approves {count} unapproved {label} file(s) written to {parent_dir}."
                        ),
                        rationale=(
                            f"{count} unapproved file(s) with extension '{label}' found in {parent_dir}. "
                            "A File Creation Control rule locally approves files as they are written, "
                            "which is the Broadcom-preferred method over execution-only rules."
                        ),
                        safety_checks=[
                            "Verify the process writing these files is expected (e.g., an installer, update agent).",
                            "Narrow the process_pattern to the specific writing process before deploying.",
                            "Pilot in a single policy scope before expanding.",
                            "Do not apply to user-writable paths (Desktop, Downloads, AppData).",
                        ],
                    )
                )
            )

        # Publisher approval suggestions
        for publisher, files in sorted(publisher_groups.items(), key=lambda x: -len(x[1])):
            count = len(files)
            suggestions.append(
                asdict(
                    RuleSuggestion(
                        rule_name=f"Approve Publisher - {publisher}",
                        rule_type="Publisher Approval",
                        operation="Trust",
                        action="Approve",
                        process_pattern="Any Process",
                        file_pattern=f"All files signed by {publisher}",
                        user_scope="Any User",
                        source_event_count=count,
                        confidence=self._confidence_from_count(count, base=0.65),
                        expected_enforcement_impact=(
                            f"Approves all current and future files signed by {publisher} — "
                            f"covers at least {count} currently unapproved file(s)."
                        ),
                        rationale=(
                            f"{count} unapproved file(s) are signed by publisher '{publisher}'. "
                            "Approving at the publisher level is the highest-leverage action available: "
                            "a single rule covers all present and future binaries from this vendor."
                        ),
                        safety_checks=[
                            "Verify this publisher is a known, expected software vendor in your environment.",
                            "Review what other software this publisher has signed before trusting globally.",
                            "Consider approving in Audit mode first if any doubt exists.",
                        ],
                    )
                )
            )

        # Execution Control for global/custom-rule candidates
        for parent_dir, files in sorted(global_dir_groups.items(), key=lambda x: -len(x[1])):
            count = len(files)
            pattern = f"{parent_dir}\\*"
            suggestions.append(
                asdict(
                    RuleSuggestion(
                        rule_name=f"Execution Control - {parent_dir}",
                        rule_type="Execution Control",
                        operation="Execute",
                        action="Allow",
                        process_pattern="Any Process",
                        file_pattern=pattern,
                        user_scope="Any User",
                        source_event_count=count,
                        confidence=self._confidence_from_count(count, base=0.45),
                        expected_enforcement_impact=(
                            f"Allows execution of {count} high-prevalence file(s) in {parent_dir}."
                        ),
                        rationale=(
                            f"{count} file(s) in {parent_dir} have high prevalence and are candidates "
                            "for a global approval or Execution Control rule. Prefer File Creation Control "
                            "if a writing process can be identified."
                        ),
                        safety_checks=[
                            "Prefer File Creation Control (write-based) approval if the writing process is known.",
                            "Do not pair Execute with Approve — choose one action.",
                            "Narrow to the specific process or user if possible.",
                            "Review after rollout to confirm no unexpected files are executing.",
                        ],
                    )
                )
            )

        return suggestions

    def _is_trustworthy_and_allowed(self, binary: BinaryAnalysis, trusted_publishers: set) -> bool:
        if binary.threat_level and str(binary.threat_level).upper() in {"CRITICAL", "WARNING", "SUSPECT"}:
            return False
        if binary.trust_level and str(binary.trust_level).upper() in {"TRUSTED", "KNOWN"}:
            return True
        publisher = (binary.publisher or "").strip().lower()
        if publisher and publisher in trusted_publishers and binary.risk_score >= 0.5:
            return True
        return binary.risk_score >= 0.7

    def _is_common_application(self, binary: BinaryAnalysis) -> bool:
        return binary.prevalence >= self.high_prevalence_threshold and bool(binary.signer or binary.publisher)

    def _build_event_counts(self, event_data: Optional[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for event in self._extract_rows(event_data):
            key = str(event.get("filePath") or event.get("pathName") or "").strip().lower()
            if key:
                counts[key] = counts.get(key, 0) + 1
        return counts

    def _discovery_signal(self, description: str) -> Optional[str]:
        desc = description.upper()
        if "DISCOVEREDBY: KERNEL: WRITE" in desc:
            return "kernel_write"
        if "DISCOVEREDBY: KERNEL: CREATE" in desc:
            return "kernel_create"
        if "DISCOVEREDBY: KERNEL: RENAME" in desc:
            return "kernel_rename"
        if "DISCOVEREDBY: KERNEL: SCRIPT EXECUTE" in desc:
            return "kernel_script_execute"
        if "DISCOVEREDBY: KERNEL: EXECUTE" in desc:
            return "kernel_execute"
        return None

    def _path_matches_allowed(self, event_path: str, allowed_paths: set) -> bool:
        if not event_path:
            return False
        if event_path in allowed_paths:
            return True
        for allowed in allowed_paths:
            if allowed and (event_path.startswith(allowed) or allowed in event_path):
                return True
        return False

    def _to_file_pattern(self, raw_path: str) -> str:
        path = str(raw_path or "").strip().replace("/", "\\").lower()
        if not path:
            return "<unknown>"
        if path.startswith("\\\\"):
            return path
        last = path.split("\\")[-1]
        if "." in last:
            ext = self._extract_extension(path)
            parent = path[: path.rfind("\\")] if "\\" in path else path
            return f"{parent}\\*{ext}" if ext else f"{parent}\\*"
        return f"{path}\\*"

    def _extract_extension(self, raw_path: str) -> str:
        path = str(raw_path or "").strip().lower().replace("/", "\\")
        last = path.split("\\")[-1]
        if "." not in last:
            return ""
        return "." + last.split(".")[-1]

    def _normalize_process(self, process: Any) -> str:
        value = str(process or "Any Process").strip().lower().replace("/", "\\")
        return value or "Any Process"

    def _normalize_user_scope(self, user_scope: str) -> str:
        normalized = (user_scope or "Any User").strip()
        if not normalized:
            return "Any User"
        if normalized.lower() == "authenticated users":
            return "Any User"
        return normalized

    def _confidence_from_count(self, count: int, base: float) -> float:
        step = min(0.4, count * 0.02)
        return round(min(0.95, base + step), 2)

    def _dedupe_and_rank_suggestions(self, suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for suggestion in suggestions:
            key = "|".join(
                [
                    str(suggestion.get("rule_type") or ""),
                    str(suggestion.get("operation") or ""),
                    str(suggestion.get("action") or ""),
                    str(suggestion.get("process_pattern") or ""),
                    str(suggestion.get("file_pattern") or ""),
                    str(suggestion.get("user_scope") or ""),
                ]
            )
            previous = deduped.get(key)
            if not previous or (suggestion.get("source_event_count") or 0) > (previous.get("source_event_count") or 0):
                deduped[key] = suggestion

        return sorted(
            deduped.values(),
            key=lambda x: (
                x.get("weighted_confidence", x.get("confidence", 0)),
                x.get("source_event_count", 0),
            ),
            reverse=True,
        )

    def _build_rule_source_quality(self, software_rules: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize available rule-source endpoint quality for recommendation weighting."""
        accessible = set()

        if isinstance(software_rules, dict):
            for endpoint in software_rules.get("rule_endpoints_accessible", []):
                if endpoint:
                    accessible.add(str(endpoint))

        for row in self._extract_rows(software_rules):
            endpoint = row.get("_ruleSourceEndpoint")
            if endpoint:
                accessible.add(str(endpoint))

        high = sorted([ep for ep in accessible if ep in self.RULE_SOURCE_TIERS["high"]])
        medium = sorted([ep for ep in accessible if ep in self.RULE_SOURCE_TIERS["medium"]])
        low = sorted([ep for ep in accessible if ep in self.RULE_SOURCE_TIERS["low"]])

        if high:
            baseline_weight = 1.1
            dominant_tier = "high"
        elif medium:
            baseline_weight = 1.0
            dominant_tier = "medium"
        elif low:
            baseline_weight = 0.9
            dominant_tier = "low"
        else:
            baseline_weight = 1.0
            dominant_tier = "unknown"

        return {
            "dominant_tier": dominant_tier,
            "baseline_weight": baseline_weight,
            "high_quality_sources": high,
            "medium_quality_sources": medium,
            "low_quality_sources": low,
            "all_accessible_sources": sorted(accessible),
        }

    def _apply_source_quality_weighting(
        self,
        suggestions: List[Dict[str, Any]],
        source_quality: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply endpoint-quality weighting to each suggestion confidence."""
        accessible = set(source_quality.get("all_accessible_sources", []))
        weighted: List[Dict[str, Any]] = []

        for suggestion in suggestions:
            rule_type = str(suggestion.get("rule_type") or "")
            base_conf = float(suggestion.get("confidence", 0.0))

            weight = float(source_quality.get("baseline_weight", 1.0))
            if rule_type == "Execution Control" and "/api/bit9platform/v1/executionControlRule" in accessible:
                weight = max(weight, 1.2)
            elif rule_type == "File Creation Control" and "/api/bit9platform/v1/fileCreationControlRule" in accessible:
                weight = max(weight, 1.2)
            elif rule_type == "Performance Optimization" and (
                "/api/bit9platform/v1/rapidConfig" in accessible or "/api/bit9platform/v1/updater" in accessible
            ):
                weight = max(weight, 1.05)

            weighted_conf = round(min(0.99, base_conf * weight), 2)

            enriched = dict(suggestion)
            enriched["source_quality_weight"] = round(weight, 2)
            enriched["weighted_confidence"] = weighted_conf
            weighted.append(enriched)

        return weighted

    def _detect_rule_antipatterns(self, software_rules: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        macro_tokens = [
            "<sha256:",
            "<certissuer:",
            "<certserial:",
            "<certsha1:",
            "<certmd5:",
            "<onlyif:company:",
            "<onlyif:fileversion:",
            "<onlyif:productname:",
            "<onlyif:productversion:",
        ]

        for row in self._extract_rows(software_rules):
            text = " ".join(
                [
                    str(row.get("name") or ""),
                    str(row.get("description") or ""),
                    str(row.get("type") or ""),
                    str(row.get("operation") or row.get("operations") or ""),
                    str(row.get("action") or row.get("actions") or ""),
                    str(row.get("process") or ""),
                    str(row.get("pathName") or row.get("filePath") or ""),
                    str(row.get("user") or row.get("userName") or ""),
                    str(row.get("target") or ""),
                    str(row.get("tag") or row.get("tags") or ""),
                ]
            ).lower()
            rule_name = str(row.get("name") or row.get("id") or "<unnamed>")

            if "execute" in text and "approve" in text:
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "Execute + Approve combination can cause significant performance degradation.",
                        "recommended_fix": "Prefer File Creation Control Approve for write discoveries; avoid execute-time approve.",
                    }
                )
            if "allow" in text and "promote" in text:
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "Allow + Promote can unintentionally elevate nested child processes.",
                        "recommended_fix": "Use only for tightly constrained multi-layer installers.",
                    }
                )
            if "open" in text and "read" in text:
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "Open/Read operations in Expert rules can hurt agent performance.",
                        "recommended_fix": "Limit to explicit Ignore/Block use cases with narrow paths.",
                    }
                )
            if "authenticated users" in text:
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "Authenticated Users can drive excessive rule expansion across concurrent logons.",
                        "recommended_fix": "Prefer Any User or Security Groups to reduce expansion.",
                    }
                )
            if ("write" in text or "modify" in text) and "yara" in text and "pre-configured" not in text:
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "Custom YARA with Write/Modify can force expensive pre-write analysis.",
                        "recommended_fix": "Use pre-built YARA tags for File Creation; reserve custom YARA for Execution Control.",
                    }
                )
            if ("write" in text or "modify" in text) and any(token in text for token in macro_tokens):
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "File-property/certificate macros with Write/Modify can increase CPU usage.",
                        "recommended_fix": "Move these macros to Execute-oriented rules where possible.",
                    }
                )
            if "write" in text and "execute" in text:
                findings.append(
                    {
                        "rule": rule_name,
                        "risk": "Write + Execute in a single advanced rule can create redundant duplicate rules.",
                        "recommended_fix": "Use File Creation rule alone when local approval is sufficient.",
                    }
                )

        unique: Dict[str, Dict[str, Any]] = {}
        for finding in findings:
            unique[f"{finding['rule']}|{finding['risk']}"] = finding
        return list(unique.values())

    def _flatten_rules_text(self, software_rules: Optional[Dict[str, Any]]) -> str:
        values: List[str] = []
        for row in self._extract_rows(software_rules):
            for key in ("name", "description", "pathName", "filePath", "process", "target"):
                value = row.get(key)
                if value:
                    values.append(str(value).strip().lower())
        return "\n".join(values)

    def _extract_rows(self, payload: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not payload:
            return []
        if isinstance(payload, list):
            return payload
        return payload.get("results", payload.get("rows", []))

    def _recurrence_label(self, count: int) -> str:
        if count >= self.recurring_event_threshold:
            return "high"
        if count >= 2:
            return "medium"
        return "low"
