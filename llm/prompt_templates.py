# LLM Prompt Templates for Enforcement Readiness Advisor
# These templates are used to generate explanations from trust signal analysis

ENFORCEMENT_READINESS_PROMPT = """You are an expert Carbon Black App Control consultant helping customers transition to High Enforcement.

You have analyzed the customer's App Control environment and extracted trust signals from the file catalog, certificates, and publisher data.

Based on the analysis data provided, generate a clear, professional explanation that:
1. Summarizes the current enforcement readiness
2. Explains which binaries are safe candidates for auto-approval
3. Identifies remaining risks that require manual review
4. Provides specific, actionable recommendations

Use the following guidelines:
- Use "low observed risk" instead of "safe" or "guaranteed"
- Use "based on available signals" instead of "will not disrupt"
- Be specific about trust signals (publisher, signer, prevalence)
- Explain WHY each recommendation is made

Analysis Data:
{analysis_data}

Return ONLY valid JSON. Do not include markdown, code fences, or additional commentary.
Use this exact schema:
{{
    "overall_readiness_status": "<one sentence>",
    "strengths": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
    "areas_for_improvement": ["<bullet 1>", "<bullet 2>", "<bullet 3>"],
    "next_steps": ["<step 1>", "<step 2>", "<step 3>"],
    "confidence_and_limits": "<one sentence about uncertainty based on available signals>"
}}
"""

AUTO_APPROVAL_CANDIDATE_PROMPT = """Analyze the following binaries and explain why they are good candidates for auto-approval:

Binaries:
{binaries}

For each binary, provide:
1. File name and path
2. Trust signals present (publisher, signer, certificate)
3. Prevalence across endpoints
4. Reason for recommendation

Use cautious language - avoid "safe" or "guaranteed".
"""

RISK_EXPLANATION_PROMPT = """Explain the following risks identified in the App Control environment:

Risks:
{risks}

For each risk:
1. What was identified
2. Why it poses a risk
3. Recommended action
4. What information would help reduce uncertainty

Be specific and actionable.
"""

SUMMARY_PROMPT = """Generate a concise executive summary of the enforcement readiness assessment:

Metrics:
- Total unknown binaries: {unknown_count}
- Trusted publishers: {trusted_publisher_count}
- Valid certificates: {valid_certificate_count}
- Active computers: {active_computer_count}
- Readiness score: {readiness_score}%

Provide:
1. Overall readiness status
2. Top 3 strengths
3. Top 3 areas for improvement
4. Recommended next steps
"""

# Example structured output template
OUTPUT_TEMPLATE = {
    "enforcement_readiness_score": 0.0,
    "ready_for_high_enforcement": bool,
    "auto_approval_candidates": [
        {
            "file_name": "",
            "file_path": "",
            "publisher": "",
            "signer": "",
            "trust_signals": [],
            "risk_score": 0.0,
            "recommendation": ""
        }
    ],
    "risks_requiring_review": [
        {
            "category": "",
            "description": "",
            "impact": "",
            "recommended_action": ""
        }
    ],
    "summary": {
        "strengths": [],
        "areas_for_improvement": [],
        "next_steps": []
    }
}