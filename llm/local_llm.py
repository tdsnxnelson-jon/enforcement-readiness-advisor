# Local LLM Integration for Enforcement Readiness Advisor
# Uses Ollama API to interact with local LLM models

import json
import logging
import re
from typing import Dict, List, Any, Optional
import requests

logger = logging.getLogger(__name__)


class LocalLLM:
    """Interface for local LLM (Ollama-compatible)."""
    
    def __init__(self, model: str = "mistral", base_url: str = "http://localhost:11434"):
        """
        Initialize the local LLM interface.
        
        Args:
            model: Model name (e.g., "mistral", "llama3", "phi3")
            base_url: Base URL for Ollama API
        """
        self.model = model
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def generate(self, prompt: str, 
                 system_prompt: Optional[str] = None,
                 temperature: float = 0.3,
                 max_tokens: int = 2000) -> str:
        """
        Generate a response from the LLM.
        
        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Sampling temperature (lower = more deterministic)
            max_tokens: Maximum tokens to generate
            
        Returns:
            Generated text response
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "temperature": temperature,
            "options": {
                "num_predict": max_tokens
            },
            "stream": False
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=300  # 5 minute timeout
            )
            response.raise_for_status()
            result = response.json()
            return result.get('response', '')
        except requests.exceptions.RequestException as e:
            logger.error(f"LLM generation failed: {e}")
            raise LLMError(f"Failed to generate response: {e}")
    
    def is_available(self) -> bool:
        """
        Check if the LLM is available and running.
        
        Returns:
            True if LLM is accessible
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return any(m.get('name', '').startswith(self.model) for m in models)
            return False
        except Exception as e:
            logger.warning(f"LLM availability check failed: {e}")
            return False
    
    def list_models(self) -> List[str]:
        """
        List available models.
        
        Returns:
            List of model names
        """
        try:
            response = self.session.get(f"{self.base_url}/api/tags", timeout=10)
            response.raise_for_status()
            return [m.get('name', '') for m in response.json().get('models', [])]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            return []


class ExplanationGenerator:
    """Generates human-readable explanations from analysis results."""
    
    def __init__(self, llm: LocalLLM):
        self.llm = llm
    
    def generate_enforcement_readiness_explanation(
        self, 
        analysis_data: Dict,
        readiness_score: float
    ) -> Dict[str, Any]:
        """
        Generate enforcement readiness explanation.
        
        Args:
            analysis_data: Trust signal analysis data
            readiness_score: Calculated readiness score
            
        Returns:
            Human-readable explanation
        """
        from llm.prompt_templates import ENFORCEMENT_READINESS_PROMPT
        
        # Format analysis data for prompt
        formatted_data = self._format_analysis_data(analysis_data)
        
        prompt = ENFORCEMENT_READINESS_PROMPT.format(
            analysis_data=formatted_data
        )
        
        raw_response = self.llm.generate(prompt, temperature=0.3)
        return self._parse_structured_enforcement_response(
            raw_response,
            readiness_score,
            analysis_data
        )

    def generate_enforcement_readiness_fallback(
        self,
        analysis_data: Dict,
        readiness_score: float,
        error_reason: str
    ) -> Dict[str, Any]:
        """Create a deterministic fallback explanation when LLM output is unavailable."""
        return {
            "source": "fallback",
            "parse_error": error_reason,
            "readiness_score": readiness_score,
            "overall_readiness_status": (
                f"Readiness score is {readiness_score}%. Continue staged approvals before high enforcement."
            ),
            "strengths": [
                "Assessment completed successfully using collected API trust signals.",
                "Path-based filtering was applied to exclude user-writable auto-approvals.",
                "Approval workflow guidance was generated for prioritized review."
            ],
            "areas_for_improvement": [
                "Publisher trust coverage remains limited in current dataset.",
                "Unknown binaries still require manual triage and targeted approvals.",
                "Some readiness components rely on placeholder metrics and should be implemented fully."
            ],
            "next_steps": [
                "Review top acceleration candidates and approve low observed risk files in batches.",
                "Expand trusted publisher and certificate-based approvals where policy allows.",
                "Re-run assessment after each approval cycle to validate readiness gains."
            ],
            "confidence_and_limits": (
                "This fallback summary is deterministic and based on available signals; "
                "it does not include model-generated nuance."
            ),
            "signal_summary": {
                "unknown_binaries": self._get_unknown_binaries_count(analysis_data),
                "trusted_publishers": len(analysis_data.get('publisher_analysis', {}).get('trusted', [])),
                "valid_certificates": analysis_data.get('certificate_analysis', {}).get('valid_count', 0)
            }
        }
    
    def generate_auto_approval_explanations(
        self, 
        candidates: List[Dict]
    ) -> str:
        """
        Generate explanations for auto-approval candidates.
        
        Args:
            candidates: List of auto-approval candidate binaries
            
        Returns:
            Explanations for each candidate
        """
        from llm.prompt_templates import AUTO_APPROVAL_CANDIDATE_PROMPT
        
        # Format candidates
        binaries_text = self._format_candidates(candidates)
        
        prompt = AUTO_APPROVAL_CANDIDATE_PROMPT.format(
            binaries=binaries_text
        )
        
        return self.llm.generate(prompt, temperature=0.2)
    
    def generate_risk_explanations(
        self, 
        risks: List[Dict]
    ) -> str:
        """
        Generate explanations for identified risks.
        
        Args:
            risks: List of risk items
            
        Returns:
            Risk explanations
        """
        from llm.prompt_templates import RISK_EXPLANATION_PROMPT
        
        prompt = RISK_EXPLANATION_PROMPT.format(
            risks=self._format_risks(risks)
        )
        
        return self.llm.generate(prompt, temperature=0.3)
    
    def generate_summary(
        self, 
        summary_data: Dict
    ) -> str:
        """
        Generate executive summary.
        
        Args:
            summary_data: Summary metrics
            
        Returns:
            Executive summary
        """
        from llm.prompt_templates import SUMMARY_PROMPT
        
        prompt = SUMMARY_PROMPT.format(
            unknown_count=summary_data.get('unknown_count', 0),
            trusted_publisher_count=summary_data.get('trusted_publisher_count', 0),
            valid_certificate_count=summary_data.get('valid_certificate_count', 0),
            active_computer_count=summary_data.get('active_computer_count', 0),
            readiness_score=summary_data.get('readiness_score', 0)
        )
        
        return self.llm.generate(prompt, temperature=0.3)
    
    def _format_analysis_data(self, data: Dict) -> str:
        """Format analysis data for prompt."""
        lines = []
        
        if 'unknown_binaries' in data:
            lines.append(f"Unknown binaries: {self._get_unknown_binaries_count(data)}")
        
        if 'publisher_analysis' in data:
            pa = data['publisher_analysis']
            lines.append(f"Trusted publishers: {len(pa.get('trusted', []))}")
            lines.append(f"Blocked publishers: {len(pa.get('blocked', []))}")
            lines.append(f"Unknown publishers: {len(pa.get('unknown', []))}")
        
        if 'certificate_analysis' in data:
            ca = data['certificate_analysis']
            lines.append(f"Valid certificates: {ca.get('valid_count', 0)}")
            lines.append(f"Invalid certificates: {ca.get('invalid_count', 0)}")
        
        if 'prevalence_analysis' in data:
            pa = data['prevalence_analysis']
            lines.append(f"High prevalence files: {len(pa.get('high_prevalence', []))}")
            lines.append(f"Medium prevalence files: {len(pa.get('medium_prevalence', []))}")
            lines.append(f"Low prevalence files: {len(pa.get('low_prevalence', []))}")
        
        return '\n'.join(lines) if lines else "No analysis data available"

    def _get_unknown_binaries_count(self, data: Dict) -> int:
        """Safely derive unknown binary count when value is a list or numeric aggregate."""
        value = data.get('unknown_binaries', 0)
        if isinstance(value, list):
            return len(value)
        if isinstance(value, (int, float)):
            return int(value)
        return 0

    def _extract_json_object(self, text: str) -> Dict[str, Any]:
        """Extract the first valid JSON object from model output."""
        stripped = text.strip()
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

        # Handle occasional code-fenced model output.
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
        if fence_match:
            return json.loads(fence_match.group(1))

        brace_match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if brace_match:
            return json.loads(brace_match.group(0))

        raise LLMError("Model response did not contain a valid JSON object")

    def _parse_structured_enforcement_response(
        self,
        raw_response: str,
        readiness_score: float,
        analysis_data: Dict
    ) -> Dict[str, Any]:
        """Parse and validate structured JSON response from the model."""
        parsed = self._extract_json_object(raw_response)

        required_fields = [
            'overall_readiness_status',
            'strengths',
            'areas_for_improvement',
            'next_steps',
            'confidence_and_limits'
        ]
        missing = [field for field in required_fields if field not in parsed]
        if missing:
            raise LLMError(f"Structured response missing required fields: {', '.join(missing)}")

        # Normalize list fields for predictable downstream output.
        for key in ['strengths', 'areas_for_improvement', 'next_steps']:
            value = parsed.get(key, [])
            if isinstance(value, str):
                parsed[key] = [value]
            elif isinstance(value, list):
                parsed[key] = [str(v) for v in value]
            else:
                parsed[key] = [str(value)]

        parsed['source'] = 'llm'
        parsed['readiness_score'] = readiness_score
        parsed['signal_summary'] = {
            'unknown_binaries': self._get_unknown_binaries_count(analysis_data),
            'trusted_publishers': len(analysis_data.get('publisher_analysis', {}).get('trusted', [])),
            'valid_certificates': analysis_data.get('certificate_analysis', {}).get('valid_count', 0)
        }
        return parsed
    
    def _format_candidates(self, candidates: List[Dict]) -> str:
        """Format candidates for prompt."""
        lines = []
        for i, c in enumerate(candidates[:10], 1):  # Limit to 10
            lines.append(f"{i}. {c.get('file_name', 'Unknown')}")
            lines.append(f"   Path: {c.get('file_path', 'Unknown')}")
            lines.append(f"   Publisher: {c.get('publisher', 'None')}")
            lines.append(f"   Signer: {c.get('signer', 'None')}")
            lines.append(f"   Risk Score: {c.get('risk_score', 0):.2f}")
            lines.append("")
        return '\n'.join(lines)
    
    def _format_risks(self, risks: List[Dict]) -> str:
        """Format risks for prompt."""
        lines = []
        for i, r in enumerate(risks, 1):
            lines.append(f"{i}. {r.get('category', 'Unknown')}")
            lines.append(f"   Description: {r.get('description', 'None')}")
            lines.append(f"   Impact: {r.get('impact', 'Unknown')}")
            lines.append("")
        return '\n'.join(lines)


class LLMError(Exception):
    """Custom exception for LLM errors."""
    pass