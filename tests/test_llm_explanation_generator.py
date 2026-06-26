import json

import pytest

from llm.local_llm import ExplanationGenerator, LLMError, LocalLLM
from analysis.trust_signals import EnforcementReadinessScorer


class FakeLLM:
    def __init__(self, response: str):
        self.response = response

    def generate(self, prompt: str, temperature: float = 0.3):
        return self.response


def test_local_llm_uses_explicit_remote_base_url():
    llm = LocalLLM(base_url="https://ollama.internal.example:11434/")
    assert llm.base_url == "https://ollama.internal.example:11434"


def test_local_llm_uses_ollama_host_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "ollama-vm.internal:11434")
    llm = LocalLLM()
    assert llm.base_url == "http://ollama-vm.internal:11434"


def test_get_unknown_binaries_count_accepts_integer():
    generator = ExplanationGenerator(FakeLLM("{}"))
    count = generator._get_unknown_binaries_count({"unknown_binaries": 7})
    assert count == 7


def test_generate_enforcement_readiness_parses_json_with_code_fence():
    model_payload = {
        "overall_readiness_status": "Not ready for high enforcement yet.",
        "strengths": ["Signal collection is complete"],
        "areas_for_improvement": ["Publisher trust coverage is low"],
        "next_steps": ["Approve low observed risk binaries in batches"],
        "confidence_and_limits": "Based on available signals only."
    }
    fenced_json = f"```json\n{json.dumps(model_payload)}\n```"

    generator = ExplanationGenerator(FakeLLM(fenced_json))
    result = generator.generate_enforcement_readiness_explanation(
        {
            "unknown_binaries": [{"file": "a.exe"}, {"file": "b.exe"}],
            "publisher_analysis": {"trusted": ["Microsoft"]},
            "certificate_analysis": {"valid_count": 10},
        },
        readiness_score=42.5,
    )

    assert result["source"] == "llm"
    assert result["readiness_score"] == 42.5
    assert result["signal_summary"]["unknown_binaries"] == 2


def test_generate_enforcement_readiness_raises_when_required_fields_missing():
    incomplete = json.dumps({"overall_readiness_status": "Missing other fields"})
    generator = ExplanationGenerator(FakeLLM(incomplete))

    with pytest.raises(LLMError):
        generator.generate_enforcement_readiness_explanation(
            {"unknown_binaries": 3},
            readiness_score=12.0,
        )


def test_fallback_contains_deterministic_structure():
    generator = ExplanationGenerator(FakeLLM("{}"))
    fallback = generator.generate_enforcement_readiness_fallback(
        {"unknown_binaries": 5},
        readiness_score=33.1,
        error_reason="parse failed",
    )

    assert fallback["source"] == "fallback"
    assert fallback["parse_error"] == "parse failed"
    assert fallback["signal_summary"]["unknown_binaries"] == 5
    assert isinstance(fallback["next_steps"], list)


def test_format_analysis_data_counts_opaque_list_objects():
    """_format_analysis_data must count a list of arbitrary objects (e.g. BinaryAnalysis dataclasses)."""
    class FakeBinary:
        pass

    generator = ExplanationGenerator(FakeLLM("{}"))
    data = {
        "unknown_binaries": [FakeBinary(), FakeBinary(), FakeBinary()],
        "publisher_analysis": {"trusted": ["Microsoft"], "blocked": [], "unknown": []},
        "certificate_analysis": {"valid_count": 4, "invalid_count": 1},
        "prevalence_analysis": {
            "high_prevalence": [], "medium_prevalence": [], "low_prevalence": [], "single_endpoint": []
        },
    }
    formatted = generator._format_analysis_data(data)
    assert "Unknown binaries: 3" in formatted
    assert "Trusted publishers: 1" in formatted
    assert "Valid certificates: 4" in formatted


def test_generate_enforcement_readiness_parses_plain_json():
    """Model response without code fences must parse correctly."""
    model_payload = {
        "overall_readiness_status": "Not yet ready.",
        "strengths": ["Signal collection complete"],
        "areas_for_improvement": ["Low certificate count"],
        "next_steps": ["Approve in batches"],
        "confidence_and_limits": "Based on available signals.",
    }
    generator = ExplanationGenerator(FakeLLM(json.dumps(model_payload)))
    result = generator.generate_enforcement_readiness_explanation(
        {
            "unknown_binaries": 5,
            "publisher_analysis": {"trusted": []},
            "certificate_analysis": {"valid_count": 0},
        },
        readiness_score=60.0,
    )
    assert result["source"] == "llm"
    assert result["overall_readiness_status"] == "Not yet ready."
    assert result["readiness_score"] == 60.0


def test_generate_enforcement_readiness_raises_on_llm_error():
    """LLMError raised by generate() must propagate out without being swallowed."""
    class ErrorLLM:
        def generate(self, prompt, temperature=0.3):
            raise LLMError("connection refused")

    generator = ExplanationGenerator(ErrorLLM())
    with pytest.raises(LLMError, match="connection refused"):
        generator.generate_enforcement_readiness_explanation(
            {"unknown_binaries": 0},
            readiness_score=50.0,
        )


class TestReadinessScorer:
    def setup_method(self):
        self.scorer = EnforcementReadinessScorer()

    def test_weights_sum_to_one(self):
        assert sum(self.scorer.weights.values()) == pytest.approx(1.0)

    def test_approval_requests_not_in_weights(self):
        assert 'approval_requests' not in self.scorer.weights

    def test_calculate_readiness_score_returns_expected_keys(self):
        summary = {
            'unknown_count': 10, 'approved_count': 90,
            'active_computer_count': 30,
        }
        result = self.scorer.calculate_readiness_score(summary, {})
        assert 'total_score' in result
        assert 'breakdown' in result
        assert 'ready_for_high_enforcement' in result
        assert 'approval_requests' not in result['breakdown']
