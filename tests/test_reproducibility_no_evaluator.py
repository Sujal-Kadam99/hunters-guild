import pytest
from hunters_guild.modules.reproducibility import ReproducibilityVerifier
from hunters_guild.core.schemas import TargetProfile, AuditMission

async def mock_transceiver(target, history):
    return ("hello", 1.0, None)

@pytest.mark.asyncio
async def test_reproducibility_no_evaluator():
    verifier = ReproducibilityVerifier(transceiver_fn=mock_transceiver, max_verification_attempts=3)
    target = TargetProfile(endpoint_url="mock://test", model_identifier="mock")
    mission = AuditMission(target=target, objective="test", owasp_category="LLM01")
    
    result = await verifier.verify_reproducibility(
        mission=mission,
        winning_probe="test",
        evaluator_fn=None,
        expected_leak_pattern=None
    )
    
    assert result.status == "unknown"
    assert result.total_trials == 3
    assert result.successful_reproductions == 0
