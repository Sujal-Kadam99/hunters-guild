import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from hunters_guild.connectors.batch_runner import BatchMissionRunner
from hunters_guild.engine.orchestrator import GuildMaster
from hunters_guild.connectors.target_ingestor import TargetManifest, PlatformType
from hunters_guild.core.schemas import BountyPoC, GuildState, AuditMission, TargetProfile, AttackTurn

@pytest.mark.asyncio
async def test_batch_runner_direct():
    mock_orchestrator = MagicMock(spec=GuildMaster)
    
    # Mock run_chat_mission to return a mock GuildState
    mock_state = GuildState(
        mission=AuditMission(
            target=TargetProfile(endpoint_url="http://mock", model_identifier="mock"),
            objective="test",
            owasp_category="LLM01"
        ),
        history=[
            AttackTurn(
                turn_index=0,
                attack_technique="test",
                probe_payload="test",
                raw_response="test",
                latent_latency_ms=1.0,
                judge_score=100,
                violation_flag=True,
                reasoning="test"
            )
        ],
        mission_mode="chat",
        target_endpoint_url="http://mock",
        target_model_name="mock",
        max_judge_score=90,
        confirmed_poc=BountyPoC(
            vulnerability_title="Test Vuln",
            cwe_id="CWE-77",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            estimated_bounty_severity="Low",
            reproduction_steps=["step1"],
            full_trace=[{"turn_index": 0, "attack_technique": "test", "probe_payload": "test", "raw_response": "test", "latent_latency_ms": 1.0, "judge_score": 100, "violation_flag": True, "reasoning": "test", "timestamp": "2026-10-04T05:00:00Z"}],
            remediation="Fix it"
        )
    )
    mock_orchestrator.run_mission = AsyncMock(return_value=mock_state)
    
    runner = BatchMissionRunner(
        orchestrator=mock_orchestrator,
        concurrency_limit=2,
        delay_between_targets_sec=0.1
    )
    
    manifests = [
        TargetManifest(
            target_name="target1",
            platform=PlatformType.HACKERONE,
            endpoint_url="http://mock1",
            model_identifier="m1",
            api_key="k1",
            mode="chat",
            objective="test"
        )
    ]
    
    results = await runner.execute_batch(manifests=manifests, output_dir="./scratch/batch_output")
    
    assert results["total_targets"] == 1
    assert results["confirmed_vulnerabilities"] == 1
    assert results["reports"][0]["verdict"] == "VULNERABILITY_CONFIRMED"
