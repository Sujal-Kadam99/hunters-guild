"""Unit tests for DoSStressEngine."""

import pytest
from aiohttp import web
from hunters_guild.modules.dos_stress import (
    DoSStressEngine,
    DoSTechnique,
)


@pytest.fixture
def dos_engine():
    return DoSStressEngine(timeout_seconds=4.0)


def test_recursive_expansion_payload(dos_engine):
    probe = dos_engine.generate_recursive_expansion_payload(depth=3)
    assert probe.technique == DoSTechnique.RECURSIVE_EXPANSION
    assert "Rule 3:" in probe.payload_text
    assert probe.estimated_tokens > 10


def test_context_flood_payload(dos_engine):
    probe = dos_engine.generate_context_flood_payload(token_target=2000)
    assert probe.technique == DoSTechnique.CONTEXT_FLOODING
    assert probe.estimated_tokens >= 1800
    assert len(probe.payload_text) >= 7000


def test_unbounded_generation_payload(dos_engine):
    probe = dos_engine.generate_unbounded_generation_payload()
    assert probe.technique == DoSTechnique.UNBOUNDED_OUTPUT_GENERATION
    assert "Do not omit" in probe.payload_text


@pytest.mark.asyncio
async def test_evaluate_latency_degradation_mock(dos_engine):
    async def mock_handler(request):
        data = await request.json()
        content = data["messages"][0]["content"]
        if len(content) > 5000:
            return web.json_response({"choices": [{"message": {"content": "Buffered output"}}]}, status=200)
        return web.json_response({"choices": [{"message": {"content": "Fast ping"}}]}, status=200)

    app = web.Application()
    app.router.add_post("/v1/chat/completions", mock_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 9966)
    await site.start()

    try:
        report = await dos_engine.evaluate_latency_degradation(
            target_url="http://127.0.0.1:9966/v1/chat/completions",
            auth_token="test-token",
            model_name="benchmark-model",
            steps=2,
        )
        assert len(report.metrics_trail) == 2
        assert report.baseline_latency_ms > 0
    finally:
        await runner.cleanup()
