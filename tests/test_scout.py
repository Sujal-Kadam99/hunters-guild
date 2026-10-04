"""
Unit and Integration Tests for ScoutAgent
Project: Hunters Guild - Autonomous AI Robustness & Security Verification Framework
"""

import asyncio
import json
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

from hunters_guild.agents.scout import ScoutAgent
from hunters_guild.core.schemas import TargetProfile


@pytest_asyncio.fixture
async def mock_llm_server():
    """
    Spawns a mock LLM HTTP server simulating OpenAI-compatible inference gateway,
    models endpoint, function calling, delimiters, guardrail headers, and SSE streaming.
    """
    app = web.Application()

    async def handle_models(request):
        auth = request.headers.get("Authorization")
        if not auth or "Bearer" not in auth:
            return web.json_response({"error": "Unauthorized"}, status=401)
        return web.json_response({
            "object": "list",
            "data": [
                {"id": "gpt-4o-custom", "object": "model", "owned_by": "organization"},
                {"id": "claude-3-5-sonnet", "object": "model", "owned_by": "anthropic"},
            ]
        })

    async def handle_chat_completions(request):
        auth = request.headers.get("Authorization")
        data = await request.json()
        messages = data.get("messages", [])
        last_msg = messages[-1]["content"] if messages else ""
        stream = data.get("stream", False)

        # 1. Handle Streaming
        if stream:
            response = web.StreamResponse(
                status=200,
                reason="OK",
                headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"}
            )
            await response.prepare(request)
            chunk1 = "data: " + json.dumps({"choices": [{"delta": {"content": "pong stream"}}]}) + "\n\n"
            chunk2 = "data: [DONE]\n\n"
            await response.write(chunk1.encode("utf-8"))
            await response.write(chunk2.encode("utf-8"))
            await response.write_eof()
            return response

        # 2. Handle Tool Calling Probe
        if "tools" in data:
            return web.json_response({
                "id": "chatcmpl-tools",
                "system_fingerprint": "fp_audit_9876",
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "call_123",
                            "type": "function",
                            "function": {
                                "name": "check_system_status",
                                "arguments": "{\"service\": \"audit\"}"
                            }
                        }]
                    }
                }]
            })

        # 3. Handle Delimiter Probes
        if "ACK_MD_VALID" in last_msg:
            return web.json_response({
                "choices": [{"message": {"role": "assistant", "content": "ACK_MD_VALID parsed successfully"}}]
            })
        if "ACK_XML_VALID" in last_msg:
            return web.json_response({
                "choices": [{"message": {"role": "assistant", "content": "ACK_XML_VALID parsed successfully"}}]
            })
        if "ACK_JSON_VALID" in last_msg:
            return web.json_response({
                "choices": [{"message": {"role": "assistant", "content": "ACK_JSON_VALID parsed successfully"}}]
            })

        # 4. Handle Guardrail Probe
        if "buffer overflow" in last_msg:
            # Simulate dual-model inline moderation latency & header signature
            await asyncio.sleep(0.2)  # 200ms sleep for latency shift
            return web.json_response(
                {"choices": [{"message": {"role": "assistant", "content": "Boundary checking enforces memory safety."}}]},
                headers={"x-azure-content-safety": "pass", "x-moderation-verdict": "clean"}
            )

        # 5. Handle Standard Ping
        return web.json_response({
            "id": "chatcmpl-ping",
            "system_fingerprint": "fp_audit_9876",
            "choices": [{"message": {"role": "assistant", "content": "pong"}}]
        }, headers={"x-system-fingerprint": "fp_audit_9876"})

    app.router.add_get("/v1/models", handle_models)
    app.router.add_post("/v1/chat/completions", handle_chat_completions)

    server = TestServer(app)
    await server.start_server()
    yield server
    await server.close()


@pytest.mark.asyncio
async def test_scout_full_recon_pipeline(mock_llm_server):
    endpoint_url = f"http://{mock_llm_server.host}:{mock_llm_server.port}/v1/chat/completions"
    agent = ScoutAgent(timeout=5.0, max_retries=2)

    profile = await agent.fingerprint_endpoint(
        endpoint_url=endpoint_url,
        auth_token="sk-test-token-12345",
    )

    assert isinstance(profile, TargetProfile)
    assert profile.endpoint_url == endpoint_url
    assert profile.model_identifier == "gpt-4o-custom"
    assert profile.auth_header == "Bearer sk-test-token-12345"
    assert profile.system_fingerprint == "fp_audit_9876"
    assert profile.supports_streaming is True

    # Check detected tools and capabilities
    assert "tool_calling:openai_functions" in profile.detected_tools
    assert "tool_execution:active_invocation" in profile.detected_tools
    assert "delimiter:markdown_headers" in profile.detected_tools
    assert "delimiter:xml_wrappers" in profile.detected_tools
    assert "delimiter:json_schema_brackets" in profile.detected_tools
    assert "guardrail:azure_content_safety" in profile.detected_tools
    assert "guardrail:inline_header_signature_detected" in profile.detected_tools
    assert "guardrail:inline_inspection_latency_shift" in profile.detected_tools


@pytest.mark.asyncio
async def test_scout_custom_model_override(mock_llm_server):
    endpoint_url = f"http://{mock_llm_server.host}:{mock_llm_server.port}/v1/chat/completions"
    agent = ScoutAgent(timeout=5.0)

    profile = await agent.fingerprint_endpoint(
        endpoint_url=endpoint_url,
        auth_token="Bearer my-prefixed-token",
        model_name="custom-model-override",
    )

    assert profile.model_identifier == "custom-model-override"
    assert profile.auth_header == "Bearer my-prefixed-token"


@pytest.mark.asyncio
async def test_scout_rate_limiting_retry():
    """
    Tests handling of HTTP 429 rate limit with automatic exponential backoff.
    """
    app = web.Application()
    call_counts = {"attempts": 0}

    async def handle_rate_limit(request):
        call_counts["attempts"] += 1
        if call_counts["attempts"] < 2:
            return web.Response(
                status=429,
                headers={"Retry-After": "0.1", "Content-Type": "application/json"},
                text=json.dumps({"error": "rate_limited"})
            )
        return web.json_response({
            "choices": [{"message": {"role": "assistant", "content": "pong after retry"}}]
        })

    app.router.add_post("/v1/chat/completions", handle_rate_limit)
    server = TestServer(app)
    await server.start_server()

    endpoint = f"http://{server.host}:{server.port}/v1/chat/completions"
    agent = ScoutAgent(timeout=5.0, max_retries=3)

    profile = await agent.fingerprint_endpoint(endpoint_url=endpoint)
    assert isinstance(profile, TargetProfile)
    assert call_counts["attempts"] >= 2

    await server.close()


@pytest.mark.asyncio
async def test_scout_network_failure_fallback():
    """
    Tests that ScoutAgent gracefully falls back and constructs a valid TargetProfile
    even if the endpoint is non-responsive or times out.
    """
    agent = ScoutAgent(timeout=0.2, max_retries=1)
    # Using an unreachable port / mock URL
    unreachable_url = "http://127.0.0.1:59999/v1/chat/completions"

    profile = await agent.fingerprint_endpoint(
        endpoint_url=unreachable_url,
        auth_token="dummy-token",
        model_name="fallback-model",
    )

    assert isinstance(profile, TargetProfile)
    assert profile.endpoint_url == unreachable_url
    assert profile.model_identifier == "fallback-model"
    assert profile.supports_streaming is False
    assert profile.detected_tools == []
