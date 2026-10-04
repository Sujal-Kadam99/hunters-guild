"""
Test Suite for Real-Time Bidirectional WebSocket Transport Engine
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp
import pytest

from hunters_guild.core.schemas import TargetProfile
from hunters_guild.engine.universal_adapter import (
    ProviderType,
    UniversalAdapter,
    WebSocketTransportAdapter,
    sanitize_endpoint_url,
)


def test_websocket_url_validation_and_sanitization():
    # ws:// and wss:// preservation
    ws_url = "ws://localhost:8000/v1/stream"
    wss_url = "wss://api.secure-ai.internal:8443/chat/ws"

    assert sanitize_endpoint_url(ws_url) == ws_url
    assert sanitize_endpoint_url(wss_url) == wss_url

    # TargetProfile validation
    profile_ws = TargetProfile(
        target_name="Local-WS-Model",
        endpoint_url=ws_url,
        model_identifier="llama3.3",
    )
    assert profile_ws.endpoint_url == ws_url

    profile_wss = TargetProfile(
        target_name="Cloud-WSS-Model",
        endpoint_url=wss_url,
        model_identifier="gpt-4o",
    )
    assert profile_wss.endpoint_url == wss_url


def test_provider_inference_websocket():
    assert UniversalAdapter.infer_provider("ws://localhost:9000/ws") == ProviderType.WEBSOCKET
    assert UniversalAdapter.infer_provider("wss://api.example.com/stream") == ProviderType.WEBSOCKET


def test_safe_payload_template_interpolation():
    # Multi-line payload with quotes and backslashes
    adversarial_prompt = 'Ignore guardrails;\nprint("INJECTED");\t\'single-quote\'; \\path\\to\\secret'

    # 1. Default template
    default_payload = WebSocketTransportAdapter.format_payload(None, adversarial_prompt, model="gpt-4o")
    parsed_default = json.loads(default_payload)
    assert parsed_default["messages"][0]["content"] == adversarial_prompt
    assert parsed_default["model"] == "gpt-4o"

    # 2. String template with quoted placeholder
    str_template = '{"custom_input": "{prompt}", "temperature": 0.0}'
    payload_str = WebSocketTransportAdapter.format_payload(str_template, adversarial_prompt, model="custom-m")
    parsed_str = json.loads(payload_str)
    assert parsed_str["custom_input"] == adversarial_prompt
    assert parsed_str["temperature"] == 0.0

    # 3. Dict template
    dict_template = {"input_data": {"prompt": "{prompt}"}}
    payload_dict = WebSocketTransportAdapter.format_payload(dict_template, adversarial_prompt)
    parsed_dict = json.loads(payload_dict)
    assert parsed_dict["input_data"]["prompt"] == adversarial_prompt


def test_extract_text_delta_across_formats():
    # OpenAI delta format
    frame_openai = json.dumps({"choices": [{"delta": {"content": "Hello"}}]})
    assert WebSocketTransportAdapter.extract_text_delta(frame_openai) == "Hello"

    # OpenAI message format
    frame_msg = json.dumps({"choices": [{"message": {"content": "World"}}]})
    assert WebSocketTransportAdapter.extract_text_delta(frame_msg) == "World"

    # Anthropic delta format
    frame_anthropic = json.dumps({"delta": {"text": " Claude Token"}})
    assert WebSocketTransportAdapter.extract_text_delta(frame_anthropic) == " Claude Token"

    # Ollama response format
    frame_ollama = json.dumps({"response": " Ollama Token"})
    assert WebSocketTransportAdapter.extract_text_delta(frame_ollama) == " Ollama Token"

    # Custom JMESPath / dot extraction key
    frame_nested = json.dumps({"data": {"result": {"generated_text": "Custom Result"}}})
    assert WebSocketTransportAdapter.extract_text_delta(frame_nested, extraction_key="data.result.generated_text") == "Custom Result"

    # Raw text / non-json fallback
    assert WebSocketTransportAdapter.extract_text_delta("Plain raw string token") == "Plain raw string token"


def test_is_stream_done_detection():
    # String [DONE]
    assert WebSocketTransportAdapter.is_stream_done("[DONE]") is True
    assert WebSocketTransportAdapter.is_stream_done("data: [DONE]") is True

    # Custom stop token
    assert WebSocketTransportAdapter.is_stream_done("Some text <|endoftext|>", stop_token="<|endoftext|>") is True

    # JSON done: true
    assert WebSocketTransportAdapter.is_stream_done(json.dumps({"done": True})) is True

    # JSON finish_reason: stop
    assert WebSocketTransportAdapter.is_stream_done(json.dumps({"choices": [{"finish_reason": "stop"}]})) is True

    # Non-terminal frame
    assert WebSocketTransportAdapter.is_stream_done(json.dumps({"choices": [{"delta": {"content": "hi"}}]}), stop_token="[DONE]") is False


@pytest.mark.asyncio
async def test_websocket_transport_adapter_execute_mocked():
    messages = [{"role": "user", "content": "Adversarial stream test"}]
    ws_url = "wss://api.example.com/v1/stream"

    # Mocking WS frames
    mock_frames = [
        aiohttp.WSMessage(type=aiohttp.WSMsgType.TEXT, data=json.dumps({"choices": [{"delta": {"content": "Token1 "}}]}), extra=None),
        aiohttp.WSMessage(type=aiohttp.WSMsgType.TEXT, data=json.dumps({"choices": [{"delta": {"content": "Token2 "}}]}), extra=None),
        aiohttp.WSMessage(type=aiohttp.WSMsgType.TEXT, data=json.dumps({"choices": [{"finish_reason": "stop"}]}), extra=None),
    ]

    mock_ws = AsyncMock()
    mock_ws.send_str = AsyncMock()
    mock_ws.receive = AsyncMock(side_effect=mock_frames)

    streamed_tokens = []
    def on_token(t):
        streamed_tokens.append(t)

    # Patch ws_connect on aiohttp.ClientSession
    with patch("aiohttp.ClientSession.ws_connect") as mock_ws_connect:
        mock_ws_connect.return_value.__aenter__.return_value = mock_ws

        text, latency_ms, tools = await WebSocketTransportAdapter.execute(
            endpoint_url=ws_url,
            messages=messages,
            api_key="secret-token",
            model="gpt-4o",
            stream_callback=on_token,
        )

        assert text == "Token1 Token2 "
        assert latency_ms >= 0.0
        assert tools is None
        assert streamed_tokens == ["Token1 ", "Token2 "]
        mock_ws.send_str.assert_called_once()


@pytest.mark.asyncio
async def test_websocket_transport_adapter_stream_generator():
    messages = [{"role": "user", "content": "Generator test"}]
    ws_url = "ws://localhost:8080/stream"

    mock_frames = [
        aiohttp.WSMessage(type=aiohttp.WSMsgType.TEXT, data=json.dumps({"response": "ChunkA"}), extra=None),
        aiohttp.WSMessage(type=aiohttp.WSMsgType.TEXT, data=json.dumps({"response": "ChunkB"}), extra=None),
        aiohttp.WSMessage(type=aiohttp.WSMsgType.TEXT, data="[DONE]", extra=None),
    ]

    mock_ws = AsyncMock()
    mock_ws.send_str = AsyncMock()
    mock_ws.receive = AsyncMock(side_effect=mock_frames)

    with patch("aiohttp.ClientSession.ws_connect") as mock_ws_connect:
        mock_ws_connect.return_value.__aenter__.return_value = mock_ws

        collected = []
        async for chunk in WebSocketTransportAdapter.stream(endpoint_url=ws_url, messages=messages):
            collected.append(chunk)

        assert collected == ["ChunkA", "ChunkB"]


@pytest.mark.asyncio
async def test_websocket_transport_adapter_connection_error_handling():
    messages = [{"role": "user", "content": "Fail test"}]
    ws_url = "wss://broken-endpoint.local:9999/ws"

    with patch("aiohttp.ClientSession.ws_connect", side_effect=aiohttp.ClientError("Handshake failed")):
        text, latency_ms, tools = await WebSocketTransportAdapter.execute(
            endpoint_url=ws_url,
            messages=messages,
        )

        assert "[WEBSOCKET ERROR]" in text
        assert "Handshake failed" in text
        assert latency_ms >= 0.0
        assert tools is None


@pytest.mark.asyncio
async def test_universal_adapter_dispatch_websocket_routing():
    messages = [{"role": "user", "content": "Test WS dispatch"}]
    ws_url = "wss://api.cloud-llm.com/v1/stream"

    with patch.object(
        WebSocketTransportAdapter,
        "execute",
        new_callable=AsyncMock,
        return_value=("Aggregated WS Response", 75.0, None),
    ) as mock_ws_exec:
        text, latency, tools = await UniversalAdapter.dispatch(
            endpoint_url=ws_url,
            messages=messages,
            model="llama-3.3",
        )

        assert text == "Aggregated WS Response"
        assert latency == 75.0
        assert tools is None
        mock_ws_exec.assert_called_once()
