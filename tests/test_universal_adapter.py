import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from hunters_guild.engine.universal_adapter import (
    ProviderType,
    PROVIDER_PRESETS,
    is_reasoning_model,
    is_openai_reasoning_model,
    sanitize_endpoint_url,
    UniversalAdapter,
)

def test_sanitize_endpoint_url():
    # Test markdown stripping
    assert sanitize_endpoint_url("[https://api.openai.com/v1/chat/completions](https://api.openai.com/v1/chat/completions)") == "https://api.openai.com/v1/chat/completions"
    assert sanitize_endpoint_url("[OpenAI Link](https://api.openai.com/v1/chat/completions)") == "https://api.openai.com/v1/chat/completions"
    
    # Test brackets/quotes stripping
    assert sanitize_endpoint_url(' "https://api.openai.com/v1/chat/completions" ') == "https://api.openai.com/v1/chat/completions"
    assert sanitize_endpoint_url("<https://api.openai.com/v1/chat/completions>") == "https://api.openai.com/v1/chat/completions"
    
    # Test auto append path
    assert sanitize_endpoint_url("https://api.openai.com/v1") == "https://api.openai.com/v1/chat/completions"
    assert sanitize_endpoint_url("https://api.groq.com/openai/v1") == "https://api.groq.com/openai/v1/chat/completions"
    
    # Test anthropic bypass
    assert sanitize_endpoint_url("https://api.anthropic.com/v1/messages") == "https://api.anthropic.com/v1/messages"


def test_provider_presets_expanded():
    assert ProviderType.OPENAI.value in PROVIDER_PRESETS
    assert ProviderType.GEMINI.value in PROVIDER_PRESETS
    assert ProviderType.GROQ.value in PROVIDER_PRESETS
    assert ProviderType.OPENROUTER.value in PROVIDER_PRESETS
    assert ProviderType.ANTHROPIC.value in PROVIDER_PRESETS
    assert ProviderType.DEEPSEEK.value in PROVIDER_PRESETS
    assert ProviderType.XAI.value in PROVIDER_PRESETS
    assert ProviderType.MISTRAL_AND_FABLE.value in PROVIDER_PRESETS
    assert ProviderType.OLLAMA.value in PROVIDER_PRESETS
    assert ProviderType.SSH.value in PROVIDER_PRESETS
    assert ProviderType.WEBSOCKET.value in PROVIDER_PRESETS

    # Check generational models
    gemini_models = PROVIDER_PRESETS[ProviderType.GEMINI.value]["models"]
    assert "gemini-3.7-flash" in gemini_models
    assert "gemini-3.5-pro" in gemini_models
    assert "gemini-1.0-ultra" in gemini_models

    openai_models = PROVIDER_PRESETS[ProviderType.OPENAI.value]["models"]
    assert "gpt-5" in openai_models
    assert "o3" in openai_models
    assert "gpt-3.5-turbo" in openai_models

    anthropic_models = PROVIDER_PRESETS[ProviderType.ANTHROPIC.value]["models"]
    assert "claude-4-5-sonnet" in anthropic_models
    assert "claude-instant-1.2" in anthropic_models

    deepseek_models = PROVIDER_PRESETS[ProviderType.DEEPSEEK.value]["models"]
    assert "deepseek-reasoner" in deepseek_models
    assert "deepseek-r1" in deepseek_models

    xai_models = PROVIDER_PRESETS[ProviderType.XAI.value]["models"]
    assert "grok-3" in xai_models

    mistral_models = PROVIDER_PRESETS[ProviderType.MISTRAL_AND_FABLE.value]["models"]
    assert "fable-5" in mistral_models
    assert "mistral-large-latest" in mistral_models


def test_reasoning_model_detection():
    assert is_reasoning_model("o1") is True
    assert is_reasoning_model("o1-mini") is True
    assert is_reasoning_model("o3") is True
    assert is_reasoning_model("o3-mini") is True
    assert is_reasoning_model("deepseek-reasoner") is True
    assert is_reasoning_model("deepseek-r1") is True
    assert is_reasoning_model("deepseek-r1-distill-llama-70b") is True
    assert is_reasoning_model("gpt-4o") is False
    assert is_reasoning_model("gpt-5") is False
    assert is_reasoning_model("claude-3-5-sonnet") is False

    assert is_openai_reasoning_model("o1") is True
    assert is_openai_reasoning_model("o3-mini") is True
    assert is_openai_reasoning_model("deepseek-reasoner") is False
    assert is_openai_reasoning_model("gpt-4o") is False


def test_reasoning_payload_sanitization_openai():
    # Test o1 / o3: temperature must be omitted, max_completion_tokens must be used
    headers, payload, url = UniversalAdapter.format_request(
        provider=ProviderType.OPENAI,
        endpoint_url="https://api.openai.com/v1",
        api_key="sk-test",
        model="o1-mini",
        messages=[{"role": "user", "content": "Explain quantum entanglement"}],
        temperature=0.8,
    )
    assert "temperature" not in payload
    assert "max_completion_tokens" in payload
    assert payload["max_completion_tokens"] == 1024
    assert "max_tokens" not in payload
    assert payload["model"] == "o1-mini"


def test_reasoning_payload_sanitization_deepseek():
    # Test deepseek-reasoner: temperature must be omitted, max_tokens used
    headers, payload, url = UniversalAdapter.format_request(
        provider=ProviderType.DEEPSEEK,
        endpoint_url="https://api.deepseek.com",
        api_key="sk-deepseek",
        model="deepseek-reasoner",
        messages=[{"role": "user", "content": "Solve math proof"}],
        temperature=0.5,
    )
    assert "temperature" not in payload
    assert "max_tokens" in payload
    assert payload["model"] == "deepseek-reasoner"


def test_universal_adapter_format_openai_standard():
    headers, payload, url = UniversalAdapter.format_request(
        provider=ProviderType.OPENAI,
        endpoint_url="https://api.openai.com/v1",
        api_key="sk-test",
        model="gpt-4o",
        messages=[{"role": "user", "content": "Hello"}],
    )
    assert url == "https://api.openai.com/v1/chat/completions"
    assert headers["Authorization"] == "Bearer sk-test"
    assert payload["model"] == "gpt-4o"
    assert payload["temperature"] == 0.7
    assert payload["max_tokens"] == 1024
    assert payload["messages"] == [{"role": "user", "content": "Hello"}]


def test_universal_adapter_format_anthropic():
    headers, payload, url = UniversalAdapter.format_request(
        provider=ProviderType.ANTHROPIC,
        endpoint_url="https://api.anthropic.com/v1/messages",
        api_key="sk-test",
        model="claude-3-5-sonnet",
        messages=[{"role": "system", "content": "Sys"}, {"role": "user", "content": "Hello"}],
    )
    assert url == "https://api.anthropic.com/v1/messages"
    assert headers["x-api-key"] == "sk-test"
    assert headers["anthropic-version"] == "2023-06-01"
    assert payload["system"] == "Sys"
    assert payload["max_tokens"] == 2048
    assert payload["messages"] == [{"role": "user", "content": "Hello"}]


def test_universal_adapter_format_gemini_native():
    headers, payload, url = UniversalAdapter.format_request(
        provider=ProviderType.GEMINI,
        endpoint_url="https://generativelanguage.googleapis.com/v1beta",
        api_key="AIzaSyTest",
        model="gemini-1.5-pro",
        messages=[{"role": "system", "content": "Sys"}, {"role": "user", "content": "Hello"}],
    )
    assert "?key=AIzaSyTest" in url
    assert "generateContent" in url
    assert "Authorization" not in headers
    assert "systemInstruction" in payload
    assert payload["systemInstruction"]["parts"][0]["text"] == "Sys"
    assert payload["contents"][0]["role"] == "user"
    assert payload["contents"][0]["parts"][0]["text"] == "Hello"


def test_universal_adapter_format_gemini_openai_compat():
    headers, payload, url = UniversalAdapter.format_request(
        provider=ProviderType.GEMINI,
        endpoint_url="https://generativelanguage.googleapis.com/v1beta/openai",
        api_key="AIzaSyTest",
        model="gemini-1.5-pro",
        messages=[{"role": "user", "content": "Hello"}],
    )
    assert url == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    assert headers["Authorization"] == "Bearer AIzaSyTest"
    assert payload["model"] == "gemini-1.5-pro"


def test_infer_provider():
    assert UniversalAdapter.infer_provider("https://api.openai.com/v1") == ProviderType.OPENAI
    assert UniversalAdapter.infer_provider("https://api.anthropic.com/v1/messages") == ProviderType.ANTHROPIC
    assert UniversalAdapter.infer_provider("https://api.deepseek.com/chat/completions") == ProviderType.DEEPSEEK
    assert UniversalAdapter.infer_provider("https://api.x.ai/v1/chat/completions") == ProviderType.XAI
    assert UniversalAdapter.infer_provider("https://api.mistral.ai/v1/chat/completions") == ProviderType.MISTRAL_AND_FABLE
    assert UniversalAdapter.infer_provider("https://api.groq.com/openai/v1") == ProviderType.GROQ
    assert UniversalAdapter.infer_provider("https://openrouter.ai/api/v1") == ProviderType.OPENROUTER
    assert UniversalAdapter.infer_provider("http://localhost:11434/v1") == ProviderType.OLLAMA
    assert UniversalAdapter.infer_provider("https://some-custom-domain.com/v1") == ProviderType.CUSTOM


def test_parse_retry_delay_variations():
    # 1. Standard Retry-After Header
    assert UniversalAdapter.parse_retry_delay({"Retry-After": "5"}, "") == 5.0
    assert UniversalAdapter.parse_retry_delay({"retry-after": "12.5"}, "") == 12.5

    # 2. Google RPC Error Details
    google_rpc_err = json.dumps({
        "error": {
            "code": 429,
            "message": "Resource has been exhausted (e.g. check quota).",
            "status": "RESOURCE_EXHAUSTED",
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.RetryInfo",
                    "retryDelay": "49s"
                }
            ]
        }
    })
    assert UniversalAdapter.parse_retry_delay({}, google_rpc_err) == 49.0

    # 3. Regex string fallback
    raw_text = 'Rate limit reached. Please retry in 15s.'
    assert UniversalAdapter.parse_retry_delay({}, raw_text) == 15.0


def test_is_quota_exhausted_detection():
    # Delay > 60s considered daily quota exhaustion
    assert UniversalAdapter.is_quota_exhausted("rate limit", delay=65.0) is True
    assert UniversalAdapter.is_quota_exhausted("rate limit", delay=20.0) is False

    # Metric per day
    err_per_day = "Quota exceeded for metric 'GenerateRequestsPerDay' and limit '1000'"
    assert UniversalAdapter.is_quota_exhausted(err_per_day, delay=10.0) is True


@pytest.mark.asyncio
async def test_http_429_retry_and_recovery():
    # Mock first response 429 with retryDelay, second response 200 OK
    resp_429 = MagicMock()
    resp_429.status = 429
    resp_429.headers = {"Retry-After": "0.01"}
    resp_429.text = AsyncMock(return_value="Rate limit exceeded. retryDelay: 0.01s")

    resp_200 = MagicMock()
    resp_200.status = 200
    resp_200.json = AsyncMock(return_value={"choices": [{"message": {"content": "Recovered Response"}}]})

    mock_session = MagicMock()
    mock_session.post.return_value.__aenter__ = AsyncMock(side_effect=[resp_429, resp_200])
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession") as mock_session_cls, patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_session_cls.return_value.__aenter__.return_value = mock_session

        text, latency, tools = await UniversalAdapter.generate(
            endpoint_url="https://api.openai.com/v1",
            api_key="test-key",
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert text == "Recovered Response"
        assert mock_sleep.called
        assert mock_session.post.return_value.__aenter__.call_count == 2


@pytest.mark.asyncio
async def test_http_429_quota_exhausted_immediate_failover():
    resp_429 = MagicMock()
    resp_429.status = 429
    resp_429.headers = {}
    resp_429.text = AsyncMock(return_value=json.dumps({
        "error": {
            "status": "RESOURCE_EXHAUSTED",
            "message": "Quota exceeded for quota metric GenerateRequestsPerDay",
            "details": [{"retryDelay": "86400s"}]
        }
    }))

    mock_session = MagicMock()
    mock_session.post.return_value.__aenter__ = AsyncMock(return_value=resp_429)
    mock_session.post.return_value.__aexit__ = AsyncMock(return_value=None)

    with patch("aiohttp.ClientSession") as mock_session_cls, patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_session_cls.return_value.__aenter__.return_value = mock_session

        text, latency, tools = await UniversalAdapter.generate(
            endpoint_url="https://generativelanguage.googleapis.com/v1beta/openai",
            api_key="test-key",
            model="gemini-2.0-flash",
            messages=[{"role": "user", "content": "Hello"}],
            safe_harbor=False
        )

        assert "[QUOTA EXHAUSTED]" in text
        assert "Switch provider or model preset" in text
        assert not mock_sleep.called

