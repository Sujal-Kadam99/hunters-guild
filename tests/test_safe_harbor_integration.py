import pytest
from unittest.mock import patch, AsyncMock
from hunters_guild.engine.universal_adapter import UniversalAdapter, ProviderType

@pytest.mark.asyncio
async def test_safe_harbor_headers_injected():
    messages = [{"role": "user", "content": "Hello"}]
    
    with patch("aiohttp.ClientSession.post", new_callable=AsyncMock) as mock_post:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"choices": [{"message": {"content": "Hi"}}]})
        
        mock_post.return_value.__aenter__.return_value = mock_response
        
        await UniversalAdapter.dispatch(
            endpoint_url="http://mock.endpoint/v1",
            messages=messages,
            api_key="sk-mock",
            model="mock-model",
            provider=ProviderType.OPENAI
        )
        
        assert mock_post.called
        
        call_args, call_kwargs = mock_post.call_args
        headers = call_kwargs.get("headers", {})
        
        assert "X-Bug-Bounty-Researcher" in headers
        assert "X-Security-Research-Program" in headers
        assert "X-Hunters-Guild-Attribution" in headers
        assert headers["X-Hunters-Guild-Attribution"] == "Automated-Boundary-Verification-Framework"
