import pytest
import time
import asyncio
from unittest.mock import patch, AsyncMock
from hunters_guild.engine.universal_adapter import UniversalAdapter, ProviderType

@pytest.mark.asyncio
async def test_delay_with_safe_harbor():
    with patch("aiohttp.ClientSession.post", new_callable=AsyncMock) as mock_post:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"choices": [{"message": {"content": "Hi"}}]})
        mock_post.return_value.__aenter__.return_value = mock_response

        # Use an already exhausted bucket or just rely on jitter
        # But wait, SafeHarborEngine applies jitter by default (0.5 to 2.0s)
        
        start = time.perf_counter()
        await UniversalAdapter.dispatch(
            endpoint_url="http://mock.endpoint/v1",
            messages=[{"role": "user", "content": "hi"}],
            model="mock-model",
            provider=ProviderType.OPENAI,
            safe_harbor=True
        )
        duration = time.perf_counter() - start
        print(f"\nDuration WITH Safe Harbor: {duration:.3f}s")
        assert duration >= 0.5, "Expected Safe Harbor jitter delay >= 0.5s"

@pytest.mark.asyncio
async def test_delay_without_safe_harbor():
    with patch("aiohttp.ClientSession.post", new_callable=AsyncMock) as mock_post:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"choices": [{"message": {"content": "Hi"}}]})
        mock_post.return_value.__aenter__.return_value = mock_response
        
        start = time.perf_counter()
        await UniversalAdapter.dispatch(
            endpoint_url="http://mock.endpoint/v1",
            messages=[{"role": "user", "content": "hi"}],
            model="mock-model",
            provider=ProviderType.OPENAI,
            safe_harbor=False
        )
        duration = time.perf_counter() - start
        print(f"\nDuration WITHOUT Safe Harbor: {duration:.3f}s")
        assert duration < 0.1, "Expected no delay with safe_harbor=False"
