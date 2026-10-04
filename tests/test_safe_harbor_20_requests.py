import time
import asyncio
from unittest.mock import patch, AsyncMock
from hunters_guild.engine.universal_adapter import UniversalAdapter, ProviderType

async def run_20_requests():
    with patch("aiohttp.ClientSession.post") as mock_post:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"choices": [{"message": {"content": "Hi"}}]})
        mock_post.return_value.__aenter__.return_value = mock_response

        total_start = time.perf_counter()
        
        for i in range(20):
            req_start = time.perf_counter()
            await UniversalAdapter.dispatch(
                endpoint_url="http://mock.endpoint/v1",
                messages=[{"role": "user", "content": "hi"}],
                model="mock-model",
                provider=ProviderType.OPENAI,
                safe_harbor=True
            )
            req_duration = time.perf_counter() - req_start
            print(f"Request {i+1} delay: {req_duration:.3f}s")
            
        total_duration = time.perf_counter() - total_start
        print(f"Total time for 20 requests: {total_duration:.3f}s")

if __name__ == "__main__":
    asyncio.run(run_20_requests())
