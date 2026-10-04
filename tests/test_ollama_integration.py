import pytest
import aiohttp
from hunters_guild.engine.universal_adapter import UniversalAdapter, ProviderType

async def check_ollama_running():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://localhost:11434/", timeout=1) as response:
                return response.status == 200
    except Exception:
        return False

@pytest.mark.asyncio
async def test_ollama_integration():
    is_running = await check_ollama_running()
    if not is_running:
        pytest.skip("Ollama is not running locally on port 11434")
        
    messages = [{"role": "user", "content": "Hello, how are you? Please reply with a short greeting."}]
    
    text, latency, tool_calls = await UniversalAdapter.dispatch(
        endpoint_url="http://localhost:11434/v1/chat/completions",
        api_key="",
        model="llama3.2", # assuming this model is available
        messages=messages,
        provider=ProviderType.OLLAMA
    )
    
    assert text is not None
    assert len(text) > 0
    # Just asserting we get a response, avoiding hardcoded judge scores
