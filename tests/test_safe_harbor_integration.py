import pytest
import aiohttp
from aiohttp import web
import asyncio
from hunters_guild.engine.universal_adapter import UniversalAdapter, ProviderType
import time
import json
import socket
from contextlib import asynccontextmanager

async def http_handler(request):
    headers = dict(request.headers)
    return web.json_response({"choices": [{"message": {"content": json.dumps(headers)}}]})

async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    headers = dict(request.headers)
    
    async for msg in ws:
        if msg.type == aiohttp.WSMsgType.TEXT:
            await ws.send_json({"text": json.dumps(headers)})
            await ws.send_str("[DONE]")
            break
    
    return ws

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

@asynccontextmanager
async def start_local_server():
    app = web.Application()
    app.router.add_post('/v1/chat/completions', http_handler)
    app.router.add_get('/v1/ws', ws_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    port = get_free_port()
    site = web.TCPSite(runner, '127.0.0.1', port)
    await site.start()
    
    try:
        yield port
    finally:
        await runner.cleanup()

@pytest.mark.asyncio
async def test_safe_harbor_http():
    async with start_local_server() as port:
        url = f"http://127.0.0.1:{port}/v1/chat/completions"
        
        start = time.perf_counter()
        text, latency, _ = await UniversalAdapter.dispatch(
            endpoint_url=url,
            messages=[{"role": "user", "content": "hi"}],
            model="mock",
            provider=ProviderType.OPENAI
        )
        duration = time.perf_counter() - start
        
        headers = json.loads(text)
        assert "X-Bug-Bounty-Researcher" in headers
        assert headers["X-Hunters-Guild-Attribution"] == "Automated-Boundary-Verification-Framework"
        
        print(f"\nHTTP Request Delay: {duration:.2f}s")

@pytest.mark.asyncio
async def test_safe_harbor_ws():
    async with start_local_server() as port:
        url = f"ws://127.0.0.1:{port}/v1/ws"
        
        start = time.perf_counter()
        text, latency, _ = await UniversalAdapter.dispatch(
            endpoint_url=url,
            messages=[{"role": "user", "content": "hi"}],
            model="mock",
        )
        duration = time.perf_counter() - start
        
        assert "X-Bug-Bounty-Researcher" in text
        assert "Automated-Boundary-Verification-Framework" in text
        
        print(f"\nWebSocket Request Delay: {duration:.2f}s")

@pytest.mark.asyncio
async def test_safe_harbor_disabled():
    async with start_local_server() as port:
        url = f"http://127.0.0.1:{port}/v1/chat/completions"
        
        text, latency, _ = await UniversalAdapter.dispatch(
            endpoint_url=url,
            messages=[{"role": "user", "content": "hi"}],
            model="mock",
            provider=ProviderType.OPENAI,
            safe_harbor=False
        )
        
        headers = json.loads(text)
        assert "X-Bug-Bounty-Researcher" not in headers
        assert "X-Hunters-Guild-Attribution" not in headers

