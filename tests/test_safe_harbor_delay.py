import asyncio
import time
from hunters_guild.modules.safe_harbor import SafeHarborEngine

async def run():
    engine = SafeHarborEngine()
    start_t = time.perf_counter()
    total_injected = 0.0
    for _ in range(20):
        # acquire_permission returns the delay it added
        delay = await engine.acquire_permission()
        total_injected += delay
    
    elapsed = time.perf_counter() - start_t
    print(f"Total time elapsed: {elapsed:.2f}s")
    print(f"Total injected delay reported by engine: {total_injected:.2f}s")
    print(f"Average delay per request: {total_injected / 20:.2f}s")

if __name__ == "__main__":
    asyncio.run(run())
