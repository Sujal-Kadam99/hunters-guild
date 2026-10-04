import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("HuntersGuild.LLMClient")


class UniversalLLMClient:
    """
    A universal asynchronous HTTP client that automatically formats requests for 
    OpenAI, Anthropic, or Gemini native APIs based on the endpoint URL or model.
    """

    @staticmethod
    async def generate(
        endpoint_url: str,
        api_key: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        timeout: float = 45.0,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """
        Sends an LLM generation request.
        Returns: (text_response, latency_ms, optional_tool_calls)
        """
        from hunters_guild.engine.universal_adapter import UniversalAdapter
        return await UniversalAdapter.generate(
            endpoint_url=endpoint_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
            tools=tools,
            timeout=timeout,
        )
