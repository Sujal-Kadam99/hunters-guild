import json
import logging
from typing import Any, Dict, List, Tuple

import aiohttp

from hunters_guild.core.schemas import TargetProfile

logger = logging.getLogger("HuntersGuild.StreamAdapter")


class StreamSchemaAdapter:
    """
    Stream Handling & API Schema Normalizer.
    Normalizes requests for various provider schemas and parses chunked SSE streams.
    """

    @classmethod
    def normalize_request(
        cls, 
        target_profile: TargetProfile, 
        messages: List[Dict[str, str]], 
        stream: bool = False
    ) -> Dict[str, Any]:
        """
        Normalizes the request payload based on the detected API format.
        Supports OpenAI, Anthropic, and generic Raw formats.
        """
        url_lower = target_profile.endpoint_url.lower()
        payload: Dict[str, Any] = {}

        if "anthropic.com" in url_lower or "claude" in target_profile.model_identifier.lower():
            # Anthropic Schema
            sys_msg = next((m["content"] for m in messages if m["role"] == "system"), None)
            anthropic_msgs = [m for m in messages if m["role"] != "system"]
            payload = {
                "model": target_profile.model_identifier,
                "messages": anthropic_msgs,
                "max_tokens": 1024,
                "stream": stream
            }
            if sys_msg:
                payload["system"] = sys_msg

        elif "raw" in url_lower or "generic" in url_lower:
            # Raw Prompt / Query Format
            # Combine messages into a single prompt string
            prompt = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages)
            
            # Simple heuristic to determine if endpoint prefers "query" or "prompt"
            if "query" in url_lower:
                payload = {"query": prompt, "stream": stream}
            else:
                payload = {"prompt": prompt, "stream": stream}

        else:
            # Default OpenAI Format
            payload = {
                "model": target_profile.model_identifier,
                "messages": messages,
                "stream": stream
            }

        return payload

    @classmethod
    async def parse_response_stream(
        cls, 
        response: aiohttp.ClientResponse
    ) -> Tuple[str, int]:
        """
        Detects `text/event-stream` / chunked SSE responses and parses them.
        Falls back to standard `response.json()` if `application/json`.
        Returns: (full_reassembled_string, number_of_chunks_processed)
        """
        content_type = response.headers.get("Content-Type", "")
        
        # 1. Fallback for non-streaming JSON
        if "application/json" in content_type:
            try:
                data = await response.json()
                # Try OpenAI format
                choices = data.get("choices", [])
                if choices and isinstance(choices, list):
                    message = choices[0].get("message", {})
                    return message.get("content", "") or "", 1
                
                # Try Anthropic format
                content = data.get("content", [])
                if content and isinstance(content, list) and content[0].get("type") == "text":
                    return content[0].get("text", ""), 1

                # Try Raw string
                if isinstance(data, dict):
                    if "response" in data:
                        return data["response"], 1
                    elif "text" in data:
                        return data["text"], 1

                return json.dumps(data), 1
            except Exception as e:
                logger.error(f"Failed to parse JSON response: {e}")
                return await response.text(), 1

        # 2. SSE Stream Parsing
        full_text = []
        chunks_processed = 0

        async for line in response.content:
            line = line.decode('utf-8').strip()
            if not line:
                continue
            
            if line.startswith("data: "):
                data_str = line[6:]
                if data_str == "[DONE]":
                    break
                
                try:
                    chunk = json.loads(data_str)
                    
                    # OpenAI chunk format
                    choices = chunk.get("choices", [])
                    if choices and isinstance(choices, list):
                        delta = choices[0].get("delta", {})
                        if "content" in delta:
                            full_text.append(delta["content"])
                            chunks_processed += 1
                            continue
                            
                    # Anthropic chunk format
                    if chunk.get("type") == "content_block_delta":
                        delta = chunk.get("delta", {})
                        if delta.get("type") == "text_delta":
                            full_text.append(delta.get("text", ""))
                            chunks_processed += 1
                            continue

                except json.JSONDecodeError:
                    pass

        return "".join(full_text), chunks_processed
