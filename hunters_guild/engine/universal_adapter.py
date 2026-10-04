"""
Hunters Guild - Universal Provider & Multi-Protocol Transport Engine
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework

Implements multi-provider payload formatting, dynamic request building, parameter sanitization,
and multi-protocol transceiving (HTTP/HTTPS, SSH, WebSocket, Mock) for LLMs across all generational tiers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
import ssl
import time
from enum import Enum
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import unquote, urlsplit

import aiohttp
from aiohttp import ClientSession, TCPConnector, ClientTimeout, WSMsgType

from hunters_guild.modules.safe_harbor import SafeHarborEngine

logger = logging.getLogger("HuntersGuild.UniversalAdapter")

_safe_harbor_engine = SafeHarborEngine()


class ProviderType(str, Enum):
    """Supported LLM Providers & Transport Protocols."""
    OPENAI = "OPENAI"
    GEMINI = "GEMINI"
    GROQ = "GROQ"
    OPENROUTER = "OPENROUTER"
    ANTHROPIC = "ANTHROPIC"
    DEEPSEEK = "DEEPSEEK"
    XAI = "XAI"
    MISTRAL_AND_FABLE = "MISTRAL_AND_FABLE"
    MISTRAL = "MISTRAL"
    OLLAMA = "OLLAMA"
    SSH = "SSH"
    WEBSOCKET = "WEBSOCKET"
    CUSTOM = "CUSTOM"


PROVIDER_PRESETS: Dict[str, Dict[str, Any]] = {
    ProviderType.GEMINI.value: {
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "models": [
            "gemini-3.7-flash",
            "gemini-3.5-pro",
            "gemini-3.0-pro",
            "gemini-3.0-flash",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-2.0-flash-lite",
            "gemini-2.0-pro-exp-02-05",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-1.5-flash-8b",
            "gemini-1.0-pro",
            "gemini-1.0-ultra",
        ],
    },
    ProviderType.OPENAI.value: {
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "models": [
            "gpt-5",
            "gpt-5-turbo",
            "gpt-4.5-preview",
            "o3",
            "o3-mini",
            "o1",
            "o1-mini",
            "o1-preview",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-4",
            "gpt-3.5-turbo",
        ],
    },
    ProviderType.ANTHROPIC.value: {
        "endpoint": "https://api.anthropic.com/v1/messages",
        "models": [
            "claude-4-5-sonnet",
            "claude-4-opus",
            "claude-4-sonnet",
            "claude-3-7-sonnet-latest",
            "claude-3-5-sonnet-latest",
            "claude-3-5-haiku-latest",
            "claude-3-opus-latest",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
            "claude-2.1",
            "claude-2.0",
            "claude-instant-1.2",
        ],
    },
    ProviderType.DEEPSEEK.value: {
        "endpoint": "https://api.deepseek.com/chat/completions",
        "models": [
            "deepseek-reasoner",
            "deepseek-chat",
            "deepseek-v3",
            "deepseek-r1",
        ],
    },
    ProviderType.XAI.value: {
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "models": [
            "grok-3",
            "grok-2-latest",
            "grok-2-vision-1212",
            "grok-beta",
        ],
    },
    ProviderType.MISTRAL_AND_FABLE.value: {
        "endpoint": "https://api.mistral.ai/v1/chat/completions",
        "models": [
            "fable-5",
            "mistral-large-latest",
            "mistral-small-latest",
            "codestral-latest",
            "pixtral-large-latest",
            "open-mixtral-8x22b",
            "open-mistral-nemo",
        ],
    },
    ProviderType.MISTRAL.value: {
        "endpoint": "https://api.mistral.ai/v1/chat/completions",
        "models": [
            "fable-5",
            "mistral-large-latest",
            "mistral-small-latest",
            "codestral-latest",
            "pixtral-large-latest",
            "open-mixtral-8x22b",
            "open-mistral-nemo",
        ],
    },
    ProviderType.GROQ.value: {
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "models": [
            "deepseek-r1-distill-llama-70b",
            "deepseek-r1-distill-qwen-32b",
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "qwen-2.5-coder-32b",
            "qwen-2.5-72b-instruct",
            "mixtral-8x7b-32768",
        ],
    },
    ProviderType.OPENROUTER.value: {
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "models": [
            "deepseek/deepseek-r1:free",
            "meta-llama/llama-3.3-70b-instruct:free",
            "google/gemini-2.0-flash-exp:free",
            "anthropic/claude-3.5-sonnet",
            "openai/gpt-4o",
            "mistralai/mistral-large-2411",
        ],
    },
    ProviderType.OLLAMA.value: {
        "endpoint": "http://localhost:11434/v1/chat/completions",
        "models": [
            "llama3.3",
            "llama3.2",
            "mistral",
            "qwen2.5",
            "deepseek-r1",
            "phi4",
        ],
    },
    ProviderType.SSH.value: {
        "endpoint": "ssh://user@localhost:22/ollama run llama3.3 \"{prompt}\"",
        "models": [
            "llama3.3",
            "deepseek-r1",
            "mistral",
            "qwen2.5-coder",
            "vllm-local",
            "custom-command",
        ],
    },
    ProviderType.WEBSOCKET.value: {
        "endpoint": "wss://api.example.com/v1/stream",
        "models": [
            "gpt-4o",
            "llama-3.3",
            "claude-3-7-sonnet",
            "deepseek-r1",
            "qwen-2.5-coder",
            "custom-stream",
        ],
    },
}


def sanitize_endpoint_url(raw_url: str) -> str:
    """
    Robust URL Sanitizer.
    - Removes markdown links e.g. [https://...](https://...) -> https://...
    - Strips enclosing quotes, brackets, and parentheses without breaking internal payload strings.
    - Strictly preserves non-HTTP protocols (ssh://, ws://, wss://, mock://) without modification.
    - Automatically appends /chat/completions if the base URL ends with /v1, /openai, or /v1beta/openai
      and doesn't already have the completions path (and is not Anthropic).
    """
    if not raw_url:
        return ""
        
    url = raw_url.strip()
    
    # Remove markdown link format [link](url) or [name](url)
    md_match = re.search(r'\]\(([^)]+)\)', url)
    if md_match:
        url = md_match.group(1).strip()
        
    # Strip enclosing quotes, angle brackets, brackets, parens only if matched on both ends
    while len(url) >= 2 and (
        (url.startswith('"') and url.endswith('"'))
        or (url.startswith("'") and url.endswith("'"))
        or (url.startswith("<") and url.endswith(">"))
        or (url.startswith("[") and url.endswith("]"))
        or (url.startswith("(") and url.endswith(")"))
    ):
        url = url[1:-1].strip()

    # Strictly preserve non-HTTP schemas
    if url.startswith(("ssh://", "ws://", "wss://", "mock://")):
        return url
    
    # Auto-append /chat/completions logic
    if not url.endswith("/chat/completions") and "anthropic.com" not in url:
        if url.endswith("/v1") or url.endswith("/openai") or url.endswith("/v1beta/openai"):
            url = f"{url}/chat/completions"
            
    return url


def is_reasoning_model(model: str) -> bool:
    """
    Determines if a model identifier belongs to a reasoning model.
    Reasoning models (such as o1, o3, deepseek-reasoner, deepseek-r1) do not support the
    temperature parameter on standard completions endpoints.
    """
    m = model.lower().strip()
    if re.match(r"^(o1|o3|o4|o5)(-[a-z0-9]+)*$", m):
        return True
    if any(k in m for k in ["deepseek-reasoner", "deepseek-r1", "r1-distill", "/deepseek-r1"]):
        return True
    return False


def is_openai_reasoning_model(model: str) -> bool:
    """
    Determines if a model is an OpenAI reasoning model (e.g. o1, o3 series)
    which requires 'max_completion_tokens' instead of 'max_tokens'.
    """
    m = model.lower().strip()
    return bool(re.match(r"^(o1|o3|o4|o5)(-[a-z0-9]+)*$", m))


# =============================================================================
# SSH TRANSPORT ADAPTER
# =============================================================================

class SSHTransportAdapter:
    """
    Asynchronous SSH Transport Adapter for executing remote model probes,
    CLI LLM processes (e.g. Ollama, vLLM, llama.cpp), and custom daemon scripts over SSH.
    """

    @staticmethod
    def parse_ssh_url(url: str) -> Dict[str, Any]:
        """
        Parses `ssh://[user[:password]@]host[:port][/command_template]` syntax with full URL-decoding
        for special characters in credentials and commands.
        """
        parsed = urlsplit(url)
        if parsed.scheme.lower() != "ssh":
            raise ValueError(f"Invalid SSH URL scheme: {url}. Expected 'ssh://'")

        username = unquote(parsed.username) if parsed.username else None
        password = unquote(parsed.password) if parsed.password else None
        hostname = parsed.hostname or "localhost"
        port = parsed.port or 22

        raw_cmd = parsed.path
        if raw_cmd.startswith("/"):
            raw_cmd = raw_cmd[1:]
        if parsed.query:
            raw_cmd = f"{raw_cmd}?{parsed.query}"
        if parsed.fragment:
            raw_cmd = f"{raw_cmd}#{parsed.fragment}"

        command_template = unquote(raw_cmd) if raw_cmd else 'ollama run llama3.3 "{prompt}"'

        return {
            "username": username,
            "password": password,
            "host": hostname,
            "port": port,
            "command_template": command_template,
        }

    @staticmethod
    def format_command(command_template: str, prompt: str) -> str:
        """
        Applies shell quoting to the adversarial prompt to safely interpolate it into the
        remote command template without escaping errors, subshell injection, or broken quotes.
        """
        quoted_prompt = shlex.quote(prompt)

        if "{prompt}" in command_template:
            return command_template.replace("{prompt}", quoted_prompt)
        elif '"{prompt}"' in command_template:
            return command_template.replace('"{prompt}"', quoted_prompt)
        elif "'{prompt}'" in command_template:
            return command_template.replace("'{prompt}'", quoted_prompt)
        else:
            return f"{command_template.strip()} {quoted_prompt}"

    @classmethod
    async def execute(
        cls,
        endpoint_url: str,
        messages: List[Dict[str, str]],
        timeout: float = 30.0,
        key_filename: Optional[str] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """
        Executes a prompt sequence over SSH.
        Returns: (output_text, latency_ms, tool_calls)
        """
        start_time = time.perf_counter()
        config = cls.parse_ssh_url(endpoint_url)

        user = username or config["username"] or "root"
        pwd = password or config["password"]
        host = config["host"]
        port = config["port"]
        cmd_template = config["command_template"]

        prompt_text = ""
        user_msgs = [m["content"] for m in messages if m.get("role") == "user"]
        if user_msgs:
            prompt_text = user_msgs[-1]
        elif messages:
            prompt_text = messages[-1].get("content", "")

        remote_cmd = cls.format_command(cmd_template, prompt_text)
        logger.info("Executing remote SSH probe on %s@%s:%d -> %s", user, host, port, remote_cmd[:100])

        output_text = await cls._execute_remote_command(
            host=host,
            port=port,
            username=user,
            password=pwd,
            key_filename=key_filename,
            command=remote_cmd,
            timeout=timeout,
        )

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return output_text, latency_ms, None

    @classmethod
    async def _execute_remote_command(
        cls,
        host: str,
        port: int,
        username: str,
        password: Optional[str],
        key_filename: Optional[str],
        command: str,
        timeout: float,
    ) -> str:
        """
        Executes remote command via Paramiko (if available) with async thread offloading,
        or falls back to local SSH subprocess execution.
        """
        loop = asyncio.get_running_loop()

        resolved_key = key_filename
        if not resolved_key and not password:
            for candidate in [os.path.expanduser("~/.ssh/id_rsa"), os.path.expanduser("~/.ssh/id_ed25519")]:
                if os.path.isfile(candidate):
                    resolved_key = candidate
                    break

        try:
            import paramiko  # type: ignore

            def _paramiko_exec() -> str:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        password=password,
                        key_filename=resolved_key,
                        timeout=timeout,
                    )
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
                    out_bytes = stdout.read()
                    err_bytes = stderr.read()
                    out_str = out_bytes.decode("utf-8", errors="replace").strip()
                    err_str = err_bytes.decode("utf-8", errors="replace").strip()
                    return out_str if out_str else (f"[STDERR] {err_str}" if err_str else "[EMPTY_RESPONSE]")
                finally:
                    ssh.close()

            return await loop.run_in_executor(None, _paramiko_exec)

        except ImportError:
            ssh_args = [
                "ssh",
                "-p", str(port),
                "-o", "StrictHostKeyChecking=no",
                "-o", f"ConnectTimeout={int(timeout)}",
            ]
            if resolved_key:
                ssh_args.extend(["-i", resolved_key])

            target_spec = f"{username}@{host}" if username else host
            ssh_args.extend([target_spec, command])

            try:
                proc = await asyncio.create_subprocess_exec(
                    *ssh_args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_data, stderr_data = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                out_str = stdout_data.decode("utf-8", errors="replace").strip()
                err_str = stderr_data.decode("utf-8", errors="replace").strip()
                return out_str if out_str else (f"[STDERR] {err_str}" if err_str else "[EMPTY_RESPONSE]")
            except asyncio.TimeoutError:
                return f"[SSH TIMEOUT] Remote command timed out after {timeout} seconds."
            except Exception as exc:
                return f"[SSH SUBPROCESS ERROR] {str(exc)}"
        except Exception as exc:
            return f"[SSH ERROR] {str(exc)}"


# =============================================================================
# WEBSOCKET TRANSPORT ADAPTER
# =============================================================================

class WebSocketTransportAdapter:
    """
    Real-Time Bidirectional WebSocket Transport Adapter (ws:// and wss://).
    Manages custom handshakes, TLS verification bypass, safe payload interpolation,
    keepalive ping/pong, frame aggregation, stop-token detection, and TTFT latency measurement.
    """

    DEFAULT_CONNECT_TIMEOUT: float = 15.0
    DEFAULT_FRAME_TIMEOUT: float = 45.0
    DEFAULT_PING_INTERVAL: float = 20.0
    DEFAULT_STOP_TOKENS: List[str] = ["[DONE]", "<|im_end|>", "<|endoftext|>", "STOP"]

    @staticmethod
    def format_payload(
        template: Optional[Union[str, Dict[str, Any]]],
        prompt: str,
        model: Optional[str] = None,
    ) -> str:
        """
        Safely formats the adversarial prompt into a JSON template using strict JSON serialization
        to avoid syntax corruption on multi-line or special-character payloads.
        """
        if not template:
            payload_dict: Dict[str, Any] = {"messages": [{"role": "user", "content": prompt}]}
            if model:
                payload_dict["model"] = model
            return json.dumps(payload_dict)

        if isinstance(template, dict):
            template_str = json.dumps(template)
        else:
            template_str = str(template).strip()

        if '"{prompt}"' in template_str:
            escaped_json = json.dumps(prompt)
            formatted_str = template_str.replace('"{prompt}"', escaped_json)
        elif "{prompt}" in template_str:
            inner_escaped = json.dumps(prompt)[1:-1]
            formatted_str = template_str.replace("{prompt}", inner_escaped)
        else:
            try:
                data = json.loads(template_str)
                if isinstance(data, dict):
                    if "messages" in data and isinstance(data["messages"], list):
                        data["messages"].append({"role": "user", "content": prompt})
                    else:
                        data["prompt"] = prompt
                    if model and "model" not in data:
                        data["model"] = model
                    return json.dumps(data)
            except Exception:
                pass
            formatted_str = json.dumps({"prompt": prompt, "model": model or "default"})

        try:
            parsed = json.loads(formatted_str)
            if model and isinstance(parsed, dict) and "model" not in parsed:
                parsed["model"] = model
            return json.dumps(parsed)
        except Exception:
            return formatted_str

    @classmethod
    def extract_text_delta(cls, data: Any, extraction_key: Optional[str] = None) -> str:
        """
        Extracts token deltas from nested frame structures (OpenAI delta, Anthropic block, Ollama response, or text).
        """
        if isinstance(data, bytes):
            try:
                data = data.decode("utf-8", errors="replace")
            except Exception:
                return ""

        if isinstance(data, str):
            raw_str = data.strip()
            if raw_str.startswith("data:"):
                raw_str = raw_str[5:].strip()
            if not raw_str or raw_str in ["[DONE]", "data: [DONE]", "data:[DONE]"]:
                return ""
            try:
                data = json.loads(raw_str)
            except Exception:
                return raw_str

        if not isinstance(data, dict):
            return str(data)

        # Custom extraction key (dot or bracket notation)
        if extraction_key:
            val: Any = data
            tokens = re.split(r"[\.\[\]]+", extraction_key.strip("."))
            tokens = [t for t in tokens if t]
            try:
                for tok in tokens:
                    if isinstance(val, dict):
                        val = val.get(tok)
                    elif isinstance(val, list) and tok.isdigit():
                        val = val[int(tok)]
                    else:
                        val = None
                    if val is None:
                        break
                if val is not None:
                    return str(val)
            except Exception:
                pass

        # Standard heuristics across LLM APIs
        # 1. OpenAI streaming choices[0].delta.content or text
        choices = data.get("choices")
        if choices and isinstance(choices, list) and len(choices) > 0:
            c0 = choices[0]
            if isinstance(c0, dict):
                delta = c0.get("delta", {})
                if isinstance(delta, dict) and "content" in delta:
                    return str(delta.get("content") or "")
                if "text" in c0:
                    return str(c0.get("text") or "")
                msg = c0.get("message", {})
                if isinstance(msg, dict) and "content" in msg:
                    return str(msg.get("content") or "")

        # 2. Anthropic delta / content_block
        if "delta" in data and isinstance(data["delta"], dict):
            return str(data["delta"].get("text") or "")

        # 3. Ollama response
        if "response" in data:
            return str(data["response"] or "")

        # 4. Generic text / message / content keys
        for k in ["text", "message", "content", "output", "token"]:
            if k in data and isinstance(data[k], (str, int, float)):
                return str(data[k])

        return ""

    @classmethod
    def is_stream_done(
        cls,
        frame_raw: str,
        parsed_json: Optional[Dict[str, Any]] = None,
        stop_token: Optional[str] = None,
    ) -> bool:
        """
        Detects stream completion across standard triggers:
        [DONE], finish_reason: "stop", done: true, or custom stop token.
        """
        trimmed = frame_raw.strip()
        if trimmed in ["[DONE]", "data: [DONE]", "data:[DONE]"]:
            return True

        if stop_token and stop_token in frame_raw:
            return True

        # Check JSON flags
        data = parsed_json
        if data is None and (trimmed.startswith("{") or trimmed.startswith("data:")):
            raw_target = trimmed[5:].strip() if trimmed.startswith("data:") else trimmed
            try:
                data = json.loads(raw_target)
            except Exception:
                pass

        if isinstance(data, dict):
            if data.get("done") is True or data.get("is_final") is True:
                return True
            if data.get("type") in ["message_stop", "completion_stop"]:
                return True
            if data.get("finish_reason") in ["stop", "end_turn", "length", "eos"]:
                return True
            choices = data.get("choices")
            if choices and isinstance(choices, list) and len(choices) > 0:
                c0 = choices[0]
                if isinstance(c0, dict) and c0.get("finish_reason") in ["stop", "end_turn", "length", "eos"]:
                    return True

        return False

    @classmethod
    async def execute(
        cls,
        endpoint_url: str,
        messages: List[Dict[str, str]],
        api_key: str = "",
        model: str = "",
        payload_template: Optional[str] = None,
        extraction_key: Optional[str] = None,
        stop_token: Optional[str] = None,
        timeout: float = 45.0,
        connect_timeout: float = 15.0,
        stream_callback: Optional[Callable[[str], Any]] = None,
        ssl_verify: bool = True,
        headers: Optional[Dict[str, str]] = None,
        safe_harbor: bool = True,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """
        Connects to a WebSocket endpoint, transmits the formatted payload, and aggregates
        incoming frames into a complete response.
        Returns: (aggregated_text, latency_ms, None)
        """
        if safe_harbor:
            await _safe_harbor_engine.acquire_permission()
        start_time = time.perf_counter()
        ttft_ms: Optional[float] = None

        prompt_text = ""
        user_msgs = [m["content"] for m in messages if m.get("role") == "user"]
        if user_msgs:
            prompt_text = user_msgs[-1]
        elif messages:
            prompt_text = messages[-1].get("content", "")

        payload_str = cls.format_payload(payload_template, prompt_text, model=model)

        req_headers: Dict[str, str] = {}
        if api_key:
            if api_key.lower().startswith("bearer "):
                req_headers["Authorization"] = api_key
            else:
                req_headers["Authorization"] = f"Bearer {api_key}"
                req_headers["X-API-Key"] = api_key
        
        if safe_harbor:
            req_headers.update(_safe_harbor_engine.build_compliant_headers())
        
        if headers:
            req_headers.update(headers)

        accumulated_chunks: List[str] = []

        try:
            client_timeout = aiohttp.ClientTimeout(total=timeout, connect=connect_timeout)
            connector = aiohttp.TCPConnector(ssl=False if not ssl_verify else None)

            async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
                async with session.ws_connect(
                    endpoint_url,
                    headers=req_headers if req_headers else None,
                    heartbeat=cls.DEFAULT_PING_INTERVAL,
                ) as ws:
                    await ws.send_str(payload_str)

                    while True:
                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=cls.DEFAULT_FRAME_TIMEOUT)
                        except asyncio.TimeoutError:
                            logger.warning("WebSocket frame read timed out on %s", endpoint_url)
                            break

                        if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSE):
                            break
                        if msg.type == aiohttp.WSMsgType.ERROR:
                            logger.warning("WebSocket error frame received: %s", ws.exception())
                            break

                        if msg.type == aiohttp.WSMsgType.TEXT:
                            raw_text = msg.data
                            if cls.is_stream_done(raw_text, stop_token=stop_token):
                                # If there's an extraction delta in the final frame before done, capture it
                                delta = cls.extract_text_delta(raw_text, extraction_key=extraction_key)
                                if delta:
                                    accumulated_chunks.append(delta)
                                break

                            delta = cls.extract_text_delta(raw_text, extraction_key=extraction_key)
                            if delta:
                                if ttft_ms is None:
                                    ttft_ms = (time.perf_counter() - start_time) * 1000.0
                                accumulated_chunks.append(delta)
                                if stream_callback:
                                    try:
                                        if asyncio.iscoroutinefunction(stream_callback):
                                            await stream_callback(delta)
                                        else:
                                            stream_callback(delta)
                                    except Exception as cb_err:
                                        logger.debug("WebSocket stream callback error: %s", cb_err)

                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            try:
                                raw_text = msg.data.decode("utf-8", errors="replace")
                                delta = cls.extract_text_delta(raw_text, extraction_key=extraction_key)
                                if delta:
                                    accumulated_chunks.append(delta)
                            except Exception:
                                pass

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error("WebSocket connection error on %s: %s", endpoint_url, exc)
            return f"[WEBSOCKET ERROR] {str(exc)}", latency_ms, None

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        final_text = "".join(accumulated_chunks)
        if not final_text:
            final_text = "[EMPTY_WEBSOCKET_RESPONSE]"

        return final_text, latency_ms, None

    @classmethod
    async def stream(
        cls,
        endpoint_url: str,
        messages: List[Dict[str, str]],
        api_key: str = "",
        model: str = "",
        payload_template: Optional[str] = None,
        extraction_key: Optional[str] = None,
        stop_token: Optional[str] = None,
        timeout: float = 45.0,
        connect_timeout: float = 15.0,
        ssl_verify: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> AsyncGenerator[str, None]:
        """
        Async generator that yields token deltas in real time as they arrive over WebSocket.
        """
        prompt_text = ""
        user_msgs = [m["content"] for m in messages if m.get("role") == "user"]
        if user_msgs:
            prompt_text = user_msgs[-1]
        elif messages:
            prompt_text = messages[-1].get("content", "")

        await _safe_harbor_engine.acquire_permission()
        payload_str = cls.format_payload(payload_template, prompt_text, model=model)

        req_headers: Dict[str, str] = {}
        if api_key:
            req_headers["Authorization"] = f"Bearer {api_key}"
            
        req_headers.update(_safe_harbor_engine.build_compliant_headers())
        
        if headers:
            req_headers.update(headers)

        client_timeout = aiohttp.ClientTimeout(total=timeout, connect=connect_timeout)
        connector = aiohttp.TCPConnector(ssl=False if not ssl_verify else None)

        async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
            async with session.ws_connect(
                endpoint_url,
                headers=req_headers if req_headers else None,
                heartbeat=cls.DEFAULT_PING_INTERVAL,
            ) as ws:
                await ws.send_str(payload_str)

                while True:
                    try:
                        msg = await asyncio.wait_for(ws.receive(), timeout=cls.DEFAULT_FRAME_TIMEOUT)
                    except asyncio.TimeoutError:
                        break

                    if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSE):
                        break
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        raw_text = msg.data
                        if cls.is_stream_done(raw_text, stop_token=stop_token):
                            delta = cls.extract_text_delta(raw_text, extraction_key=extraction_key)
                            if delta:
                                yield delta
                            break

                        delta = cls.extract_text_delta(raw_text, extraction_key=extraction_key)
                        if delta:
                            yield delta


# =============================================================================
# UNIVERSAL ADAPTER & MULTI-PROTOCOL DISPATCH ENGINE
# =============================================================================

class UniversalAdapter:
    """
    Universal formatting and multi-protocol transceiver dispatch engine.
    Standardizes outbound payloads, headers, and execution across HTTP/HTTPS, SSH,
    WebSocket, and Mock backends.
    """

    @classmethod
    def prepare_payload(
        cls,
        provider: ProviderType,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tokens: int = 1024,
    ) -> Dict[str, Any]:
        """
        Prepares and normalizes the JSON request payload tailored to the provider and model architecture.
        - Reasoning models (o1, o3, deepseek-reasoner, deepseek-r1): omits temperature to prevent 400 Bad Request.
        - OpenAI reasoning models: uses max_completion_tokens instead of max_tokens.
        - Anthropic: extracts system message to top-level 'system' key and sets max_tokens (default >= 2048).
        """
        reasoning = is_reasoning_model(model)
        openai_reasoning = is_openai_reasoning_model(model)

        if provider == ProviderType.ANTHROPIC:
            sys_msg = next((m["content"] for m in messages if m["role"] == "system"), None)
            anthropic_msgs = [m for m in messages if m["role"] != "system"]
            payload: Dict[str, Any] = {
                "model": model,
                "messages": anthropic_msgs,
                "max_tokens": max(max_tokens, 2048),
            }
            if not reasoning:
                payload["temperature"] = temperature
            if sys_msg:
                payload["system"] = sys_msg
            if tools:
                payload["tools"] = tools
            return payload

        # Standard OpenAI-compatible schema (OpenAI, DeepSeek, xAI, Groq, Mistral, OpenRouter, Ollama, Custom)
        payload = {
            "model": model,
            "messages": messages,
        }

        if not reasoning:
            payload["temperature"] = temperature

        if openai_reasoning:
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["max_tokens"] = max_tokens

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        return payload

    @classmethod
    def format_request(
        cls,
        provider: ProviderType,
        endpoint_url: str,
        api_key: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tokens: int = 1024,
        safe_harbor: bool = True,
    ) -> Tuple[Dict[str, str], Dict[str, Any], str]:
        """
        Builds the HTTP headers, payload, and final URL for the specified provider.
        Returns: (headers, payload, final_url)
        """
        url = sanitize_endpoint_url(endpoint_url)
        headers = {"Content-Type": "application/json"}

        if provider == ProviderType.ANTHROPIC:
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
            payload = cls.prepare_payload(
                provider=provider,
                model=model,
                messages=messages,
                temperature=temperature,
                tools=tools,
                max_tokens=max_tokens,
            )
            return headers, payload, url

        # Gemini Native handling (generativelanguage.googleapis.com without /openai path)
        if provider == ProviderType.GEMINI and "openai" not in url.lower() and "generativelanguage" in url.lower():
            if "?key=" not in url and api_key:
                url = f"{url.rstrip('/')}/v1beta/models/{model}:generateContent?key={api_key}"
                
            gemini_messages = []
            sys_instr = None
            for msg in messages:
                if msg["role"] == "system":
                    sys_instr = {"parts": [{"text": msg["content"]}]}
                else:
                    role = "user" if msg["role"] == "user" else "model"
                    gemini_messages.append({"role": role, "parts": [{"text": msg["content"]}]})

            gen_config: Dict[str, Any] = {}
            if not is_reasoning_model(model):
                gen_config["temperature"] = temperature
            if max_tokens:
                gen_config["maxOutputTokens"] = max_tokens

            payload = {
                "contents": gemini_messages,
            }
            if gen_config:
                payload["generationConfig"] = gen_config
            if sys_instr:
                payload["systemInstruction"] = sys_instr
                
            return headers, payload, url

        # Default OpenAI-compatible format
        headers["User-Agent"] = "HuntersGuild-UniversalAdapter/1.0"
        if api_key:
            if api_key.lower().startswith("bearer "):
                headers["Authorization"] = api_key
            else:
                headers["Authorization"] = f"Bearer {api_key}"

        payload = cls.prepare_payload(
            provider=provider,
            model=model,
            messages=messages,
            temperature=temperature,
            tools=tools,
            max_tokens=max_tokens,
        )

        if safe_harbor:
            safe_headers = _safe_harbor_engine.build_compliant_headers(api_key if api_key else None)
            headers.update(safe_headers)

        return headers, payload, url

    @classmethod
    def parse_response(cls, provider: ProviderType, data: Dict[str, Any]) -> Tuple[str, Optional[List[Dict[str, Any]]]]:
        """Parses the JSON response based on the provider format."""
        text = ""
        tool_calls = None
        
        if provider == ProviderType.ANTHROPIC:
            content = data.get("content", [])
            if content and content[0].get("type") == "text":
                text = content[0].get("text", "")
                
        elif provider == ProviderType.GEMINI and "candidates" in data:
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    text = parts[0].get("text", "")
                    
        else:
            choices = data.get("choices", [])
            if choices and isinstance(choices, list):
                message = choices[0].get("message", {})
                text = message.get("content", "") or ""
                tool_calls = message.get("tool_calls")
                if tool_calls and not text:
                    text = f"[TOOL_CALL] {json.dumps(tool_calls)}"
                    
        if not text and not tool_calls:
            text = str(data)
            
        return text, tool_calls

    @classmethod
    def infer_provider(cls, url: str) -> ProviderType:
        """Helper to infer the ProviderType from an endpoint URL or connection scheme."""
        lower_url = url.lower()
        if lower_url.startswith("ssh://"):
            return ProviderType.SSH
        if lower_url.startswith(("ws://", "wss://")):
            return ProviderType.WEBSOCKET
        if "generativelanguage.googleapis.com" in lower_url:
            return ProviderType.GEMINI
        if "api.deepseek.com" in lower_url:
            return ProviderType.DEEPSEEK
        if "api.x.ai" in lower_url:
            return ProviderType.XAI
        if "api.mistral.ai" in lower_url:
            return ProviderType.MISTRAL_AND_FABLE
        if "api.groq.com" in lower_url:
            return ProviderType.GROQ
        if "openrouter.ai" in lower_url:
            return ProviderType.OPENROUTER
        if "api.anthropic.com" in lower_url:
            return ProviderType.ANTHROPIC
        if "api.openai.com" in lower_url:
            return ProviderType.OPENAI
        if "localhost:11434" in lower_url or "127.0.0.1:11434" in lower_url:
            return ProviderType.OLLAMA
        return ProviderType.CUSTOM

    @classmethod
    async def dispatch(
        cls,
        endpoint_url: str,
        messages: List[Dict[str, str]],
        api_key: str = "",
        model: str = "",
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        timeout: float = 45.0,
        provider: Optional[ProviderType] = None,
        safe_harbor: bool = True,
        **kwargs: Any,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """
        Unified multi-protocol transceiver dispatch engine.
        Routes dynamically across:
        - ssh:// -> SSHTransportAdapter.execute()
        - ws:// / wss:// -> WebSocketTransportAdapter.execute()
        - http:// / https:// -> Asynchronous HTTP transceiving (aiohttp)
        - mock:// -> Mock simulated responses
        """
        clean_url = sanitize_endpoint_url(endpoint_url)

        # 1. SSH Protocol Route
        if clean_url.startswith("ssh://"):
            return await SSHTransportAdapter.execute(
                endpoint_url=clean_url,
                messages=messages,
                timeout=timeout,
                key_filename=kwargs.get("key_filename"),
                password=api_key or kwargs.get("password"),
                username=kwargs.get("username"),
            )

        # 2. WebSocket Protocol Route
        if clean_url.startswith(("ws://", "wss://")):
            return await WebSocketTransportAdapter.execute(
                endpoint_url=clean_url,
                messages=messages,
                api_key=api_key,
                model=model,
                payload_template=kwargs.get("payload_template"),
                extraction_key=kwargs.get("extraction_key"),
                stop_token=kwargs.get("stop_token"),
                timeout=timeout,
                connect_timeout=kwargs.get("connect_timeout", 15.0),
                stream_callback=kwargs.get("stream_callback"),
                ssl_verify=kwargs.get("ssl_verify", True),
                headers=kwargs.get("headers"),
            )

        # 3. Mock Protocol Route
        if clean_url.startswith("mock://"):
            return await cls._dispatch_mock(clean_url, messages, model=model)

        # 4. Standard HTTP/HTTPS Route
        if provider is None:
            provider = cls.infer_provider(clean_url)

        return await cls._dispatch_http(
            endpoint_url=clean_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
            tools=tools,
            timeout=timeout,
            provider=provider,
            safe_harbor=safe_harbor,
        )

    @classmethod
    async def generate(
        cls,
        endpoint_url: str,
        api_key: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        tools: Optional[List[Dict[str, Any]]] = None,
        timeout: float = 45.0,
        provider: Optional[ProviderType] = None,
        **kwargs: Any,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """
        Sends an LLM generation request using the universal multi-protocol dispatch engine.
        Returns: (text_response, latency_ms, optional_tool_calls)
        """
        return await cls.dispatch(
            endpoint_url=endpoint_url,
            messages=messages,
            api_key=api_key,
            model=model,
            temperature=temperature,
            tools=tools,
            timeout=timeout,
            provider=provider,
            **kwargs,
        )

    @staticmethod
    def parse_retry_delay(headers: Dict[str, str], error_text: str) -> Optional[float]:
        """
        Parses Retry-After headers or Google RPC / OpenAI / Anthropic rate-limit metadata.
        """
        # 1. Check HTTP Retry-After header
        retry_header = headers.get("retry-after") or headers.get("Retry-After")
        if retry_header:
            try:
                return float(str(retry_header).strip())
            except ValueError:
                pass

        # 2. Check JSON error body for Google RPC retryDelay or details
        if error_text:
            try:
                data = json.loads(error_text)
                if isinstance(data, dict):
                    # Google RPC error structure
                    error_obj = data.get("error", {})
                    if isinstance(error_obj, dict):
                        details = error_obj.get("details", [])
                        if isinstance(details, list):
                            for item in details:
                                if isinstance(item, dict):
                                    retry_delay = item.get("retryDelay")
                                    if retry_delay and isinstance(retry_delay, str):
                                        clean_d = retry_delay.rstrip("s").strip()
                                        return float(clean_d)
                    # Direct retry_after field
                    if "retry_after" in data:
                        return float(data["retry_after"])
            except Exception:
                pass

            # Regex fallback for "retryDelay": "49s" or "Please retry after 12s"
            match = re.search(r'retryDelay["\']?\s*:\s*["\']?([0-9\.]+)s?["\']?', error_text, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    pass

            match_after = re.search(r'retry (?:in|after)\s+([0-9\.]+)\s*s', error_text, re.IGNORECASE)
            if match_after:
                try:
                    return float(match_after.group(1))
                except ValueError:
                    pass

        return None

    @staticmethod
    def is_quota_exhausted(error_text: str, delay: Optional[float] = None) -> bool:
        """Determines if the error represents a non-recoverable daily/monthly quota exhaustion."""
        if delay is not None and delay > 60.0:
            return True
        lower = error_text.lower()
        if any(q in lower for q in ["perday", "per_day", "daily limit", "generaterequestsperday", "insufficient_quota", "billing"]):
            return True
        return False

    @classmethod
    async def _dispatch_http(
        cls,
        endpoint_url: str,
        api_key: str,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float,
        tools: Optional[List[Dict[str, Any]]],
        timeout: float,
        provider: ProviderType,
        safe_harbor: bool = True,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """Handles HTTP/HTTPS endpoint requests with dynamic 429 backoff and quota failover."""
        if safe_harbor:
            await _safe_harbor_engine.acquire_permission()
        headers, payload, final_url = cls.format_request(
            provider=provider,
            endpoint_url=endpoint_url,
            api_key=api_key,
            model=model,
            messages=messages,
            temperature=temperature,
            tools=tools,
            safe_harbor=safe_harbor,
        )

        req_timeout = aiohttp.ClientTimeout(total=timeout)
        start_time = time.perf_counter()
        max_retries = 2

        for attempt in range(max_retries + 1):
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(timeout=req_timeout, connector=connector) as session:
                    async with session.post(final_url, headers=headers, json=payload) as resp:
                        latency_ms = (time.perf_counter() - start_time) * 1000.0
                        if resp.status == 200:
                            data = await resp.json()
                            text, tool_calls = cls.parse_response(provider, data)
                            return text, latency_ms, tool_calls

                        error_text = await resp.text()

                        # Check HTTP 429 or RESOURCE_EXHAUSTED
                        if resp.status == 429 or "RESOURCE_EXHAUSTED" in error_text:
                            delay = cls.parse_retry_delay(dict(resp.headers), error_text)
                            if cls.is_quota_exhausted(error_text, delay):
                                logger.warning(f"UniversalAdapter quota exhausted on {final_url}: {error_text[:200]}")
                                return "[QUOTA EXHAUSTED] Upstream daily limit reached. Switch provider or model preset.", latency_ms, None

                            if attempt < max_retries:
                                retry_header = resp.headers.get("retry-after") or resp.headers.get("Retry-After")
                                await _safe_harbor_engine.handle_rate_limit_response(resp.status, retry_header)
                                continue
                            else:
                                return "[QUOTA EXHAUSTED] Upstream daily limit reached. Switch provider or model preset.", latency_ms, None

                        logger.warning(f"UniversalAdapter HTTP {resp.status} on {final_url}: {error_text[:200]}")
                        return f"[HTTP {resp.status} ERROR] {error_text}", latency_ms, None

            except Exception as exc:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                logger.error(f"UniversalAdapter connection error on {final_url}: {exc}")
                return f"[NETWORK ERROR] {str(exc)}", latency_ms, None

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return "[QUOTA EXHAUSTED] Upstream daily limit reached. Switch provider or model preset.", latency_ms, None

    @classmethod
    async def _dispatch_mock(
        cls,
        url: str,
        messages: List[Dict[str, str]],
        model: str,
    ) -> Tuple[str, float, Optional[List[Dict[str, Any]]]]:
        """Simulates mock target responses for test harnesses."""
        start_time = time.perf_counter()
        await asyncio.sleep(0.01)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        last_msg = messages[-1]["content"] if messages else ""
        return f"[MOCK TARGET RESPONSE for {model}]: Received '{last_msg[:60]}'", latency_ms, None
