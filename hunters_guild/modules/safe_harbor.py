"""
Safe Harbor, Pacing, and Rate Limiting Compliance Engine
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework

Implements token-bucket rate limiting, randomized request jitter, Safe Harbor attribution headers,
exponential backoff with Retry-After resolution, and human-in-the-loop submission verification gates.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("HuntersGuild.SafeHarbor")


class RateLimitConfig(BaseModel):
    """
    Configuration parameters for outbound request pacing and anti-throttling jitter.
    """
    model_config = ConfigDict(extra="allow")

    requests_per_minute: int = Field(default=30, description="Target sustained request throughput limit.")
    burst_capacity: int = Field(default=5, description="Maximum bucket token capacity for initial bursts.")
    enable_random_jitter: bool = Field(default=True, description="Whether to inject random pacing delays.")
    min_jitter_seconds: float = Field(default=0.5, description="Minimum randomized jitter delay.")
    max_jitter_seconds: float = Field(default=2.0, description="Maximum randomized jitter delay.")


class SafeHarborIdentity(BaseModel):
    """
    Attribution and contact metadata identifying security research traffic.
    """
    model_config = ConfigDict(extra="allow")

    researcher_handle: str = Field(default="HuntersGuild-Auditor", description="Researcher username or ID.")
    platform_name: str = Field(default="HackerOne", description="Platform or authorization context.")
    contact_email: Optional[str] = Field(default=None, description="Security contact email for defensive triage.")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Additional enterprise headers.")


class ThrottlingState(BaseModel):
    """
    Real-time tracking of rate limits, throttling status, and backoff history.
    """
    model_config = ConfigDict(extra="allow")

    is_throttled: bool = Field(default=False, description="True if currently paused under a backoff window.")
    consecutive_429_count: int = Field(default=0, description="Consecutive HTTP 429/503 responses received.")
    backoff_delay_seconds: float = Field(default=0.0, description="Current or latest backoff duration.")
    total_requests_served: int = Field(default=0, description="Total requests successfully granted permission.")
    total_delays_incurred: float = Field(default=0.0, description="Cumulative throttling delay incurred in seconds.")


class SubmissionVerification(BaseModel):
    """
    Human-in-the-loop review gatekeeper verdict before publishing vulnerability disclosures.
    """
    model_config = ConfigDict(extra="allow")

    report_id: str = Field(..., description="Unique submission report tracking identifier.")
    confidence_score: int = Field(..., description="Judge or Inquisitor verification score (0 to 100).")
    has_reproducible_poc: bool = Field(..., description="True if a valid, copy-pasteable curl trace exists.")
    human_review_required: bool = Field(default=True, description="True if human auditor sign-off is pending.")
    ready_for_dispatch: bool = Field(..., description="True only if approved and meeting quality standards.")


class SafeHarborEngine:
    """
    Enforces ethical research standards, request pacing, and disclosure gatekeeping.
    """

    def __init__(
        self,
        identity: Optional[SafeHarborIdentity] = None,
        rate_config: Optional[RateLimitConfig] = None,
    ) -> None:
        """
        Initialize the Safe Harbor & Pacing Engine.
        """
        self.identity = identity or SafeHarborIdentity()
        self.rate_config = rate_config or RateLimitConfig()

        # Token Bucket State
        self.capacity: float = float(self.rate_config.burst_capacity)
        self.tokens: float = float(self.capacity)
        self.fill_rate: float = float(self.rate_config.requests_per_minute) / 60.0
        self.last_update: float = time.perf_counter()

        self._lock = asyncio.Lock()
        self.state = ThrottlingState()

    async def acquire_permission(self) -> float:
        """
        Asynchronously acquires permission to send a request based on token bucket capacity,
        applying jitter if configured. Returns total delay elapsed in seconds.
        """
        start_t = time.perf_counter()
        total_delay = 0.0

        async with self._lock:
            now = time.perf_counter()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + (elapsed * self.fill_rate))
            self.last_update = now

            if self.tokens < 1.0:
                deficit = 1.0 - self.tokens
                wait_seconds = deficit / self.fill_rate
                await asyncio.sleep(wait_seconds)
                self.tokens = 0.0
                self.last_update = time.perf_counter()
                total_delay += wait_seconds
            else:
                self.tokens -= 1.0

        # Inject randomized pacing jitter outside the lock to prevent blocking concurrent tasks
        if self.rate_config.enable_random_jitter and self.rate_config.max_jitter_seconds > 0:
            jitter = random.uniform(
                self.rate_config.min_jitter_seconds,
                self.rate_config.max_jitter_seconds,
            )
            await asyncio.sleep(jitter)
            total_delay += jitter

        self.state.total_requests_served += 1
        return total_delay

    def build_compliant_headers(self, base_token: Optional[str] = None) -> Dict[str, str]:
        """
        Generates headers containing standard researcher identity and attribution tokens.
        """
        headers: Dict[str, str] = {
            "User-Agent": f"HuntersGuild-SafeHarbor/{self.identity.researcher_handle} ({self.identity.platform_name})",
            "X-Bug-Bounty-Researcher": self.identity.researcher_handle,
            "X-Security-Research-Program": self.identity.platform_name,
            "X-Hunters-Guild-Attribution": "Automated-Boundary-Verification-Framework",
        }

        if self.identity.contact_email:
            headers["X-Researcher-Email"] = self.identity.contact_email

        if base_token:
            auth_val = base_token if (base_token.startswith("Bearer ") or base_token.startswith("Basic ")) else f"Bearer {base_token}"
            headers["Authorization"] = auth_val

        # Append custom headers
        headers.update(self.identity.custom_headers)
        return headers

    async def handle_rate_limit_response(
        self,
        status_code: int,
        retry_after_header: Optional[str] = None,
    ) -> float:
        """
        Calculates exponential backoff with jitter when encountering HTTP 429/503 responses
        and pauses worker execution. Returns backoff delay in seconds.
        """
        if status_code in (429, 503):
            self.state.consecutive_429_count += 1
            self.state.is_throttled = True

            delay: float = 0.0
            if retry_after_header:
                try:
                    delay = float(retry_after_header.strip())
                except ValueError:
                    delay = 5.0
            else:
                # Exponential backoff with jitter: 2^n + uniform(0.1, 1.0)
                backoff_base = 2.0 ** min(self.state.consecutive_429_count, 6)
                delay = min(60.0, backoff_base + random.uniform(0.1, 1.0))

            self.state.backoff_delay_seconds = delay
            self.state.total_delays_incurred += delay

            logger.warning(
                "Rate limit hit (HTTP %d). Applying backoff delay of %.2fs (Consecutive count: %d)",
                status_code,
                delay,
                self.state.consecutive_429_count,
            )

            await asyncio.sleep(delay)
            self.state.is_throttled = False
            return delay

        # Clean response resets consecutive error streak
        self.state.consecutive_429_count = 0
        self.state.is_throttled = False
        self.state.backoff_delay_seconds = 0.0
        return 0.0

    def verify_submission_readiness(
        self,
        confidence_score: int,
        has_curl_trace: bool,
        manual_approval: bool = False,
    ) -> SubmissionVerification:
        """
        Enforces human-in-the-loop review and minimum PoC quality standards
        before permitting vulnerability disclosure export.
        """
        report_id = f"HG-SUB-{uuid.uuid4().hex[:8].upper()}"
        human_review_required = not manual_approval

        ready = (
            manual_approval
            and (confidence_score >= 75)
            and has_curl_trace
        )

        return SubmissionVerification(
            report_id=report_id,
            confidence_score=confidence_score,
            has_reproducible_poc=has_curl_trace,
            human_review_required=human_review_required,
            ready_for_dispatch=ready,
        )
