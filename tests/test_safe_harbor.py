"""
Unit and Integration Tests for Safe Harbor & Rate Limiting Compliance Engine
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework
"""

import pytest

from hunters_guild.modules.safe_harbor import (
    RateLimitConfig,
    SafeHarborEngine,
    SafeHarborIdentity,
    SubmissionVerification,
    ThrottlingState,
)


@pytest.fixture
def safe_harbor():
    identity = SafeHarborIdentity(
        researcher_handle="EliteHunter_01",
        platform_name="HackerOne",
        contact_email="security@huntersguild.local",
        custom_headers={"X-Custom-Audit-ID": "AUDIT-2026-99"},
    )
    config = RateLimitConfig(
        requests_per_minute=120,
        burst_capacity=4,
        enable_random_jitter=False,
    )
    return SafeHarborEngine(identity=identity, rate_config=config)


def test_safe_harbor_identity_and_headers(safe_harbor):
    """
    Verifies construction of ethical research Safe Harbor attribution headers.
    """
    headers = safe_harbor.build_compliant_headers(base_token="sk-target-key-9988")

    assert headers["X-Bug-Bounty-Researcher"] == "EliteHunter_01"
    assert headers["X-Security-Research-Program"] == "HackerOne"
    assert headers["X-Researcher-Email"] == "security@huntersguild.local"
    assert headers["X-Custom-Audit-ID"] == "AUDIT-2026-99"
    assert headers["Authorization"] == "Bearer sk-target-key-9988"
    assert "HuntersGuild-SafeHarbor/EliteHunter_01" in headers["User-Agent"]


@pytest.mark.asyncio
async def test_token_bucket_acquisition_burst(safe_harbor):
    """
    Tests token-bucket burst capacity and consumption.
    """
    # 4 tokens available immediately in burst
    for i in range(4):
        delay = await safe_harbor.acquire_permission()
        assert delay < 0.05

    assert safe_harbor.state.total_requests_served == 4


@pytest.mark.asyncio
async def test_exponential_backoff_and_retry_after(safe_harbor):
    """
    Tests rate limit handling with explicit Retry-After headers and clean response reset.
    """
    # Simulate HTTP 429 with Retry-After: 0.05s
    delay = await safe_harbor.handle_rate_limit_response(
        status_code=429,
        retry_after_header="0.05",
    )

    assert delay >= 0.04
    assert safe_harbor.state.consecutive_429_count == 1
    assert safe_harbor.state.total_delays_incurred >= 0.04

    # Subsequent clean 200 OK resets error streak
    reset_delay = await safe_harbor.handle_rate_limit_response(status_code=200)
    assert reset_delay == 0.0
    assert safe_harbor.state.consecutive_429_count == 0
    assert safe_harbor.state.is_throttled is False


def test_submission_gatekeeper_readiness(safe_harbor):
    """
    Tests human-in-the-loop gatekeeping logic for vulnerability disclosure dispatch.
    """
    # Scenario A: High score + PoC, but no human manual approval yet
    pending_review = safe_harbor.verify_submission_readiness(
        confidence_score=95,
        has_curl_trace=True,
        manual_approval=False,
    )
    assert isinstance(pending_review, SubmissionVerification)
    assert pending_review.human_review_required is True
    assert pending_review.ready_for_dispatch is False

    # Scenario B: High score + PoC + manual approval -> Ready for dispatch
    approved_review = safe_harbor.verify_submission_readiness(
        confidence_score=95,
        has_curl_trace=True,
        manual_approval=True,
    )
    assert approved_review.human_review_required is False
    assert approved_review.ready_for_dispatch is True

    # Scenario C: Approved manually, but low confidence score (<75) -> Blocked
    low_confidence_review = safe_harbor.verify_submission_readiness(
        confidence_score=50,
        has_curl_trace=True,
        manual_approval=True,
    )
    assert low_confidence_review.ready_for_dispatch is False
