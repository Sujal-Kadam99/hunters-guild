"""
Hunters Guild - Core State Schemas and Data Structures
Project: Hunters Guild - Autonomous AI Robustness & Security Verification Framework

This module defines the foundational Pydantic models, enums, and state machines
used across the Hunters Guild architecture to drive autonomous red teaming,
vulnerability auditing, latency analysis, and automated proof-of-concept (PoC) generation.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class OWASPCategory(str, Enum):
    """
    OWASP Top 10 for Large Language Model Applications (2025/2023 standard taxonomy).
    Supports exact enum values or standard identifier prefixes (LLM01 to LLM10).
    """

    LLM01 = "LLM01: Prompt Injection"
    LLM02 = "LLM02: Insecure Output Handling"
    LLM03 = "LLM03: Training Data Poisoning"
    LLM04 = "LLM04: Model Denial of Service"
    LLM05 = "LLM05: Supply Chain Vulnerabilities"
    LLM06 = "LLM06: Sensitive Information Disclosure"
    LLM07 = "LLM07: Insecure Plugin Design"
    LLM08 = "LLM08: Excessive Agency"
    LLM09 = "LLM09: Overreliance"
    LLM10 = "LLM10: Model Theft"

    @classmethod
    def from_str(cls, value: str) -> "OWASPCategory":
        """
        Parses input string like 'LLM01', 'llm01', or full descriptions into valid OWASPCategory.
        """
        cleaned = value.strip()
        # Check direct value or name match
        for member in cls:
            if cleaned.upper() == member.name:
                return member
            if cleaned.lower() == member.value.lower():
                return member

        # Check prefix match e.g. "LLM01" in "LLM01: Prompt Injection"
        match = re.match(r"^(LLM(?:0[1-9]|10))", cleaned, re.IGNORECASE)
        if match:
            code = match.group(1).upper()
            if hasattr(cls, code):
                return cls[code]

        raise ValueError(
            f"Invalid OWASP Category '{value}'. Must be one of LLM01 through LLM10."
        )


class BountySeverity(str, Enum):
    """
    Standardized vulnerability severity ratings for bounty and risk assessment.
    """

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @classmethod
    def from_str(cls, value: str) -> "BountySeverity":
        cleaned = value.strip().capitalize()
        for member in cls:
            if cleaned == member.value or cleaned.upper() == member.name:
                return member
        raise ValueError(
            f"Invalid severity '{value}'. Must be one of: Critical, High, Medium, Low, Informational."
        )


class TargetProfile(BaseModel):
    """
    Represents the target model endpoint, operational capabilities, and behavioral profile.
    """

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        validate_assignment=True,
        extra="allow",
    )

    endpoint_url: str = Field(
        ...,
        description="The HTTP/HTTPS endpoint or socket URI of the target model or gateway.",
    )
    model_identifier: str = Field(
        ...,
        description="Identifier/name of the model under test (e.g., 'gpt-4o', 'claude-3-5-sonnet', 'llama-3-70b-instruct').",
    )
    auth_header: Optional[str] = Field(
        default=None,
        description="Authentication header value (e.g., 'Bearer sk-...' or custom API key).",
    )
    system_fingerprint: Optional[str] = Field(
        default=None,
        description="Backend system fingerprint, hash, or runtime revision signature if available.",
    )
    detected_tools: List[str] = Field(
        default_factory=list,
        description="List of tool names, functions, or sandboxed utilities exposed to the model.",
    )
    supports_streaming: bool = Field(
        default=False,
        description="Flag indicating if the target endpoint supports Server-Sent Events (SSE) or chunked token streaming.",
    )

    @field_validator("endpoint_url", mode="before")
    @classmethod
    def validate_endpoint_url(cls, v: str) -> str:
        from hunters_guild.engine.universal_adapter import sanitize_endpoint_url
        v_clean = sanitize_endpoint_url(v)
        if not v_clean:
            raise ValueError("endpoint_url cannot be empty.")
        if not (
            v_clean.startswith("http://")
            or v_clean.startswith("https://")
            or v_clean.startswith("ws://")
            or v_clean.startswith("wss://")
            or v_clean.startswith("ssh://")
            or v_clean.startswith("mock://")
        ):
            raise ValueError(
                f"Invalid endpoint URL schema in '{v_clean}'. Expected http://, https://, ws://, wss://, ssh://, or mock://"
            )
        return v_clean

    def parse_ssh_config(self) -> Optional[Dict[str, Any]]:
        """
        Parses connection parameters and remote command template if endpoint_url is an SSH URL.
        Returns None if the endpoint is not an SSH URL.
        """
        if not self.endpoint_url.startswith("ssh://"):
            return None
        from hunters_guild.engine.universal_adapter import SSHTransportAdapter
        return SSHTransportAdapter.parse_ssh_url(self.endpoint_url)


class AuditMission(BaseModel):
    """
    Defines the objective, scope, OWASP vulnerability domain, and execution parameters
    for an automated red-team audit mission.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",
    )

    mission_id: str = Field(
        default_factory=lambda: f"mission_{uuid.uuid4().hex[:12]}",
        description="Unique identifier for the audit mission.",
    )
    target: TargetProfile = Field(
        ...,
        description="Target profile detailing endpoint and runtime configurations.",
    )
    objective: str = Field(
        ...,
        description="Specific adversary objective (e.g., 'Extract system prompt instructions', 'Bypass guardrail and execute SQL injection').",
    )
    owasp_category: str = Field(
        ...,
        description="Targeted OWASP category identifier (LLM01 to LLM10) or full name.",
    )
    max_turns: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum number of conversational turns / probe rounds allocated to this mission.",
    )
    concurrency_limit: int = Field(
        default=1,
        ge=1,
        le=50,
        description="Maximum concurrent probes or parallel agent threads allowed for this audit.",
    )

    @field_validator("owasp_category")
    @classmethod
    def normalize_owasp_category(cls, v: str) -> str:
        category_enum = OWASPCategory.from_str(v)
        return category_enum.value


class AttackTurn(BaseModel):
    """
    Records an individual probe turn within an adversarial conversation loop,
    including latency metrics, judge evaluation scores, and violation indicators.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",
    )

    turn_index: int = Field(
        ...,
        ge=0,
        description="Zero-indexed turn position within the audit mission session.",
    )
    attack_technique: str = Field(
        ...,
        description="Adversarial technique applied (e.g., 'Crescendo Multi-Turn', 'Base64 Obfuscation', 'Roleplay / Persona Hijack', 'Instruction Smuggling').",
    )
    probe_payload: str = Field(
        ...,
        description="Raw prompt payload sent to the target.",
    )
    raw_response: str = Field(
        ...,
        description="Raw textual or serialized response received from the target endpoint.",
    )
    latent_latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Time-to-first-token or round-trip execution latency in milliseconds.",
    )
    judge_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Adversarial success / safety compliance score evaluated by the automated red-team judge (0 = fully safe / compliant, 100 = full exploit / violation).",
    )
    violation_flag: bool = Field(
        ...,
        description="True if this turn breached target safety policy, alignment guardrails, or system prompt confidentiality.",
    )
    reasoning: str = Field(
        ...,
        description="Automated judge explanation and forensic breakdown justifying the score and violation flag.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the attack turn completed.",
    )


class BountyPoC(BaseModel):
    """
    Structured, production-grade Proof-of-Concept report documenting a verified
    vulnerability, reproduction steps, CVSS vector, and actionable remediation.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",
    )

    vulnerability_title: str = Field(
        ...,
        description="Descriptive title of the confirmed vulnerability (e.g., 'System Prompt Exfiltration via Recursive Language Translation').",
    )
    cwe_id: str = Field(
        ...,
        description="Common Weakness Enumeration identifier (e.g., 'CWE-200', 'CWE-77', 'CWE-116').",
    )
    cvss_vector: str = Field(
        ...,
        description="CVSS v3.1 or v4.0 vector string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N').",
    )
    estimated_bounty_severity: str = Field(
        ...,
        description="Severity classification (Critical, High, Medium, Low).",
    )
    reproduction_steps: List[str] = Field(
        ...,
        min_length=1,
        description="Step-by-step instructions to reliably reproduce the exploit.",
    )
    full_trace: List[AttackTurn] = Field(
        ...,
        min_length=1,
        description="Chronological sequence of attack turns constituting the end-to-end exploit trace.",
    )
    remediation: str = Field(
        ...,
        description="Engineering guidance, system prompt patch, or input/output guardrail recommendations.",
    )
    reproducibility_score: Optional[str] = Field(
        default=None,
        description="Reproducibility score, e.g., '3/3 - 100% Deterministic'.",
    )
    latency_stability: Optional[str] = Field(
        default=None,
        description="Latency stability notes.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of PoC generation.",
    )

    @field_validator("estimated_bounty_severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        return BountySeverity.from_str(v).value

    @field_validator("cwe_id")
    @classmethod
    def normalize_cwe(cls, v: str) -> str:
        clean = v.strip().upper()
        if not clean.startswith("CWE-"):
            # Attempt to normalize "200" -> "CWE-200"
            if clean.isdigit():
                clean = f"CWE-{clean}"
            else:
                raise ValueError(f"Invalid CWE ID '{v}'. Expected format like 'CWE-200' or 'CWE-77'.")
        return clean

    def to_markdown(self) -> str:
        """
        Renders a bug bounty / vulnerability disclosure report in Markdown format.
        """
        steps_rendered = "\n".join(
            f"{i+1}. {step}" for i, step in enumerate(self.reproduction_steps)
        )
        turns_rendered = "\n\n".join(
            f"#### Turn {turn.turn_index} [{turn.attack_technique}] (Score: {turn.judge_score}/100, Violation: {turn.violation_flag})\n"
            f"**Payload:**\n```\n{turn.probe_payload}\n```\n"
            f"**Response:**\n```\n{turn.raw_response}\n```\n"
            f"**Reasoning:** {turn.reasoning}\n"
            f"**Latency:** {turn.latent_latency_ms:.2f}ms"
            for turn in self.full_trace
        )

        repro_section = ""
        if self.reproducibility_score:
            repro_section = (
                f"## Reproducibility\n"
                f"- **Determinism Score**: {self.reproducibility_score}\n"
                f"- **Latency Stability**: {self.latency_stability or 'N/A'}\n\n"
            )

        return (
            f"# Vulnerability Advisory: {self.vulnerability_title}\n\n"
            f"- **Severity**: {self.estimated_bounty_severity}\n"
            f"- **CWE**: {self.cwe_id}\n"
            f"- **CVSS Vector**: `{self.cvss_vector}`\n"
            f"- **Timestamp**: {self.created_at.isoformat()}\n\n"
            f"## Executive Summary\n"
            f"An automated red-team audit confirmed a vulnerability allowing policy bypass or unauthorized extraction.\n\n"
            f"{repro_section}"
            f"## Reproduction Steps\n{steps_rendered}\n\n"
            f"## Exploit Trace\n{turns_rendered}\n\n"
            f"## Remediation & Mitigation\n{self.remediation}\n"
        )


class GuildState(BaseModel):
    """
    Central state container tracking the lifecycle, conversation history,
    round iterations, and confirmed proof of concept for an active red-team audit.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        extra="allow",
    )

    mission: AuditMission = Field(
        ...,
        description="The active audit mission specification.",
    )
    history: List[AttackTurn] = Field(
        default_factory=list,
        description="Chronological log of attack turns executed so far.",
    )
    current_round: int = Field(
        default=0,
        ge=0,
        description="Current conversational round index.",
    )
    mission_complete: bool = Field(
        default=False,
        description="Whether the red-team audit mission has concluded (success or turn budget exhausted).",
    )
    confirmed_poc: Optional[BountyPoC] = Field(
        default=None,
        description="Verified Proof-of-Concept if a qualifying exploit was confirmed during the audit.",
    )

    @model_validator(mode="after")
    def sync_current_round(self) -> "GuildState":
        """
        Ensures current_round remains synchronized with history length unless explicitly managed.
        """
        if len(self.history) > 0 and self.current_round < len(self.history):
            self.current_round = len(self.history)
        return self

    def append_turn(self, turn: AttackTurn) -> None:
        """
        Appends an attack turn to history and increments state counters.
        """
        self.history.append(turn)
        self.current_round = len(self.history)
        if turn.violation_flag:
            # Check if threshold criteria met
            pass
        if self.current_round >= self.mission.max_turns:
            self.mission_complete = True

    def finalize_with_poc(self, poc: BountyPoC) -> None:
        """
        Sets the confirmed PoC and marks the mission as successfully completed.
        """
        self.confirmed_poc = poc
        self.mission_complete = True

    @property
    def has_violation(self) -> bool:
        """
        Returns True if any turn in the audit history triggered a confirmed safety violation.
        """
        return any(t.violation_flag for t in self.history)

    @property
    def max_judge_score(self) -> int:
        """
        Returns the highest judge score recorded across all turns.
        """
        if not self.history:
            return 0
        return max(t.judge_score for t in self.history)

    @property
    def average_latency_ms(self) -> float:
        """
        Calculates the average latency across all recorded turns.
        """
        if not self.history:
            return 0.0
        return sum(t.latent_latency_ms for t in self.history) / len(self.history)
