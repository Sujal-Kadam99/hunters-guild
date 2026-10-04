"""
Platform Target Ingestor - Multi-Platform Target Manifest Parsing and Normalization
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework

This module parses, validates, and normalizes target definitions from diverse platforms
including HackerOne, Bugcrowd, Huntr, Odin, GenBounty, Gray Swan Arena, and custom YAML files.
"""

from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hunters_guild.core.schemas import AuditMission, OWASPCategory, TargetProfile

logger = logging.getLogger("HuntersGuild.TargetIngestor")


class PlatformType(str, Enum):
    """Supported bug bounty platforms, benchmarking arenas, and custom ingest formats."""
    HACKERONE = "HACKERONE"
    BUGCROWD = "BUGCROWD"
    HUNTR = "HUNTR"
    ODIN = "ODIN"
    GENBOUNTY = "GENBOUNTY"
    GRAYSWAN_ARENA = "GRAYSWAN_ARENA"
    CUSTOM_YAML = "CUSTOM_YAML"


class TargetManifest(BaseModel):
    """
    Normalized specification of an audit target ingested from a platform or manifest file.
    """
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    platform: PlatformType = Field(
        default=PlatformType.CUSTOM_YAML,
        description="The source platform or manifest origin.",
    )
    target_name: str = Field(
        ...,
        description="Human-readable identifier of the target model or application under test.",
    )
    endpoint_url: str = Field(
        ...,
        description="The HTTP/HTTPS API endpoint to query during the audit.",
    )
    auth_token: Optional[str] = Field(
        default=None,
        description="Authentication header token (e.g., 'Bearer sk-...' or API key).",
    )
    system_prompt: Optional[str] = Field(
        default=None,
        description="Known or suspected system prompt instructions for baseline verification.",
    )
    objective: str = Field(
        ...,
        description="Adversarial evaluation objective to test against the target.",
    )
    owasp_category: OWASPCategory = Field(
        default=OWASPCategory.LLM01,
        description="The primary OWASP Top 10 for LLMs vulnerability category under evaluation.",
    )
    audit_mode: str = Field(
        default="chat",
        description="Audit execution mode: 'chat', 'doc', or 'tool'.",
    )
    doc_type: Optional[str] = Field(
        default=None,
        description="Document format when audit_mode is 'doc' ('pdf', 'csv', 'md').",
    )
    researcher_id: Optional[str] = Field(
        default=None,
        description="Researcher or auditor username/identifier for platform attribution.",
    )

    @field_validator("owasp_category", mode="before")
    @classmethod
    def validate_category(cls, v: Any) -> OWASPCategory:
        if isinstance(v, OWASPCategory):
            return v
        if isinstance(v, str):
            return OWASPCategory.from_str(v)
        return OWASPCategory.LLM01

    def to_audit_mission(self, max_turns: int = 4, concurrency_limit: int = 1) -> AuditMission:
        """
        Converts the manifest into an executable AuditMission data structure.
        """
        target = TargetProfile(
            endpoint_url=self.endpoint_url,
            model_identifier=self.target_name,
            auth_header=self.auth_token,
        )
        return AuditMission(
            target=target,
            objective=self.objective,
            owasp_category=self.owasp_category.value,
            max_turns=max_turns,
            concurrency_limit=concurrency_limit,
        )


class TargetIngestor:
    """
    Ingests and normalizes target specifications from configuration files and platform connectors.
    """

    @staticmethod
    def load_from_yaml(file_path: Union[str, Path]) -> List[TargetManifest]:
        """
        Ingests and validates multi-target YAML configuration files.

        Expected YAML schema:
        ```yaml
        targets:
          - platform: HACKERONE
            target_name: CustomerSupportLLM
            endpoint_url: https://api.target.com/v1/chat/completions
            auth_token: sk-target-test-key
            objective: Extract confidential system instructions
            owasp_category: LLM01
            audit_mode: chat
        ```
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Target manifest file not found: {path.resolve()}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return []

        raw_targets: List[Dict[str, Any]] = []
        if isinstance(data, list):
            raw_targets = data
        elif isinstance(data, dict):
            raw_targets = data.get("targets") or data.get("manifests") or [data]

        manifests: List[TargetManifest] = []
        for raw in raw_targets:
            if isinstance(raw, dict):
                manifest = TargetManifest.model_validate(raw)
                manifests.append(manifest)

        logger.info("Ingested %d target manifest(s) from %s", len(manifests), path.resolve())
        return manifests

    @staticmethod
    def load_arena_challenge(
        arena_name: str,
        endpoint_url: str,
        api_key: str,
        challenge_objective: str,
        owasp_category: Union[OWASPCategory, str] = OWASPCategory.LLM01,
    ) -> TargetManifest:
        """
        Pre-configures benchmarking arena targets (e.g. Gray Swan Arena / HackAPrompt challenges).
        """
        category = owasp_category if isinstance(owasp_category, OWASPCategory) else OWASPCategory.from_str(str(owasp_category))
        auth = api_key if (api_key.startswith("Bearer ") or api_key.startswith("Basic ")) else f"Bearer {api_key}"

        return TargetManifest(
            platform=PlatformType.GRAYSWAN_ARENA,
            target_name=f"ArenaChallenge-{arena_name}",
            endpoint_url=endpoint_url,
            auth_token=auth,
            objective=challenge_objective,
            owasp_category=category,
            audit_mode="chat",
        )

    @staticmethod
    def load_huntr_target(
        repo_name: str,
        local_service_url: str,
        objective: str,
        category: Union[OWASPCategory, str] = OWASPCategory.LLM01,
        researcher_id: Optional[str] = None,
    ) -> TargetManifest:
        """
        Structures local open-source AI package endpoints for Huntr vulnerability audits.
        """
        cat_enum = category if isinstance(category, OWASPCategory) else OWASPCategory.from_str(str(category))
        return TargetManifest(
            platform=PlatformType.HUNTR,
            target_name=f"huntr-{repo_name.replace('/', '-')}",
            endpoint_url=local_service_url,
            objective=objective,
            owasp_category=cat_enum,
            audit_mode="chat",
            researcher_id=researcher_id,
        )
