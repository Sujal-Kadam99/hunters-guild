"""
Batch Mission Runner - Concurrent Multi-Target Audit Pacing and Aggregated Reporting
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework

Executes bulk security verification missions against target manifests with rate-limited
concurrency controls, automated platform-specific advisory compilation, and summary indexing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from hunters_guild.connectors.target_ingestor import PlatformType, TargetManifest
from hunters_guild.core.schemas import AuditMission, BountyPoC, GuildState
from hunters_guild.engine.orchestrator import GuildMaster
from hunters_guild.modules.document_fuzzer import DocumentType, InjectionStyle

logger = logging.getLogger("HuntersGuild.BatchRunner")


class BatchMissionRunner:
    """
    Orchestrates bulk automated verification campaigns across target portfolios,
    applying concurrency throttling, rate-delay pacing, and multi-platform report export.
    """

    def __init__(
        self,
        orchestrator: GuildMaster,
        concurrency_limit: int = 3,
        delay_between_targets_sec: float = 2.0,
    ) -> None:
        """
        Initialize the Batch Runner with concurrency and rate pacing controls.

        Args:
            orchestrator: Configured GuildMaster engine instance.
            concurrency_limit: Maximum simultaneous target audit sessions.
            delay_between_targets_sec: Pacing pause between target launches.
        """
        self.orchestrator = orchestrator
        self.concurrency_limit = concurrency_limit
        self.delay_between_targets_sec = delay_between_targets_sec
        self._semaphore = asyncio.Semaphore(concurrency_limit)

    def _format_platform_advisory(self, manifest: TargetManifest, state: GuildState) -> str:
        """
        Generates platform-specific formatted Markdown advisories (Huntr, HackerOne, Bugcrowd).
        """
        poc: Optional[BountyPoC] = state.confirmed_poc

        if manifest.platform == PlatformType.HUNTR:
            header = (
                f"# Huntr Security Advisory: {poc.vulnerability_title if poc else 'Audit Complete'}\n\n"
                f"- **Repository Target**: `{manifest.target_name}`\n"
                f"- **Researcher**: `{manifest.researcher_id or 'HuntersGuild-Auditor'}`\n"
                f"- **CWE**: `{poc.cwe_id if poc else 'N/A'}`\n"
                f"- **CVSS Vector**: `{poc.cvss_vector if poc else 'N/A'}`\n"
                f"- **Severity**: `{poc.estimated_bounty_severity if poc else 'Informational'}`\n\n"
            )
        elif manifest.platform == PlatformType.HACKERONE:
            header = (
                f"# HackerOne Vulnerability Report: {poc.vulnerability_title if poc else 'Audit Result'}\n\n"
                f"**Target Asset**: `{manifest.endpoint_url}` ({manifest.target_name})\n"
                f"**Severity Rating**: {poc.estimated_bounty_severity if poc else 'None'} ({poc.cvss_vector if poc else 'N/A'})\n"
                f"**Weakness (CWE)**: {poc.cwe_id if poc else 'N/A'}\n\n"
            )
        else:
            header = (
                f"# Security Verification Advisory: {poc.vulnerability_title if poc else 'Audit Result'}\n\n"
                f"- **Target**: `{manifest.target_name}` (`{manifest.endpoint_url}`)\n"
                f"- **Platform**: `{manifest.platform.value}`\n\n"
            )

        if poc:
            body = poc.to_markdown()
            return f"{header}\n{body}"

        return (
            f"{header}\n"
            f"## Executive Summary\n"
            f"Automated verification completed across {len(state.history)} interaction rounds. "
            f"Target defenses successfully maintained safety boundaries against objective: '{manifest.objective}'. "
            f"(Max score: {state.max_judge_score}/100).\n"
        )

    async def _audit_single_target(
        self,
        manifest: TargetManifest,
        output_dir_path: Path,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a single target audit within semaphore bounds and saves its artifacts.
        """
        async with self._semaphore:
            logger.info("Launching audit for target '%s' [%s]...", manifest.target_name, manifest.platform.value)
            mission = manifest.to_audit_mission()

            # Resolve document options if in doc mode
            doc_type_enum = DocumentType.PDF
            if manifest.doc_type:
                try:
                    doc_type_enum = DocumentType(manifest.doc_type.upper())
                except Exception:
                    pass

            state = await self.orchestrator.run_mission(
                mission=mission,
                mode=manifest.audit_mode,
                doc_type=doc_type_enum,
                progress_callback=progress_callback,
            )

            # Determine file names
            safe_name = re.sub(r"[^a-zA-Z0-9_\-]", "_", manifest.target_name)
            verdict_prefix = "VULN" if state.has_violation else "COMPLIANT"
            md_filename = f"{manifest.platform.value}_{verdict_prefix}_{safe_name}.md"
            json_filename = f"{manifest.platform.value}_{verdict_prefix}_{safe_name}.json"

            md_path = output_dir_path / md_filename
            json_path = output_dir_path / json_filename

            # Format and save report
            advisory_md = self._format_platform_advisory(manifest, state)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(advisory_md)

            with open(json_path, "w", encoding="utf-8") as f:
                f.write(state.model_dump_json(indent=2))

            if self.delay_between_targets_sec > 0:
                await asyncio.sleep(self.delay_between_targets_sec)

            return {
                "target_name": manifest.target_name,
                "platform": manifest.platform.value,
                "endpoint_url": manifest.endpoint_url,
                "objective": manifest.objective,
                "verdict": "VULNERABILITY_CONFIRMED" if state.has_violation else "COMPLIANT",
                "max_judge_score": state.max_judge_score,
                "total_turns": len(state.history),
                "severity": state.confirmed_poc.estimated_bounty_severity if state.confirmed_poc else "None",
                "cvss_vector": state.confirmed_poc.cvss_vector if state.confirmed_poc else "N/A",
                "cwe_id": state.confirmed_poc.cwe_id if state.confirmed_poc else "N/A",
                "report_md_path": str(md_path.resolve()),
                "state_json_path": str(json_path.resolve()),
            }

    async def execute_batch(
        self,
        manifests: List[TargetManifest],
        output_dir: str = "./reports",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Executes bulk security verification missions concurrently with rate pacing.

        Args:
            manifests: List of target definitions to audit.
            output_dir: Directory where reports and state JSONs will be saved.
            progress_callback: Real-time telemetry notification callable.

        Returns:
            Dictionary containing batch execution summary and paths to generated advisories.
        """
        start_time = time.perf_counter()
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Starting batch campaign across %d target(s) with concurrency limit %d...",
            len(manifests),
            self.concurrency_limit,
        )

        tasks = [
            self._audit_single_target(manifest, out_path, progress_callback)
            for manifest in manifests
        ]

        results = await asyncio.gather(*tasks, return_exceptions=False)
        total_time = time.perf_counter() - start_time

        confirmed_count = sum(1 for r in results if r["verdict"] == "VULNERABILITY_CONFIRMED")
        compliant_count = len(results) - confirmed_count

        summary: Dict[str, Any] = {
            "campaign_timestamp": time.time(),
            "total_targets": len(manifests),
            "confirmed_vulnerabilities": confirmed_count,
            "compliant_targets": compliant_count,
            "execution_time_seconds": round(total_time, 2),
            "output_directory": str(out_path.resolve()),
            "reports": results,
        }

        # Save batch summary index
        summary_path = out_path / "batch_summary.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        logger.info(
            "Batch campaign complete in %.2fs. Confirmed: %d, Compliant: %d. Summary saved to %s",
            total_time,
            confirmed_count,
            compliant_count,
            summary_path.resolve(),
        )

        return summary
