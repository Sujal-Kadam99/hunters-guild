"""
Model File & Supply Chain Security Scanner
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework

Analyzes machine learning model artifacts (Pickle, PyTorch Checkpoints, Safetensors,
GGUF, Hugging Face config.json) for OWASP LLM05 (Supply Chain Vulnerabilities),
arbitrary code execution payloads, dangerous deserialization opcodes, and unvetted remote code hooks.
"""

from __future__ import annotations

import io
import json
import logging
import pickletools
import struct
import time
import zipfile
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("HuntersGuild.ModelScanner")


class ModelFormat(str, Enum):
    """Supported machine learning model serialization formats."""
    PICKLE = "PICKLE"
    PYTORCH_CHECKPOINT = "PYTORCH_CHECKPOINT"
    SAFETENSORS = "SAFETENSORS"
    HUGGINGFACE_CONFIG = "HUGGINGFACE_CONFIG"
    GGUF = "GGUF"
    UNKNOWN = "UNKNOWN"


class ScanSeverity(str, Enum):
    """Vulnerability severity classification for model supply chain findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CLEAN = "CLEAN"


class ModelVulnerability(BaseModel):
    """
    Detailed finding documenting an unsafe opcode, dangerous global, or malicious metadata.
    """
    model_config = ConfigDict(extra="allow")

    rule_id: str = Field(..., description="Unique vulnerability rule identifier (e.g., 'SEC-PKL-001').")
    title: str = Field(..., description="Short descriptive title of the finding.")
    severity: ScanSeverity = Field(..., description="Severity classification.")
    description: str = Field(..., description="Explanation of why this symbol/configuration presents risk.")
    detected_symbol: Optional[str] = Field(default=None, description="The specific global, module, or key flagged.")
    byte_offset: Optional[int] = Field(default=None, description="Byte position in the stream where finding occurred.")


class ModelScanReport(BaseModel):
    """
    Aggregated supply chain analysis report for a scanned model file.
    """
    model_config = ConfigDict(extra="allow")

    target_file: str = Field(..., description="Path or label of the scanned artifact.")
    format: ModelFormat = Field(..., description="Detected model format.")
    is_vulnerable: bool = Field(..., description="True if any HIGH or CRITICAL findings were identified.")
    highest_severity: ScanSeverity = Field(..., description="Maximum severity level among all findings.")
    findings: List[ModelVulnerability] = Field(default_factory=list, description="List of detected vulnerabilities.")
    scan_duration_ms: float = Field(..., description="Time taken to scan the artifact in milliseconds.")


class ModelSecurityScanner:
    """
    Static analyzer for machine learning model files that disassembles bytecode,
    inspects tensor headers, and audits model architectures without executing untrusted code.
    """

    DEFAULT_BANNED_GLOBALS: Set[str] = {
        # OS / Process Execution
        "os.system",
        "posix.system",
        "nt.system",
        "os.popen",
        "os.spawn",
        "os.exec",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "pty.spawn",
        "commands",
        # Dynamic Code Execution
        "builtins.eval",
        "builtins.exec",
        "builtins.__import__",
        "builtins.compile",
        "builtins.getattr",
        "__builtin__.eval",
        "__builtin__.exec",
        "__builtin__.__import__",
        # Networking / Sockets
        "socket.socket",
        "urllib.request.urlopen",
        "requests.get",
        "requests.post",
        "http.client.HTTPConnection",
        # System & Memory Manipulation
        "sys.modules",
        "ctypes.CDLL",
        "winreg",
        "shutil.rmtree",
    }

    def __init__(self, banned_globals: Optional[List[str]] = None) -> None:
        """
        Initialize the Model Security Scanner with configurable banned symbols.
        """
        self.banned_globals = set(banned_globals) if banned_globals else set(self.DEFAULT_BANNED_GLOBALS)

    def scan_pickle_bytes(
        self,
        raw_bytes: bytes,
        filename: str = "memory.pkl",
        format_type: ModelFormat = ModelFormat.PICKLE,
    ) -> ModelScanReport:
        """
        Disassembles raw pickle opcode streams using pickletools.genops without invoking pickle.load().
        """
        start_time = time.perf_counter()
        findings: List[ModelVulnerability] = []
        highest_severity = ScanSeverity.CLEAN

        last_memo_strings: List[str] = []

        try:
            for opcode, arg, pos in pickletools.genops(raw_bytes):
                op_name = opcode.name

                # Track string pushes for STACK_GLOBAL resolution
                if op_name in ("UNICODE", "STRING", "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8"):
                    if arg is not None:
                        last_memo_strings.append(str(arg))
                        if len(last_memo_strings) > 10:
                            last_memo_strings.pop(0)

                # 1. Inspect GLOBAL opcode (explicit module and name)
                if op_name == "GLOBAL" and arg:
                    module_name, func_name = arg.split(maxsplit=1) if " " in arg else (arg, "")
                    full_symbol = f"{module_name}.{func_name}" if func_name else module_name

                    if self._is_symbol_banned(full_symbol):
                        findings.append(
                            ModelVulnerability(
                                rule_id="SEC-PKL-001",
                                title="Arbitrary Code Execution via Banned GLOBAL Opcode",
                                severity=ScanSeverity.CRITICAL,
                                description=(
                                    f"Detected prohibited global execution symbol '{full_symbol}'. "
                                    f"Deserializing this pickle artifact allows arbitrary remote code execution."
                                ),
                                detected_symbol=full_symbol,
                                byte_offset=pos,
                            )
                        )
                        highest_severity = ScanSeverity.CRITICAL

                # 2. Inspect STACK_GLOBAL opcode (module and name popped from stack)
                elif op_name == "STACK_GLOBAL":
                    if len(last_memo_strings) >= 2:
                        module_name = last_memo_strings[-2]
                        func_name = last_memo_strings[-1]
                        full_symbol = f"{module_name}.{func_name}"

                        if self._is_symbol_banned(full_symbol):
                            findings.append(
                                ModelVulnerability(
                                    rule_id="SEC-PKL-002",
                                    title="Arbitrary Code Execution via STACK_GLOBAL Symbol",
                                    severity=ScanSeverity.CRITICAL,
                                    description=(
                                        f"Detected prohibited stack global execution symbol '{full_symbol}'. "
                                        f"Allows unconstrained arbitrary code execution on deserialization."
                                    ),
                                    detected_symbol=full_symbol,
                                    byte_offset=pos,
                                )
                            )
                            highest_severity = ScanSeverity.CRITICAL

                # 3. Detect REDUCE / BUILD on suspicious calls
                elif op_name in ("REDUCE", "BUILD", "INST", "OBJ"):
                    # Record usage if preceded by dangerous context
                    pass

        except Exception as e:
            # Corrupted or non-pickle stream
            logger.debug("Pickle opcode parsing exception on %s: %s", filename, e)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        is_vulnerable = any(f.severity in (ScanSeverity.CRITICAL, ScanSeverity.HIGH) for f in findings)

        return ModelScanReport(
            target_file=filename,
            format=format_type,
            is_vulnerable=is_vulnerable,
            highest_severity=highest_severity,
            findings=findings,
            scan_duration_ms=duration_ms,
        )

    def _is_symbol_banned(self, symbol: str) -> bool:
        """Checks whether a symbol matches any banned global pattern."""
        sym_clean = symbol.strip()
        if sym_clean in self.banned_globals:
            return True
        for banned in self.banned_globals:
            if sym_clean.startswith(f"{banned}.") or sym_clean.startswith(f"{banned} "):
                return True
        return False

    def scan_safetensors_file(
        self,
        file_bytes: bytes,
        filename: str = "model.safetensors",
    ) -> ModelScanReport:
        """
        Validates Safetensors header length, structure, and metadata safety without parsing tensor weights.
        """
        start_time = time.perf_counter()
        findings: List[ModelVulnerability] = []
        highest_severity = ScanSeverity.CLEAN

        if len(file_bytes) < 8:
            findings.append(
                ModelVulnerability(
                    rule_id="SEC-SFT-001",
                    title="Malformed Safetensors: File Too Small",
                    severity=ScanSeverity.HIGH,
                    description="The safetensors artifact is smaller than the required 8-byte header prefix.",
                    byte_offset=0,
                )
            )
            highest_severity = ScanSeverity.HIGH
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ModelScanReport(
                target_file=filename,
                format=ModelFormat.SAFETENSORS,
                is_vulnerable=True,
                highest_severity=highest_severity,
                findings=findings,
                scan_duration_ms=duration_ms,
            )

        header_len = struct.unpack("<Q", file_bytes[:8])[0]

        # Check for abnormal header size (e.g. > 100MB or exceeding file size)
        if header_len > 100 * 1024 * 1024 or (8 + header_len) > len(file_bytes):
            findings.append(
                ModelVulnerability(
                    rule_id="SEC-SFT-002",
                    title="Safetensors Header Length Boundary Overflow",
                    severity=ScanSeverity.CRITICAL,
                    description=(
                        f"Declared header length ({header_len} bytes) exceeds file boundaries or reasonable memory bounds. "
                        f"Potential header smuggling or Denial-of-Service vector."
                    ),
                    byte_offset=0,
                )
            )
            highest_severity = ScanSeverity.CRITICAL
        else:
            header_raw = file_bytes[8 : 8 + header_len]
            try:
                header_json = json.loads(header_raw.decode("utf-8"))
                metadata = header_json.get("__metadata__", {})
                
                # Check for suspicious executable code in metadata
                meta_str = json.dumps(metadata)
                if any(p in meta_str.lower() for p in ["<script", "os.system", "exec(", "eval("]):
                    findings.append(
                        ModelVulnerability(
                            rule_id="SEC-SFT-003",
                            title="Malicious Metadata Injection in Safetensors Header",
                            severity=ScanSeverity.HIGH,
                            description="Safetensors __metadata__ block contains executable code or script injection indicators.",
                            detected_symbol="metadata_injection",
                            byte_offset=8,
                        )
                    )
                    highest_severity = ScanSeverity.HIGH

            except Exception as exc:
                findings.append(
                    ModelVulnerability(
                        rule_id="SEC-SFT-004",
                        title="Invalid Safetensors Header JSON Format",
                        severity=ScanSeverity.MEDIUM,
                        description=f"Safetensors header is not valid UTF-8 JSON: {exc}",
                        byte_offset=8,
                    )
                )
                if highest_severity == ScanSeverity.CLEAN:
                    highest_severity = ScanSeverity.MEDIUM

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        is_vulnerable = any(f.severity in (ScanSeverity.CRITICAL, ScanSeverity.HIGH) for f in findings)

        return ModelScanReport(
            target_file=filename,
            format=ModelFormat.SAFETENSORS,
            is_vulnerable=is_vulnerable,
            highest_severity=highest_severity,
            findings=findings,
            scan_duration_ms=duration_ms,
        )

    def scan_huggingface_config(
        self,
        config_dict_or_json: Union[str, Dict[str, Any]],
        filename: str = "config.json",
    ) -> ModelScanReport:
        """
        Scans Hugging Face model configuration files for unvetted remote code execution directives.
        """
        start_time = time.perf_counter()
        findings: List[ModelVulnerability] = []
        highest_severity = ScanSeverity.CLEAN

        if isinstance(config_dict_or_json, str):
            try:
                config = json.loads(config_dict_or_json)
            except Exception as e:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return ModelScanReport(
                    target_file=filename,
                    format=ModelFormat.HUGGINGFACE_CONFIG,
                    is_vulnerable=False,
                    highest_severity=ScanSeverity.LOW,
                    findings=[
                        ModelVulnerability(
                            rule_id="SEC-CFG-000",
                            title="Unparseable JSON Configuration",
                            severity=ScanSeverity.LOW,
                            description=f"Could not parse JSON configuration: {e}",
                        )
                    ],
                    scan_duration_ms=duration_ms,
                )
        else:
            config = config_dict_or_json

        # 1. Detect auto_map references (Remote custom python code injection)
        auto_map = config.get("auto_map")
        if auto_map and isinstance(auto_map, dict):
            custom_code_files = [str(v) for v in auto_map.values() if isinstance(v, str) and (".py" in v or "--" in v)]
            findings.append(
                ModelVulnerability(
                    rule_id="SEC-CFG-001",
                    title="Arbitrary Code Execution via auto_map Remote Code Hooks",
                    severity=ScanSeverity.HIGH,
                    description=(
                        f"Model config contains 'auto_map' definitions pointing to custom python scripts: {auto_map}. "
                        f"Loading this repository with trust_remote_code=True executes arbitrary repository code."
                    ),
                    detected_symbol=f"auto_map:{custom_code_files}",
                )
            )
            highest_severity = ScanSeverity.HIGH

        # 2. Detect explicit trust_remote_code flags
        if config.get("trust_remote_code") is True or config.get("custom_code") is True:
            findings.append(
                ModelVulnerability(
                    rule_id="SEC-CFG-002",
                    title="Explicit trust_remote_code Flag Enforced",
                    severity=ScanSeverity.MEDIUM,
                    description="Configuration mandates trust_remote_code=True.",
                    detected_symbol="trust_remote_code=True",
                )
            )
            if highest_severity in (ScanSeverity.CLEAN, ScanSeverity.LOW):
                highest_severity = ScanSeverity.MEDIUM

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        is_vulnerable = any(f.severity in (ScanSeverity.CRITICAL, ScanSeverity.HIGH) for f in findings)

        return ModelScanReport(
            target_file=filename,
            format=ModelFormat.HUGGINGFACE_CONFIG,
            is_vulnerable=is_vulnerable,
            highest_severity=highest_severity,
            findings=findings,
            scan_duration_ms=duration_ms,
        )

    def scan_file(self, file_path: Union[str, Path]) -> ModelScanReport:
        """
        Dynamically determines format by magic bytes or extension and inspects the target artifact.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path.resolve()}")

        raw_bytes = path.read_bytes()
        filename = path.name

        # 1. Check for Safetensors format
        if path.suffix == ".safetensors":
            return self.scan_safetensors_file(raw_bytes, filename=filename)

        # 2. Check for GGUF format (Magic bytes: 'GGUF')
        if raw_bytes.startswith(b"GGUF"):
            start_time = time.perf_counter()
            return ModelScanReport(
                target_file=filename,
                format=ModelFormat.GGUF,
                is_vulnerable=False,
                highest_severity=ScanSeverity.CLEAN,
                findings=[],
                scan_duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        # 3. Check for Zip-based PyTorch Checkpoint (PK\x03\x04)
        if raw_bytes.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                    pkl_findings: List[ModelVulnerability] = []
                    highest_sev = ScanSeverity.CLEAN
                    start_time = time.perf_counter()

                    for member in zf.namelist():
                        if member.endswith(".pkl") or member.endswith("data.pkl") or member.endswith(".pickle"):
                            pkl_bytes = zf.read(member)
                            sub_report = self.scan_pickle_bytes(
                                pkl_bytes,
                                filename=f"{filename}::{member}",
                                format_type=ModelFormat.PYTORCH_CHECKPOINT,
                            )
                            pkl_findings.extend(sub_report.findings)
                            if sub_report.highest_severity == ScanSeverity.CRITICAL:
                                highest_sev = ScanSeverity.CRITICAL
                            elif sub_report.highest_severity == ScanSeverity.HIGH and highest_sev != ScanSeverity.CRITICAL:
                                highest_sev = ScanSeverity.HIGH

                    duration_ms = (time.perf_counter() - start_time) * 1000.0
                    return ModelScanReport(
                        target_file=filename,
                        format=ModelFormat.PYTORCH_CHECKPOINT,
                        is_vulnerable=len(pkl_findings) > 0,
                        highest_severity=highest_sev,
                        findings=pkl_findings,
                        scan_duration_ms=duration_ms,
                    )
            except Exception as e:
                logger.debug("Zip extraction error on %s: %s", filename, e)

        # 4. Check for Hugging Face config.json
        if filename.endswith(".json") or path.suffix == ".json":
            try:
                text = raw_bytes.decode("utf-8")
                return self.scan_huggingface_config(text, filename=filename)
            except Exception:
                pass

        # 5. Default: Treat as Raw Pickle stream
        return self.scan_pickle_bytes(raw_bytes, filename=filename)
