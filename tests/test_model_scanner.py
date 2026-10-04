"""
Unit and Integration Tests for Model File & Supply Chain Security Scanner
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework
"""

import io
import json
import os
import pickle
import struct
import subprocess
import zipfile
from pathlib import Path
import pytest

from hunters_guild.modules.model_scanner import (
    ModelFormat,
    ModelScanReport,
    ModelSecurityScanner,
    ModelVulnerability,
    ScanSeverity,
)


class MaliciousOsSystemPayload:
    def __reduce__(self):
        return (os.system, ("echo VULNERABLE",))


class MaliciousSubprocessPayload:
    def __reduce__(self):
        return (subprocess.Popen, (["whoami"],))


def test_detect_dangerous_pickle_os_system():
    """
    Tests detection of dangerous os.system GLOBAL opcode in raw pickle streams without execution.
    """
    scanner = ModelSecurityScanner()
    raw_pickle = pickle.dumps(MaliciousOsSystemPayload())

    report = scanner.scan_pickle_bytes(raw_pickle, filename="exploit.pkl")

    assert isinstance(report, ModelScanReport)
    assert report.is_vulnerable is True
    assert report.highest_severity == ScanSeverity.CRITICAL
    assert len(report.findings) >= 1
    assert any(
        any(sys_sym in (f.detected_symbol or "") for sys_sym in ("os.system", "nt.system", "posix.system"))
        for f in report.findings
    )
    assert report.findings[0].rule_id in ("SEC-PKL-001", "SEC-PKL-002")


def test_detect_dangerous_pickle_subprocess_popen():
    """
    Tests detection of dangerous subprocess.Popen execution payload.
    """
    scanner = ModelSecurityScanner()
    raw_pickle = pickle.dumps(MaliciousSubprocessPayload())

    report = scanner.scan_pickle_bytes(raw_pickle, filename="subprocess_exploit.pkl")

    assert report.is_vulnerable is True
    assert report.highest_severity == ScanSeverity.CRITICAL
    assert any("subprocess.Popen" in (f.detected_symbol or "") for f in report.findings)


def test_detect_stack_global_opcode():
    """
    Tests detection of STACK_GLOBAL opcode (Protocol 4+).
    """
    scanner = ModelSecurityScanner()
    # Construct raw protocol 4 pickle opcode stream with STACK_GLOBAL for builtins.eval
    # \x80\x04 (proto 4) \x8c\x08builtins \x8c\x04eval \x93 (STACK_GLOBAL) .
    raw_bytecode = b"\x80\x04\x8c\x08builtins\x94\x8c\x04eval\x94\x93."

    report = scanner.scan_pickle_bytes(raw_bytecode, filename="stack_global_eval.pkl")

    assert report.is_vulnerable is True
    assert report.highest_severity == ScanSeverity.CRITICAL
    assert any("builtins.eval" in (f.detected_symbol or "") for f in report.findings)


def test_benign_pickle_scan():
    """
    Tests that standard benign objects (dicts, lists, numpy-like data) scan clean.
    """
    scanner = ModelSecurityScanner()
    benign_data = {
        "model_weights": [0.12, 0.45, -0.98, 1.05],
        "layer_names": ["layer1.weight", "layer1.bias"],
        "metadata": {"version": 1.0, "author": "HuntersGuild"},
    }
    raw_pickle = pickle.dumps(benign_data)

    report = scanner.scan_pickle_bytes(raw_pickle, filename="benign_weights.pkl")

    assert report.is_vulnerable is False
    assert report.highest_severity == ScanSeverity.CLEAN
    assert len(report.findings) == 0


def test_safetensors_valid_header():
    """
    Tests validation of well-formed Safetensors metadata headers.
    """
    scanner = ModelSecurityScanner()

    meta = {
        "__metadata__": {"format": "pt"},
        "weight_1": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
    }
    meta_bytes = json.dumps(meta).encode("utf-8")
    header_len = len(meta_bytes)
    header_prefix = struct.pack("<Q", header_len)
    raw_safetensors = header_prefix + meta_bytes + (b"\x00" * 16)

    report = scanner.scan_safetensors_file(raw_safetensors, filename="clean_model.safetensors")

    assert report.is_vulnerable is False
    assert report.highest_severity == ScanSeverity.CLEAN
    assert len(report.findings) == 0


def test_safetensors_header_boundary_overflow():
    """
    Tests detection of malicious/overflowing Safetensors header length.
    """
    scanner = ModelSecurityScanner()

    # Claim header is 10 MB, but file is only 30 bytes
    fake_length = 10 * 1024 * 1024
    raw_safetensors = struct.pack("<Q", fake_length) + b"short payload data"

    report = scanner.scan_safetensors_file(raw_safetensors, filename="overflow.safetensors")

    assert report.is_vulnerable is True
    assert report.highest_severity == ScanSeverity.CRITICAL
    assert report.findings[0].rule_id == "SEC-SFT-002"


def test_huggingface_config_auto_map_custom_code():
    """
    Tests detection of unvetted custom Python code execution in Hugging Face config.json auto_map.
    """
    scanner = ModelSecurityScanner()
    malicious_config = {
        "architectures": ["CustomLLMModel"],
        "model_type": "custom_llm",
        "auto_map": {
            "AutoConfig": "configuration_custom.CustomConfig",
            "AutoModelForCausalLM": "modeling_custom.CustomModelForCausalLM",
        },
    }

    report = scanner.scan_huggingface_config(malicious_config, filename="config.json")

    assert report.is_vulnerable is True
    assert report.highest_severity == ScanSeverity.HIGH
    assert report.findings[0].rule_id == "SEC-CFG-001"
    assert "auto_map" in (report.findings[0].detected_symbol or "")


def test_huggingface_config_benign():
    """
    Tests standard benign Hugging Face config scan.
    """
    scanner = ModelSecurityScanner()
    benign_config = {
        "architectures": ["LlamaForCausalLM"],
        "hidden_size": 4096,
        "num_attention_heads": 32,
        "vocab_size": 32000,
    }

    report = scanner.scan_huggingface_config(benign_config, filename="config.json")

    assert report.is_vulnerable is False
    assert report.highest_severity == ScanSeverity.CLEAN


def test_scan_file_pytorch_zip_checkpoint(tmp_path):
    """
    Tests scanning PyTorch v1.6+ zip checkpoint archive containing dangerous pickle.
    """
    scanner = ModelSecurityScanner()
    pt_file = tmp_path / "model.pt"

    # Create PyTorch-like zip archive with an embedded malicious pickle
    malicious_bytes = pickle.dumps(MaliciousOsSystemPayload())

    with zipfile.ZipFile(pt_file, "w") as zf:
        zf.writestr("archive/data.pkl", malicious_bytes)
        zf.writestr("archive/version", b"3")

    report = scanner.scan_file(pt_file)

    assert report.format == ModelFormat.PYTORCH_CHECKPOINT
    assert report.is_vulnerable is True
    assert report.highest_severity == ScanSeverity.CRITICAL
    assert len(report.findings) >= 1
