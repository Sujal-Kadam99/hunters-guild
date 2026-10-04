"""
Indirect Prompt Injection (IPI) & RAG Document Fuzzer
Project: Hunters Guild - Automated Model Alignment & Boundary Verification Framework

This module provides tools to synthesize benign-looking documents (Markdown, CSV, PDF,
JSON, TXT) containing embedded indirect prompt injection payloads, invisible font overlays,
metadata headers, and semantic retrieval boosters to evaluate RAG pipeline robustness.
"""

from hunters_guild.modules.rag_fuzzer import (
    AdvancedRAGFuzzer,
    CorpusGenerationResult,
    DocumentFuzzer,
    DocumentType,
    FuzzedDocument,
    InjectionStyle,
    RAGDocumentFuzzer,
    SplitPayloadResult,
)

__all__ = [
    "AdvancedRAGFuzzer",
    "CorpusGenerationResult",
    "DocumentFuzzer",
    "DocumentType",
    "FuzzedDocument",
    "InjectionStyle",
    "RAGDocumentFuzzer",
    "SplitPayloadResult",
]
