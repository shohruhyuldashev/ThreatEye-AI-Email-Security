from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class DetectionContext:
    email_text: str
    metadata: dict[str, Any] = field(default_factory=dict)
    user_context: dict[str, Any] = field(default_factory=dict)
    attachments: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DetectionResult:
    engine: str
    score: int
    confidence: int
    verdict: str
    signals: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""


class DetectionEngine(Protocol):
    name: str

    def analyze(self, context: DetectionContext) -> DetectionResult:
        ...


class HeuristicEngine:
    name = "heuristic"

    def analyze(self, context: DetectionContext) -> DetectionResult:
        from services.ai_detector import extract_urls, layer1_heuristics

        urls = extract_urls(context.email_text)
        score, features = layer1_heuristics(context.email_text, urls)
        signals = [key for key, value in features.items() if value]
        return DetectionResult(self.name, score, 85, "suspicious" if score >= 50 else "low risk", signals, {"features": features, "urls": urls})


class DomainIntelEngine:
    name = "domain_intel"

    def analyze(self, context: DetectionContext) -> DetectionResult:
        from services.ai_detector import extract_urls, layer3_domain_intel

        urls = extract_urls(context.email_text)
        score, features = layer3_domain_intel(urls)
        signals = []
        if features.get("typosquatting_target"):
            signals.append(f"brand spoof: {features['typosquatting_target']}")
        if features.get("is_ip_based"):
            signals.append("ip based url")
        signals.extend(features.get("suspicious_keywords", []))
        return DetectionResult(self.name, score, 80, "malicious" if score >= 80 else ("suspicious" if score >= 50 else "low risk"), signals, {"features": features, "urls": urls})


class BecDetectorEngine:
    name = "bec_detector"

    def analyze(self, context: DetectionContext) -> DetectionResult:
        from services.ai_detector import detect_bec_signals

        score, features = detect_bec_signals(context.email_text, context.metadata)
        signals = features.get("bec_keywords", [])
        return DetectionResult(self.name, score, 78, "BEC / payment fraud" if score >= 45 else "low risk", signals, {"features": features}, "Verify payment requests out-of-band." if score >= 45 else "")


class PromptGuardEngine:
    name = "prompt_guard"

    def analyze(self, context: DetectionContext) -> DetectionResult:
        from services.ai_detector import detect_prompt_injection

        score, features = detect_prompt_injection(context.email_text)
        signals = ["prompt injection pattern"] if features.get("prompt_injection_detected") else []
        return DetectionResult(self.name, score, 82, "AI evasion attempt" if score else "clean", signals, {"features": features}, "Quarantine and review adversarial content." if score >= 35 else "")


class AttachmentScannerEngine:
    name = "attachment_scanner"
    risky_extensions = {".exe", ".scr", ".js", ".vbs", ".ps1", ".hta", ".iso", ".img", ".lnk", ".docm", ".xlsm"}

    def analyze(self, context: DetectionContext) -> DetectionResult:
        signals = []
        score = 0
        for attachment in context.attachments:
            filename = str(attachment.get("filename", "")).lower()
            for ext in self.risky_extensions:
                if filename.endswith(ext):
                    signals.append(f"risky attachment: {filename}")
                    score = max(score, 75)
            if filename.endswith(".zip") and attachment.get("encrypted"):
                signals.append(f"encrypted archive: {filename}")
                score = max(score, 65)
        return DetectionResult(self.name, score, 75, "risky attachment" if score else "clean", signals, {"attachments": context.attachments}, "Hold and sandbox attachment." if score else "")


class LLMEngine:
    name = "llm_soc"

    def analyze(self, context: DetectionContext) -> DetectionResult:
        from services.ai_detector import analyze_email_hybrid

        result = analyze_email_hybrid(context.email_text, context.metadata, context.user_context)
        evidence = result.get("evidence", {})
        signals = evidence.get("signals", []) if isinstance(evidence, dict) else []
        return DetectionResult(
            self.name,
            int(result.get("llm_score", result.get("final_risk_score", 0))),
            int(result.get("confidence_score", 60)),
            result.get("threat_type", "Unknown"),
            signals[:8],
            result,
            result.get("recommended_action", ""),
        )


DEFAULT_ENGINES: list[DetectionEngine] = [
    HeuristicEngine(),
    DomainIntelEngine(),
    BecDetectorEngine(),
    PromptGuardEngine(),
    AttachmentScannerEngine(),
]


def run_detection_pipeline(context: DetectionContext, include_llm: bool = False) -> list[DetectionResult]:
    engines: list[DetectionEngine] = list(DEFAULT_ENGINES)
    if include_llm:
        engines.append(LLMEngine())
    return [engine.analyze(context) for engine in engines]

