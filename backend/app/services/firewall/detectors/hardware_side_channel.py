"""
Hardware Side-Channel Detector — Threat Layer 26 (Enterprise/Hardware)

Detects prompt injection vectors specifically designed to exploit hardware
characteristics, such as:
- GPU/TPU timing attacks
- MIG (Multi-Instance GPU) isolation escape attempts
- Tensor Core starvation patterns
- Cache-timing probes
- Power/thermal side-channel triggers
"""

import time
import re
from typing import Optional
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.hardware")

class HardwareSideChannelDetector:
    """Detects hardware-level side-channel prompt injection attacks."""

    async def initialize(self) -> None:
        logger.info("hardware_side_channel_detector_initialized")

    async def detect(self, text: str) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        text_lower = text.lower()

        # 1. MIG (Multi-Instance GPU) Isolation Escape patterns
        # Adversaries might try to overload specific SMs to observe cross-MIG latency
        if re.search(r"(compute workload overflow|mig isolation|cross-partition crosstalk|gpu partition|nvlink|multi-instance gpu)", text_lower):
            detections.append(DetectionResult(
                detector="hardware_side_channel",
                confidence=0.85,
                category="hardware.mig_isolation_probe",
                description="Detected prompt designed to probe or exploit MIG (Multi-Instance GPU) isolation boundaries.",
                severity="critical",
                matched_content=text[:80]
            ))

        # 2. Timing/Cache Attack patterns
        if re.search(r"(cache line|flush\.reload|prime\.probe|memory bandwidth|cache timing|l2 flush|l3 hit rate)", text_lower):
            detections.append(DetectionResult(
                detector="hardware_side_channel",
                confidence=0.82,
                category="hardware.cache_timing",
                description="Detected cache-timing or memory bandwidth probing (e.g., Flush+Reload, Prime+Probe).",
                severity="high",
                matched_content=text[:80]
            ))
            
        # 3. Tensor Core / Compute Starvation (Sponge-like hardware focus)
        # Attempting to force precise floating-point exceptions or high-energy power states
        if re.search(r"(fp64|float64|denormalized|nan poisoning|subnormal|fused multiply add|fma|tensor core saturation)", text_lower):
            detections.append(DetectionResult(
                detector="hardware_side_channel",
                confidence=0.78,
                category="hardware.tensor_starvation",
                description="Detected attempt to induce compute starvation or floating-point anomalies (NaN/subnormal poisoning).",
                severity="high",
                matched_content=text[:80]
            ))
            
        # 4. Power/Thermal Side-Channel
        if re.search(r"(thermal throttling|power draw|energy consumption|tdc limit|edp limit|clock skew)", text_lower):
            detections.append(DetectionResult(
                detector="hardware_side_channel",
                confidence=0.75,
                category="hardware.power_side_channel",
                description="Detected power or thermal side-channel elicitation (TDC/EDP limit probing).",
                severity="high",
                matched_content=text[:80]
            ))

        # 5. Infrastructure Reconnaissance — probing for system specs, GPU model, OS, IP addresses
        infra_patterns = [
            r"(what|which|tell me|reveal|show|list)\s+.{0,30}(cuda|gpu|vram|graphics card|accelerator|tpu|npu)",
            r"(what|which|tell me|reveal|show)\s+.{0,30}(operating system|python version|web framework|server|ip address)",
            r"(how much|what)\s+.{0,20}(memory|ram|vram|storage)\s+.{0,20}(allocated|available|used|running)",
            r"(what|reveal|show|list)\s+.{0,20}(environment variable|env var|config|secret|api.?key)",
            r"(what|which)\s+.{0,20}(port|hostname|container|docker|kubernetes|cluster)\s+.{0,20}(running|using|deployed)",
            r"(system|server|infra|infrastructure)\s+(info|information|detail|spec|specification|recon|reconnaissance)",
        ]
        for pat in infra_patterns:
            if re.search(pat, text_lower):
                detections.append(DetectionResult(
                    detector="hardware_side_channel",
                    confidence=0.80,
                    category="hardware.infrastructure_recon",
                    description="Detected infrastructure reconnaissance: prompt probes for GPU specs, OS details, IP addresses, or deployment information.",
                    severity="high",
                    matched_content=text[:120]
                ))
                break

        # 6. Hardware Attack Keywords — explicit attack technique names
        hardware_attack_keywords = [
            (r"(memory\s+access\s+pattern|attention\s+head\s+memory|memory\s+layout)\s*(probe|attack|describe|reveal|dump|extract)?", "hardware.memory_access_probe", "Memory access pattern probing detected"),
            (r"(rowhammer|row\s+hammer)\s*(attempt|attack|probe|repeat|flip)", "hardware.rowhammer", "Rowhammer attack attempt detected"),
            (r"(spectre|meltdown|speculative\s+execution)\s*(probe|attack|exploit|vulnerability)", "hardware.spectre_meltdown", "Spectre/Meltdown side-channel probe detected"),
            (r"(cold\s+boot)\s*(attack|simulation|dump|extract)", "hardware.cold_boot", "Cold boot attack simulation detected"),
            (r"(timing\s+analysis|timing\s+attack|timing\s+side.?channel)\s*:?\s*(respond|measure|report|execute)", "hardware.timing_attack", "Timing analysis/attack detected"),
            (r"(dump|extract|read)\s+.{0,30}(gpu\s+vram|model\s+weights?\s+from\s+(gpu|memory|vram))", "hardware.vram_dump", "GPU VRAM dump attempt detected"),
            (r"(memory\s+address|0x[0-9a-f]{4,})\s*.{0,30}(report|access|read|dump|contents)", "hardware.memory_address_probe", "Direct memory address access attempt"),
            (r"(power\s+analysis|differential\s+power\s+analysis|dpa)\s*:?\s*(vary|measure|report)", "hardware.power_analysis", "Power analysis side-channel probe"),
            # Hardware fingerprinting via latency/response measurement
            (r"(measure|profile|record|observe)\s+.{0,30}(latency|response\s+time|timing|throughput)\s+.{0,30}(fingerprint|identify|detect|determine|infer)\s+.{0,20}(hardware|gpu|infrastructure|server|model)", "hardware.fingerprinting", "Hardware fingerprinting via latency measurement detected"),
            (r"(fingerprint|identify|detect|profile)\s+.{0,20}(your\s+)?(hardware|gpu|infrastructure|server|accelerator)", "hardware.fingerprinting", "Hardware fingerprinting attempt detected"),
            # Batch/concurrent request probing
            (r"(send|fire|launch|submit)\s+.{0,20}(\d{3,}|thousands?\s+of|millions?\s+of)\s+.{0,20}(concurrent|simultaneous|parallel)\s+request", "hardware.load_probe", "Infrastructure load probing detected"),
        ]
        for pat, cat, desc in hardware_attack_keywords:
            if re.search(pat, text_lower):
                detections.append(DetectionResult(
                    detector="hardware_side_channel",
                    confidence=0.88,
                    category=cat,
                    description=desc,
                    severity="critical",
                    matched_content=text[:120]
                ))

        return detections
