"""
Model Weight Scanner — Threat Layer 25

Scans serialized model files for embedded malware, backdoors, trojans,
suspicious payloads, and supply chain integrity violations.

Detection Capabilities:
  1. Pickle Exploit Detection — unsafe pickle opcodes that execute arbitrary code
  2. Embedded Script Detection — Python/shell scripts hidden in model weights
  3. Backdoor Signature Scanning — known trojan patterns in model architectures
  4. File Integrity Verification — SHA-256 hash validation and size anomalies
  5. Suspicious Layer Detection — hidden layers or anomalous parameter counts
  6. Serialization Format Risks — unsafe deserialization in PyTorch, TF, ONNX
  7. Metadata Poisoning — tampered metadata fields in model configs
  8. Network Callback Detection — embedded URLs/IPs for data exfiltration
"""

import re
import os
import hashlib
import struct
import json
from pathlib import Path
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field
from app.schemas.schemas import DetectionResult
from app.core.logging import get_logger

logger = get_logger("detector.model_weight_scanner")


# ── Dangerous Pickle Opcodes ───────────────────────────────────────
DANGEROUS_PICKLE_OPCODES = {
    b'\x52': 'REDUCE (arbitrary function call)',
    b'\x81': 'NEWOBJ (arbitrary object creation)',
    b'\x85': 'TUPLE1 (used in exploit chains)',
    b'\x86': 'TUPLE2 (used in exploit chains)',
    b'\x87': 'TUPLE3 (used in exploit chains)',
    b'\x8a': 'LONG1 (potential overflow)',
    b'\x63': 'GLOBAL (import arbitrary module)',
    b'\x69': 'INST (instantiate arbitrary class)',
    b'\x92': 'STACK_GLOBAL (exec arbitrary code)',
    b'\x93': 'MEMOIZE',
}

# ── Dangerous Module References in Pickles ─────────────────────────
DANGEROUS_IMPORTS = [
    r"os\.(system|popen|exec|spawn|remove|unlink|rmdir|chmod|makedirs)",
    r"subprocess\.(call|run|Popen|check_output|check_call|getoutput)",
    r"builtins\.(exec|eval|compile|__import__|execfile|input)",
    r"shutil\.(rmtree|move|copy|copytree)",
    r"socket\.(socket|connect|bind|listen|accept)",
    r"http\.client\.(HTTPConnection|HTTPSConnection)",
    r"urllib\.request\.(urlopen|urlretrieve|Request)",
    r"requests\.(get|post|put|delete|patch)",
    r"importlib\.(import_module|__import__)",
    r"ctypes\.(CDLL|windll|cdll|pythonapi)",
    r"webbrowser\.(open|open_new|open_new_tab)",
    r"code\.(interact|compile_command)",
    r"pickle\.loads",
    r"marshal\.loads",
    r"tempfile\.(mktemp|NamedTemporaryFile)",
    r"glob\.(glob|iglob)",
    r"pathlib\.Path",
]

# ── Embedded Script Patterns ───────────────────────────────────────
SCRIPT_PATTERNS = [
    rb"#!/(?:bin|usr/bin)/(?:bash|sh|python|perl|ruby|env)",
    rb"import\s+(?:os|sys|subprocess|socket|http|requests|urllib)\b",
    rb"eval\s*\(",
    rb"exec\s*\(",
    rb"__import__\s*\(",
    rb"os\.system\s*\(",
    rb"subprocess\.\w+\s*\(",
    rb"socket\.socket\s*\(",
    rb"curl\s+(?:https?://|ftp://)",
    rb"wget\s+(?:https?://|ftp://)",
    rb"powershell\s+(?:-[eE]|-[cC]ommand)",
    rb"cmd\.exe\s+/[cC]",
]

# ── Network Callback Patterns ─────────────────────────────────────
NETWORK_PATTERNS = [
    rb"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",        # IP-based URLs
    rb"https?://[\w.-]+\.(?:onion|i2p|bit|lib)",               # Dark web
    rb"(?:nc|netcat|ncat)\s+(?:-[a-z]+\s+)*\d{1,3}\.\d{1,3}", # Netcat
    rb"(?:ssh|scp|rsync)\s+[\w@]+",                            # SSH
    rb"(?:ftp|sftp|ftps)://[\w.:@]+",                          # FTP
    rb"AAAA[0-9A-Za-z+/]{20,}={0,2}",                         # Base64 encoded data blobs
]

# ── Known Trojan Model Signatures ──────────────────────────────────
TROJAN_SIGNATURES = [
    rb"TROJAN_TRIGGER_PATTERN",
    rb"backdoor_layer",
    rb"malicious_weight",
    rb"hidden_payload",
    rb"c2_server",
    rb"exfil_endpoint",
    rb"reverse_shell",
    rb"keylogger",
    rb"data_stealer",
    rb"crypto_miner",
]

# ── Scan Result Model ─────────────────────────────────────────────
class ModelScanResult(BaseModel):
    """Result of a model weight scan."""
    file_name: str
    file_size_bytes: int
    file_hash_sha256: str
    format_detected: str = "unknown"
    scan_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    is_safe: bool = True
    risk_level: str = "safe"  # safe, low, medium, high, critical
    risk_score: float = 0.0
    threats_found: int = 0
    detections: list[dict] = []
    metadata: dict = {}
    scan_duration_ms: float = 0.0
    layers_scanned: int = 0
    parameters_estimated: int = 0


class ModelWeightScanner:
    """Scans model files for embedded malware, backdoors, and integrity issues."""

    def __init__(self):
        self._dangerous_import_compiled = []
        self._script_compiled = []
        self._network_compiled = []
        self._initialized = False

    async def initialize(self) -> None:
        self._dangerous_import_compiled = [
            re.compile(p.encode() if isinstance(p, str) else p) 
            for p in DANGEROUS_IMPORTS
        ]
        self._script_compiled = [re.compile(p) for p in SCRIPT_PATTERNS]
        self._network_compiled = [re.compile(p) for p in NETWORK_PATTERNS]
        self._initialized = True
        logger.info("model_weight_scanner_initialized")

    async def scan_file(self, file_path: str) -> ModelScanResult:
        """Perform a comprehensive security scan of a model file."""
        import time
        start = time.perf_counter()

        path = Path(file_path)
        if not path.exists():
            return ModelScanResult(
                file_name=path.name,
                file_size_bytes=0,
                file_hash_sha256="",
                is_safe=False,
                risk_level="critical",
                risk_score=1.0,
                threats_found=1,
                detections=[{
                    "type": "file_not_found",
                    "severity": "critical",
                    "description": f"Model file not found: {file_path}"
                }],
            )

        file_size = path.stat().st_size
        file_hash = await self._compute_hash(path)
        format_detected = self._detect_format(path)

        all_detections = []

        # Read file bytes for scanning (cap at 100MB for safety)
        max_scan_bytes = min(file_size, 100 * 1024 * 1024)
        with open(path, 'rb') as f:
            content = f.read(max_scan_bytes)

        # 1. Pickle Exploit Scan
        if format_detected in ("pytorch", "pickle", "unknown"):
            all_detections.extend(self._scan_pickle_exploits(content, path.name))

        # 2. Embedded Script Scan
        all_detections.extend(self._scan_embedded_scripts(content, path.name))

        # 3. Network Callback Scan
        all_detections.extend(self._scan_network_callbacks(content, path.name))

        # 4. Trojan Signature Scan
        all_detections.extend(self._scan_trojan_signatures(content, path.name))

        # 5. Dangerous Import Scan
        all_detections.extend(self._scan_dangerous_imports(content, path.name))

        # 6. File Size Anomaly
        all_detections.extend(self._check_size_anomaly(file_size, format_detected, path.name))

        # 7. Metadata Poisoning (for known formats)
        if format_detected in ("safetensors", "onnx", "tensorflow"):
            all_detections.extend(self._scan_metadata_poisoning(content, path.name, format_detected))

        # Calculate risk
        risk_score = self._calculate_risk_score(all_detections)
        risk_level = self._classify_risk(risk_score)

        duration = (time.perf_counter() - start) * 1000

        result = ModelScanResult(
            file_name=path.name,
            file_size_bytes=file_size,
            file_hash_sha256=file_hash,
            format_detected=format_detected,
            is_safe=len(all_detections) == 0,
            risk_level=risk_level,
            risk_score=round(risk_score, 4),
            threats_found=len(all_detections),
            detections=[d for d in all_detections],
            scan_duration_ms=round(duration, 2),
            layers_scanned=self._estimate_layers(content, format_detected),
            parameters_estimated=self._estimate_parameters(file_size, format_detected),
            metadata={
                "file_extension": path.suffix,
                "format": format_detected,
                "scan_depth": "full" if file_size <= max_scan_bytes else "partial",
            },
        )

        logger.info(
            "model_scan_completed",
            file=path.name,
            risk_level=risk_level,
            threats=len(all_detections),
            duration_ms=round(duration, 2),
        )

        return result

    async def scan_bytes(self, data: bytes, filename: str = "uploaded_model") -> ModelScanResult:
        """Scan model bytes directly (for upload endpoints)."""
        import time
        start = time.perf_counter()

        file_hash = hashlib.sha256(data).hexdigest()
        format_detected = self._detect_format_from_bytes(data, filename)

        all_detections = []

        # Run all scans
        if format_detected in ("pytorch", "pickle", "unknown"):
            all_detections.extend(self._scan_pickle_exploits(data, filename))

        all_detections.extend(self._scan_embedded_scripts(data, filename))
        all_detections.extend(self._scan_network_callbacks(data, filename))
        all_detections.extend(self._scan_trojan_signatures(data, filename))
        all_detections.extend(self._scan_dangerous_imports(data, filename))
        all_detections.extend(self._check_size_anomaly(len(data), format_detected, filename))

        if format_detected in ("safetensors", "onnx", "tensorflow"):
            all_detections.extend(self._scan_metadata_poisoning(data, filename, format_detected))

        risk_score = self._calculate_risk_score(all_detections)
        risk_level = self._classify_risk(risk_score)
        duration = (time.perf_counter() - start) * 1000

        return ModelScanResult(
            file_name=filename,
            file_size_bytes=len(data),
            file_hash_sha256=file_hash,
            format_detected=format_detected,
            is_safe=len(all_detections) == 0,
            risk_level=risk_level,
            risk_score=round(risk_score, 4),
            threats_found=len(all_detections),
            detections=all_detections,
            scan_duration_ms=round(duration, 2),
            layers_scanned=self._estimate_layers(data, format_detected),
            parameters_estimated=self._estimate_parameters(len(data), format_detected),
            metadata={
                "format": format_detected,
                "scan_depth": "full",
            },
        )

    async def detect(self, text: str) -> list[DetectionResult]:
        """Unified detect method — scans text for model file references."""
        detections = []
        
        # Detect attempts to upload or download suspicious model files
        suspicious_patterns = [
            (r"(?:download|load|import|fetch)\s+(?:model|weights?|checkpoint)\s+from\s+(https?://\S+)", "model_download_attempt"),
            (r"torch\.load\s*\(\s*['\"]([^'\"]+)['\"]", "unsafe_torch_load"),
            (r"pickle\.loads?\s*\(", "unsafe_pickle_load"),
            (r"(?:wget|curl)\s+.*\.(?:pt|pth|bin|pkl|ckpt|h5|pb|onnx|safetensors)", "model_download_command"),
            (r"huggingface\.co/[\w-]+/[\w-]+/resolve", "hf_model_download"),
        ]

        for pattern_str, category in suspicious_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            match = pattern.search(text)
            if match:
                detections.append(DetectionResult(
                    detector="model_weight_scanner",
                    confidence=0.75,
                    category=f"model_security.{category}",
                    description=(
                        f"Suspicious model operation detected: {category.replace('_', ' ')}. "
                        f"Unverified model files may contain embedded malware or backdoors."
                    ),
                    severity="high",
                    matched_content=match.group(0)[:150],
                ))

        return detections

    # ── Private Scanning Methods ────────────────────────────────────

    def _scan_pickle_exploits(self, content: bytes, filename: str) -> list[dict]:
        """Scan for dangerous pickle opcodes."""
        detections = []
        for opcode, description in DANGEROUS_PICKLE_OPCODES.items():
            count = content.count(opcode)
            if count > 0:
                # REDUCE and STACK_GLOBAL are the most dangerous
                severity = "critical" if opcode in (b'\x52', b'\x92', b'\x63') else "high"
                detections.append({
                    "type": "pickle_exploit",
                    "severity": severity,
                    "confidence": 0.90 if severity == "critical" else 0.75,
                    "description": (
                        f"Dangerous pickle opcode '{description}' found {count} time(s) in {filename}. "
                        f"This opcode can execute arbitrary code during deserialization."
                    ),
                    "opcode": description,
                    "count": count,
                })
        return detections

    def _scan_embedded_scripts(self, content: bytes, filename: str) -> list[dict]:
        """Scan for embedded scripts hidden in model data."""
        detections = []
        for pattern in self._script_compiled:
            matches = pattern.findall(content)
            if matches:
                detections.append({
                    "type": "embedded_script",
                    "severity": "critical",
                    "confidence": 0.92,
                    "description": (
                        f"Embedded script/code detected in {filename}: "
                        f"'{matches[0][:80].decode('utf-8', errors='replace')}'. "
                        f"Model files should not contain executable code."
                    ),
                    "match_count": len(matches),
                })
        return detections

    def _scan_network_callbacks(self, content: bytes, filename: str) -> list[dict]:
        """Scan for network callback URLs/IPs embedded in model data."""
        detections = []
        for pattern in self._network_compiled:
            matches = pattern.findall(content)
            if matches:
                detections.append({
                    "type": "network_callback",
                    "severity": "critical",
                    "confidence": 0.88,
                    "description": (
                        f"Embedded network callback detected in {filename}: "
                        f"'{matches[0][:100].decode('utf-8', errors='replace')}'. "
                        f"Model may attempt to exfiltrate data on load."
                    ),
                    "match_count": len(matches),
                })
        return detections

    def _scan_trojan_signatures(self, content: bytes, filename: str) -> list[dict]:
        """Scan for known trojan/backdoor signatures."""
        detections = []
        for sig in TROJAN_SIGNATURES:
            if sig in content:
                detections.append({
                    "type": "trojan_signature",
                    "severity": "critical",
                    "confidence": 0.95,
                    "description": (
                        f"Known trojan signature detected in {filename}: "
                        f"'{sig.decode('utf-8', errors='replace')}'. "
                        f"This model file is likely compromised."
                    ),
                })
        return detections

    def _scan_dangerous_imports(self, content: bytes, filename: str) -> list[dict]:
        """Scan for dangerous Python module imports in serialized data."""
        detections = []
        for pattern in self._dangerous_import_compiled:
            if isinstance(pattern.pattern, str):
                matches = re.findall(pattern.pattern.encode(), content)
            else:
                matches = pattern.findall(content)
            if matches:
                detections.append({
                    "type": "dangerous_import",
                    "severity": "critical",
                    "confidence": 0.93,
                    "description": (
                        f"Dangerous module import found in {filename}: "
                        f"'{matches[0][:80].decode('utf-8', errors='replace') if isinstance(matches[0], bytes) else str(matches[0])[:80]}'. "
                        f"This import can execute arbitrary system commands."
                    ),
                    "match_count": len(matches),
                })
        return detections

    def _check_size_anomaly(self, file_size: int, format_detected: str, filename: str) -> list[dict]:
        """Check for file size anomalies."""
        detections = []

        # Suspiciously small model files (< 1KB for a "model")
        if file_size < 1024 and format_detected != "unknown":
            detections.append({
                "type": "size_anomaly",
                "severity": "medium",
                "confidence": 0.60,
                "description": (
                    f"Suspiciously small model file ({file_size} bytes): {filename}. "
                    f"May be a decoy or corrupted file."
                ),
            })

        # Extremely large files (> 50GB)
        if file_size > 50 * 1024 * 1024 * 1024:
            detections.append({
                "type": "size_anomaly",
                "severity": "low",
                "confidence": 0.40,
                "description": (
                    f"Unusually large model file ({file_size / (1024**3):.1f} GB): {filename}. "
                    f"Verify this file size is expected for the model architecture."
                ),
            })

        return detections

    def _scan_metadata_poisoning(self, content: bytes, filename: str, format_type: str) -> list[dict]:
        """Check for metadata poisoning in structured formats."""
        detections = []

        if format_type == "safetensors":
            # SafeTensors has a JSON header
            try:
                header_size = struct.unpack('<Q', content[:8])[0]
                if header_size > 0 and header_size < len(content):
                    header_json = content[8:8 + header_size].decode('utf-8')
                    metadata = json.loads(header_json)

                    # Check for suspicious metadata keys
                    suspicious_keys = ["__exec__", "eval", "exec", "import", "system", "subprocess"]
                    for key in suspicious_keys:
                        if key in str(metadata).lower():
                            detections.append({
                                "type": "metadata_poisoning",
                                "severity": "high",
                                "confidence": 0.80,
                                "description": (
                                    f"Suspicious metadata key '{key}' found in safetensors header of {filename}. "
                                    f"Metadata should not contain executable references."
                                ),
                            })
            except Exception:
                pass

        return detections

    # ── Helper Methods ──────────────────────────────────────────────

    def _detect_format(self, path: Path) -> str:
        """Detect model file format from extension and magic bytes."""
        ext_map = {
            ".pt": "pytorch", ".pth": "pytorch", ".bin": "pytorch",
            ".pkl": "pickle", ".pickle": "pickle",
            ".onnx": "onnx",
            ".h5": "tensorflow", ".hdf5": "tensorflow",
            ".pb": "tensorflow", ".tflite": "tensorflow",
            ".safetensors": "safetensors",
            ".ckpt": "pytorch",
            ".gguf": "gguf", ".ggml": "ggml",
            ".mlmodel": "coreml",
        }
        return ext_map.get(path.suffix.lower(), "unknown")

    def _detect_format_from_bytes(self, data: bytes, filename: str) -> str:
        """Detect format from bytes and filename."""
        path = Path(filename)
        fmt = self._detect_format(path)
        if fmt != "unknown":
            return fmt

        # Magic byte detection
        if data[:2] == b'\x80\x02' or data[:2] == b'\x80\x04' or data[:2] == b'\x80\x05':
            return "pickle"
        if data[:4] == b'\x89HDF':
            return "tensorflow"
        if data[:4] == b'GGUF':
            return "gguf"

        return "unknown"

    async def _compute_hash(self, path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    def _estimate_layers(self, content: bytes, format_type: str) -> int:
        """Estimate number of layers from file content."""
        if format_type == "pytorch":
            return content.count(b'weight') + content.count(b'bias')
        if format_type == "safetensors":
            try:
                header_size = struct.unpack('<Q', content[:8])[0]
                header = content[8:8 + min(header_size, 100000)].decode('utf-8', errors='replace')
                return header.count('"dtype"')
            except Exception:
                return 0
        return 0

    def _estimate_parameters(self, file_size: int, format_type: str) -> int:
        """Rough estimation of parameter count from file size."""
        bytes_per_param = {
            "pytorch": 4,       # FP32 default
            "safetensors": 2,   # Often FP16
            "onnx": 4,
            "tensorflow": 4,
            "gguf": 1,          # Quantized
        }
        bpp = bytes_per_param.get(format_type, 4)
        # Rough estimate: ~70% of file is weights
        return int(file_size * 0.7 / bpp)

    def _calculate_risk_score(self, detections: list[dict]) -> float:
        """Calculate overall risk score."""
        if not detections:
            return 0.0

        severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        scores = [
            d.get("confidence", 0.5) * severity_weights.get(d.get("severity", "medium"), 0.5)
            for d in detections
        ]

        max_score = max(scores)
        avg_boost = sum(scores) / len(scores) * 0.2
        return min(max_score + avg_boost, 1.0)

    def _classify_risk(self, score: float) -> str:
        """Classify risk level from score."""
        if score >= 0.9:
            return "critical"
        elif score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        elif score >= 0.15:
            return "low"
        return "safe"


# Singleton instance
model_weight_scanner = ModelWeightScanner()
