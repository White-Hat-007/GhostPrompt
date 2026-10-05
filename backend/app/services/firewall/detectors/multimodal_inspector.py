"""
Multimodal Inspector — Prompt Injection Detection across Image, Audio, Video

Detects hidden or embedded adversarial instructions injected via:
- Images: OCR-based text extraction (EasyOCR with PIL/pytesseract fallback)
- Audio: Speech-to-text transcription (SpeechRecognition / Whisper)
- Video: Frame extraction (OpenCV) + per-frame OCR + audio analysis

All detections flow into the standard DetectionResult schema.
"""

import asyncio
import base64
import io
import re
import tempfile
import os
from PIL import Image
from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("firewall.multimodal")

# ── Adversarial phrase patterns ──
INJECTION_PHRASES = [
    "ignore previous", "ignore all previous", "disregard",
    "you are now", "developer mode", "jailbreak", "do anything now",
    "forget instructions", "system prompt", "override", "bypass",
    "act as", "pretend you", "new instruction", "hidden instruction",
    "base64", "admin mode", "maintenance mode", "unlock", "unrestricted",
    "no restrictions", "ignore the above", "ignore above",
]

INJECTION_PATTERN = re.compile(
    "|".join(re.escape(p) for p in INJECTION_PHRASES), re.IGNORECASE
)

METADATA_INJECTION = re.compile(
    r"(ignore|disregard|system:|<\|im_start\||INST|SYS:|<<SYS>>|\[INST\])",
    re.IGNORECASE
)


def _score_text(extracted_text: str) -> list[DetectionResult]:
    """Score extracted text for adversarial content."""
    detections = []
    text_lower = extracted_text.lower().strip()
    if not text_lower:
        return detections

    matches = INJECTION_PATTERN.findall(text_lower)
    if matches:
        unique = list(set(m.lower() for m in matches))
        confidence = min(0.6 + len(unique) * 0.1, 0.97)
        detections.append(DetectionResult(
            detector="multimodal_inspector",
            confidence=round(confidence, 3),
            category="multimodal.hidden_prompt_injection",
            description=f"Adversarial instructions found in media: [{', '.join(unique[:3])}]",
            matched_content=extracted_text[:200],
            severity="high" if confidence >= 0.8 else "medium",
        ))

    if METADATA_INJECTION.search(extracted_text):
        detections.append(DetectionResult(
            detector="multimodal_inspector",
            confidence=0.85,
            category="multimodal.template_injection",
            description="LLM template injection markers detected in media content",
            matched_content=extracted_text[:200],
            severity="high",
        ))

    return detections


class MultimodalInspector:
    def __init__(self):
        self.reader = None
        self._initialized = False

    async def initialize(self):
        if not self._initialized:
            try:
                import easyocr
                self.reader = easyocr.Reader(['en'], gpu=False)
                logger.info("EasyOCR initialized successfully")
            except Exception as e:
                logger.warning(f"EasyOCR unavailable, using fallback: {e}")
            self._initialized = True

    # ── Public: base64 list from proxy/scan ──
    async def inspect_media(self, media_payloads: list[str]) -> list[DetectionResult]:
        """Inspect base64 encoded image payloads for hidden instructions."""
        detections = []
        for payload in media_payloads:
            try:
                if "," in payload:
                    payload = payload.split(",", 1)[1]
                image_bytes = base64.b64decode(payload)
                new_detections = await self._scan_image_bytes(image_bytes, source="base64_payload")
                detections.extend(new_detections)
            except Exception as e:
                logger.warning(f"Error processing base64 media: {e}")
        return detections

    # ── Public: scan uploaded file bytes by MIME type ──
    async def scan_file_bytes(
        self,
        file_bytes: bytes,
        content_type: str,
        filename: str = "upload",
    ) -> tuple[list[DetectionResult], str]:
        """Scan raw uploaded file bytes. Returns (detections, extracted_text)."""
        ct = content_type.lower()
        fn = filename.lower()
        try:
            if ct.startswith("image/") or fn.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff")):
                detections = await self._scan_image_bytes(file_bytes, source=filename)
                extracted = await self._extract_image_text(file_bytes)
                return detections, extracted

            elif ct.startswith("audio/") or fn.endswith((".mp3", ".wav", ".ogg", ".m4a", ".flac")):
                extracted, detections = await self._scan_audio_bytes(file_bytes, filename)
                return detections, extracted

            elif ct.startswith("video/") or fn.endswith((".mp4", ".mov", ".avi", ".mkv", ".webm")):
                extracted, detections = await self._scan_video_bytes(file_bytes, filename)
                return detections, extracted

            else:
                # Generic fallback: try image
                try:
                    detections = await self._scan_image_bytes(file_bytes, source=filename)
                    extracted = await self._extract_image_text(file_bytes)
                    return detections, extracted
                except Exception:
                    return [], ""
        except Exception as e:
            logger.error(f"scan_file_bytes error for {filename}: {e}")
            return [], ""

    # ── IMAGE ──
    async def _extract_image_text(self, image_bytes: bytes) -> str:
        try:
            if self.reader:
                results = await asyncio.to_thread(self.reader.readtext, image_bytes, detail=0)
                return " ".join(results)
            return await self._pytesseract_fallback(image_bytes)
        except Exception as e:
            logger.warning(f"Image OCR failed: {e}")
            return ""

    async def _pytesseract_fallback(self, image_bytes: bytes) -> str:
        try:
            import pytesseract
            img = Image.open(io.BytesIO(image_bytes))
            text = await asyncio.to_thread(pytesseract.image_to_string, img)
            return text
        except Exception:
            return self._extract_exif_text(image_bytes)

    def _extract_exif_text(self, image_bytes: bytes) -> str:
        try:
            img = Image.open(io.BytesIO(image_bytes))
            info = img.info or {}
            parts = []
            for v in info.values():
                if isinstance(v, str):
                    parts.append(v)
                elif isinstance(v, bytes):
                    parts.append(v.decode("utf-8", errors="ignore"))
            return " ".join(parts)
        except Exception:
            return ""

    async def _scan_image_bytes(self, image_bytes: bytes, source: str) -> list[DetectionResult]:
        detections = []

        # 1. OCR text
        extracted_text = await self._extract_image_text(image_bytes)
        if extracted_text:
            detections.extend(_score_text(extracted_text))

        # 2. EXIF/metadata injection
        exif_text = self._extract_exif_text(image_bytes)
        if exif_text and exif_text.strip() != extracted_text.strip():
            meta_dets = _score_text(exif_text)
            for d in meta_dets:
                d.category = "multimodal.metadata_injection"
                d.description = f"[EXIF/Metadata] {d.description}"
            detections.extend(meta_dets)

        # 3. Steganography heuristic
        try:
            img = Image.open(io.BytesIO(image_bytes))
            w, h = img.size
            pixels = w * h
            bytes_per_pixel = len(image_bytes) / max(pixels, 1)
            if img.format in ("PNG", "BMP") and bytes_per_pixel > 6:
                detections.append(DetectionResult(
                    detector="multimodal_inspector",
                    confidence=0.55,
                    category="multimodal.steganography_heuristic",
                    description=f"Unusually high data density ({bytes_per_pixel:.1f} bytes/pixel) — possible steganographic payload",
                    matched_content=f"{w}x{h} {img.format}, {len(image_bytes)//1024}KB",
                    severity="medium",
                ))
        except Exception:
            pass

        return detections

    # ── AUDIO ──
    async def _scan_audio_bytes(self, audio_bytes: bytes, filename: str) -> tuple[str, list[DetectionResult]]:
        transcript = await self._transcribe_audio(audio_bytes, filename)
        if not transcript:
            return "", [DetectionResult(
                detector="multimodal_inspector",
                confidence=0.3,
                category="multimodal.audio_unreadable",
                description="Audio could not be transcribed. Manual review recommended.",
                matched_content=filename,
                severity="low",
            )]
        detections = _score_text(transcript)
        for d in detections:
            d.category = d.category.replace("multimodal.", "multimodal.audio_")
            d.description = f"[AUDIO TRANSCRIPT] {d.description}"
        return transcript, detections

    async def _transcribe_audio(self, audio_bytes: bytes, filename: str) -> str:
        ext = os.path.splitext(filename)[1] or ".wav"

        # Method 1: SpeechRecognition
        try:
            import speech_recognition as sr
            recognizer = sr.Recognizer()
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(audio_bytes)
                tmp_path = tmp.name
            try:
                with sr.AudioFile(tmp_path) as source:
                    audio_data = recognizer.record(source)
                text = await asyncio.to_thread(recognizer.recognize_google, audio_data)
                return text
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"SpeechRecognition failed: {e}")

        # Method 2: Whisper
        try:
            import whisper
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
                tmp.write(audio_bytes)
                tmp_path = tmp.name
            try:
                model = await asyncio.to_thread(whisper.load_model, "base")
                result = await asyncio.to_thread(model.transcribe, tmp_path)
                return result.get("text", "")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Whisper failed: {e}")

        return ""

    # ── VIDEO ──
    async def _scan_video_bytes(self, video_bytes: bytes, filename: str) -> tuple[str, list[DetectionResult]]:
        all_text_parts = []
        all_detections = []

        ext = os.path.splitext(filename)[1] or ".mp4"
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(video_bytes)
            tmp_path = tmp.name

        try:
            frames = await asyncio.to_thread(self._extract_video_frames, tmp_path)
            if not frames:
                all_detections.append(DetectionResult(
                    detector="multimodal_inspector",
                    confidence=0.3,
                    category="multimodal.video_unreadable",
                    description="Video frames could not be extracted. OpenCV may not be installed.",
                    matched_content=filename,
                    severity="low",
                ))
            else:
                for i, frame_bytes in enumerate(frames):
                    frame_text = await self._extract_image_text(frame_bytes)
                    if frame_text.strip():
                        all_text_parts.append(f"[Frame {i+1}] {frame_text}")
                        frame_dets = _score_text(frame_text)
                        for d in frame_dets:
                            d.category = d.category.replace("multimodal.", "multimodal.video_frame_")
                            d.description = f"[VIDEO Frame {i+1}] {d.description}"
                        all_detections.extend(frame_dets)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        return "\n".join(all_text_parts), all_detections

    def _extract_video_frames(self, video_path: str, max_frames: int = 8) -> list[bytes]:
        try:
            import cv2
            cap = cv2.VideoCapture(video_path)
            total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            if total <= 0:
                cap.release()
                return []
            indices = [int(total * i / max_frames) for i in range(max_frames)]
            frame_list = []
            for idx in indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
                ret, frame = cap.read()
                if ret:
                    _, buf = cv2.imencode(".png", frame)
                    frame_list.append(buf.tobytes())
            cap.release()
            return frame_list
        except Exception as e:
            logger.warning(f"Video frame extraction failed: {e}")
            return []
