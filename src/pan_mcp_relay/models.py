from typing import Optional
from pydantic import BaseModel

from aisecurity.generated_openapi_client import ScanResponse


class Detections(BaseModel):
    """
    Detection flags for different categories of potential issues.
    - dlp: Data Loss Prevention violations detected (e.g., sensitive data leakage).
    - injection: Prompt/code injection detected.
    - url_cats: Suspicious or malicious URLs detected.
    """

    dlp: bool
    injection: bool
    url_cats: bool


class DetectionEntry(BaseModel):
    """
    Represents a single detection result for a tool invocation.
    - detections: Boolean flags indicating which categories triggered.
    - threats: List of threat labels or identifiers (e.g., ["context poisoning", "credential leakage"]).
    - tool_invoked: (Optional) Name of the tool that triggered this detection.
    """

    detections: Detections
    threats: list[str]
    tool_invoked: Optional[str] = None


class DetectionEntries(BaseModel):
    """
    A container for multiple detection entries.
    - detection_entries: Optional list of DetectionEntry objects.
    """

    detection_entries: Optional[list[DetectionEntry]] = None


class ToolDetected(BaseModel):
    """
    Encapsulates detection results for a scanned tool.
    - summary: A high-level summary (DetectionEntry) of the detection outcome.
    - input_detected: (Optional) Detection results specific to tool input.
    - output_detected: (Optional) Detection results specific to tool output.
    """

    summary: DetectionEntry
    input_detected: Optional[DetectionEntries] = None
    output_detected: Optional[DetectionEntries] = None


class ToolScanResponse(ScanResponse):
    """
    Extends the base ScanResponse with tool-specific detection results.
    - tool_detected: (Optional) ToolDetected object containing detection summaries and details.
    """

    tool_detected: Optional[ToolDetected] = None
