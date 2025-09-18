# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
# https://polyformproject.org/licenses/internal-use/1.0.0
# (or)
# https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md
#
# As far as the law allows, the software comes as is, without any warranty
# or condition, and the licensor will not be liable to you for any damages
# arising out of these terms or the use or nature of the software, under
# any kind of legal claim.

from typing import Optional

from aisecurity.generated_openapi_client import ScanResponse
from pydantic import BaseModel

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
    tool_invoked: str | None = None


class DetectionEntries(BaseModel):

    """
    A container for multiple detection entries.
    - detection_entries: Optional list of DetectionEntry objects.
    """

    detection_entries: list[DetectionEntry] | None = None


class ToolDetected(BaseModel):
    """
    Encapsulates detection results for a scanned tool.
    - summary: A high-level summary (DetectionEntry) of the detection outcome.
    - input_detected: (Optional) Detection results specific to tool input.
    - output_detected: (Optional) Detection results specific to tool output.
    """

    summary: DetectionEntry
    input_detected: DetectionEntries | None = None
    output_detected: DetectionEntries | None = None


class ToolScanResponse(ScanResponse):

    """
    Extends the base ScanResponse with tool-specific detection results.
    - tool_detected: (Optional) ToolDetected object containing detection summaries and details.
    """

    tool_detected: ToolDetected | None = None
