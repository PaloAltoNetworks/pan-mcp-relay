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

from aisecurity.generated_openapi_client import ScanResponse
from pydantic import BaseModel


class Detections(BaseModel):
    dlp: bool
    injection: bool
    url_cats: bool


class DetectionEntry(BaseModel):
    detections: Detections
    threats: list[str]
    tool_invoked: str | None = None


class DetectionEntries(BaseModel):
    detection_entries: list[DetectionEntry] | None = None


class ToolDetected(BaseModel):
    summary: DetectionEntry
    input_detected: DetectionEntries | None = None
    output_detected: DetectionEntries | None = None


class ToolScanResponse(ScanResponse):
    tool_detected: ToolDetected | None = None
