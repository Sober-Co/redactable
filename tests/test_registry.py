import logging

from redactable.detectors.base import Finding
from redactable.detectors.registry import DetectorRegistry


class _BrokenDetector:
    name = "broken"

    def detect(self, text: str):  # pragma: no cover - only raises
        raise RuntimeError("boom")


class _StaticDetector:
    name = "static"

    def __init__(self, finding: Finding) -> None:
        self._finding = finding

    def detect(self, text: str):
        return [self._finding]


def test_scan_logs_and_skips_detector_errors(caplog):
    expected = Finding(kind="ok", value="value", span=(1, 2), confidence=0.5)
    registry = DetectorRegistry([_BrokenDetector(), _StaticDetector(expected)])

    with caplog.at_level(logging.ERROR):
        findings = registry.scan("dummy text")

    assert findings == [expected]
    error_messages = [record.getMessage() for record in caplog.records]
    assert any("broken" in message for message in error_messages)
