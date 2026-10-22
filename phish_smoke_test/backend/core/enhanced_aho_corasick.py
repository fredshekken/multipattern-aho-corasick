import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[3]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from enhanced_aho.enhanced_aho_corasick import EnhancedAhoCorasick


class EnhancedAhoCorasickPipeline:
    """Minimal adapter exposing the thesis engine as a simple pipeline."""

    def __init__(self, pattern_file: str | None = None):
        default_pattern_file = repo_root / "enhanced_aho" / "default_patterns.txt"
        self.engine = EnhancedAhoCorasick.from_pattern_file(
            str(pattern_file) if pattern_file else str(default_pattern_file)
        )

    def analyze(self, text: str):
        assessment = self.engine.assess_message(text)
        detections = assessment.get("detections", [])

        detected_patterns = []
        for detection in detections:
            breakdown = detection.get("score_breakdown", {})
            pattern = breakdown.get("pattern")
            if pattern and pattern not in detected_patterns:
                detected_patterns.append(pattern)

        max_risk = max((item.get("risk_score", 0.0) for item in detections), default=0.0)

        return {
            "tier": assessment.get("action_tier", 0),
            "detected_patterns": detected_patterns,
            "max_risk": round(max_risk, 3),
        }
