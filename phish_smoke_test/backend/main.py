import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.enhanced_aho_corasick import EnhancedAhoCorasick


def _find_pattern_file():
    """Looks for default_patterns.txt: env var, then backend/core, then repo enhanced_aho/."""
    here = Path(__file__).resolve().parent
    candidates = []
    if os.environ.get("PHISH_PATTERNS"):
        candidates.append(Path(os.environ["PHISH_PATTERNS"]))
    candidates.append(here / "core" / "default_patterns.txt")
    candidates.append(here.parents[1] / "enhanced_aho" / "default_patterns.txt")
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError(
        "default_patterns.txt not found. Set PHISH_PATTERNS or copy it to backend/core/."
    )


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = EnhancedAhoCorasick.from_pattern_file(_find_pattern_file())


class MessagePayload(BaseModel):
    text: str


@app.post("/scan")
def scan_message(payload: MessagePayload):
    # Message-level result: one tier per message (not per keyword).
    # tier: 0 none, 1 low (passive), 2 moderate (advisory), 3 high/critical (active)
    result = engine.assess_message(payload.text)

    tokens = []
    for detection in result["detections"]:
        breakdown = detection.get("score_breakdown", {})
        token = breakdown.get("matched_text") or breakdown.get("pattern")
        if token and token not in tokens:
            tokens.append(token)

    return {
        "tier": result["action_tier"],
        "severity": result["severity"],
        "tokens": tokens,
        "risk_score": result["global_risk"],
        "evidence_groups": result["evidence_groups"],
    }