"""
Viber webhook server — Enhanced Aho-Corasick phishing guard.

Setup (see README.md for the full walkthrough):
  1. Create a Viber bot account at https://partners.viber.com and copy its
     auth token into the VIBER_AUTH_TOKEN environment variable.
  2. Run this server, expose it publicly (e.g. `ngrok http 5000` during
     development), then run register_webhook.py with the public HTTPS URL.
  3. Add the bot to a Viber conversation or group. Every message sent to the
     bot (1:1, or in a group where it is a member) will be scanned.

Scope note: Viber's Bot API only receives messages sent directly to the bot
(1:1 chats with it, or groups it has been added to) — it cannot passively
read a user's other private conversations with other contacts. This matches
what is realistically achievable with the officially documented API.
"""

import os
import logging
from pathlib import Path

import _bootstrap  # noqa: F401 — sets up sys.path for enhanced_aho/ and original_aho/
from flask import Flask, request, jsonify

from enhanced_aho_corasick import EnhancedAhoCorasick
from baseline_aho_corasick import BaselineAhoCorasick
from viber_client import ViberClient
from conversation_tracker import ConversationTracker
from detection_log import DetectionLog

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("viber_phishing_guard")

app = Flask(__name__)

AUTH_TOKEN = os.environ.get("VIBER_AUTH_TOKEN", "")
PATTERN_FILE = os.environ.get(
    "PATTERN_FILE",
    str(Path(__file__).resolve().parent.parent / "enhanced_aho" / "default_patterns.txt"),
)
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.45"))

viber = ViberClient(auth_token=AUTH_TOKEN)
tracker = ConversationTracker()
log = DetectionLog()

# ── Engine toggle ──────────────────────────────────────────────────────
# ENGINE_MODE env var sets the startup default ("enhanced" or "baseline").
# During a live demo, sending the bot the text "/mode baseline" or
# "/mode enhanced" switches it on the fly (per-process, affects everyone
# talking to this bot instance) — this is the side-by-side proof-of-concept
# switch, distinct from compare_engines.py which is the batch/dataset
# evaluation used for the actual Chapter 4 numbers.
_engines = {}


def _load_engines():
    if os.path.exists(PATTERN_FILE):
        _engines["enhanced"] = EnhancedAhoCorasick.from_pattern_file(
            PATTERN_FILE, anomaly_threshold=ANOMALY_THRESHOLD
        )
        _engines["baseline"] = BaselineAhoCorasick.from_pattern_file(PATTERN_FILE)
    else:
        logger.warning(
            "PATTERN_FILE '%s' not found — starting with an empty dictionary.",
            PATTERN_FILE,
        )
        _engines["enhanced"] = EnhancedAhoCorasick({}, anomaly_threshold=ANOMALY_THRESHOLD)
        _engines["baseline"] = BaselineAhoCorasick([])


_load_engines()
current_mode = {"value": os.environ.get("ENGINE_MODE", "enhanced")}
if current_mode["value"] not in _engines:
    current_mode["value"] = "enhanced"


def get_engine():
    return _engines[current_mode["value"]]


TIER_1_TEMPLATE = None  # silent — no message sent, log only

TIER_2_TEMPLATE = (
    "\u26a0\ufe0f Heads up — this message has some signs of a phishing "
    "attempt ({patterns}). Be careful before clicking links or sharing any "
    "account details."
)

TIER_3_TEMPLATE = (
    "\U0001f6d1 CRITICAL WARNING: This conversation shows strong signs of a "
    "phishing scam ({patterns}). Do NOT click any links, share your OTP, "
    "password, or send money. If you're unsure, verify directly through the "
    "official app or hotline — never through a link sent in chat.\n\n"
    "Tap below once you've read this."
)


def _pattern_summary(detections):
    names = []
    for item in detections:
        alert = item.get("alert", "")
        if "'" in alert:
            names.append(alert.split("'")[1])
    seen = set()
    unique = [n for n in names if not (n in seen or seen.add(n))]
    return ", ".join(unique) if unique else "suspicious content"


@app.route("/webhook", methods=["POST"])
def webhook():
    event = request.get_json(silent=True) or {}
    event_type = event.get("event")

    if event_type != "message":
        # subscribed / conversation_started / etc. — nothing to scan
        return jsonify({"status": 0}), 200

    message = event.get("message", {})
    if message.get("type") != "text":
        return jsonify({"status": 0}), 200

    text = message.get("text", "")
    sender = event.get("sender", {})
    sender_id = sender.get("id", "unknown")
    sender_name = sender.get("name", "unknown")
    # chat_id groups messages from the same conversation; falls back to the
    # sender id for 1:1 chats where Viber does not send a separate chat_id.
    chat_id = event.get("chat_hostname") or event.get("chat_id") or sender_id

    state = tracker.get(chat_id)

    # A tap on the Level-3 acknowledgment button arrives as a normal text
    # message with this ActionBody as its content.
    if text == "ACK_BLOCK":
        state.acknowledge()
        return jsonify({"status": 0}), 200

    # Live demo toggle: "/mode baseline" or "/mode enhanced"
    if text.strip().lower().startswith("/mode"):
        parts = text.strip().split()
        if len(parts) == 2 and parts[1].lower() in _engines:
            current_mode["value"] = parts[1].lower()
            viber.send_text(sender_id, f"Engine switched to: {current_mode['value'].upper()}")
        else:
            viber.send_text(sender_id, "Usage: /mode baseline  OR  /mode enhanced "
                                        f"(currently: {current_mode['value'].upper()})")
        return jsonify({"status": 0}), 200

    engine = get_engine()
    assessment = engine.assess_message(text)
    message_tier = assessment["action_tier"]
    session_tier = state.session_tier(message_tier)
    state.record(message_tier, assessment["detections"])

    log.record(
        chat_id=chat_id, sender_name=sender_name, message_text=text,
        action_tier=message_tier, session_tier=session_tier,
        detections=assessment["detections"],
    )

    mode_tag = f"[{current_mode['value'].upper()}] "

    if session_tier <= 0:
        pass  # clean message, nothing to do
    elif session_tier == 1:
        logger.info("[Tier 1 - flagged, silent] chat=%s text=%r", chat_id, text)
    elif session_tier == 2:
        patterns = _pattern_summary(assessment["detections"])
        viber.send_text(sender_id, mode_tag + TIER_2_TEMPLATE.format(patterns=patterns))
        logger.info("[Tier 2 - warning sent] chat=%s text=%r", chat_id, text)
    elif session_tier >= 3:
        patterns = _pattern_summary(assessment["detections"])
        viber.send_text(
            sender_id,
            mode_tag + TIER_3_TEMPLATE.format(patterns=patterns),
            keyboard=ViberClient.acknowledgment_keyboard(),
        )
        logger.info("[Tier 3 - blocked/escalated] chat=%s text=%r", chat_id, text)

    return jsonify({"status": 0}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "engine_mode": current_mode["value"],
        "patterns_loaded": len(get_engine().patterns),
    }), 200


@app.route("/logs/<chat_id>", methods=["GET"])
def get_logs(chat_id):
    """Simple JSON view of a conversation's detection history, for the demo."""
    return jsonify(log.recent_for_chat(chat_id)), 200


@app.route("/logs", methods=["GET"])
def get_all_flagged():
    min_tier = int(request.args.get("min_tier", 1))
    return jsonify(log.all_flagged(min_tier=min_tier)), 200


if __name__ == "__main__":
    if not AUTH_TOKEN:
        logger.warning(
            "VIBER_AUTH_TOKEN is not set — outgoing messages (Tier 2/3) will "
            "fail until it is configured. See README.md."
        )
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
