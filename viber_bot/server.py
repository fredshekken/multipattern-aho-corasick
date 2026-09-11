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
import csv
import json
import logging
import sys
import time
import uuid
from collections import defaultdict
from pathlib import Path

import _bootstrap  # noqa: F401 — sets up sys.path for enhanced_aho/ and original_aho/
from flask import Flask, request, jsonify

from enhanced_aho_corasick import EnhancedAhoCorasick
from baseline_aho_corasick import BaselineAhoCorasick
from viber_client import ViberClient
from conversation_tracker import ConversationTracker
from detection_log import DetectionLog
from compare_engines import load_csv, evaluate, baseline_predict, enhanced_predict

csv.field_size_limit(sys.maxsize)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("viber_phishing_guard")

app = Flask(__name__)

AUTH_TOKEN = os.environ.get("VIBER_AUTH_TOKEN", "")
PATTERN_FILE = os.environ.get(
    "PATTERN_FILE",
    str(Path(__file__).resolve().parent.parent / "enhanced_aho" / "default_patterns.txt"),
)
ANOMALY_THRESHOLD = float(os.environ.get("ANOMALY_THRESHOLD", "0.45"))

# ── Dataset storage (Dashboard "Datasets" tab) ──────────────────────────
UPLOADED_DATASETS_DIR = Path(__file__).resolve().parent / "uploaded_datasets"
UPLOADED_DATASETS_DIR.mkdir(exist_ok=True)
DATASET_INDEX_PATH = UPLOADED_DATASETS_DIR / "index.json"


def _load_dataset_index():
    if DATASET_INDEX_PATH.exists():
        return json.loads(DATASET_INDEX_PATH.read_text(encoding="utf-8"))
    return {}


def _save_dataset_index(index):
    DATASET_INDEX_PATH.write_text(json.dumps(index, indent=2), encoding="utf-8")

# ── Simulation mode ────────────────────────────────────────────────────
# Real Viber bot creation now requires a paid commercial application (since
# Feb 2024) that is outside this project's control/timeline. When no real
# VIBER_AUTH_TOKEN is configured, the server automatically runs in
# simulation mode: instead of calling the real Viber REST API, outgoing
# messages are queued in memory per-user and pulled by demo_chat.html
# (a small local page that mimics the Viber UI). All detection, tiering,
# and escalation logic is 100% identical either way — only the transport
# for delivering the reply differs. Setting VIBER_AUTH_TOKEN later (once a
# real bot account exists, on Viber or another platform's equivalent) is
# the only change needed to go live.
SIMULATION_MODE = not bool(AUTH_TOKEN)
_sim_outbox = defaultdict(list)

viber = ViberClient(auth_token=AUTH_TOKEN)
tracker = ConversationTracker()
log = DetectionLog()


def deliver(receiver, text, keyboard=None):
    """Send a message to the user via the real Viber API, or queue it for
    the local simulator if no real token is configured."""
    if SIMULATION_MODE:
        _sim_outbox[receiver].append({"text": text, "keyboard": keyboard})
    else:
        viber.send_text(receiver, text, keyboard=keyboard)

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


def build_reply_for_tier(session_tier, detections, mode_tag=""):
    """
    Shared logic for turning a session tier into a reply. Returns
    (reply_text_or_None, keyboard_or_None). Used by both the live Viber
    webhook and the dashboard's dual-engine comparison endpoint, so the two
    surfaces can never drift into inconsistent behavior.
    """
    if session_tier <= 0 or session_tier == 1:
        return None, None
    patterns = _pattern_summary(detections)
    if session_tier == 2:
        return mode_tag + TIER_2_TEMPLATE.format(patterns=patterns), None
    return (mode_tag + TIER_3_TEMPLATE.format(patterns=patterns),
            ViberClient.acknowledgment_keyboard())


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
            tracker.reset(chat_id)  # clear session history for a clean A/B comparison
            deliver(sender_id, f"Engine switched to: {current_mode['value'].upper()} "
                                f"(conversation history cleared for a clean comparison)")
        else:
            deliver(sender_id, "Usage: /mode baseline  OR  /mode enhanced "
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
    reply_text, keyboard = build_reply_for_tier(session_tier, assessment["detections"], mode_tag)

    if session_tier == 1:
        logger.info("[Tier 1 - flagged, silent] chat=%s text=%r", chat_id, text)
    elif reply_text:
        deliver(sender_id, reply_text, keyboard=keyboard)
        logger.info("[Tier %d - reply sent] chat=%s text=%r", session_tier, chat_id, text)

    return jsonify({"status": 0}), 200


@app.route("/simulate/outbox/<user_id>", methods=["GET"])
def simulate_outbox(user_id):
    """Polled by demo_chat.html to fetch queued bot replies for a user when
    running in simulation mode (no real VIBER_AUTH_TOKEN configured)."""
    messages = _sim_outbox.pop(user_id, [])
    return jsonify({"messages": messages}), 200


@app.after_request
def add_cors_headers(response):
    # Simulation mode is a local-only demo aid — CORS is opened so
    # demo_chat.html (opened directly as a file:// page) can call this
    # server running on localhost. Not used/needed in real Viber operation.
    if SIMULATION_MODE:
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/webhook", methods=["OPTIONS"])
@app.route("/simulate/outbox/<user_id>", methods=["OPTIONS"])
def cors_preflight(user_id=None):
    return jsonify({}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "simulation_mode": SIMULATION_MODE,
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


# ── Dashboard: Datasets tab ──────────────────────────────────────────────

def _sniff_columns(file_path):
    with open(file_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        row_count = sum(1 for _ in reader)
    return header, row_count


@app.route("/api/datasets/upload", methods=["POST"])
def upload_dataset():
    if "file" not in request.files:
        return jsonify({"error": "No file part named 'file' in the upload"}), 400
    uploaded = request.files["file"]
    filename = uploaded.filename
    if not filename or not filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are accepted"}), 400

    dataset_id = uuid.uuid4().hex[:12]
    stored_name = f"{dataset_id}_{filename}"
    stored_path = UPLOADED_DATASETS_DIR / stored_name
    uploaded.save(stored_path)

    try:
        columns, row_count = _sniff_columns(stored_path)
    except Exception as exc:
        stored_path.unlink(missing_ok=True)
        return jsonify({"error": f"Could not read CSV: {exc}"}), 400

    index = _load_dataset_index()
    index[dataset_id] = {
        "id": dataset_id,
        "original_filename": uploaded.filename,
        "stored_filename": stored_name,
        "columns": columns,
        "row_count": row_count,
        "uploaded_at": time.time(),
    }
    _save_dataset_index(index)
    return jsonify(index[dataset_id]), 200


@app.route("/api/datasets/list", methods=["GET"])
def list_datasets():
    index = _load_dataset_index()
    return jsonify(list(index.values())), 200


@app.route("/api/datasets/<dataset_id>", methods=["DELETE"])
def delete_dataset(dataset_id):
    index = _load_dataset_index()
    entry = index.pop(dataset_id, None)
    if entry is None:
        return jsonify({"error": "Dataset not found"}), 404
    (UPLOADED_DATASETS_DIR / entry["stored_filename"]).unlink(missing_ok=True)
    _save_dataset_index(index)
    return jsonify({"deleted": dataset_id}), 200


@app.route("/api/datasets/<dataset_id>/analyze", methods=["POST"])
def analyze_dataset(dataset_id):
    """
    Runs the same baseline-vs-enhanced comparison as compare_engines.py, but
    over HTTP for the dashboard's metrics modal. Capped to a sample by
    default (analyze is meant for fast, interactive exploration) — use the
    compare_engines.py CLI directly for the full-dataset official numbers
    reported in Chapter 4.
    """
    index = _load_dataset_index()
    entry = index.get(dataset_id)
    if entry is None:
        return jsonify({"error": "Dataset not found"}), 404

    body = request.get_json(silent=True) or {}
    text_col = body.get("text_col")
    label_col = body.get("label_col")
    positive_label = body.get("positive_label", "1")
    max_text_chars = body.get("max_text_chars", 5000)
    sample_size = body.get("sample_size", 2000)

    if not text_col or not label_col:
        return jsonify({"error": "text_col and label_col are required"}), 400
    if text_col not in entry["columns"] or label_col not in entry["columns"]:
        return jsonify({"error": "text_col/label_col not found in this dataset's columns",
                         "available_columns": entry["columns"]}), 400

    dataset_path = UPLOADED_DATASETS_DIR / entry["stored_filename"]
    full_dataset = load_csv(str(dataset_path), text_col, label_col, positive_label,
                             max_text_chars=max_text_chars)

    truncated = False
    if sample_size and len(full_dataset) > sample_size:
        import random
        rng = random.Random(42)
        dataset = rng.sample(full_dataset, sample_size)
        truncated = True
    else:
        dataset = full_dataset

    baseline_metrics = evaluate(_engines["baseline"], dataset, baseline_predict)
    enhanced_metrics = evaluate(_engines["enhanced"], dataset, enhanced_predict)
    delta = {
        key: enhanced_metrics[key] - baseline_metrics[key]
        for key in ("accuracy", "precision", "recall", "f1", "fpr")
    }

    return jsonify({
        "dataset_id": dataset_id,
        "rows_used": len(dataset),
        "rows_total": len(full_dataset),
        "sampled": truncated,
        "baseline": baseline_metrics,
        "enhanced": enhanced_metrics,
        "delta": delta,
    }), 200


# ── Dashboard: Live Simulation tab (side-by-side dual engine) ───────────
_dual_trackers = {"baseline": ConversationTracker(), "enhanced": ConversationTracker()}
_dual_sessions = {}


@app.route("/api/dual/message", methods=["POST"])
def dual_message():
    """
    Runs the SAME message through both engines simultaneously and returns
    both sides' full assessment in one response — the backend for the
    dashboard's side-by-side Live Simulation view. Unlike /webhook, this
    returns results directly (synchronous) instead of via the Viber API or
    the simulation outbox, since the dashboard renders both panels itself.
    """
    body = request.get_json(silent=True) or {}
    session_id = body.get("session_id", "default")
    text = body.get("text", "")
    if not text:
        return jsonify({"error": "text is required"}), 400

    results = {}
    for engine_name in ("baseline", "enhanced"):
        engine = _engines[engine_name]
        state = _dual_trackers[engine_name].get(session_id)
        assessment = engine.assess_message(text)
        message_tier = assessment["action_tier"]
        session_tier = state.session_tier(message_tier)
        state.record(message_tier, assessment["detections"])
        reply_text, keyboard = build_reply_for_tier(session_tier, assessment["detections"])
        results[engine_name] = {
            "detections": assessment["detections"],
            "severity": assessment.get("severity"),
            "message_tier": message_tier,
            "session_tier": session_tier,
            "reply_text": reply_text,
            "has_block_keyboard": keyboard is not None,
        }
    session = _dual_sessions.setdefault(
        session_id,
        {"session_id": session_id, "created_at": time.time(), "messages": []},
    )
    session["updated_at"] = time.time()
    session["messages"].append({"text": text, "results": results})
    return jsonify(results), 200


@app.route("/api/dual/reset/<session_id>", methods=["POST"])
def dual_reset(session_id):
    for tracker_by_engine in _dual_trackers.values():
        tracker_by_engine.reset(session_id)
    return jsonify({"reset": session_id}), 200


@app.route("/api/dual/sessions", methods=["GET"])
def dual_sessions():
    sessions = [
        {
            "session_id": session["session_id"],
            "created_at": session["created_at"],
            "updated_at": session.get("updated_at", session["created_at"]),
            "message_count": len(session["messages"]),
        }
        for session in _dual_sessions.values()
    ]
    sessions.sort(key=lambda item: item["updated_at"], reverse=True)
    return jsonify(sessions), 200


@app.route("/api/dual/sessions/<session_id>", methods=["GET"])
def dual_session_detail(session_id):
    session = _dual_sessions.get(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(session), 200


@app.route("/api/dual/report", methods=["POST"])
def dual_report():
    """
    Marks a specific message (on one engine's side) as a user-confirmed
    phishing report, distinct from a passive 'acknowledged' dismissal.
    Returns a confirmation payload for the dashboard's report modal.
    """
    body = request.get_json(silent=True) or {}
    session_id = body.get("session_id", "")
    engine_name = body.get("engine_name", "")
    message_text = body.get("text", "")

    session = _dual_sessions.get(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    matched_message = None
    for message in session["messages"]:
        if message["text"] == message_text and engine_name in message["results"]:
            message["results"][engine_name]["user_reported"] = True
            matched_message = message
            break

    if matched_message is None:
        return jsonify({"error": "Message not found in this session"}), 404

    side = matched_message["results"][engine_name]
    pattern_names = []
    for detection in side["detections"]:
        alert = detection.get("alert", "")
        if "'" in alert:
            pattern_names.append(alert.split("'")[1])
    seen = set()
    unique_patterns = [p for p in pattern_names if not (p in seen or seen.add(p))]

    return jsonify({
        "session_id": session_id,
        "engine_name": engine_name,
        "message_text": message_text,
        "severity": side.get("severity"),
        "patterns": unique_patterns,
        "reported_at": time.time(),
    }), 200


@app.route("/api/datasets/upload", methods=["OPTIONS"])
@app.route("/api/datasets/list", methods=["OPTIONS"])
@app.route("/api/datasets/<dataset_id>", methods=["OPTIONS"])
@app.route("/api/datasets/<dataset_id>/analyze", methods=["OPTIONS"])
@app.route("/api/dual/message", methods=["OPTIONS"])
@app.route("/api/dual/reset/<session_id>", methods=["OPTIONS"])
@app.route("/api/dual/sessions", methods=["OPTIONS"])
@app.route("/api/dual/sessions/<session_id>", methods=["OPTIONS"])
@app.route("/api/dual/report", methods=["OPTIONS"])
def api_cors_preflight(dataset_id=None, session_id=None):
    return jsonify({}), 200


if __name__ == "__main__":
    if SIMULATION_MODE:
        logger.info(
            "No VIBER_AUTH_TOKEN set — running in SIMULATION MODE. "
            "Open demo_chat.html in a browser to test locally."
        )
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))