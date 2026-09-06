"""
Persistent detection log (SQLite).

Level 1 detections must be recorded ("noted sa system") without interrupting
the user, so they need somewhere durable to live even though no message is
sent back into the chat. This also gives Level 2/3 events an audit trail for
the thesis defense demo (e.g. "show the log for this conversation").
"""

import json
import sqlite3
import time
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).parent / "detections.db"


class DetectionLog:
    def __init__(self, db_path=DEFAULT_DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    chat_id TEXT NOT NULL,
                    sender_name TEXT,
                    message_text TEXT,
                    action_tier INTEGER NOT NULL,
                    session_tier INTEGER NOT NULL,
                    detections_json TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_id ON detections(chat_id)"
            )

    def record(self, chat_id, sender_name, message_text, action_tier,
               session_tier, detections):
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO detections
                   (ts, chat_id, sender_name, message_text, action_tier,
                    session_tier, detections_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    time.time(), chat_id, sender_name, message_text,
                    action_tier, session_tier, json.dumps(detections),
                ),
            )

    def recent_for_chat(self, chat_id, limit=50):
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT ts, sender_name, message_text, action_tier,
                          session_tier, detections_json
                   FROM detections WHERE chat_id = ?
                   ORDER BY ts DESC LIMIT ?""",
                (chat_id, limit),
            )
            rows = cur.fetchall()
        return [
            {
                "ts": r[0], "sender_name": r[1], "message_text": r[2],
                "action_tier": r[3], "session_tier": r[4],
                "detections": json.loads(r[5]) if r[5] else [],
            }
            for r in rows
        ]

    def all_flagged(self, min_tier=1, limit=200):
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT ts, chat_id, sender_name, message_text, action_tier,
                          session_tier
                   FROM detections WHERE action_tier >= ?
                   ORDER BY ts DESC LIMIT ?""",
                (min_tier, limit),
            )
            rows = cur.fetchall()
        return [
            {
                "ts": r[0], "chat_id": r[1], "sender_name": r[2],
                "message_text": r[3], "action_tier": r[4], "session_tier": r[5],
            }
            for r in rows
        ]
