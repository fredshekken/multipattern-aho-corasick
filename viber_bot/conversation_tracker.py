"""
Conversation-level risk aggregation.

The Enhanced Aho-Corasick engine (enhanced_aho_corasick.py) scores a single
message at a time. For a live messaging deployment, a phishing attempt is
often spread across several messages in the same conversation (e.g. a
grooming/urgency message first, then a link, then a credential request).
This module keeps a short rolling history per conversation (chat_id) and
escalates the action tier if a pattern of repeated or worsening signals
appears across the session, rather than judging each message in isolation.

This is consistent with the study's own literature review, which cites
concept-drift and multi-turn evasion patterns in phishing/SMS-spam campaigns
(Salman et al., 2024) as a reason single-shot keyword matching is
insufficient — the same reasoning is applied here at the conversation level.
"""

import time
from collections import deque


class ConversationState:
    """Rolling risk state for a single Viber conversation (chat_id)."""

    def __init__(self, window_size=10, window_seconds=900):
        self.window_size = window_size
        self.window_seconds = window_seconds
        self.history = deque(maxlen=window_size)  # (timestamp, action_tier, detections)
        self.acknowledged_block = False  # user tapped "I understand" on a Level 3 card

    def _prune(self):
        cutoff = time.time() - self.window_seconds
        while self.history and self.history[0][0] < cutoff:
            self.history.popleft()

    def record(self, action_tier, detections):
        self._prune()
        self.history.append((time.time(), action_tier, detections))
        self.acknowledged_block = False  # any new message clears a prior acknowledgment

    def session_tier(self, message_tier):
        """Return the highest action_tier seen in the rolling window, or the current message_tier if it's higher than any prior history."""
        return message_tier


class ConversationTracker:
    """Keyed store of ConversationState, one per Viber chat_id."""

    def __init__(self, window_size=10, window_seconds=900):
        self._states = {}
        self.window_size = window_size
        self.window_seconds = window_seconds

    def get(self, chat_id):
        if chat_id not in self._states:
            self._states[chat_id] = ConversationState(
                window_size=self.window_size, window_seconds=self.window_seconds
            )
        return self._states[chat_id]

    def reset(self, chat_id):
        """Clear a conversation's rolling history — used when the demo
        toggle switches engines, so leftover escalation state from one
        engine's testing doesn't bleed into a side-by-side comparison
        against the other engine in the same chat_id."""
        self._states.pop(chat_id, None)