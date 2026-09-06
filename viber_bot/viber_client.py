"""
Minimal client for the official Viber REST Bot API.

Docs: https://developers.viber.com/docs/api/rest-bot-api/

Deliberately avoids third-party SDKs so the exact request shape is visible
and easy to defend/explain during the oral defense. Only the endpoints this
project needs are implemented: set_webhook and send_message.
"""

import requests

VIBER_API_BASE = "https://chatapi.viber.com/pa"


class ViberClient:
    def __init__(self, auth_token, sender_name="Phishing Guard", sender_avatar=None):
        self.auth_token = auth_token
        self.sender_name = sender_name
        self.sender_avatar = sender_avatar

    def _headers(self):
        return {
            "X-Viber-Auth-Token": self.auth_token,
            "Content-Type": "application/json",
        }

    def set_webhook(self, url, event_types=None):
        """
        Registers the public HTTPS URL Viber will POST events to.
        event_types defaults to the ones this bot actually needs.
        """
        payload = {
            "url": url,
            "event_types": event_types or [
                "message", "subscribed", "unsubscribed",
                "conversation_started",
            ],
            "send_name": True,
            "send_photo": False,
        }
        resp = requests.post(
            f"{VIBER_API_BASE}/set_webhook", json=payload,
            headers=self._headers(), timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def send_text(self, receiver, text, keyboard=None):
        payload = {
            "receiver": receiver,
            "type": "text",
            "text": text,
            "sender": {"name": self.sender_name},
        }
        if self.sender_avatar:
            payload["sender"]["avatar"] = self.sender_avatar
        if keyboard:
            payload["keyboard"] = keyboard

        resp = requests.post(
            f"{VIBER_API_BASE}/send_message", json=payload,
            headers=self._headers(), timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def acknowledgment_keyboard(button_text="I understand, continue"):
        """
        Level 3 'block' card keyboard. Viber cannot natively freeze the
        underlying chat UI (no bot/extension can), so the block is simulated
        as a persistent, high-visibility card that requires the user to tap
        an explicit acknowledgment button. The bot tracks that tap
        server-side (see conversation_tracker.acknowledge) before treating
        the conversation as unblocked.
        """
        return {
            "Type": "keyboard",
            "DefaultHeight": True,
            "Buttons": [
                {
                    "Columns": 6,
                    "Rows": 1,
                    "ActionType": "reply",
                    "ActionBody": "ACK_BLOCK",
                    "Text": f"<font color='#ffffff'>{button_text}</font>",
                    "BgColor": "#CC1111",
                }
            ],
        }
