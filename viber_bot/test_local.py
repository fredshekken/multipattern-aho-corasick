"""
Local smoke test — simulates Viber webhook POSTs without needing a real
Viber account or public URL. Run with: python test_local.py
"""

import json
from unittest.mock import patch

import server


def send_message(client, chat_id, sender_id, text, sender_name="Tester"):
    payload = {
        "event": "message",
        "message": {"type": "text", "text": text},
        "sender": {"id": sender_id, "name": sender_name},
        "chat_id": chat_id,
    }
    resp = client.post("/webhook", data=json.dumps(payload),
                        content_type="application/json")
    return resp


def main():
    client = server.app.test_client()

    with patch.object(server.viber, "send_text") as mock_send:
        print("--- Message 1: clean, everyday message ---")
        send_message(client, "chat1", "user1", "Team meeting moved to 3 PM tomorrow.")
        print("send_text called:", mock_send.called)
        mock_send.reset_mock()

        print("\n--- Message 2: mild single keyword, benign context (Tier 1 expected) ---")
        send_message(client, "chat1", "user1", "Nag-update na ako ng info ko kanina.")
        print("send_text called:", mock_send.called)
        mock_send.reset_mock()

        print("\n--- Message 3: clear phishing keyword cluster (Tier 2/3 expected) ---")
        send_message(client, "chat1", "user1",
                     "URGENT: Your gcash account is blocked. I-verify agad, "
                     "click here: https://gcash.verify-now.com/login")
        print("send_text called:", mock_send.called)
        if mock_send.called:
            print("Message sent to user:", mock_send.call_args[0][1][:120], "...")
        mock_send.reset_mock()

        print("\n--- Message 4: acknowledgment tap ---")
        send_message(client, "chat1", "user1", "ACK_BLOCK")
        print("send_text called (should be False):", mock_send.called)

    print("\n--- Multi-message escalation test (chat2) ---")
    with patch.object(server.viber, "send_text") as mock_send:
        msgs = [
            "Kailangan mo i-verify ang account mo, may isyu kasi.",
            "Pakiclick na lang po itong link para ma-verify.",
            "Sige po ilagay niyo na lang po yung otp niyo dito.",
        ]
        for i, m in enumerate(msgs, 1):
            send_message(client, "chat2", "user2", m)
            print(f"After msg {i}: send_text called this call =", mock_send.called)
            mock_send.reset_mock()

    print("\n--- Logs for chat1 ---")
    resp = client.get("/logs/chat1")
    for entry in resp.get_json():
        print(entry["action_tier"], entry["session_tier"], entry["message_text"][:60])


    print("\n--- Engine toggle test (chat3) ---")
    obfuscated = "URGENT: Ang iyong G-C@sh ay na-bl0cked. Paki-berify agad."
    with patch.object(server.viber, "send_text") as mock_send:
        print("Mode:", server.current_mode["value"])
        send_message(client, "chat3", "user3", obfuscated)
        print("  [enhanced] send_text called:", mock_send.called)
        mock_send.reset_mock()

        send_message(client, "chat3", "user3", "/mode baseline")
        mock_send.reset_mock()  # clear the "Engine switched to..." confirmation call
        send_message(client, "chat3", "user3", obfuscated)
        print("Mode:", server.current_mode["value"])
        print("  [baseline] send_text called (expected False — baseline can't see obfuscation):",
              mock_send.called)
        mock_send.reset_mock()
        send_message(client, "chat3", "user3", "/mode enhanced")  # reset for other tests


if __name__ == "__main__":
    main()
