"""
Run once after your server is publicly reachable over HTTPS (e.g. via ngrok
during development, or a real deployment for the actual defense demo).

Usage:
    export VIBER_AUTH_TOKEN=xxxxxxxxxxxxxxxx
    python register_webhook.py https://your-public-url.ngrok.io/webhook
"""

import os
import sys

from viber_client import ViberClient


def main():
    if len(sys.argv) != 2:
        print("Usage: python register_webhook.py <public-https-url>/webhook")
        sys.exit(1)

    url = sys.argv[1]
    token = os.environ.get("VIBER_AUTH_TOKEN", "")
    if not token:
        print("ERROR: set VIBER_AUTH_TOKEN environment variable first.")
        sys.exit(1)

    client = ViberClient(auth_token=token)
    result = client.set_webhook(url)
    print("Viber response:", result)

    if result.get("status") == 0:
        print(f"\nWebhook registered successfully: {url}")
    else:
        print("\nSomething went wrong — check status_message above.")


if __name__ == "__main__":
    main()
