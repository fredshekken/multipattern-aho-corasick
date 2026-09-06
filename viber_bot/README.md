# Enhanced Aho-Corasick Phishing Guard — Viber Integration

Real-time phishing detection deployed as a Viber bot, using the Enhanced
Aho-Corasick engine developed for the thesis "An Enhancement of Aho-Corasick
Algorithm Applied in Phishing Detection in Tagalog-English Encrypted
Messaging" (Magaan & Sanchez, PLM, 2026).

## What this actually is (read this first)

Viber has no scriptable web client (unlike WhatsApp Web/Telegram Web), so a
browser extension cannot passively read an existing Viber conversation. The
only officially supported way to have code observe and respond to Viber
messages is the **Bot API**: a Viber account that a user adds and messages
directly, or that is added to a group. This bot receives every message sent
to it (1:1, or in a group it belongs to), scans it, and responds according
to its risk tier. It cannot see a user's *other* private chats with other
contacts, and it cannot force-block the native Viber UI the way a browser
extension can block a webpage — no bot on any platform can do that. Tier 3
"blocking" is simulated as a high-visibility, un-ignorable warning card that
requires an explicit tap to acknowledge.

## Architecture

```
Viber app (user) <---> Viber servers <---> /webhook (this Flask server)
                                                  |
                                          enhanced_aho_corasick.py
                                          (Objectives 1-4 engine)
                                                  |
                                          conversation_tracker.py
                                          (multi-message escalation)
                                                  |
                                    tier 1: detection_log.py (silent)
                                    tier 2: viber_client.send_text (warning)
                                    tier 3: viber_client.send_text + keyboard (block card)
```

## Risk tiers (basis)

The engine's `final_risk` score (already defined in Chapter 3, Step 4 of the
algorithm) is bucketed into four qualitative severity bands, adapted from
the CVSS-style None/Low/Medium/High/Critical convention (FIRST.org, CVSS
v3.1) and rescaled to this study's score range instead of CVSS's 0-10 scale.
These four bands are the same "Warning Notification Levels" already shown
as the system's output in Figure 3.1. They are mapped onto the three
user-facing intervention tiers used here:

| final_risk    | Severity (thesis Fig. 3.1) | Action tier | Behavior                     |
|---------------|-----------------------------|-------------|-------------------------------|
| < 1.5         | Low                         | **1**       | Logged only, no interruption |
| 1.5 – 2.49    | Moderate                    | **2**       | Warning message sent         |
| 2.5 – 3.99    | High                        | **3**       | Block card + acknowledgment  |
| ≥ 4.0         | Critical                    | **3**       | Block card + acknowledgment  |

On top of per-message scoring, `conversation_tracker.py` reviews the whole
session: if two or more messages within a rolling window each reach Tier 2+,
the conversation escalates to Tier 3 even if no single message alone was
that severe — this reflects multi-turn social-engineering patterns
(build urgency → send link → request credentials) documented in the
related-studies review (Salman et al., 2024, on evolving evasive SMS/phishing
techniques).

## What's "validated per Chapter 3" vs "deployment addition"

Be precise about this distinction if a panelist probes it:

**Validated per Chapter 3 (your tested thesis contribution):**
- `enhanced_aho_corasick.py` — normalization, Bitap fuzzy matching, IDW
  proximity weighting, phonetic/affix stripping, URL segmentation. One bug
  fix was made here: prefix/suffix stripping order was corrected to true
  longest-first (see code comments) — no formulas, thresholds, or weights
  were changed.
- `ahocorasick.py` — your own unmodified `AhoCorasickDFA` from
  `original_aho/` (the same class behind Figures 1.1-1.8 and Tables
  1.1-1.3 in Chapter 1). Copied here verbatim, zero edits.
- `baseline_aho_corasick.py` — a thin adapter subclassing `AhoCorasickDFA`
  to add `from_pattern_file()` and `assess_message()` for interface parity
  with the enhanced engine. Adds no detection logic — see its docstring.

**Deployment addition (built for the Viber demo, not independently
validated against the datasets, and should be framed as an application
layer rather than a tested objective):**
- `conversation_tracker.py` — multi-message session escalation.
- The 4-band risk thresholds in `classify_risk_level()` (low/moderate/high/
  critical cut points) — a reasoned adaptation of the CVSS-style severity
  convention, not empirically derived from your datasets.
- `server.py`, `viber_client.py`, `detection_log.py` — the bot plumbing
  itself.

## Baseline vs Enhanced comparison (Chapter 4: Performance Output)

`compare_engines.py` runs both algorithms over the same labeled dataset and
reports accuracy, precision, recall, F1-score, false positive rate, and
timing for each — the exact metrics specified in Section 3.1.

```bash
python compare_engines.py --csv your_dataset.csv \
    --text-col message --label-col label --positive-label phishing
```

Run it with no `--csv` first to sanity-check against a tiny built-in sample
before pointing it at your real Kaggle CSVs.

## Live baseline/enhanced toggle (Chapter 4: System Output)

The bot itself can run either engine, switchable live in-chat without a
restart — useful for demonstrating the difference to the panel on the same
message in real time:

```
/mode baseline     -> switches this bot instance to the unmodified algorithm
/mode enhanced      -> switches back (this is also the startup default)
```

Verified locally (`test_local.py`): the same obfuscated message
("G-C@sh", "na-bl0cked", "berify") is caught under `enhanced` and missed
entirely under `baseline` — reproducing the exact blind spot documented in
the thesis's own Figure 1.1.

## Fallback: local simulation mode (no real Viber account needed)

Real Viber bot creation now requires a paid commercial application (since
Feb 2024, €100/month + approval process) — outside this project's timeline
and control. Until a real account exists (Viber, or another platform
substituted after adviser approval), the server **auto-detects** this and
runs in simulation mode:

```bash
cd viber_bot
python server.py          # no VIBER_AUTH_TOKEN set -> simulation mode
```
Then open `demo_chat.html` directly in a browser (just double-click it —
no web server needed for the HTML itself). It's a small Viber-styled chat
UI that POSTs real webhook-shaped JSON to `http://localhost:5000/webhook`
and polls `/simulate/outbox/<user_id>` for replies — the exact same
`server.py`, detection engine, tiering, and escalation logic runs either
way. Only the message-delivery transport differs (in-memory queue instead
of the real Viber REST call).

Use the "Use Enhanced" / "Use Baseline" buttons in the demo page to
reproduce the side-by-side comparison live in front of the panel. Once a
real bot account exists on whichever platform is approved, set
`VIBER_AUTH_TOKEN` (or the equivalent) and simulation mode turns off
automatically — no other code changes needed.

## Setup (once a real bot account is approved)

### 1. Create a Viber bot account
Go to https://partners.viber.com, create a bot account, and copy its
**authentication token**.

### 2. Install dependencies
```bash
cd viber_bot
pip install -r requirements.txt
```

### 3. Run the server
```bash
export VIBER_AUTH_TOKEN="your-token-here"
python server.py
```
Runs on `http://0.0.0.0:5000` by default (`PORT` env var to change it).

### 4. Expose it publicly (development)
Viber requires an HTTPS webhook URL. During development:
```bash
ngrok http 5000
```
Copy the `https://...ngrok.io` URL it gives you.

### 5. Register the webhook
```bash
export VIBER_AUTH_TOKEN="your-token-here"
python register_webhook.py https://your-ngrok-url.ngrok.io/webhook
```

### 6. Test it
Add your bot in the Viber app (search by its public account name, or use
its deep link), or add it to a group. Send it a test phishing-style message
and watch the server logs / your Viber chat for the response.

## Files

- `server.py` — Flask webhook, ties everything together.
- `enhanced_aho_corasick.py` — the detection engine (Objectives 1-4 + risk
  tier classification).
- `conversation_tracker.py` — session-level escalation logic.
- `detection_log.py` — SQLite log of every detection (`viber_bot/detections.db`),
  queryable via `GET /logs/<chat_id>` and `GET /logs?min_tier=1`.
- `viber_client.py` — thin wrapper over the official Viber REST Bot API.
- `register_webhook.py` — one-time webhook registration script.
- `default_patterns.txt` — categorized phishing keyword dictionary.
- `test_local.py` — local smoke test, no real Viber account needed
  (mocks the outgoing Viber calls, runs the full detection + tiering logic).

## Known limitations for the defense

- **No live Viber test has been run from this environment** — the sandbox
  this was built in cannot reach `chatapi.viber.com`. The logic has been
  verified end-to-end with mocked Viber calls (`test_local.py`), but you
  must run steps 1-6 above yourself (or with me in a follow-up session) to
  confirm it against the real Viber API before the defense.
- The bot only sees messages sent directly to it (1:1 or in a group it's
  in) — it does not monitor a user's other existing private conversations.
  This should be stated plainly if asked, since it's a real constraint of
  the platform, not a shortcut taken here.
- The "block" action is a persistent warning card requiring acknowledgment,
  not a true UI lock — be ready to explain this distinction if a panelist
  asks whether the chat is "really" blocked.