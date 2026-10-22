console.log("[PhishShield] Endpoint listener active...");

// ---------------------------------------------------------------------------
// DISPLAY POLICY (edit this block to change what users see)
//   "none"      : nothing shown in the chat (message is only logged in the console)
//   "marker"    : tiny gray marker, details on hover
//   "collapsed" : one short amber line, click to see why
//   "banner"    : full banner (amber for advisory, red for active warning)
// ---------------------------------------------------------------------------
const TIER_DISPLAY = {
  1: "none",       // Low: recorded only, never shown
  2: "collapsed",  // Moderate: quiet "review this message" line
  3: "banner"      // High / Critical: full red warning
};

// A Tier 2 message is only shown if at least this many different kinds of
// evidence were found. Below that, it stays silent (still logged in the console).
// Set to 1 to show every Tier 2 message.
const TIER2_MIN_EVIDENCE = 2;

const BACKEND_URL = "http://127.0.0.1:8000/scan";
const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
const UI_CLASS = "phish-shield-ui";

// Plain-language reasons for each evidence group
const REASONS = {
  brand_entity: "mentions a known brand or bank",
  credential_payment: "involves account, password, or payment details",
  action_request: "asks you to take an action",
  urgency_threat: "uses urgent or threatening wording",
  url_risk: "contains a risky link",
  obfuscation: "uses disguised or misspelled words"
};

// Matches sandbox and exact Telegram Web A structure
const SELECTOR = [
  ".chat-text",
  ".message-content",
  ".message-content-wrapper .text",
  "div.text[dir='auto']"
].join(", ");

async function inspectBubble(node) {
  if (!node || node.dataset.phishScanned) return;

  // Selectors can match nested elements of the same message.
  // Skip if an ancestor or descendant was already scanned, to avoid duplicates.
  if (node.closest("[data-phish-scanned]") || node.querySelector("[data-phish-scanned]")) return;

  // Remove the timestamp span from a clone before scanning
  const textElement = node.querySelector(".text, [dir='auto']") || node;
  const clone = textElement.cloneNode(true);

  const timeElement = clone.querySelector(".time, .message-time");
  if (timeElement) {
    timeElement.remove();
  }

  const text = clone.innerText?.trim();
  // Filter out empty bubbles or single-word meta status timestamps
  if (!text || text.length < 4) return;

  // Mark immediately as scanned to prevent redundant fetches and observer loops
  node.dataset.phishScanned = "true";

  try {
    const res = await fetch(BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text })
    });

    if (!res.ok) {
      console.warn(`[PhishShield] HTTP ${res.status}: Backend returned an error.`);
      return;
    }

    const data = await res.json();
    renderResult(node, data);
  } catch (err) {
    console.error("[PhishShield] Backend scan error:", err);
  }
}

function evidenceCount(data) {
  // If an older backend does not send evidence groups, do not hide anything.
  return Array.isArray(data.evidence_groups) ? data.evidence_groups.length : Infinity;
}

function reasonText(data) {
  const groups = Array.isArray(data.evidence_groups) ? data.evidence_groups : [];
  const reasons = groups.map((g) => REASONS[g]).filter(Boolean);
  if (reasons.length === 0) return "contains wording often used in phishing";
  return reasons.join(", ");
}

function detailText(data) {
  const tokenList = (data.tokens && data.tokens.length > 0) ? data.tokens.join(", ") : "Pattern detected";
  const riskValue = data.risk_score !== undefined ? Number(data.risk_score).toFixed(3) : "N/A";
  return { tokenList, riskValue };
}

function renderResult(node, data) {
  if (!data || data.tier < 1) return;

  let mode = TIER_DISPLAY[data.tier] || "none";
  if (data.tier === 2 && evidenceCount(data) < TIER2_MIN_EVIDENCE) {
    mode = "none";
  }

  if (mode === "none") {
    const { tokenList, riskValue } = detailText(data);
    console.debug(
      `[PhishShield] Tier ${data.tier} recorded, not shown: ${tokenList} ` +
      `[Risk: ${riskValue}] [Evidence: ${(data.evidence_groups || []).join(", ") || "n/a"}]`
    );
    return;
  }

  // One UI element per message
  if (node.previousElementSibling?.classList.contains(UI_CLASS) ||
      node.querySelector(`.${UI_CLASS}`)) {
    return;
  }

  if (mode === "marker") injectMarker(node, data);
  else if (mode === "collapsed") injectCollapsed(node, data);
  else if (mode === "banner") injectBanner(node, data);
}

// Tiny gray marker, details on hover
function injectMarker(node, data) {
  const { tokenList, riskValue } = detailText(data);
  const dot = document.createElement("span");
  dot.className = UI_CLASS;
  dot.textContent = "ⓘ";
  dot.title = `PhishShield: ${reasonText(data)} (${tokenList}) [Risk: ${riskValue}]`;
  dot.style.cssText = `
    display: inline-block;
    margin-left: 6px;
    font-size: 11px;
    font-family: ${FONT};
    color: #9ca3af;
    cursor: help;
    user-select: none;
  `;
  node.appendChild(dot);
}

// One short line, click to expand the reason
function injectCollapsed(node, data) {
  const { tokenList, riskValue } = detailText(data);

  const wrap = document.createElement("div");
  wrap.className = UI_CLASS;
  wrap.style.cssText = `
    box-sizing: border-box;
    width: 100%;
    margin-bottom: 4px;
    font-family: ${FONT};
    font-size: 11px;
    line-height: 1.4;
  `;

  const header = document.createElement("div");
  header.textContent = "⚠️ Review this message ▾";
  header.style.cssText = `
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    cursor: pointer;
    user-select: none;
    font-weight: 600;
    background-color: #fef3c7;
    color: #92400e;
  `;

  const details = document.createElement("div");
  details.textContent = `This message ${reasonText(data)}.`;
  details.title = `Matched: ${tokenList} [Risk: ${riskValue}]`;
  details.style.cssText = `
    display: none;
    margin-top: 3px;
    padding: 4px 8px;
    border-radius: 4px;
    word-break: break-word;
    background-color: #fffbeb;
    color: #92400e;
  `;

  header.addEventListener("click", () => {
    const open = details.style.display === "block";
    details.style.display = open ? "none" : "block";
    header.textContent = open ? "⚠️ Review this message ▾" : "⚠️ Review this message ▴";
  });

  wrap.appendChild(header);
  wrap.appendChild(details);
  node.parentNode.insertBefore(wrap, node);
}

// Full banner. Red for Tier 3, amber for anything lower that is set to "banner".
function injectBanner(node, data) {
  const { tokenList, riskValue } = detailText(data);
  const isActive = data.tier >= 3;
  const isCritical = data.severity === "critical";
  const why = reasonText(data);

  let label;
  if (!isActive) {
    label = `⚠️ Possible phishing: this message ${why}.`;
  } else if (isCritical) {
    label = `🚨 Phishing detected: do not click or reply. This message ${why}.`;
  } else {
    label = `🚨 Likely phishing: verify the sender first. This message ${why}.`;
  }

  const banner = document.createElement("div");
  banner.className = UI_CLASS;
  banner.title = `Matched: ${tokenList} [Risk: ${riskValue}]`;
  banner.style.cssText = `
    display: block;
    box-sizing: border-box;
    width: 100%;
    margin-bottom: 6px;
    padding: 6px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-family: ${FONT};
    font-weight: 600;
    line-height: 1.4;
    z-index: 10;
    word-break: break-word;
    position: relative;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12);
    background-color: ${isActive ? "#fee2e2" : "#fef3c7"};
    color: ${isActive ? "#991b1b" : "#92400e"};
    border-left: 4px solid ${isActive ? "#dc2626" : "#d97706"};
  `;
  banner.textContent = label;

  node.parentNode.insertBefore(banner, node);
}

// Initial sweep for existing chat bubbles on page load
document.querySelectorAll(SELECTOR).forEach(inspectBubble);

// Dynamic MutationObserver for incoming live messages
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        // Direct match
        if (node.matches && node.matches(SELECTOR)) {
          inspectBubble(node);
        }
        // Descendant match (handles nested wrapper divs injected by SPA frameworks)
        if (node.querySelectorAll) {
          node.querySelectorAll(SELECTOR).forEach(inspectBubble);
        }
      }
    });
  });
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});