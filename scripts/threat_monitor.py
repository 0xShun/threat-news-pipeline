#!/usr/bin/env python3
import os
import json
import hashlib
import logging
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

DEFAULT_KEYWORDS = [
    "fortinet",
    "fortigate",
    "fortios",
    "forticlient",
    "fortiweb",
    "fortimanager",
    "fortianalyzer",
]

THREAT_FEEDS = [
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/news.xml", "type": "rss"},
    {"name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "cisa_kev"},
    {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "rss"},
    {"name": "Security Week", "url": "https://www.securityweek.com/feed/", "type": "rss"},
    {"name": "Rapid7 Blog", "url": "https://blog.rapid7.com/rss/", "type": "rss"},
    {"name": "Fortinet PSIRT", "url": "https://www.fortiguard.com/rss/ir.xml", "type": "rss"},
    {"name": "NVD CVE 2.0 (Fortinet)", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "type": "nvd_v2"},
]

LOOKBACK_HOURS = 13
CACHE_FILE = Path("seen_articles_cache.json")
LOG_FILE = Path("threat_intel_log.json")

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def load_cache() -> set:
    if CACHE_FILE.exists():
        try:
            return set(json.loads(CACHE_FILE.read_text()))
        except Exception:
            return set()
    return set()


def save_cache(seen: set):
    CACHE_FILE.write_text(json.dumps(list(seen), indent=2))


def article_id(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def clean_html(raw: str) -> str:
    if not raw:
        return ""
    if "<" not in raw:
        return re.sub(r'\s+', ' ', raw.strip())[:500]
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text(separator=" ").strip()
    return re.sub(r'\s+', ' ', text)[:500]


def is_recent(pub_date, lookback_hours: int = LOOKBACK_HOURS) -> bool:
    if not pub_date:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    if isinstance(pub_date, str):
        for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                pub_date = datetime.strptime(pub_date, fmt)
                break
            except ValueError:
                continue
        else:
            return True
    if pub_date.tzinfo is None:
        pub_date = pub_date.replace(tzinfo=timezone.utc)
    return pub_date >= cutoff


def matches_keywords(text: str, keywords: list[str]) -> list[str]:
    text_lower = text.lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


# ─────────────────────────────────────────────
# Feed Parsers
# ─────────────────────────────────────────────

def fetch_rss_articles(feed: dict) -> list[dict]:
    articles = []
    try:
        parsed = feedparser.parse(feed["url"])
        for entry in parsed.entries:
            pub = entry.get("published") or entry.get("updated") or ""
            try:
                pub_struct = entry.get("published_parsed") or entry.get("updated_parsed")
                pub_dt = datetime(*pub_struct[:6], tzinfo=timezone.utc) if pub_struct else None
            except Exception:
                pub_dt = None
            articles.append({
                "source": feed["name"],
                "title": entry.get("title", "No title"),
                "url": entry.get("link", ""),
                "summary": clean_html(entry.get("summary", "")),
                "published": pub,
                "pub_dt": pub_dt,
            })
    except Exception as e:
        log.warning(f"Failed to fetch RSS {feed['name']}: {e}")
    return articles


def fetch_cisa_kev(feed: dict) -> list[dict]:
    articles = []
    try:
        resp = requests.get(feed["url"], timeout=15)
        resp.raise_for_status()
        data = resp.json()
        for vuln in data.get("vulnerabilities", []):
            date_added = vuln.get("dateAdded", "")
            pub_dt = None
            if date_added:
                try:
                    pub_dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass
            articles.append({
                "source": "CISA KEV",
                "title": f"[CISA KEV] {vuln.get('cveID', '')} — {vuln.get('vulnerabilityName', '')}",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "summary": (
                    f"Vendor: {vuln.get('vendorProject', '')} | "
                    f"Product: {vuln.get('product', '')} | "
                    f"Action: {vuln.get('requiredAction', '')} | "
                    f"Due: {vuln.get('dueDate', '')}"
                ),
                "published": date_added,
                "pub_dt": pub_dt,
            })
    except Exception as e:
        log.warning(f"Failed to fetch CISA KEV: {e}")
    return articles


def fetch_nvd_v2(feed: dict, keywords: list[str]) -> list[dict]:
    articles = []
    api_key = os.environ.get("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    params = {
        "keywordSearch": "fortinet",
        "pubStartDate": cutoff.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
        "startIndex": 0,
    }
    try:
        resp = requests.get(feed["url"], params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            pub_str = cve.get("published", "")
            pub_dt = None
            if pub_str:
                try:
                    pub_dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                except ValueError:
                    pass
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")
            metrics = cve.get("metrics", {})
            cvss_str = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    score = entries[0].get("cvssData", {}).get("baseScore", "")
                    severity = entries[0].get("cvssData", {}).get("baseSeverity", "")
                    if score:
                        cvss_str = f"CVSS {score} ({severity})"
                    break
            summary = desc[:400]
            if cvss_str:
                summary = f"{cvss_str} — {summary}"
            articles.append({
                "source": "NVD",
                "title": f"{cve_id} — {desc[:80]}{'…' if len(desc) > 80 else ''}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": summary,
                "published": pub_str,
                "pub_dt": pub_dt,
            })
    except Exception as e:
        log.warning(f"Failed to fetch NVD v2: {e}")
    return articles


def fetch_all_articles(feeds: list[dict], keywords: list[str] = None) -> list[dict]:
    all_articles = []
    for feed in feeds:
        if feed["type"] == "rss":
            articles = fetch_rss_articles(feed)
        elif feed["type"] == "cisa_kev":
            articles = fetch_cisa_kev(feed)
        elif feed["type"] == "nvd_v2":
            articles = fetch_nvd_v2(feed, keywords or [])
        else:
            log.info(f"Skipping unsupported feed type: {feed['type']}")
            continue
        log.info(f"  [{feed['name']}] fetched {len(articles)} items")
        all_articles.extend(articles)
    return all_articles


# ─────────────────────────────────────────────
# Gemini Summarization
# ─────────────────────────────────────────────

def summarize_with_gemini(alerts: list[dict], keywords: list[str]) -> str:
    """
    Sends matched alerts to Google Gemini API and returns a synthesized
    threat intelligence summary.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        log.warning("GEMINI_API_KEY not set — skipping AI summary.")
        return ""

    alerts_text = ""
    for i, alert in enumerate(alerts, 1):
        alerts_text += (
            f"\nAlert {i}:\n"
            f"  Source: {alert['source']}\n"
            f"  Title: {alert['title']}\n"
            f"  Published: {alert.get('published', 'Unknown')}\n"
            f"  Matched Keywords: {', '.join(alert['matched_keywords'])}\n"
            f"  Summary: {alert.get('summary', 'No summary available')}\n"
            f"  URL: {alert['url']}\n"
        )

    prompt = (
        f"You are a cybersecurity analyst. You have been given {len(alerts)} threat intelligence "
        f"alert(s) related to the following keywords: {', '.join(keywords)}.\n\n"
        f"Analyze the alerts below and write a concise threat intelligence briefing.\n\n"
        f"Your briefing must:\n"
        f"- Start with a 2-3 sentence executive summary of the overall threat landscape\n"
        f"- Group and prioritize alerts by severity (Critical → High → Medium → Info)\n"
        f"- For each alert, mention the key risk and any recommended action in 1-2 sentences\n"
        f"- Use plain language — avoid unnecessary jargon\n"
        f"- Be direct and actionable\n\n"
        f"Do NOT include the article URLs in your summary (they will be listed separately).\n"
        f"Do NOT use markdown headers with #. Use plain text with emoji for visual structure.\n\n"
        f"Alerts to analyze:\n{alerts_text}"
    )

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
    }

    try:
        resp = requests.post(url, params={"key": api_key}, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        summary = data["candidates"][0]["content"]["parts"][0]["text"]
        log.info("Gemini summary generated successfully.")
        return summary.strip()
    except Exception as e:
        log.warning(f"Gemini API call failed: {e}")
        return ""


# ─────────────────────────────────────────────
# Slack Notification
# ─────────────────────────────────────────────

def send_slack_notification(
    webhook_url: str,
    alerts: list[dict],
    keywords: list[str],
    ai_summary: str,
    dry_run: bool = False,
):
    """
    Posts a threat intelligence briefing to Slack.
    Includes an AI-generated summary followed by a list of article links.
    If no alerts, sends a brief 'nothing new' message.
    """
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    hour = datetime.now(timezone.utc).hour
    session_label = "Morning Brief" if hour < 12 else "Afternoon Brief"

    # ── No alerts case ────────────────────────
    if not alerts:
        payload = {
            "blocks": [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"🛡️ *Threat Intelligence — {session_label}*\n"
                        f"_{timestamp}_\n\n"
                        f"✅ No new alerts for `{'`, `'.join(keywords)}` "
                        f"in the last {LOOKBACK_HOURS} hours. All clear."
                    ),
                },
            }]
        }
        if dry_run:
            log.info("DRY RUN — Slack payload (no alerts):")
            print(json.dumps(payload, indent=2))
            return
        resp = requests.post(webhook_url, json=payload, timeout=15)
        resp.raise_for_status()
        log.info("Slack 'nothing new' message sent.")
        return

    # ── Header ────────────────────────────────
    count = len(alerts)
    noun  = "alert" if count == 1 else "alerts"

    blocks = [
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"🛡️ *Threat Intelligence — {session_label}*\n"
                    f"_{timestamp}  ·  {count} new {noun} found_"
                ),
            },
        },
        {"type": "divider"},
    ]

    # ── AI Summary ────────────────────────────
    if ai_summary:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*🤖 AI Threat Summary*\n\n{ai_summary}"},
        })
        blocks.append({"type": "divider"})

    # ── Article links ─────────────────────────
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*📰 Source Articles*"},
    })

    alerts_sorted = sorted(
        alerts,
        key=lambda a: a.get("pub_dt") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    for alert in alerts_sorted:
        combined = (alert["source"] + " " + alert["title"]).lower()
        if any(k in combined for k in ("cisa kev", "exploit", "0-day", "zero-day", "rce", "critical")):
            emoji = "🔴"
        elif any(k in combined for k in ("high", "patch", "advisory")):
            emoji = "🟡"
        else:
            emoji = "🔵"

        kw_str  = ", ".join(f"`{k}`" for k in alert["matched_keywords"])
        pub_str = alert.get("published", "")[:16] or "Unknown date"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *<{alert['url']}|{alert['title']}>*\n"
                    f"_{alert['source']}  ·  {pub_str}_\n"
                    f"Keywords: {kw_str}"
                ),
            },
        })

    blocks.append({"type": "divider"})
    payload = {"blocks": blocks}

    if dry_run:
        log.info("DRY RUN — Slack payload:")
        print(json.dumps(payload, indent=2))
        return

    resp = requests.post(webhook_url, json=payload, timeout=15)
    resp.raise_for_status()
    log.info(f"Slack notification sent successfully (HTTP {resp.status_code}).")


# ─────────────────────────────────────────────
# Teams Notification (kept for future use)
# ─────────────────────────────────────────────

_SEVERITY_COLOURS = {
    "cisa kev": "Attention", "exploit": "Attention", "0-day": "Attention",
    "zero-day": "Attention", "rce": "Attention", "critical": "Attention",
    "high": "Warning", "patch": "Warning", "advisory": "Warning",
    "default": "Good",
}


def _alert_colour(alert: dict) -> str:
    combined = (alert["source"] + " " + alert["title"]).lower()
    for key, colour in _SEVERITY_COLOURS.items():
        if key in combined:
            return colour
    return _SEVERITY_COLOURS["default"]


def _format_published(pub_str: str) -> str:
    if not pub_str:
        return "Unknown date"
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(pub_str[:25].strip(), fmt)
            return dt.strftime("%d %b %Y, %H:%M UTC")
        except ValueError:
            continue
    return pub_str[:20]


def send_teams_alert(webhook_url: str, alerts: list[dict], keywords: list[str], dry_run: bool = False):
    alerts_sorted = sorted(
        alerts,
        key=lambda a: a.get("pub_dt") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    hour = datetime.now(timezone.utc).hour
    session_label = "Morning Brief" if hour < 12 else "Afternoon Brief"
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    count = len(alerts_sorted)
    noun  = "alert" if count == 1 else "alerts"

    header = {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard", "version": "1.5",
            "body": [{"type": "ColumnSet", "columns": [
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": "🛡️", "size": "ExtraLarge"}]},
                {"type": "Column", "width": "stretch", "items": [
                    {"type": "TextBlock", "text": f"Threat Intelligence — {session_label}", "weight": "Bolder", "size": "Large"},
                    {"type": "TextBlock", "text": f"{count} new {noun} found  ·  {timestamp}", "size": "Small", "isSubtle": True, "spacing": "None"},
                ]},
            ]}],
        }}],
    }

    payloads = [header]
    for alert in alerts_sorted:
        colour = _alert_colour(alert)
        container_style = {"Attention": "attention", "Warning": "warning", "Good": "good"}.get(colour, "default")
        pub_str = _format_published(alert.get("published", ""))
        matched_kw = "  ·  ".join(alert["matched_keywords"])
        summary = alert.get("summary", "").strip()[:297] + "…" if len(alert.get("summary", "")) > 300 else alert.get("summary", "").strip()
        body = [
            {"type": "TextBlock", "text": f"[{alert['title']}]({alert['url']})", "weight": "Bolder", "size": "Medium", "wrap": True, "color": colour},
            {"type": "ColumnSet", "spacing": "Small", "columns": [
                {"type": "Column", "width": "stretch", "items": [{"type": "TextBlock", "text": f"📰 {alert['source']}", "size": "Small", "isSubtle": True, "wrap": False}]},
                {"type": "Column", "width": "auto", "items": [{"type": "TextBlock", "text": f"🕐 {pub_str}", "size": "Small", "isSubtle": True, "wrap": False, "horizontalAlignment": "Right"}]},
            ]},
        ]
        if summary:
            body.append({"type": "TextBlock", "text": summary, "wrap": True, "size": "Small", "spacing": "Small"})
        body.append({"type": "TextBlock", "text": f"🔍 **Keywords matched:** {matched_kw}", "wrap": True, "size": "Small", "spacing": "Small", "color": colour})
        payloads.append({
            "type": "message",
            "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard", "version": "1.5",
                "body": [{"type": "Container", "style": container_style, "bleed": True, "items": body}],
            }}],
        })

    if dry_run:
        log.info("DRY RUN — Teams Adaptive Card payloads:")
        for p in payloads:
            print(json.dumps(p, indent=2))
        return

    for i, payload in enumerate(payloads):
        resp = requests.post(webhook_url, json=payload, timeout=15)
        resp.raise_for_status()
        log.info(f"  Posted Teams card {i + 1}/{len(payloads)} (HTTP {resp.status_code})")
    log.info("All Teams cards sent successfully.")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    keywords_override = os.environ.get("KEYWORDS_OVERRIDE", "").strip()
    if keywords_override:
        keywords = [k.strip() for k in keywords_override.split(",") if k.strip()]
        log.info(f"Using override keywords: {keywords}")
    else:
        keywords = DEFAULT_KEYWORDS
        log.info(f"Using default keywords: {keywords}")

    dry_run       = os.environ.get("DRY_RUN", "false").lower() == "true"
    teams_webhook = os.environ.get("TEAMS_WEBHOOK_URL", "")
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")

    if not teams_webhook and not slack_webhook and not dry_run:
        raise EnvironmentError(
            "No webhook configured. Set SLACK_WEBHOOK_URL or TEAMS_WEBHOOK_URL "
            "in GitHub Secrets, or set DRY_RUN=true."
        )

    seen = load_cache()
    log.info(f"Cache loaded: {len(seen)} previously seen articles")

    log.info("Fetching threat intelligence feeds...")
    all_articles = fetch_all_articles(THREAT_FEEDS, keywords)
    log.info(f"Total articles fetched: {len(all_articles)}")

    matched_alerts = []
    newly_seen = set()

    for article in all_articles:
        if not is_recent(article.get("pub_dt")):
            continue
        full_text = f"{article['title']} {article['summary']}"
        matched = matches_keywords(full_text, keywords)
        if not matched:
            continue
        aid = article_id(article["url"] + article["title"])
        if aid in seen:
            log.debug(f"Skipping already-seen: {article['title'][:60]}")
            continue
        article["matched_keywords"] = matched
        matched_alerts.append(article)
        newly_seen.add(aid)

    log.info(f"New matched alerts: {len(matched_alerts)}")

    log_data = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "keywords": keywords,
        "total_fetched": len(all_articles),
        "new_alerts": len(matched_alerts),
        "alerts": [
            {"source": a["source"], "title": a["title"], "url": a["url"],
             "matched_keywords": a["matched_keywords"], "published": a.get("published", ""),
             "summary": a.get("summary", "")}
            for a in matched_alerts
        ],
    }
    LOG_FILE.write_text(json.dumps(log_data, indent=2))

    # Gemini summarization (only when there are alerts)
    ai_summary = ""
    if matched_alerts:
        log.info("Generating AI summary with Gemini...")
        ai_summary = summarize_with_gemini(matched_alerts, keywords)

    # Slack
    if slack_webhook or dry_run:
        log.info("Sending Slack notification...")
        send_slack_notification(
            webhook_url=slack_webhook,
            alerts=matched_alerts,
            keywords=keywords,
            ai_summary=ai_summary,
            dry_run=dry_run,
        )

    # Teams (when webhook is available)
    if teams_webhook:
        log.info("Sending Teams notification...")
        send_teams_alert(teams_webhook, matched_alerts, keywords, dry_run=dry_run)

    seen.update(newly_seen)
    save_cache(seen)
    log.info("Cache updated. Done.")


if __name__ == "__main__":
    main()
