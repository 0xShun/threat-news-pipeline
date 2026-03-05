#!/usr/bin/env python3
"""
Threat Intelligence Monitor
----------------------------
Fetches latest cybersecurity news from multiple RSS/API sources,
filters by configurable keywords, and sends alerts to Microsoft Teams.
"""

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

# Default keywords — extend this list or override via env/GitHub input
DEFAULT_KEYWORDS = [
    "fortinet",
    "fortigate",
    "fortios",
    "forticlient",
    "fortiweb",
    "fortimanager",
    "fortianalyzer",
]

# Threat intelligence RSS feeds
THREAT_FEEDS = [
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/news.xml",
        "type": "rss",
    },
    {
        "name": "CISA Known Exploited Vulnerabilities",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "cisa_kev",
    },
    {
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "type": "rss",
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "type": "rss",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "type": "rss",
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "type": "rss",
    },
    {
        "name": "Security Week",
        "url": "https://www.securityweek.com/feed/",
        "type": "rss",
    },
    {
        "name": "Rapid7 Blog",
        "url": "https://blog.rapid7.com/rss/",
        "type": "rss",
    },
    {
        "name": "Fortinet PSIRT",
        "url": "https://www.fortiguard.com/rss/ir.xml",
        "type": "rss",
    },
    {
        "name": "NVD CVE 2.0 (Fortinet)",
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "type": "nvd_v2",
    },
]

# How far back to look (hours) — 13 h covers the morning→afternoon and overnight gaps
# with a 1-hour overlap buffer to ensure no articles fall through between runs.
LOOKBACK_HOURS = 13

# Seen-articles cache to avoid duplicate alerts
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
    # If the string contains no HTML tags, skip BeautifulSoup to avoid
    # MarkupResemblesLocatorWarning when a bare URL or plain text is passed in.
    if "<" not in raw:
        return re.sub(r'\s+', ' ', raw.strip())[:500]
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text(separator=" ").strip()
    return re.sub(r'\s+', ' ', text)[:500]


def is_recent(pub_date, lookback_hours: int = LOOKBACK_HOURS) -> bool:
    """Return True if pub_date is within the lookback window."""
    if not pub_date:
        return True  # assume recent if no date
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    if isinstance(pub_date, str):
        for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                pub_date = datetime.strptime(pub_date, fmt)
                break
            except ValueError:
                continue
        else:
            return True  # unparseable — include it
    if pub_date.tzinfo is None:
        pub_date = pub_date.replace(tzinfo=timezone.utc)
    return pub_date >= cutoff


def matches_keywords(text: str, keywords: list[str]) -> list[str]:
    """Return list of matched keywords found in text (case-insensitive)."""
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
                if pub_struct:
                    pub_dt = datetime(*pub_struct[:6], tzinfo=timezone.utc)
                else:
                    pub_dt = None
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
                "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
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
    """
    Query the NVD CVE API 2.0 for recent CVEs matching our keywords.
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    Requires NVD_API_KEY env var for higher rate limits (50 req/30s vs 5 req/30s).
    """
    articles = []
    api_key  = os.environ.get("NVD_API_KEY", "")
    headers  = {"apiKey": api_key} if api_key else {}

    # Build the cutoff timestamp in the format NVD expects
    cutoff   = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    pub_start = cutoff.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    # We query once per unique vendor-level keyword group to keep requests minimal.
    # NVD keywordSearch is OR within the query but we want Fortinet-family hits.
    search_term = "fortinet"

    params = {
        "keywordSearch":     search_term,
        "pubStartDate":      pub_start,
        "pubEndDate":        pub_end,
        "resultsPerPage":    50,
        "startIndex":        0,
    }

    try:
        resp = requests.get(feed["url"], params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Published date
            pub_str = cve.get("published", "")
            pub_dt  = None
            if pub_str:
                try:
                    pub_dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            # Description (prefer English)
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available.",
            )

            # CVSS score — try v3.1, then v3.0, then v2
            metrics  = cve.get("metrics", {})
            cvss_str = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    score    = entries[0].get("cvssData", {}).get("baseScore", "")
                    severity = entries[0].get("cvssData", {}).get("baseSeverity", "")
                    if score:
                        cvss_str = f"CVSS {score} ({severity})"
                    break

            summary = desc[:400]
            if cvss_str:
                summary = f"{cvss_str} — {summary}"

            articles.append({
                "source":    "NVD",
                "title":     f"{cve_id} — {desc[:80]}{'…' if len(desc) > 80 else ''}",
                "url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary":   summary,
                "published": pub_str,
                "pub_dt":    pub_dt,
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
# Teams Notification (Power Automate webhook)
# ─────────────────────────────────────────────
# Uses the "When a Teams webhook request is received" trigger in Power Automate
# (Microsoft Teams connector). That trigger generates a webhook URL and expects
# Adaptive Card payloads in the format below.
# Store the generated webhook URL in GitHub Secrets as TEAMS_WEBHOOK_URL.
# No additional Power Automate actions are needed — the trigger posts the card
# directly to the channel you configure when creating the flow.
# ─────────────────────────────────────────────

# Severity colour mapping — based on source/title keyword signals
_SEVERITY_COLOURS = {
    "cisa kev":  "Attention",   # red   — confirmed exploited
    "exploit":   "Attention",
    "0-day":     "Attention",
    "zero-day":  "Attention",
    "rce":       "Attention",
    "critical":  "Attention",
    "high":      "Warning",     # yellow
    "patch":     "Warning",
    "advisory":  "Warning",
    "default":   "Good",        # green — informational
}


def _alert_colour(alert: dict) -> str:
    combined = (alert["source"] + " " + alert["title"]).lower()
    for key, colour in _SEVERITY_COLOURS.items():
        if key in combined:
            return colour
    return _SEVERITY_COLOURS["default"]


def _format_published(pub_str: str) -> str:
    """Return a clean, human-readable date string."""
    if not pub_str:
        return "Unknown date"
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(pub_str[:25].strip(), fmt)
            return dt.strftime("%d %b %Y, %H:%M UTC")
        except ValueError:
            continue
    return pub_str[:20]


def build_single_alert_card(alert: dict) -> dict:
    """
    Build one Adaptive Card per alert for the Power Automate
    'When a Teams webhook request is received' trigger.
    """
    colour     = _alert_colour(alert)
    pub_str    = _format_published(alert.get("published", ""))
    matched_kw = "  ·  ".join(alert["matched_keywords"])
    summary    = alert.get("summary", "").strip()
    if len(summary) > 300:
        summary = summary[:297] + "…"

    container_style = {
        "Attention": "attention",
        "Warning":   "warning",
        "Good":      "good",
    }.get(colour, "default")

    body = [
        {
            "type":   "TextBlock",
            "text":   f"[{alert['title']}]({alert['url']})",
            "weight": "Bolder",
            "size":   "Medium",
            "wrap":   True,
            "color":  colour,
        },
        {
            "type":    "ColumnSet",
            "spacing": "Small",
            "columns": [
                {
                    "type":  "Column",
                    "width": "stretch",
                    "items": [{
                        "type":     "TextBlock",
                        "text":     f"📰 {alert['source']}",
                        "size":     "Small",
                        "isSubtle": True,
                        "wrap":     False,
                    }],
                },
                {
                    "type":  "Column",
                    "width": "auto",
                    "items": [{
                        "type":               "TextBlock",
                        "text":               f"🕐 {pub_str}",
                        "size":               "Small",
                        "isSubtle":           True,
                        "wrap":               False,
                        "horizontalAlignment": "Right",
                    }],
                },
            ],
        },
    ]

    if summary:
        body.append({
            "type":    "TextBlock",
            "text":    summary,
            "wrap":    True,
            "size":    "Small",
            "spacing": "Small",
        })

    body.append({
        "type":    "TextBlock",
        "text":    f"🔍 **Keywords matched:** {matched_kw}",
        "wrap":    True,
        "size":    "Small",
        "spacing": "Small",
        "color":   colour,
    })

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl":  None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.5",
                "body": [{
                    "type":  "Container",
                    "style": container_style,
                    "bleed": True,
                    "items": body,
                }],
            },
        }],
    }


def build_digest_header(alerts: list[dict], session_label: str) -> dict:
    """Header card — posted before the individual alert cards."""
    timestamp = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M UTC")
    count = len(alerts)
    noun  = "alert" if count == 1 else "alerts"

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl":  None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type":    "AdaptiveCard",
                "version": "1.5",
                "body": [{
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type":  "Column",
                            "width": "auto",
                            "items": [{"type": "TextBlock", "text": "🛡️", "size": "ExtraLarge"}],
                        },
                        {
                            "type":  "Column",
                            "width": "stretch",
                            "items": [
                                {
                                    "type":   "TextBlock",
                                    "text":   f"Threat Intelligence — {session_label}",
                                    "weight": "Bolder",
                                    "size":   "Large",
                                },
                                {
                                    "type":     "TextBlock",
                                    "text":     f"{count} new {noun} found  ·  {timestamp}",
                                    "size":     "Small",
                                    "isSubtle": True,
                                    "spacing":  "None",
                                },
                            ],
                        },
                    ],
                }],
            },
        }],
    }


def send_teams_alert(webhook_url: str, alerts: list[dict], keywords: list[str], dry_run: bool = False):
    """
    Posts one header card + one Adaptive Card per alert to Teams via the
    Power Automate 'When a Teams webhook request is received' trigger.
    Alerts are ordered most recently published first.
    """
    alerts_sorted = sorted(
        alerts,
        key=lambda a: a.get("pub_dt") or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    hour = datetime.now(timezone.utc).hour
    session_label = "Morning Brief" if hour < 12 else "Afternoon Brief"

    payloads = [build_digest_header(alerts_sorted, session_label)]
    for alert in alerts_sorted:
        payloads.append(build_single_alert_card(alert))

    if dry_run:
        log.info("DRY RUN — Power Automate Adaptive Card payloads:")
        for p in payloads:
            print(json.dumps(p, indent=2))
        return

    for i, payload in enumerate(payloads):
        resp = requests.post(webhook_url, json=payload, timeout=15)
        resp.raise_for_status()
        log.info(f"  Posted card {i + 1}/{len(payloads)} (HTTP {resp.status_code})")

    log.info("All Teams cards sent successfully.")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    # ── Resolve keywords ──────────────────────
    keywords_override = os.environ.get("KEYWORDS_OVERRIDE", "").strip()
    if keywords_override:
        keywords = [k.strip() for k in keywords_override.split(",") if k.strip()]
        log.info(f"Using override keywords: {keywords}")
    else:
        keywords = DEFAULT_KEYWORDS
        log.info(f"Using default keywords: {keywords}")

    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "")

    if not webhook_url and not dry_run:
        raise EnvironmentError(
            "TEAMS_WEBHOOK_URL secret is not set. "
            "Add it in Settings → Secrets and Variables → Actions."
        )

    # ── Load cache ────────────────────────────
    seen = load_cache()
    log.info(f"Cache loaded: {len(seen)} previously seen articles")

    # ── Fetch articles ────────────────────────
    log.info("Fetching threat intelligence feeds...")
    all_articles = fetch_all_articles(THREAT_FEEDS, keywords)
    log.info(f"Total articles fetched: {len(all_articles)}")

    # ── Filter: recent + keyword match + not seen ──
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

    # ── Write log ─────────────────────────────
    log_data = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "keywords": keywords,
        "total_fetched": len(all_articles),
        "new_alerts": len(matched_alerts),
        "alerts": [
            {
                "source": a["source"],
                "title": a["title"],
                "url": a["url"],
                "matched_keywords": a["matched_keywords"],
                "published": a.get("published", ""),
                "summary": a.get("summary", ""),
            }
            for a in matched_alerts
        ],
    }
    LOG_FILE.write_text(json.dumps(log_data, indent=2))

    # ── Send Teams alert ──────────────────────
    if matched_alerts:
        log.info("Sending Teams notification...")
        send_teams_alert(webhook_url, matched_alerts, keywords, dry_run=dry_run)
    else:
        log.info("No new relevant alerts — Teams notification skipped.")

    # ── Update cache ──────────────────────────
    seen.update(newly_seen)
    save_cache(seen)
    log.info("Cache updated. Done.")


if __name__ == "__main__":
    main()
