"""
dork.py — Brave Search URL scraper
Scrapes organic result URLs across multiple pages using advanced TLS fingerprinting.
One URL per root domain, big platforms filtered out.
"""
from __future__ import annotations

import asyncio
import html as _html_mod
import logging
import re
from urllib.parse import quote_plus, urlparse

from curl_cffi.requests import AsyncSession

log = logging.getLogger("dork")
log.setLevel(logging.DEBUG)

# ── Constants ─────────────────────────────────────────────────────────────────
BASE_URL    = "https://search.brave.com/search"
MAX_PAGES   = 10
PAGE_DELAY  = 1.2
REQ_TIMEOUT = 30

# Exact headers from HAR capture — Brave browser fingerprint
_HEADERS_BASE = {
    "accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "accept-encoding":           "gzip, deflate",   # no br/zstd — proxies corrupt brotli
    "accept-language":           "en-US,en;q=0.6",
    "priority":                  "u=0, i",
    "sec-ch-ua":                 '"Brave";v="149", "Chromium";v="149", "Not)A;Brand";v="24"',
    "sec-ch-ua-mobile":          "?0",
    "sec-ch-ua-platform":        '"Windows"',
    "sec-fetch-dest":            "document",
    "sec-fetch-mode":            "navigate",
    "sec-fetch-user":            "?1",
    "sec-gpc":                   "1",
    "upgrade-insecure-requests": "1",
    "user-agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
}

# Brave internal / CDN
_BRAVE_DOMAINS = {
    "search.brave.com", "safesearch.brave.com", "cdn.search.brave.com",
    "brave.com", "accounts.brave.com", "brave.app", "status.brave.app",
}

# Big tech, social media, marketplaces, app stores — never useful as dork targets
_BLOCKED_DOMAINS = {
    # Social
    "facebook.com", "fb.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "pinterest.com", "tiktok.com", "reddit.com", "snapchat.com",
    "telegram.org", "t.me", "whatsapp.com", "discord.com", "tumblr.com",
    "quora.com", "vk.com", "weibo.com",
    # Video
    "youtube.com", "youtu.be", "vimeo.com", "dailymotion.com", "twitch.tv",
    "rumble.com", "bitchute.com",
    # App stores
    "play.google.com", "apps.apple.com", "apple.com", "microsoft.com",
    # E-commerce giants
    "amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.fr",
    "amazon.ca", "amazon.com.au", "amazon.com.br", "amazon.es", "amazon.it",
    "amazon.co.jp", "amazon.com.mx", "amazon.sg", "amazon.ae",
    "ebay.com", "ebay.co.uk", "aliexpress.com", "etsy.com", "walmart.com",
    "wish.com", "shopify.com", "alibaba.com",
    # Tech / developer
    "github.com", "stackoverflow.com", "medium.com", "dev.to", "npmjs.com",
    "pypi.org", "gitlab.com", "bitbucket.org", "codepen.io", "jsfiddle.net",
    "hackerone.com", "bugcrowd.com",
    # Reviews / directories
    "trustpilot.com", "yelp.com", "tripadvisor.com", "glassdoor.com",
    "sitejabber.com", "g2.com", "capterra.com", "producthunt.com",
    # Search engines
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com",
    "yandex.com", "aol.com", "ask.com",
    # Reference / news
    "wikipedia.org", "wikimedia.org", "wikidata.org", "wiktionary.org",
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "reuters.com",
    "techcrunch.com", "theguardian.com", "forbes.com", "bloomberg.com",
    "businessinsider.com", "wired.com", "washingtonpost.com",
    "huffpost.com", "independent.co.uk", "telegraph.co.uk",
    # Cloud / hosting / CMS
    "cloudflare.com", "wordpress.com", "blogger.com", "wix.com",
    "squarespace.com", "weebly.com", "godaddy.com",
    # Google properties
    "support.google.com", "accounts.google.com", "mail.google.com",
    "drive.google.com", "maps.google.com", "docs.google.com",
    "console.cloud.google.com",
    # Misc big corps
    "adobe.com", "salesforce.com", "oracle.com", "ibm.com", "cisco.com",
    "intel.com", "hp.com", "dell.com", "samsung.com", "lg.com",
}


# ── Domain helpers ────────────────────────────────────────────────────────────

# Known short second-level labels used in country TLDs (co.uk, com.au, org.uk…)
_SHORT_SLD = {"co", "com", "org", "net", "gov", "edu", "ac", "me", "ne", "or"}


def _root_domain(url: str) -> str:
    """
    Extract the registrable root domain for deduplication.
    e.g.  https://sub.example.co.uk/path  →  example.co.uk
          https://www.mobilerecharge.com/apps  →  mobilerecharge.com
    """
    try:
        host = urlparse(url).netloc.lower()
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        if len(parts) >= 3 and parts[-2] in _SHORT_SLD:
            return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return url


def _is_blocked(root: str) -> bool:
    """Return True if the root domain should be filtered out."""
    # Brave internal
    if any(root == bd or root.endswith("." + bd) for bd in _BRAVE_DOMAINS):
        return True
    # Big platform blocklist
    if any(root == bd or root.endswith("." + bd) for bd in _BLOCKED_DOMAINS):
        return True
    return False


# ── Proxy helper ──────────────────────────────────────────────────────────────

def _proxy_str_to_curl(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    proxy = proxy.strip()
    if proxy.startswith(("http://", "https://", "socks5://", "socks4://")):
        return {"http": proxy, "https": proxy}
    parts = proxy.split(":")
    if len(parts) == 4:
        ip, port, user, pw = parts
        url = f"http://{user}:{pw}@{ip}:{port}"
    elif len(parts) == 2:
        url = f"http://{parts[0]}:{parts[1]}"
    else:
        return None
    return {"http": url, "https": url}


# ── URL extraction from HTML ──────────────────────────────────────────────────

def _extract_urls(html: str) -> list[str]:
    """
    Extract candidate URLs from Brave Search HTML.
    Returns raw URLs (not yet deduplicated by domain).
    """
    seen_href: set[str] = set()
    urls: list[str] = []

    for href in re.findall(r'href=["\']?(https?://[^"\'>\s]+)', html):
        # Unescape HTML entities (&amp; → &)
        href = _html_mod.unescape(href)
        # Strip Brave internal tracking suffixes
        if "brave.com" in href:
            href = href.split("?")[0]
        # Drop static assets
        if href.endswith((".css", ".js", ".woff2", ".woff", ".png", ".jpg", ".svg", ".ico")):
            continue
        if href not in seen_href:
            seen_href.add(href)
            urls.append(href)

    return urls


# ── Main scrape function ───────────────────────────────────────────────────────

async def scrape_dork(
    query: str,
    proxy: str | None = None,
    max_pages: int = MAX_PAGES,
    on_progress: "asyncio.coroutine | None" = None,
) -> list[str]:
    """
    Scrape Brave Search for `query`.

    Returns:
        One clean URL per unique root domain, big platforms excluded.
    """
    proxies = _proxy_str_to_curl(proxy)
    all_urls: list[str]   = []
    seen_domains: set[str] = set()   # root-domain dedup
    q_enc = quote_plus(query)

    log.info(f"[DORK] Starting: query={query!r} max_pages={max_pages} proxy={'yes' if proxies else 'no'}")

    async with AsyncSession(impersonate="chrome131") as session:
        for page in range(max_pages):
            if page == 0:
                url     = f"{BASE_URL}?q={q_enc}&source=desktop"
                headers = {**_HEADERS_BASE, "sec-fetch-site": "none"}
            else:
                url     = f"{BASE_URL}?q={q_enc}&offset={page}&spellcheck=0"
                headers = {
                    **_HEADERS_BASE,
                    "referer": f"{BASE_URL}?q={q_enc}&source=desktop",
                    "sec-fetch-site": "same-origin",
                }

            kwargs: dict = {"headers": headers, "timeout": REQ_TIMEOUT}
            if proxies:
                kwargs["proxies"] = proxies

            try:
                log.info(f"[DORK] Page {page + 1}/{max_pages} GET {url}")
                resp = await session.get(url, **kwargs)
                html = resp.text
                log.info(f"[DORK] Page {page + 1} status={resp.status_code} size={len(html)}")

                if resp.status_code == 429:
                    log.warning("[DORK] Rate-limited by Brave — stopping")
                    break
                if resp.status_code != 200:
                    log.warning(f"[DORK] Non-200 on page {page + 1}: {resp.status_code}")
                    break

                log.debug(f"[DORK] HTML snippet: {html[:400]!r}")
                raw_urls  = _extract_urls(html)
                log.info(f"[DORK] Page {page + 1} raw hrefs: {len(raw_urls)}")

                new_added = 0
                for u in raw_urls:
                    root = _root_domain(u)
                    if _is_blocked(root):
                        log.debug(f"[DORK] Blocked: {root}")
                        continue
                    if root in seen_domains:
                        log.debug(f"[DORK] Dup domain: {root} ({u})")
                        continue
                    seen_domains.add(root)
                    all_urls.append(u)
                    new_added += 1

                log.info(f"[DORK] Page {page + 1}: +{new_added} new domains (total {len(all_urls)})")
                if all_urls:
                    log.debug(f"[DORK] Latest: {all_urls[-min(3, len(all_urls)):]}")

                if on_progress:
                    try:
                        await on_progress(page + 1, len(all_urls))
                    except Exception:
                        pass

                if new_added == 0 and page > 0:
                    log.info(f"[DORK] No new domains on page {page + 1} — stopping early")
                    break

            except Exception as exc:
                log.warning(f"[DORK] Page {page + 1} error [{type(exc).__name__}]: {exc}")
                break

            if page < max_pages - 1:
                await asyncio.sleep(PAGE_DELAY)

    log.info(f"[DORK] Done: {len(all_urls)} unique domain URLs")
    return all_urls
