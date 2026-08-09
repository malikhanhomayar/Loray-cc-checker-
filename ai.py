"""
Kimi AI (Moonshot) integration for the Telegram bot.
Loads system prompt from the 'ai skill' directory and exposes ask_kimi().
"""
import io
import os
import asyncio
import httpx

# ── Config ────────────────────────────────────────────────────────────────────
# Primary: Kimi Code (subscription) — https://www.kimi.com/code/docs/en/
KIMI_CODE_KEY      = "sk-kimi-T3LA3oYSbJTSDvwsANa2lc5M5CD7RaXYpZcRqOe2"
KIMI_CODE_BASE_URL = "https://api.kimi.com/coding/v1"
KIMI_CODE_MODEL    = "kimi-for-coding"       # stable ID, always maps to latest model

# Fallback: Kimi Platform (pay-per-use) — https://platform.kimi.ai/docs/overview
KIMI_PLAT_KEY      = "sk-kMnOVMyO956c95X3PP2uC66sE1tbmT"
KIMI_PLAT_BASE_URL = "https://api.moonshot.ai/v1"  # note: .ai not .cn
KIMI_PLAT_MODEL    = "kimi-k2.6"             # general-purpose, 256K context

KIMI_TIMEOUT = 90                            # seconds per request

_BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
_AI_SKILL_DIR  = os.path.join(_BASE_DIR, "ai skill")

# ── Load system prompt from every file in "ai skill/" ─────────────────────────
def _load_system_prompt() -> str:
    parts: list[str] = []
    try:
        for fname in sorted(os.listdir(_AI_SKILL_DIR)):
            fpath = os.path.join(_AI_SKILL_DIR, fname)
            if not os.path.isfile(fpath):
                continue
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
            if content:
                parts.append(content)
    except Exception:
        pass
    return "\n\n" + ("=" * 60) + "\n\n".join(parts) if parts else (
        "You are a helpful, knowledgeable AI assistant. "
        "Answer clearly and thoroughly."
    )


_SYSTEM_PROMPT: str = _load_system_prompt()


# ── Core API call ──────────────────────────────────────────────────────────────
async def _call_kimi(
    base_url: str,
    api_key: str,
    model: str,
    messages: list[dict],
) -> str:
    """Low-level POST to a Kimi-compatible endpoint.  Returns content string."""
    async with httpx.AsyncClient(timeout=KIMI_TIMEOUT) as client:
        resp = await client.post(
            f"{base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            json={
                "model":      model,
                "messages":   messages,
                "max_tokens": 8192,
                "stream":     False,
            },
        )
        resp.raise_for_status()
        data = resp.json()

    reply = (
        data.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
    ).strip()

    if not reply:
        raise ValueError("Empty response from Kimi API.")
    return reply


async def ask_kimi(
    prompt: str,
    file_contents: list[tuple[str, str]] | None = None,
    history: list[dict] | None = None,
) -> str:
    """
    Send a prompt (and optional file contents) to Kimi and return the reply text.
    Tries Kimi Code first; falls back to Kimi Platform on auth/quota errors.

    Args:
        prompt:        User's text prompt.
        file_contents: List of (filename, text_content) tuples to prepend.
        history:       Prior conversation turns [{role, content}, ...] (optional).
    Returns:
        AI reply as plain text (may include Markdown).
    Raises:
        Exception when both endpoints fail.
    """
    # Build user message
    user_parts: list[str] = []
    if file_contents:
        for fname, content in file_contents:
            sep = "=" * 50
            user_parts.append(f"{sep}\nFile: {fname}\n{sep}\n{content}\n{sep}")
    if prompt:
        user_parts.append(prompt)
    user_message = "\n\n".join(user_parts) if user_parts else prompt

    messages: list[dict] = [{"role": "system", "content": _SYSTEM_PROMPT}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": user_message})

    # ── Try Kimi Code (subscription) first ────────────────────────────────────
    try:
        return await _call_kimi(
            KIMI_CODE_BASE_URL, KIMI_CODE_KEY, KIMI_CODE_MODEL, messages
        )
    except httpx.HTTPStatusError as e:
        if e.response.status_code not in (401, 403, 429):
            raise                   # non-auth error → bubble up immediately
        code_err = e               # auth/quota error → try fallback
    except Exception:
        raise                       # network failure → bubble up

    # ── Fallback to Kimi Platform (pay-per-use) ───────────────────────────────
    try:
        return await _call_kimi(
            KIMI_PLAT_BASE_URL, KIMI_PLAT_KEY, KIMI_PLAT_MODEL, messages
        )
    except httpx.HTTPStatusError as e:
        # Both failed — surface the most useful error message
        raise httpx.HTTPStatusError(
            f"Kimi Code ({code_err.response.status_code}) and "
            f"Kimi Platform ({e.response.status_code}) both failed. "
            f"Platform response: {e.response.text[:200]}",
            request=e.request,
            response=e.response,
        ) from e


# ── Response format helpers ────────────────────────────────────────────────────
_TG_MAX_TEXT     = 3900   # leave headroom below Telegram's 4096 limit
_CODE_INDICATORS = ("```", "~~~", "    ")   # markdown fence / 4-space indent


def needs_file(text: str) -> bool:
    """Return True when the response should be sent as a file instead of text."""
    if len(text) > _TG_MAX_TEXT:
        return True
    # Substantial code blocks → send as file for clean rendering
    if "```" in text:
        # More than one fenced code block (or the block is long)
        blocks = text.split("```")
        if len(blocks) >= 3:          # at least one opening+closing fence pair
            code_len = sum(len(b) for b in blocks[1::2])
            if code_len > 300:
                return True
    return False


def choose_filename(text: str, prompt: str = "") -> str:
    """Pick an appropriate filename for the file attachment."""
    # Detect dominant language from fenced code blocks
    blocks = text.split("```")
    if len(blocks) >= 3:
        lang = blocks[1].split("\n")[0].strip().lower()
        ext_map = {
            "python": "py", "py": "py",
            "javascript": "js", "js": "js",
            "typescript": "ts", "ts": "ts",
            "cpp": "cpp", "c++": "cpp", "c": "c",
            "rust": "rs", "go": "go",
            "java": "java", "kotlin": "kt",
            "bash": "sh", "shell": "sh", "sh": "sh",
            "html": "html", "css": "css",
            "sql": "sql", "json": "json",
            "yaml": "yaml", "yml": "yaml",
        }
        if lang in ext_map:
            return f"ai_response.{ext_map[lang]}"
        if lang:
            return f"ai_response.{lang[:6]}"
    # Mixed content → markdown
    if "```" in text or "#" in text[:60]:
        return "ai_response.md"
    return "ai_response.txt"


def format_for_telegram(text: str) -> str:
    """
    Convert Markdown-ish AI output to Telegram HTML.
    Only handles the subset that Telegram accepts.
    """
    import re

    # Escape HTML special chars FIRST (before adding tags)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Fenced code blocks  ```lang\n...\n```  → <pre><code>
    def replace_fence(m):
        lang  = (m.group(1) or "").strip()
        code  = m.group(2)
        inner = code.strip()
        if lang:
            return f'<pre><code class="language-{lang}">{inner}</code></pre>'
        return f"<pre>{inner}</pre>"

    text = re.sub(r"```([^\n]*)\n(.*?)```", replace_fence, text, flags=re.DOTALL)

    # Inline code  `...`  → <code>
    text = re.sub(r"`([^`\n]+)`", r"<code>\1</code>", text)

    # Bold **...** or __...__
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text, flags=re.DOTALL)
    text = re.sub(r"__(.+?)__",     r"<b>\1</b>", text, flags=re.DOTALL)

    # Italic *...* or _..._  (single)
    text = re.sub(r"\*([^\*\n]+)\*", r"<i>\1</i>", text)
    text = re.sub(r"_([^_\n]+)_",   r"<i>\1</i>", text)

    # Strikethrough ~~...~~
    text = re.sub(r"~~(.+?)~~", r"<s>\1</s>", text, flags=re.DOTALL)

    return text
