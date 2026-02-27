import asyncio, aiohttp, re
from functools import wraps
from typing import Optional
from deep_translator import GoogleTranslator

_bot = None
URL = ""
CHAT_TOKEN = ""
LANG = ""
BOT_ID = None
_session: aiohttp.ClientSession | None = None
_translate_cache: dict[tuple[str, str], str] = {}


class KDefenderNotReady(SystemError):
    pass


async def setup(
    bot=None,
    url=None,
    chat_token=None,
    lang=None,
    timeout=5
):
    """
    Languages:
    - English (en)
    - Русский (ru)
    - Español (es)
    - Deutsch (de)
    - Français (fr)
    - Українська (uk)
    - etc in deep_translator (GoogleTranslator)
    """
    missing = []
    if not bot:
        missing.append("bot")
    if not url:
        missing.append("url")
    if not chat_token:
        missing.append("chat_token")
    if not lang:
        missing.append("lang")

    if missing:
        raise KDefenderNotReady(
            "K-Defender wrapper not configured. Missing: " + ", ".join(missing)
        )
    
    if url.endswith("/"):
        url = url[:-1]

    global URL, CHAT_TOKEN, LANG, BOT_ID, _bot, _session

    if _session and not _session.closed:
        raise KDefenderNotReady("await setup(...) has already been called. Call await close() before re-initializing.")

    try:
        _session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        )

        async with _session.get(f"{url}/status/") as resp:
            if resp.status != 200:
                await _session.close()
                raise KDefenderNotReady("K-Defender URL is not reachable or valid.")

    except asyncio.TimeoutError:
        if _session:
            await _session.close()
        raise KDefenderNotReady("K-Defender server timed out.")

    except aiohttp.ClientError:
        if _session:
            await _session.close()
        raise KDefenderNotReady("K-Defender URL is invalid or unreachable.")

    LANG = str(lang)
    URL = str(url)
    CHAT_TOKEN = str(chat_token)
    _bot = bot
    me = await bot.get_me()
    BOT_ID = me.id


def tr(text: str) -> str:
    global LANG, _translate_cache
    lang = LANG
    if lang == "en" or not text:
        return text

    cache_key = (lang, text)
    if cache_key in _translate_cache:
        return _translate_cache[cache_key]

    parts = re.split(r"(<pre>.*?</pre>|<code>.*?</code>)", text, flags=re.DOTALL | re.IGNORECASE)
    out = []
    translator = GoogleTranslator(source="auto", target=lang)
    for part in parts:
        if not part:
            continue
        if part.lower().startswith("<pre>") or part.lower().startswith("<code>"):
            out.append(part)
            continue
        if not part.strip():
            out.append(part)
            continue

        left_trim = len(part) - len(part.lstrip())
        right_trim = len(part) - len(part.rstrip())
        core = part.strip()
        if not core:
            out.append(part)
            continue
        try:
            translated_part = translator.translate(core)
            if not isinstance(translated_part, str) or translated_part is None:
                translated_part = core
            out.append(part[:left_trim] + translated_part + (part[len(part) - right_trim:] if right_trim else ""))
        except Exception:
            out.append(part)
    translated = "".join(out)
    _translate_cache[cache_key] = translated
    return translated

async def tr_async(text: str) -> str:
    return await asyncio.to_thread(tr, text)

def _extract_user_text(update) -> Optional[str]:
    # Message-like
    text = getattr(update, "text", None)
    if text:
        return text

    caption = getattr(update, "caption", None)
    if caption:
        return caption

    # CallbackQuery-like
    data = getattr(update, "data", None)
    if data:
        return data

    return None


def _blocked_reply_target(update):
    # aiogram Message
    if hasattr(update, "answer") and not hasattr(update, "data"):
        return update

    # aiogram CallbackQuery -> message
    msg = getattr(update, "message", None)
    if msg and hasattr(msg, "answer"):
        return msg

    return None


async def _send_and_wait_verdict(text: str, timeout: int = 10) -> bool:
    """
    Sends to server:
        {
        "bot_id": <bot_id>,
        "text": <user_text>,
        "token": <CHAT_TOKEN>
        }
    Waits for K-Defender JSON verdict message.

    Returns:
        True  -> ok
        False -> blocked/timeout/error
    """

    global _bot, URL, CHAT_TOKEN, BOT_ID, _session

    if not _session or _session.closed:
        raise KDefenderNotReady("HTTP session not initialized. Call setup().")

    if not URL or not CHAT_TOKEN or not _bot:
        raise KDefenderNotReady("Call await setup(...) before using decorator.")

    

    payload = {
        "bot_id": BOT_ID,
        "text": text,
        "token": CHAT_TOKEN
    }

    try:
        async with _session.post(
            URL + "/check/",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:

            if response.status != 200:
                return False

            try:
                verdict = await response.json()
            except aiohttp.ContentTypeError:
                return False

            return verdict.get("result") == "ok"

    except (asyncio.TimeoutError, aiohttp.ClientError):
        return False



def kdefender_check(param = None, timeout: int = 10):
    """
    Usage:

        @kdefender_check()
        async def handler(message: Message):

    or strict mode:

        @kdefender_check(param="message")
        async def handler(message: Message):

    If param is defined and not found → raises error.
    """

    def deco(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):

            update = None

            # ---------- STRICT MODE ----------
            if param:
                if param in kwargs:
                    update = kwargs[param]
                else:
                    from inspect import signature

                    sig = signature(func)
                    params = list(sig.parameters.keys())

                    if param not in params:
                        raise KDefenderNotReady(
                            f"kdefender_check: parameter '{param}' "
                            f"not found in function '{func.__name__}'"
                        )

                    index = params.index(param)
                    if index < len(args):
                        update = args[index]

                if update is None:
                    raise KDefenderNotReady(
                        f"kdefender_check: argument '{param}' "
                        f"was not passed at runtime"
                    )

            # ---------- AUTO MODE ----------
            else:
                for a in args:
                    if hasattr(a, "chat") or hasattr(a, "data") or hasattr(a, "from_user"):
                        update = a
                        break
                if update is None:
                    update = next(iter(kwargs.values()), None)

            if not update:
                return await func(*args, **kwargs)

            text = _extract_user_text(update)
            if not text:
                return await func(*args, **kwargs)

            ok = await _send_and_wait_verdict(text, timeout=timeout)

            if not ok:
                target = _blocked_reply_target(update)
                if target:
                    await target.answer(await tr_async("Message blocked due to security reasons."))
                return

            return await func(*args, **kwargs)

        return wrapper
    return deco

async def close():
    global _session, _bot, URL, CHAT_TOKEN, LANG, BOT_ID
    if _session and not _session.closed:
        await _session.close()
    _session = None
    _bot = None
    URL = ""
    CHAT_TOKEN = ""
    LANG = ""
    BOT_ID = None
