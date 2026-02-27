import asyncio, os, json, html, secrets, hashlib, re
from typing import Any, Dict

from aiogram import Bot, Dispatcher, F, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, Message, CallbackQuery
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, KeyboardButtonRequestUser
from aiogram.fsm.context import FSMContext

from deep_translator import GoogleTranslator

import dotenv
dotenv.load_dotenv()

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
from io import BytesIO

# =========================
# Bot API
# =========================
TOKEN = os.getenv("TOKEN")
api_base = os.getenv("KDEFENDER_API_BASE", "http://127.0.0.1:8000")
save_verify_msg = None
if api_base.endswith("/"): api_base = api_base[:-1]

if not TOKEN:
    raise RuntimeError("TOKEN env is missing")

bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()

STATE_FILE = "state.json"
SIG_FILE = "signatures.json"

_autosave_task = None
_alerts_task = None

logs_num = 5000
LOGS_PER_PAGE = 30

DRAFT_BOT_KEY = "new_bot"   # temp slot while connecting (must be not numeric, not equal to any bot_id)


# =========================
# Default signatures/settings
# =========================
DEFAULT_SIGNATURES = {
    "SQLi": {
        "patterns": ["'", '"', "--", " or ", " and ", "1=1", "union select", "sleep(", "benchmark("],
        "risk": 100
    },
    "XSS": {
        "patterns": ["<script", "onerror=", "onload=", "javascript:", "<img", "<iframe"],
        "risk": 80
    },
    # Others are “logical” toggles; risk can be kept 0 if you only want them to affect strict behavior later
    "Inline_injection": {"patterns": [], "risk": 0},
    "Entity_manipulation": {"patterns": [], "risk": 0},
    "Markdown_injection": {"patterns": [], "risk": 0},
    "Bot_command_injection": {"patterns": [], "risk": 0},
    "Callback_query_injection": {"patterns": [], "risk": 0},
    "Inline_query_injection": {"patterns": [], "risk": 0},
    "Flood": {"patterns": [], "risk": 50},
}

DEFAULT_BOT_SETTINGS = {
    "SQLi": True,
    "XSS": True,
    "Inline_injection": True,
    "Entity_manipulation": True,
    "Markdown_injection": True,
    "Bot_command_injection": True,
    "Callback_query_injection": True,
    "Inline_query_injection": True,
    "Flood": True,
}

DEFAULT_USER_SETTINGS = {
    "enabled": True,
    "strict": False,
    "mode": "normal",      # normal / allow_all / block_all
    "language": "en",
    "language_selected": False,
}

LANGUAGE_OPTIONS = [
    ("English", "en"),
    ("Русский", "ru"),
    ("Español", "es"),
    ("Deutsch", "de"),
    ("Français", "fr"),
    ("Українська", "uk"),
]
LANGUAGE_NAMES = {code: name for name, code in LANGUAGE_OPTIONS}
_translate_cache: Dict[tuple[str, str], str] = {}

_SKIP_TRANSLATE_WORDS = {
    "WAF", "ID", "API", "JSON", "HTTP", "HTTPS", "SQL",
    "Inline_injection", "Entity_manipulation", "Markdown_injection",
    "Bot_command_injection", "Callback_query_injection",
    "Inline_query_injection", "Flood", "Telegram", "Webhook",
    "XSS", "SQLi", "HTML", "CSS", "JS", "K-Defender"
}


# =========================
# JSON helpers
# =========================
def _atomic_write_json(path: str, data: Any) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        _atomic_write_json(path, default)
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_state() -> None:
    _atomic_write_json(STATE_FILE, state)


def save_signatures() -> None:
    _atomic_write_json(SIG_FILE, signatures)


# =========================
# State
# =========================
state: Dict[str, Any] = load_json(STATE_FILE, {})  # user_id(str) -> data
signatures: Dict[str, Any] = load_json(SIG_FILE, DEFAULT_SIGNATURES)

# ensure defaults exist in signatures file too
changed = False
for k, v in DEFAULT_SIGNATURES.items():
    if k not in signatures:
        signatures[k] = v
        changed = True
if changed:
    save_signatures()
    

# =========================
# State helpers
# =========================
def ensure_user(user_id: int | str) -> dict:
    u = state.setdefault(str(user_id), {})
    u.setdefault("bots", {})
    u.setdefault("settings", {})
    return u


def bots_of(user_id: int | str) -> dict:
    return ensure_user(user_id)["bots"]


def ensure_draft(user_id: int | str, reset: bool = False) -> dict:
    bots = bots_of(user_id)
    if reset and DRAFT_BOT_KEY not in bots:
        bots[DRAFT_BOT_KEY] = {
            "step": 1,
            "verified": False,
            "instr_page": 0,
            "settings": {},
        }
    return bots[DRAFT_BOT_KEY]


def drop_draft(user_id: int | str) -> None:
    bots_of(user_id).pop(DRAFT_BOT_KEY, None)


def ensure_bot(user_id: int | str, bot_id: int | str) -> dict:
    bots = bots_of(user_id)
    b = bots.setdefault(str(bot_id), {})
    b.setdefault("step", 1)
    b.setdefault("verified", False)
    b.setdefault("instr_page", 0)
    b.setdefault("settings", {})
    b.setdefault("stats_total", 0)
    b.setdefault("stats_blocked", 0)
    b.setdefault("logs", [])
    b.setdefault("pending", {})  # produced by web_api, delivered by bot.py
    b["pending"].setdefault("alert", [])
    return b


def real_bots_dict(user_id: int | str) -> dict:
    bots = bots_of(user_id)
    return {k: v for k, v in bots.items() if k != DRAFT_BOT_KEY}


def get_bot_settings(user_id: int, bot_id: int | str) -> dict:
    b = ensure_bot(user_id, bot_id)
    st = b.setdefault("settings", {})
    for k, v in DEFAULT_BOT_SETTINGS.items():
        st.setdefault(k, v)
    return st


def get_user_settings(user_id: int) -> dict:
    u = ensure_user(user_id)
    st = u.setdefault("settings", {})
    for k, v in DEFAULT_USER_SETTINGS.items():
        st.setdefault(k, v)
    return st


def delete_bot(user_id: int, bot_id: int | str) -> bool:
    u = state.get(str(user_id))
    if not u:
        return False
    bots = u.get("bots", {})
    if str(bot_id) == DRAFT_BOT_KEY:
        return False
    bots.pop(str(bot_id), None)
    save_state()
    return True


def generate_bot_token(bot_username: str) -> str:
    random_part = secrets.token_hex(32)
    base = f"{bot_username}:{random_part}"
    token = hashlib.sha256(base.encode()).hexdigest()
    return token


def reset_bot_token(user_id: int, bot_id: int | str) -> str:
    u = state.get(str(user_id))
    if not u:
        raise ValueError("User not found")

    bots = u.get("bots", {})
    b = bots.get(str(bot_id))
    if not b:
        raise ValueError("Bot not found")

    bot_username = b.get("bot_username")
    if not bot_username:
        raise ValueError("Bot username missing")

    new_token = generate_bot_token(bot_username)
    b["bot_token"] = new_token

    save_state()
    return new_token


# =========================
# UI helpers
# =========================
async def edit_msg(msg: Message, text: str, reply_markup=None, parse_mode=ParseMode.HTML):
    try:
        await msg.edit_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    except TelegramBadRequest as e:
        err = str(e).lower()
        if "there is no text in the message to edit" in err or "message can't be edited" in err:
            try:
                await msg.delete()
            except Exception:
                pass
            await msg.answer(text, reply_markup=reply_markup, parse_mode=parse_mode)
            return
        raise


def _onoff(v: bool) -> str:
    return "✅ ON" if v else "❌ OFF"


def _mode_label(mode: str) -> str:
    return {
        "normal": "Normal",
        "allow_all": "Allow All (pause protection)",
        "block_all": "Block All (lockdown)",
    }.get(mode, mode)


def get_user_lang(user_id: int | str) -> str:
    st = get_user_settings(int(user_id))
    lang = st.get("language", "en")
    if lang not in LANGUAGE_NAMES:
        lang = "en"
        st["language"] = "en"
    return lang


def tr(user_id: int | str, text: str) -> str:
    lang = get_user_lang(user_id)
    if lang == "en" or not text:
        return text

    cache_key = (lang, text)
    if cache_key in _translate_cache:
        return _translate_cache[cache_key]

    parts = re.split(r"(<pre>.*?</pre>|<code>.*?</code>)", text, flags=re.DOTALL | re.IGNORECASE)

    translator = GoogleTranslator(source="auto", target=lang)
    out = []

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

        placeholders = {}
        protected_text = core

        for i, word in enumerate(_SKIP_TRANSLATE_WORDS):
            pattern = rf"\b{re.escape(word)}\b"
            placeholder = f"__NO_TRANSLATE_{i}__"
            if re.search(pattern, protected_text):
                protected_text = re.sub(pattern, placeholder, protected_text)
                placeholders[placeholder] = word

        try:
            translated_part = translator.translate(protected_text)
            if not isinstance(translated_part, str) or translated_part is None:
                translated_part = protected_text
        except Exception:
            translated_part = protected_text

        # Restore protected words
        for placeholder, original in placeholders.items():
            translated_part = translated_part.replace(placeholder, original)

        final_part = (
            part[:left_trim]
            + translated_part
            + (part[len(part) - right_trim:] if right_trim else "")
        )

        out.append(final_part)

    translated = "".join(out)
    _translate_cache[cache_key] = translated
    return translated


def make_lang_kb() -> InlineKeyboardMarkup:
    rows = []
    row = []
    for idx, (name, code) in enumerate(LANGUAGE_OPTIONS, start=1):
        row.append(InlineKeyboardButton(text=name, callback_data=f"lang:set:{code}"))
        if idx % 2 == 0:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return InlineKeyboardMarkup(inline_keyboard=rows)


# =========================
# Autosave + Alerts delivery loops
# =========================
async def autosave_loop():
    while True:
        await asyncio.sleep(30)
        try:
            save_state()
        except Exception:
            pass


async def alerts_delivery_loop():
    while True:
        await asyncio.sleep(2.0)
        try:
            global state
            state = load_json(STATE_FILE, state)

            for uid_s, u in list(state.items()):
                bots = (u.get("bots") or {})

                for bot_id, b in list(bots.items()):
                    if bot_id == DRAFT_BOT_KEY:
                        continue

                    alerts = b.get("pending", {}).get("alert", [])
                    info_msgs = b.get("pending", {}).get("info", [])
                    #print(alerts)
                    if not alerts and not info_msgs:
                        continue
                    
                    b["pending"]["alert"] = []
                    b["pending"]["info"] = []
                    for alert in alerts:
                        text = alert.get("text", "")
                        normal = alert.get("normal", "")
                        score = alert.get("score", 0)
                        time = alert.get("time", "")

                        reason = alert.get("reason", [])
                        if isinstance(reason, list):
                            reason_str = ", ".join(reason)
                        else:
                            reason_str = str(reason)

                        try:
                            await bot.send_message(
                                int(uid_s),
                                tr(
                                    int(uid_s),
                                    f"❌ <b>Blocked message</b>\n\n"
                                    f"🤖 Bot: <code>@{html.escape(b.get('bot_username','unknown'))}</code>\n"
                                    f"Score: <b>{score}</b>\n"
                                    f"Reason: <b>{html.escape(reason_str)}</b>\n\n"
                                    f"Message:\n<code>{html.escape(text)}</code>\n"
                                    f"Normalized:\n<code>{html.escape(normal)}</code>\n\n"
                                    f"Time: {time}"

                                ),
                                parse_mode=ParseMode.HTML
                            )
                            #print("SENT OK")

                        except Exception as e:
                            print("TELEGRAM ERROR:", e)
                    
                    for info in info_msgs:
                        text = info.get("text", "")
                        try:
                            if text == "Webhook verified":
                                global save_verify_msg
                                await handle_webhook_verified(int(uid_s), bot_id, save_verify_msg)
                            else:
                                await bot.send_message(
                                    int(uid_s),
                                    tr(
                                        int(uid_s),
                                        f"ℹ️ <b>Info</b>\n\n"
                                        f"🤖 Bot: <code>@{html.escape(b.get('bot_username','unknown'))}</code>\n\n"
                                        f"{html.escape(text)}"
                                    ),
                                    parse_mode=ParseMode.HTML
                                )
                        except Exception as e:
                            print("TELEGRAM ERROR:", e)

            save_state()

        except Exception as e:
            print("LOOP ERROR:", e)

# =========================
# Instruction pages
# =========================
setup_pages = [
    "<b>K-Defender Setup — Step 1</b>\n\n"
    "You will connect your protected bot using <b>Web API</b>.\n\n"
    "You need two values:\n"
    "• <b>BOT_ID</b> (numeric)\n"
    "• <b>@bot_username</b>\n\n"
    "Press Next to learn how to get BOT_ID quickly.",

    "<b>K-Defender Setup — Step 2</b>\n\n"
    "How to get <b>BOT_ID</b>:\n"
    "1) Add K-Defender and your bot somewhere (any chat) or just reply to a message from your bot.\n"
    "2) Use <code>/get_info</code> as reply — I will show id.\n\n"
    "After you know BOT_ID, continue.",

    "<b>K-Defender Setup — Step 3</b>\n\n"
    "Now send me (in private chat) this line:\n\n"
    "<code>BOT_ID @bot_username</code>\n\n"
    "Example:\n"
    "<code>123456789 @mybot</code>",

    "<b>K-Defender Setup — Step 4</b>\n\n"
    "After I register the bot, you will receive:\n"
    "• <b>CHAT_TOKEN</b> (access token)\n"
    "• <b>API endpoint</b> to send checks: <code>POST /api/check</code>\n\n"
    "Then you update your protected bot wrapper to call the API."
]

get_id_pages = [
    "<b>How to get BOT_ID — Step 1</b>\n\n"
    "Open a chat where you can see messages from your bot.",

    "<b>How to get BOT_ID — Step 2</b>\n\n"
    "Reply to a bot message and send <code>/get_info</code> to K-Defender.\n"
    "It will show id/username.",

    "<b>How to get BOT_ID — Final</b>\n\n"
    "BOT_ID is a plain number like <code>123456789</code>.\n"
    "Now go back and send:\n"
    "<code>/add_bot</code>"
]


def make_nav_kb(user_id: int, flow="setup", index=0):
    kb = []
    if flow == "setup":
        prev_data = f"setup_prev:{index}"
        next_data = f"setup_next:{index}"
        kb_row = []
        if index > 0:
            kb_row.append(InlineKeyboardButton(text=tr(user_id, "⬅ Prev"), callback_data=prev_data))
        if index < len(setup_pages) - 1:
            kb_row.append(InlineKeyboardButton(text=tr(user_id, "Next ➡"), callback_data=next_data))
        kb_row.append(InlineKeyboardButton(text=tr(user_id, "How to get BOT_ID"), callback_data="open_getid:0"))
        kb.append(kb_row)
        kb.append([InlineKeyboardButton(text=tr(user_id, "Cancel"), callback_data="cancel_setup")])
    else:  # getid flow
        prev_data = f"getid_prev:{index}"
        next_data = f"getid_next:{index}"
        kb_row = []
        if index > 0:
            kb_row.append(InlineKeyboardButton(text=tr(user_id, "⬅ Prev"), callback_data=prev_data))
        if index < len(get_id_pages) - 1:
            kb_row.append(InlineKeyboardButton(text=tr(user_id, "Next ➡"), callback_data=next_data))
        kb_row.append(InlineKeyboardButton(text=tr(user_id, "Back to Setup"), callback_data="open_setup:2"))
        kb.append(kb_row)
    return InlineKeyboardMarkup(inline_keyboard=kb)


# =========================
# Protected wizard pages
# =========================
def build_protected_bot_pages(api_base: str, bot_id: str, chat_token: str, kdefender_id: int, protected_username: str, user_id: int):
    language = get_user_lang(user_id)
    return [
        (
            "🎉 <b>Protected bot connected!</b>\n\n"
            "To delete Webhook, use this url: <pre>https://api.telegram.org/bot&lt;TOKEN&gt;/deleteWebhook</pre>"
            f"Bot: <code>@{protected_username}</code>\n"
            f"BOT_ID: <code>{bot_id}</code>\n"
            f"CHAT_TOKEN: <code>{chat_token}</code>\n"
            f"K_DEFENDER_ID: <code>{kdefender_id}</code>\n"
            f"API_BASE: <code>{html.escape(api_base)}</code>\n\n"
        ),
        (
            "📦 <b>Step 1 — Install deps</b>\n\n"
            "In your protected bot project:\n"
            "<pre>pip install kdefender-wrapper</pre>\n\n"
            "Optional (for .env autoload):\n"
            "<pre>pip install python-dotenv</pre>"
            "If you will use minimal example:\n"
            "<pre>pip install asyncio aiogram</pre>"
        ),
        (
            "🧾 <b>Step 2 — Create .env</b>\n\n"
            "Create <code>.env</code> in protected bot folder:\n"
            "<pre>"
            "TOKEN=<bot_token>"
            f"CHAT_TOKEN={chat_token}\n"
            f"KDEFENDER_API_BASE={api_base}\n"
            "</pre>\n\n"
            "You can put HTTPS URL here if you host it with Nginx."
        ),
        (
            "🧩 <b>Step 3 — How to K-Defender Web API</b>\n\n"
            "You can just use @kdefender_check() or specify parameter to check: @kdefender_check(param='parameter')\n\n"
            "Minimal example (aiogram v3):\n"
            "<pre>"
            "import os, asyncio\n"
            "from dotenv import load_dotenv\n"
            "from aiogram import Bot, Dispatcher\n"
            "from aiogram.types import Message\n"
            "from kdefender_wrapper import setup, close, kdefender_check\n\n"
            "# requires python-dotenv module\n"
            "load_dotenv()\n"
            "TOKEN = os.getenv('TOKEN')  # your bot token\n"
            "bot = Bot(TOKEN)\n"
            "dp = Dispatcher()\n\n"
            "CHAT_TOKEN = os.getenv('CHAT_TOKEN')\n"
            "URL = os.getenv('KDEFENDER_API_BASE')\n\n"
            "@dp.message()\n"
            "@kdefender_check()\n"
            "async def handler(message: Message):\n"
            "    await message.answer('OK (passed K-Defender)')\n\n"
            "async def main():\n"
            "    try:\n"
            f"        await setup(bot=bot, url=URL, chat_token=CHAT_TOKEN, lang='{language}')\n"
            "        await dp.start_polling(bot, polling_timeout=60)\n"
            "    finally:\n"
            "        await close()\n"
            "        await bot.session.close()\n\n"
            "if __name__ == '__main__':\n"
            "    asyncio.run(main())\n"
            "</pre>"
        ),
        (
            "🧪 <b>Step 4 — Quick test</b>\n\n"
            "1) Run your protected bot\n"
            "2) Send normal text → ok\n"
            "3) Send suspicious payload (SQLi/XSS) → blocked\n"
            f"You can send messages to K-Defender using <code>POST {api_base}/api/check</code> with JSON:\n"
            "<pre>{\"bot_id\": BOT_ID, \"token\": CHAT_TOKEN, \"text\": text}</pre>\n\n"
            "K-Defender will also send you DM about blocked messages."
        )
    ]


def make_protected_wiz_kb(user_id: int, bot_id: int, index: int, total: int):
    row = []
    if index > 0:
        row.append(InlineKeyboardButton(text=tr(user_id, "⬅ Prev"), callback_data=f"pw_prev:{bot_id}:{index}"))
    if index < total - 1:
        row.append(InlineKeyboardButton(text=tr(user_id, "Next ➡"), callback_data=f"pw_next:{bot_id}:{index}"))

    kb = []
    if row:
        kb.append(row)
    kb.append([InlineKeyboardButton(text=tr(user_id, "❌ Close"), callback_data=f"pw_close:{bot_id}")])
    return InlineKeyboardMarkup(inline_keyboard=kb)


# =========================
# Menus / panels
# =========================
@dp.message(Command("start"))
async def start_cmd(msg: Message):
    user_id = msg.from_user.id
    is_new = str(user_id) not in state
    ensure_user(user_id)
    st = get_user_settings(user_id)
    save_state()

    if not st.get("language_selected", False):
        await msg.answer(
            "<b>Choose your language</b>\n\n"
            "Select language. The whole bot UI will use it.",
            reply_markup=make_lang_kb(),
            parse_mode=ParseMode.HTML
        )
        return

    if is_new:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=tr(user_id, "➕ Start binding"), callback_data="bind_start")]
        ])
        await msg.answer(
            tr(
                user_id,
                "<b>K-Defender Activated</b>\n\n"
                f"Welcome to K-Defender, {html.escape(msg.from_user.first_name or '')}!\n"
                "Here you can connect your bot and see what was blocked or allowed.\n"
                "Press the button below to connect your bot."
            ),
            reply_markup=kb
        )
    else:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=tr(user_id, "Menu"), callback_data="menu")]
        ])
        await msg.answer(
            tr(user_id, f"Welcome back, {html.escape(msg.from_user.first_name or '')}!"),
            reply_markup=kb
        )


@dp.callback_query(F.data.startswith("lang:set:"))
async def set_language_callback(call: CallbackQuery):
    uid = call.from_user.id
    lang = call.data.split(":", 2)[2]
    if lang not in LANGUAGE_NAMES:
        await call.answer("Unsupported language", show_alert=True)
        return

    st = get_user_settings(uid)
    was_selected = st.get("language_selected", False)
    st["language"] = lang
    st["language_selected"] = True
    save_state()

    if was_selected:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=tr(uid, "📦 My bots"), callback_data="bots_info")],
            [InlineKeyboardButton(text=tr(uid, "📊 Stats"), callback_data="stats")],
            [InlineKeyboardButton(text=tr(uid, "🧾 Activity"), callback_data="activity")],
            [InlineKeyboardButton(text=tr(uid, "🌐 Language"), callback_data="lang:open")],
            [InlineKeyboardButton(text=tr(uid, "⚙️ Settings"), callback_data="settings")],
            [InlineKeyboardButton(text=tr(uid, "❓ Help"), callback_data="help")],
        ])
        await call.message.edit_text(tr(uid, "Menu"), reply_markup=kb)
    else:
        kb = InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=tr(uid, "➕ Start binding"), callback_data="bind_start")]
        ])
        await call.message.edit_text(
            tr(
                uid,
                "<b>K-Defender Activated</b>\n\n"
                f"Welcome to K-Defender, {html.escape(call.from_user.first_name or '')}!\n"
                "Here you can connect your bot and see what was blocked or allowed.\n"
                "Press the button below to connect your bot."
            ),
            reply_markup=kb,
            parse_mode=ParseMode.HTML
        )
    await call.answer(tr(uid, "Saved ✅"))


@dp.message(Command("menu"))
async def menu_cmd_handler(msg: Message):
    msg = await msg.answer(tr(msg.from_user.id, "Loading..."))
    await menu_cmd(msg)


@dp.callback_query(F.data == "menu")
async def menu_callback_handler(call: CallbackQuery):
    await menu_cmd(call.message)


async def menu_cmd(msg: Message):
    uid = msg.chat.id
    ensure_user(uid)
    st = get_user_settings(uid)
    if not st.get("language_selected", False):
        await edit_msg(
            msg,
            "<b>Choose your language</b>\n\nSelect language. The whole bot UI will use it.",
            reply_markup=make_lang_kb(),
            parse_mode=ParseMode.HTML
        )
        return

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=tr(uid, "📦 My bots"), callback_data="bots_info")],
        [InlineKeyboardButton(text=tr(uid, "📊 Stats"), callback_data="stats")],
        [InlineKeyboardButton(text=tr(uid, "🧾 Activity"), callback_data="activity")],
        [InlineKeyboardButton(text=tr(uid, "🌐 Language"), callback_data="lang:open")],
        [InlineKeyboardButton(text=tr(uid, "⚙️ Settings"), callback_data="settings")],
        [InlineKeyboardButton(text=tr(uid, "❓ Help"), callback_data="help")],
    ])

    await edit_msg(msg, f"🏠 {tr(uid, 'Menu')}", reply_markup=kb)

@dp.callback_query(F.data == "stats")
async def stats_panel(call: CallbackQuery):
    user = str(call.from_user.id)
    ensure_user(user)
    bots = real_bots_dict(user)

    total_bots = len(bots)
    total_msgs = 0
    total_blocked = 0
    for b in bots.values():
        total_msgs += int(b.get("stats_total", 0))
        total_blocked += int(b.get("stats_blocked", 0))

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=tr(call.from_user.id, "⬅ Back"), callback_data="menu")]
    ])

    await edit_msg(
        call.message,
        tr(
            call.from_user.id,
            "<b>📊 Stats</b>\n\n"
            f"Protected bots: <b>{total_bots}</b>\n"
            f"Checked messages: <b>{total_msgs}</b>\n"
            f"Blocked messages: <b>{total_blocked}</b>\n\n"
            "Tip: open <b>My bots</b> to see per-bot details."
        ),
        reply_markup=kb,
        parse_mode=ParseMode.HTML
    )
    await call.answer()


@dp.callback_query(F.data == "activity")
async def activity_panel(call: CallbackQuery):
    await show_activity_page(call, page=0)



async def show_activity_page(call: CallbackQuery, page: int):
    user_id = call.from_user.id
    ensure_user(user_id)

    bots = real_bots_dict(user_id)

    items = []
    for b in bots.values():
        name = b.get("bot_username", "unknown")
        for entry in (b.get("logs") or []):
            items.append((name, entry))

    items.sort(
        key=lambda x: float(x[1].get("time", 0)) if isinstance(x[1], dict) else 0,
        reverse=True
    )

    total_logs = len(items)
    total_pages = max((total_logs - 1) // LOGS_PER_PAGE + 1, 1)

    if page < 0:
        page = 0
    if page >= total_pages:
        page = total_pages - 1

    start = page * LOGS_PER_PAGE
    end = start + LOGS_PER_PAGE
    page_logs = items[start:end]

    if not page_logs:
        text = tr(user_id, "<b>No logs yet.</b>")
    else:
        text = tr(user_id, f"<b>Last messages</b>\n\n")
        for name, t in page_logs:
            if isinstance(t, dict):
                status = str(t.get("status", "unknown"))
                msg_text = str(t.get("text", ""))

                stamp = t.get("time")
                if stamp:
                    try:
                        ts = datetime.fromtimestamp(float(stamp)).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts = "unknown-time"
                else:
                    ts = "unknown-time"

                short = (msg_text[:80] + "…") if len(msg_text) > 80 else msg_text

                text += tr(user_id,
                    f"• <code>@{html.escape(name)}</code>: [{html.escape(status)}] <code>{html.escape(short)}</code> <code>{html.escape(ts)}</code>\n"
                )

    nav_row = []
    if page > 0:
        nav_row.append(
            InlineKeyboardButton(
                text="⬅ Prev",
                callback_data=f"activity_page:{page-1}"
            )
        )

    nav_row.append(
        InlineKeyboardButton(
            text=f"{page+1}/{total_pages}",
            callback_data="noop"
        )
    )

    if page < total_pages - 1:
        nav_row.append(
            InlineKeyboardButton(
                text="Next ➡",
                callback_data=f"activity_page:{page+1}"
            )
        )

    kb = InlineKeyboardMarkup(inline_keyboard=[
        nav_row,
        [InlineKeyboardButton(text="⬅ Back", callback_data="menu")]
    ])

    await edit_msg(call.message, text, reply_markup=kb, parse_mode=ParseMode.HTML)
    await call.answer()

@dp.callback_query(F.data.startswith("activity_page:"))
async def activity_page_handler(call: CallbackQuery):
    page = int(call.data.split(":")[1])
    await show_activity_page(call, page)


@dp.message(Command("help"))
async def help_cmd_handler(msg: Message):
    msg = await msg.answer(tr(msg.from_user.id, "Loading..."))
    await help_cmd(msg)


@dp.callback_query(F.data == "help")
async def help_callback_handler(call: CallbackQuery):
    await help_cmd(call.message)


async def help_cmd(msg: Message):
    uid = msg.chat.id
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=tr(uid, "⬅ Back"), callback_data="menu")]
    ])
    await edit_msg(
        msg,
        tr(
            uid,
            "<b>❓ Help</b>\n\n"
            "K-Defender protects your bot from suspicious messages.\n\n"
            "<b>How it works now:</b>\n"
            "• Your protected bot sends message to K-Defender <b>Web API</b>\n"
            "• K-Defender returns JSON: <code>{\"result\":\"ok\"}</code> / <code>{\"result\":\"blocked\"}</code>\n"
            "• Wrapper allows/blocks handler execution\n\n"
            "Commands:\n"
            "• <code>/start</code> — start or restart the bot\n"
            "• <code>/menu</code> — open the main menu\n"
            "• <code>/help</code> — show this help message\n"
        ),
        reply_markup=kb
    )


def settings_kb(user_id: int) -> InlineKeyboardMarkup:
    st = get_user_settings(user_id)
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=tr(user_id, f"🛡️ Protection: {_onoff(st['enabled'])}"), callback_data="set:enabled")],
        [InlineKeyboardButton(text=tr(user_id, f"⚡ Strict mode: {_onoff(st['strict'])}"), callback_data="set:strict")],
        [InlineKeyboardButton(text=tr(user_id, f"🧯 Mode: {_mode_label(st['mode'])}"), callback_data="set:mode")],
        [InlineKeyboardButton(text=tr(user_id, "⬅ Back"), callback_data="menu")]
    ])


def settings_text(user_id: int) -> str:
    st = get_user_settings(user_id)

    if not st["enabled"]:
        status = "🔴 Protection is OFF"
    elif st["mode"] == "allow_all":
        status = "🟡 Protection paused (Allow All)"
    elif st["mode"] == "block_all":
        status = "🔴 Lockdown (Block All)"
    else:
        status = "🟢 Protection active"

    return (
        tr(
            user_id,
            "<b>⚙️ Settings</b>\n\n"
            f"<b>Status:</b> {status}\n\n"
            "Use buttons to change behavior.\n"
            "• <b>Strict mode</b>: blocks more suspicious messages\n"
            "• <b>Mode</b>: emergency switch\n"
        )
    )


@dp.callback_query(F.data == "settings")
async def settings_callback_handler(call: CallbackQuery):
    uid = call.from_user.id
    await call.message.edit_text(
        settings_text(uid),
        parse_mode=ParseMode.HTML,
        reply_markup=settings_kb(uid),
        disable_web_page_preview=True
    )
    await call.answer()


@dp.callback_query(F.data == "lang:open")
async def open_language_picker(call: CallbackQuery):
    uid = call.from_user.id
    await call.message.edit_text(
        tr(
            uid,
            "<b>Choose your language</b>\n\n"
            "Select language. The whole bot UI will use it."
        ),
        reply_markup=make_lang_kb(),
        parse_mode=ParseMode.HTML
    )
    await call.answer()


@dp.callback_query(F.data.startswith("set:"))
async def settings_click(call: CallbackQuery):
    uid = call.from_user.id
    st = get_user_settings(uid)
    action = call.data.split(":", 1)[1]

    if action == "enabled":
        st["enabled"] = not st["enabled"]
    elif action == "strict":
        st["strict"] = not st["strict"]
    elif action == "mode":
        order = ["normal", "allow_all", "block_all"]
        st["mode"] = order[(order.index(st["mode"]) + 1) % len(order)]

    save_state()

    await call.message.edit_text(
        settings_text(uid),
        parse_mode=ParseMode.HTML,
        reply_markup=settings_kb(uid),
        disable_web_page_preview=True
    )
    await call.answer(tr(uid, "Saved ✅"))


@dp.callback_query(F.data == "bots_info")
async def bots_info(call: CallbackQuery):
    ensure_user(call.from_user.id)

    btn_arr = []
    for bot_id, data in real_bots_dict(call.from_user.id).items():
        uname = data.get("bot_username")
        if not uname:
            continue
        btn_arr.append(
            InlineKeyboardButton(
                text=f"@{uname}",
                callback_data=f"bot_{uname}"
            )
        )

    rows = []
    if btn_arr:
        rows.append(btn_arr)

    rows.append([InlineKeyboardButton(text=tr(call.from_user.id, "Add Bot"), callback_data="bind_start")])
    rows.append([InlineKeyboardButton(text=tr(call.from_user.id, "⬅ Back"), callback_data="menu")])

    kb = InlineKeyboardMarkup(inline_keyboard=rows)
    message = tr(call.from_user.id, "\nNo bots connected. Add one by pressing the button below.") if not btn_arr else ""

    await call.message.edit_text(
        f"{tr(call.from_user.id, '<code>Bots Info</code>')}{message}",
        reply_markup=kb
    )
    await call.answer()


@dp.callback_query(F.data.startswith("botset_"))
async def bot_settings_toggle(call: CallbackQuery):
    bot_username, setting = call.data.split(":")
    bot_username = "_".join(bot_username.split("_")[1:])

    # Find bot record by username (skip draft)
    for bid, b in real_bots_dict(call.from_user.id).items():
        if b.get("bot_username") == bot_username:
            st = b.setdefault("settings", {})
            for k, v in DEFAULT_BOT_SETTINGS.items():
                st.setdefault(k, v)

            st[setting] = not st.get(setting, False)

            save_state()
            await call.answer(tr(call.from_user.id, f"{setting.upper()} → {'ON' if st[setting] else 'OFF'}"), show_alert=False)
            return await show_bot_panel(call.message, b, bid)

    await call.answer(tr(call.from_user.id, "Bot not found"), show_alert=True)


@dp.callback_query(F.data.startswith("botlogs_") & ~F.data.startswith("botlogs_page:"))
async def bot_show_logs(call: CallbackQuery):
    bot_username = "_".join(call.data.split("_")[1:])
    await show_bot_logs_page(call, bot_username, page=0)

async def show_bot_logs_page(call: CallbackQuery, bot_username: str, page: int):
    user_id = call.from_user.id

    b = None
    bot_id = None

    for bid, data in real_bots_dict(user_id).items():
        if data.get("bot_username") == bot_username:
            b = data
            bot_id = bid
            break

    if not b:
        return await call.answer("Bot not found", show_alert=True)

    logs = b.get("logs", [])

    # сортировка новые → старые
    logs = sorted(
        logs,
        key=lambda x: float(x.get("time", 0)) if isinstance(x, dict) else 0,
        reverse=True
    )

    total_logs = len(logs)
    total_pages = max((total_logs - 1) // LOGS_PER_PAGE + 1, 1)

    if page < 0:
        page = 0
    if page >= total_pages:
        page = total_pages - 1

    start = page * LOGS_PER_PAGE
    end = start + LOGS_PER_PAGE
    page_logs = logs[start:end]

    if not page_logs:
        text = tr(user_id, f"<b>@{html.escape(bot_username)} — No logs yet.</b>")
    else:
        text = tr(user_id, f"<b>@{html.escape(bot_username)} logs</b>\n\n")
        for item in page_logs:
            if isinstance(item, dict):
                status = str(item.get("status", "unknown"))
                msg_text = str(item.get("text", ""))

                stamp = item.get("time")
                if stamp:
                    try:
                        ts = datetime.fromtimestamp(float(stamp)).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts = "unknown-time"
                else:
                    ts = "unknown-time"

                short = (msg_text[:80] + "…") if len(msg_text) > 80 else msg_text

                text += tr(user_id,
                    f"• [{html.escape(status)}] <code> {html.escape(short)} </code> <code>{html.escape(ts)}</code>\n"
                )

    nav_row = []

    if page > 0:
        nav_row.append(
            InlineKeyboardButton(
                text="⬅ Prev",
                callback_data=f"botlogs_page:{bot_username}:{page-1}"
            )
        )

    nav_row.append(
        InlineKeyboardButton(
            text=f"{page+1}/{total_pages}",
            callback_data="noop"
        )
    )

    if page < total_pages - 1:
        nav_row.append(
            InlineKeyboardButton(
                text="Next ➡",
                callback_data=f"botlogs_page:{bot_username}:{page+1}"
            )
        )

    kb = InlineKeyboardMarkup(inline_keyboard=[
        nav_row,
        [InlineKeyboardButton(text="⬅ Back", callback_data=f"botstats_{bot_username}")]
    ])

    await edit_msg(call.message, text, parse_mode=ParseMode.HTML, reply_markup=kb)
    await call.answer()

@dp.callback_query(F.data.startswith("botlogs_page:"))
async def bot_logs_page_handler(call: CallbackQuery):
    _, bot_username, page = call.data.split(":")
    await show_bot_logs_page(call, bot_username, int(page))


from datetime import datetime, timezone

STATUS_SAFE_VALUES = {"safe", "ok", "allowed"}
STATUS_BLOCKED_VALUES = {"blocked"}

def _bucket_ts(ts: float, step_sec: int) -> float:
    return ts - (ts % step_sec)

def _normalize_status(raw_status: Any) -> str | None:
    status = str(raw_status or "").strip().lower()
    if status in STATUS_BLOCKED_VALUES:
        return "blocked"
    if status in STATUS_SAFE_VALUES:
        return "safe"
    return None

def _iter_valid_logs(logs: list[dict]):
    for e in logs or []:
        if not isinstance(e, dict):
            continue
        try:
            t = float(e.get("time", 0) or 0)
        except (TypeError, ValueError):
            continue
        if t <= 0:
            continue
        status = _normalize_status(e.get("status"))
        if not status:
            continue
        yield t, status

def _build_timeline_series(logs: list[dict], window_sec: int, step_sec: int, now_ts: float | None = None):
    now_ts = now_ts or datetime.now().timestamp()
    since_ts = max(now_ts - window_sec, 0)
    start_bucket = int(_bucket_ts(since_ts, step_sec))
    end_bucket = int(_bucket_ts(now_ts, step_sec))

    if end_bucket < start_bucket:
        end_bucket = start_bucket

    buckets = {}
    cursor = start_bucket
    while cursor <= end_bucket:
        buckets[cursor] = {"safe": 0, "blocked": 0}
        cursor += step_sec

    for t, status in _iter_valid_logs(logs):
        if t < since_ts or t > now_ts:
            continue
        b = int(_bucket_ts(t, step_sec))
        if b < start_bucket or b > end_bucket:
            continue
        buckets[b][status] += 1

    keys = sorted(buckets.keys())
    xs = [datetime.fromtimestamp(k) for k in keys]
    safe = [buckets[k]["safe"] for k in keys]
    blocked = [buckets[k]["blocked"] for k in keys]
    return xs, safe, blocked

def generate_timeline_chart(user_id: int, title: str, logs: list[dict], window_sec: int, step_sec: int):
    xs, safe, blocked = _build_timeline_series(logs, window_sec=window_sec, step_sec=step_sec)

    fig, ax = plt.subplots(figsize=(8, 4))

    ax.plot(xs, safe, color="green", label=tr(user_id, "Safe"))
    ax.plot(xs, blocked, color="red", label=tr(user_id, "Blocked"))

    ax.set_title(tr(user_id, title))
    ax.set_xlabel(tr(user_id, "Time"))
    ax.set_ylabel(tr(user_id, "Messages"))

    ax.legend()
    max_y = max(safe + blocked + [1])
    ax.set_ylim(0, max(3, int(max_y * 1.2) + 1))
    ax.grid(alpha=0.2)
    fig.autofmt_xdate()

    buf = BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png")
    plt.close(fig)
    buf.seek(0)
    return buf


def make_bot_stats_kb(user_id: int, bot_id: str, bot_username: str):
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=tr(user_id, "🧾 View logs"), callback_data=f"botlogs_{bot_username}")],
        [InlineKeyboardButton(text=tr(user_id, "⬅ Back to bot"), callback_data=f"bot_{bot_username}")],
    ])

@dp.callback_query(F.data.startswith("botstats_"))
async def bot_stats_handler(call: CallbackQuery):
    user_id = call.from_user.id
    bot_username = call.data.split("_", 1)[1]

    b = None
    bot_id = None
    for bid, data in real_bots_dict(user_id).items():
        if data.get("bot_username") == bot_username:
            b = data
            bot_id = str(bid)
            break

    if not b:
        return await call.answer(tr(user_id, "Bot not found"), show_alert=True)

    total = int(b.get("stats_total", 0))
    blocked = int(b.get("stats_blocked", 0))
    allowed = max(total - blocked, 0)

    caption = tr(
        user_id,
        f"📊 <b>Bot statistics</b>\n\n"
        f"🤖 Bot: <code>@{html.escape(bot_username)}</code>\n\n"
        f"📨 Messages checked: <b>{total}</b>\n"
        f"✅ Allowed: <b>{allowed}</b>\n"
        f"🚫 Blocked: <b>{blocked}</b>\n\n"
        f"ℹ️ <i>Blocked messages were detected as suspicious.\n"
        f"Allowed messages passed security checks.</i>"
    )

    chart = generate_timeline_chart(
        user_id=user_id,
        title=f"@{bot_username} activity (24h)",
        logs=b.get("logs", []),
        window_sec=24 * 3600,
        step_sec=10 * 60,
    )
    kb = make_bot_stats_kb(user_id, bot_id or "", bot_username)

    try:
        await call.message.delete()
    except Exception:
        pass

    await bot.send_photo(
        chat_id=user_id,
        photo=types.BufferedInputFile(chart.getvalue(), filename="bot_stats_24h.png"),
        caption=caption,
        parse_mode=ParseMode.HTML,
        reply_markup=kb
    )

    await call.answer()


async def show_bot_panel(msg: Message, bot_state: dict, bot_id: str):
    uid = msg.chat.id
    bot_username = bot_state.get("bot_username") or "unknown"
    settings = bot_state.setdefault("settings", {})
    for k, v in DEFAULT_BOT_SETTINGS.items():
        settings.setdefault(k, v)

    total = int(bot_state.get("stats_total", 0))
    blocked = int(bot_state.get("stats_blocked", 0))
    allowed = total - blocked

    text = tr(
        uid,
        f"<b>Bot: @{html.escape(bot_username)}</b>\n"
        f"ID: <code>{html.escape(str(bot_id))}</code>\n\n"
        f"<b>Statistics:</b>\n"
        f"• Total messages: <b>{total}</b>\n"
        f"• Allowed: <b>{allowed}</b>\n"
        f"• Blocked: <b>{blocked}</b>\n\n"
        f"<b>WAF Settings:</b>"
    )

    kb_rows = []
    for inj in settings.keys():
        kb_rows.append([
            InlineKeyboardButton(
                text=tr(uid, f"{inj}: {'🟢 ON' if settings.get(inj, False) else '🔴 OFF'}"),
                callback_data=f"botset_{bot_username}:{inj}"
            )
        ])

    kb_rows.append([InlineKeyboardButton(text=tr(uid, "📊 Statistics"), callback_data=f"botstats_{bot_username}")])
    kb_rows.append([InlineKeyboardButton(text=tr(uid, "🔁 Reset access token"), callback_data=f"botresettoken_{bot_id}|{bot_username}")])
    kb_rows.append([InlineKeyboardButton(text=tr(uid, "🗑 Delete bot"), callback_data=f"botdelete_{bot_id}|{bot_username}")])
    kb_rows.append([InlineKeyboardButton(text=tr(uid, "⬅ Back"), callback_data="bots_info")])

    await edit_msg(msg, text, reply_markup=InlineKeyboardMarkup(inline_keyboard=kb_rows), parse_mode=ParseMode.HTML)


@dp.callback_query(F.data.startswith("botresettoken_"))
async def bot_reset_token_confirm(call: CallbackQuery):
    bot_info = "".join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]
    bot_username = bot_info.split("|", 1)[1]

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text=tr(call.from_user.id, "✅ Yes, reset"), callback_data=f"botresettokenyes_{bot_id}|{bot_username}"),
            InlineKeyboardButton(text=tr(call.from_user.id, "❌ Cancel"), callback_data=f"bot_{bot_username}")
        ]
    ])

    await call.message.edit_text(
        tr(
            call.from_user.id,
            "<b>🔁 Reset access token?</b>\n\n"
            "This will immediately disable the current token.\n\n"
            "Your protected bot will stop receiving checks until you "
            "update the new token in its <code>.env</code> file and restart it.\n\n"
            "Are you sure?"
        ),
        reply_markup=kb,
        parse_mode="HTML"
    )
    await call.answer()


@dp.callback_query(F.data.startswith("botresettokenyes_"))
async def bot_reset_token_apply(call: CallbackQuery):
    user_id = call.from_user.id
    bot_info = "".join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]
    bot_username = bot_info.split("|", 1)[1]

    try:
        new_token = reset_bot_token(user_id, bot_id)
    except Exception:
        await call.answer(tr(user_id, "Failed to reset token"), show_alert=True)
        return

    await call.message.edit_text(
        tr(
            user_id,
            "<b>✅ Token reset successful</b>\n\n"
            "Here is your new access token:\n"
            f"<code>{html.escape(new_token)}</code>\n\n"
            "<b>What to do next:</b>\n"
            "1) Open your protected bot project\n"
            "2) Replace <code>CHAT_TOKEN</code> in <code>.env</code>\n"
            "3) Restart the bot\n\n"
            "The old token no longer works."
        ),
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=tr(user_id, "⬅ Back to bot"), callback_data=f"bot_{bot_username}")]
        ])
    )
    await call.answer(tr(user_id, "Token reset"))


@dp.callback_query(F.data.startswith("botdelete_"))
async def bot_delete_confirm(call: CallbackQuery):
    bot_info = "".join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]
    bot_username = bot_info.split("|", 1)[1]

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text=tr(call.from_user.id, "✅ Yes, delete"), callback_data=f"botdeleteyes_{bot_id}|{bot_username}"),
            InlineKeyboardButton(text=tr(call.from_user.id, "❌ Cancel"), callback_data=f"bot_{bot_username}")
        ]
    ])

    await call.message.edit_text(
        tr(
            call.from_user.id,
            "<b>🗑 Delete bot?</b>\n\n"
            "This will immediately delete this bot from protection.\n\n"
            "Remove the wrapper call in your protected bot and restart it.\n\n"
            "Are you sure?"
        ),
        reply_markup=kb,
        parse_mode="HTML"
    )
    await call.answer()


@dp.callback_query(F.data.startswith("botdeleteyes_"))
async def bot_delete_apply(call: CallbackQuery):
    user_id = call.from_user.id
    bot_info = "".join(call.data.split("_", 1)[1])
    bot_id = bot_info.split("|", 1)[0]

    try:
        delete_bot(user_id, bot_id)
    except Exception:
        await call.answer(tr(user_id, "Failed to delete bot"), show_alert=True)
        return

    await call.message.edit_text(
        tr(
            user_id,
            "<b>✅ Bot deleted successfully</b>\n\n"
            "Protection is now removed for this bot."
        ),
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text=tr(user_id, "⬅ Back"), callback_data="bots_info")]
        ])
    )
    await call.answer(tr(user_id, "Bot deleted"))


@dp.callback_query(F.data.startswith("bot_"))
async def bot_info(call: CallbackQuery):
    bot_username = "_".join(call.data.split("_")[1:])
    bot_state = None
    bot_id = None

    for bid, b in real_bots_dict(call.from_user.id).items():
        if b.get("bot_username") == bot_username:
            bot_state = b
            bot_id = bid
            break

    if not bot_state:
        return await call.answer(tr(call.from_user.id, "Bot not found"), show_alert=True)

    return await show_bot_panel(call.message, bot_state, bot_id)


# =========================
# Binding wizard
# =========================
@dp.callback_query(F.data == "bind_start")
async def bind_start(call: CallbackQuery, state: FSMContext):
    uid = call.from_user.id
    nb = ensure_draft(uid, reset=True)
    nb["step"] = 2
    nb["instr_page"] = 0
    nb["verified"] = False
    global DEFAULT_BOT_SETTINGS
    for k, v in DEFAULT_BOT_SETTINGS.items():
        nb["settings"].setdefault(k, v)
    save_state()

    kb = ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(
                    text=tr(uid, "📎 Send Bot Contact"),
                    request_user=KeyboardButtonRequestUser(
                        request_id=1,
                        user_is_bot=True
                    )
                )
            ]
        ],
        resize_keyboard=True,
        one_time_keyboard=True,
        is_persistent=True
    )

    await call.message.delete()
    await call.message.answer(
        tr(uid, "Please select a bot to add it to K-Defender."),
        reply_markup=kb
    )

    '''
    await call.message.edit_text(
        setup_pages[0],
        reply_markup=make_nav_kb("setup", 0),
        parse_mode=ParseMode.HTML
    )
    await call.answer()'''


@dp.callback_query(
    F.data.in_(["open_getid:0", "cancel_setup"]) |
    F.data.startswith(("setup_next:", "setup_prev:", "open_setup:"))
)
async def setup_nav(call: CallbackQuery):
    uid = call.from_user.id
    nb = ensure_draft(uid, reset=False)
    data = call.data

    if data == "cancel_setup":
        drop_draft(uid)
        save_state()
        await call.message.edit_text(tr(uid, "Setup cancelled. Send /start to begin again."))
        await call.answer()
        return

    if data.startswith("open_setup:"):
        idx = int(data.split(":", 1)[1])
        nb["instr_page"] = idx
        save_state()
        await call.message.edit_text(
            tr(uid, setup_pages[idx]),
            reply_markup=make_nav_kb(uid, "setup", idx),
            parse_mode=ParseMode.HTML
        )
        await call.answer()
        return

    if data == "open_getid:0":
        nb["instr_page"] = 0
        save_state()
        await call.message.edit_text(
            tr(uid, get_id_pages[0]),
            reply_markup=make_nav_kb(uid, "getid", 0),
            parse_mode=ParseMode.HTML
        )
        await call.answer()
        return

    kind, raw = data.split(":", 1)
    idx = int(raw)
    if kind == "setup_next":
        idx = min(idx + 1, len(setup_pages) - 1)
    elif kind == "setup_prev":
        idx = max(idx - 1, 0)

    nb["instr_page"] = idx
    save_state()
    await call.message.edit_text(
        tr(uid, setup_pages[idx]),
        reply_markup=make_nav_kb(uid, "setup", idx),
        parse_mode=ParseMode.HTML
    )
    await call.answer()


@dp.callback_query(F.data.startswith(("getid_next:", "getid_prev:")))
async def getid_nav(call: CallbackQuery):
    uid = call.from_user.id
    nb = ensure_draft(uid, reset=False)

    kind, raw = call.data.split(":", 1)
    idx = int(raw)
    if kind == "getid_next":
        idx = min(idx + 1, len(get_id_pages) - 1)
    elif kind == "getid_prev":
        idx = max(idx - 1, 0)

    nb["instr_page"] = idx
    save_state()
    await call.message.edit_text(
        tr(uid, get_id_pages[idx]),
        reply_markup=make_nav_kb(uid, "getid", idx),
        parse_mode=ParseMode.HTML
    )
    await call.answer()

@dp.message(F.user_shared)
async def user_shared_handler(message: Message):
    shared = message.user_shared

    bot_id = shared.user_id

    chat = await bot.get_chat(bot_id)

    await message.answer(
        tr(
            message.from_user.id,
            f"🤖 Selected bot:\n\n"
            f"ID: <code>{bot_id}</code>\n"
            f"Username: @{chat.username if chat.username else 'N/A'}\n"
            f"Name: {chat.first_name or ''}\n"
            f"Are you <b>sure</b>?"
        ),
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [
                InlineKeyboardButton(text=tr(message.from_user.id, "✅ Yes, connect"), callback_data=f"confirm_add_bot:{bot_id}"),
                InlineKeyboardButton(text=tr(message.from_user.id, "❌ No, cancel"), callback_data="cancel_setup")
            ]
        ]),
        parse_mode=ParseMode.HTML
    )

@dp.callback_query(F.data.startswith("confirm_add_bot:"))
async def confirm_add_bot(call: CallbackQuery):

    await call.message.delete()

    uid = call.from_user.id
    bot_id_s = call.data.split(":")[1]

    bots = bots_of(uid)
    
    if bot_id_s in bots:
        await call.answer(tr(uid, "This bot is already connected."), show_alert=True)
        return

    try:
        chat = await bot.get_chat(bot_id_s)
        bot_username = chat.username or f"bot_{bot_id_s}"
    except Exception:
        await call.answer(tr(uid, "Failed to fetch bot info."), show_alert=True)
        return

    b = ensure_bot(uid, bot_id_s)
    b["bot_username"] = bot_username
    b["step"] = 5
    b["instr_page"] = 0

    nb = bots.get(DRAFT_BOT_KEY)

    if not nb:
        return
    #print(nb, nb.get("settings"))

    if isinstance(nb.get("settings"), dict) and nb["settings"]:
        b.setdefault("settings", {})
        for k, v in nb["settings"].items():
            b["settings"][k] = v
        
    #print("Bot state after copy:", b.get("settings"))

    bots.pop(DRAFT_BOT_KEY, None)
    connect_str = secrets.token_hex(32)
    b["webhook"] = connect_str
    save_state()

    global api_base, save_verify_msg
    webhook_url = f"https://api.telegram.org/bot&lt;TOKEN&gt;/setWebhook?url={api_base}/webhook/{connect_str}/"
    msg = await call.message.answer(
        tr(
            uid,
            f"Now stop @{b['bot_username']} and visit this URL to confirm that this is your bot:\n"
            f"<pre>{webhook_url}</pre>\n"
            f"After that send <code>/verify_webhook {connect_str}</code> to your bot and wait for the confirmation message here."
        ),
        parse_mode=ParseMode.HTML
    )
    save_verify_msg = msg

async def handle_webhook_verified(uid: int, bot_id_s: str, msg: Message):
    b = ensure_bot(uid, bot_id_s)
    b["verified"] = True
    token = generate_bot_token(b["bot_username"])
    b["bot_token"] = token
    b.pop("webhook", None)

    # Build wizard pages
    global api_base
    me = await bot.get_me()

    pages = build_protected_bot_pages(
        api_base=api_base,
        bot_id=str(bot_id_s),
        chat_token=token,
        kdefender_id=me.id,
        protected_username=b["bot_username"],
        user_id=uid
    )
    pages = [tr(uid, p) for p in pages]

    b["protected_wizard"] = {"index": 0, "pages": pages}

    save_state()

    await msg.delete()

    await bot.send_message(
        uid,
        pages[0],
        parse_mode=ParseMode.HTML,
        reply_markup=make_protected_wiz_kb(uid, int(bot_id_s), 0, len(pages)),
        disable_web_page_preview=True
    )

@dp.callback_query(F.data.startswith(("pw_next:", "pw_prev:", "pw_close:")))
async def protected_wizard_nav(call: CallbackQuery):
    uid = call.from_user.id
    ensure_user(uid)

    if call.data.startswith("pw_close:"):
        try:
            await call.message.delete()
        except Exception:
            pass
        await call.answer(tr(uid, "Closed."))
        return

    kind, bot_id_s, raw = call.data.split(":", 2)
    idx = int(raw)

    b = bots_of(uid).get(str(bot_id_s))
    if not b or not b.get("protected_wizard"):
        await call.answer(tr(uid, "Wizard expired. Re-connect if needed."), show_alert=True)
        return

    wiz = b["protected_wizard"]
    pages = wiz.get("pages") or []
    if not pages:
        await call.answer(tr(uid, "Wizard empty."), show_alert=True)
        return

    if kind == "pw_next":
        idx = min(idx + 1, len(pages) - 1)
    else:
        idx = max(idx - 1, 0)

    wiz["index"] = idx
    save_state()

    await call.message.edit_text(
        pages[idx],
        parse_mode=ParseMode.HTML,
        reply_markup=make_protected_wiz_kb(uid, int(bot_id_s), idx, len(pages)),
        disable_web_page_preview=True
    )
    await call.answer()

# =========================
# MAIN
# =========================
async def main():
    me = await bot.get_me()
    print(f"K-Defender running as @{me.username} ({me.id})")

    global _autosave_task, _alerts_task
    _autosave_task = asyncio.create_task(autosave_loop())
    _alerts_task = asyncio.create_task(alerts_delivery_loop())

    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot, polling_timeout=60)
    finally:
        for t in (_autosave_task, _alerts_task):
            if t:
                t.cancel()
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("K-Defender stopped by user")
