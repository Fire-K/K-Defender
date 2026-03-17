import re
import html
import base64
import binascii
import codecs
import unicodedata
from collections import deque
from urllib.parse import unquote_plus, unquote

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_WS_RE = re.compile(r"\s+")

_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
_B32_RE = re.compile(r"^[A-Z2-7=]{8,}$", re.IGNORECASE)
_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{8,}$")
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")
_UNICODE_ESC_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}){1,}")
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);")

SQLI_PATTERNS = [
    "union select", "select ", "drop table", "insert into", "delete from",
    " or 1=1", "' or '1'='1", "\" or \"1\"=\"1", "--", "/*", "*/",
]
XSS_PATTERNS = [
    "<script", "javascript:", "onerror=", "onload=", "alert(",
    "<img", "<svg", "document.cookie", "eval(",
]


def _truncate(s: str, max_len: int) -> str:
    return s[:max_len] if len(s) > max_len else s


def _safe_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(ch.isprintable() for ch in s)
    return printable / max(1, len(s))


def _signal_score(s: str) -> float:

    if not s:
        return -10

    score = 0

    lowered = s.lower()

    keywords = [
        "union select",
        "select",
        "insert",
        "drop",
        "delete",
        "<script",
        "javascript:",
        "alert(",
        "onerror",
        "onload"
    ]

    for k in keywords:
        if k in lowered:
            score += 8

    if "<" in s and ">" in s:
        score += 2

    letters = sum(c.isalpha() for c in s)
    score += letters * 0.05

    non_print = sum(not c.isprintable() for c in s)
    score -= non_print * 2

    weird = sum(c in "¦§¤¨©±÷×¼½¾¿" for c in s)
    score -= weird * 3

    #if re.fullmatch(r"[A-Za-z0-9+/=_-]{30,}", s):
    #   score -= 3

    if "%" in s:
        score -= 1

    if "\\" in s:
        score -= 1

    return score


def _basic_cleanup(
    s: str,
    *,
    lowercase: bool,
    nfkc: bool,
    strip_zero_width: bool,
    strip_controls: bool,
    collapse_whitespace: bool,
    max_len: int,
) -> str:
    s = "" if s is None else str(s)
    s = _truncate(s, max_len)

    if nfkc:
        s = unicodedata.normalize("NFKC", s)

    if strip_zero_width:
        s = _ZERO_WIDTH_RE.sub("", s)

    if strip_controls:
        s = _CTRL_RE.sub("", s)

    if collapse_whitespace:
        s = _WS_RE.sub(" ", s).strip()

    if lowercase:
        s = s.lower()

    return _truncate(s, max_len)


def _decode_url(s: str) -> list[str]:
    out = []

    for fn in (unquote, unquote_plus):
        try:
            decoded = fn(s)
            if decoded != s:
                out.append(decoded)
        except Exception:
            pass

    return out


def _decode_html_entities(s: str) -> list[str]:
    try:
        decoded = html.unescape(s)
        return [decoded] if decoded != s else []
    except Exception:
        return []


def _decode_unicode_escapes(s: str) -> list[str]:
    out = []

    if not _UNICODE_ESC_RE.search(s) and not _HEX_ESC_RE.search(s):
        return []

    def repl_u(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    def repl_U(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    def repl_x(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    s2 = re.sub(r"\\u([0-9a-fA-F]{4})", repl_u, s)
    s2 = re.sub(r"\\U([0-9a-fA-F]{8})", repl_U, s2)
    s2 = re.sub(r"\\x([0-9a-fA-F]{2})", repl_x, s2)
    if s2 != s:
        out.append(s2)

    if "\\" in s:
        try:
            dec = codecs.decode(s.encode(), "unicode_escape").decode("utf-8", "ignore")
            if dec != s:
                out.append(dec)
        except Exception:
            pass

    return list(dict.fromkeys(out))


def _looks_textual(s: str) -> bool:
    if not s:
        return False

    printable = sum(c.isprintable() for c in s)
    ratio = printable / len(s)

    if ratio < 0.6:
        return False

    return True


def _decode_hex_blob(s: str, max_out: int) -> list[str]:
    t = s.strip()
    if t.startswith("0x"):
        t = t[2:]

    if not _HEX_RE.fullmatch(s.strip()):
        return []

    if len(t) % 2 != 0:
        return []

    try:
        raw = bytes.fromhex(t)
    except Exception:
        return []

    if not raw or len(raw) > max_out:
        return []

    out = []
    for enc in ("utf-8", "latin-1"):
        try:
            dec = raw.decode(enc)
            if _safe_ratio(dec) >= 0.7:
                out.append(dec)
        except Exception:
            pass
    return list(dict.fromkeys(out))


def _decode_hex_escapes_blob(s: str) -> list[str]:
    if not _HEX_ESC_RE.search(s):
        return []

    try:
        raw = re.sub(r"\\x", "", s)
        decoded = bytes.fromhex(raw).decode("utf-8", errors="replace")
        if decoded != s:
            return [decoded]
    except Exception:
        pass
    return []


def _looks_base64(s: str) -> bool:
    s = s.strip()

    if len(s) < 8:
        return False

    if len(s) % 4 == 1:
        return False

    if not _B64_RE.fullmatch(s):
        return False

    return True


def _looks_interesting_decoded_text(s: str) -> bool:
    lowered = s.lower()

    return (
        _looks_textual(s)
        or _looks_base64(s.strip())
        or bool(_PERCENT_RE.search(s))
        or bool(_HTML_ENTITY_RE.search(s))
        or "\\" in s
        or "<" in s
        or any(pattern in lowered for pattern in SQLI_PATTERNS + XSS_PATTERNS)
    )


def _decode_base64(s: str, max_out: int) -> list[str]:

    t = s.strip()

    if not _looks_base64(t):
        return []

    normalized = t.replace("-", "+").replace("_", "/")
    padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)

    raw = None
    for validate in (True, False):
        try:
            raw = base64.b64decode(padded, validate=validate)
            break
        except Exception:
            continue

    if raw is None:
        return []

    if not raw or len(raw) > max_out:
        return []

    out = []

    for enc in ("utf-8", "latin-1"):
        try:
            decoded = raw.decode(enc)
        except Exception:
            continue

        if _looks_interesting_decoded_text(decoded):
            out.append(decoded)

    return list(dict.fromkeys(out))


def _decode_base32(s: str, max_out: int) -> list[str]:
    t = s.strip()
    if not _B32_RE.fullmatch(t):
        return []

    padded = t + "=" * ((8 - len(t) % 8) % 8)

    try:
        raw = base64.b32decode(padded, casefold=True)
    except Exception:
        return []

    if not raw or len(raw) > max_out:
        return []

    out = []
    for enc in ("utf-8", "latin-1"):
        try:
            dec = raw.decode(enc)
            if _looks_textual(dec):
                out.append(dec)
        except Exception:
            pass
    return list(dict.fromkeys(out))


def _decode_base85(s: str, max_out: int) -> list[str]:
    t = s.strip()
    if len(t) < 8:
        return []
    if not re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{10,}", t):
        return []

    out = []

    for decoder in (base64.b85decode, base64.a85decode):
        try:
            raw = decoder(t.encode())
        except Exception:
            continue

        if not raw or len(raw) > max_out:
            continue

        for enc in ("utf-8", "latin-1"):
            try:
                dec = raw.decode(enc)
                if _looks_textual(dec):
                    out.append(dec)
            except Exception:
                pass

    return list(dict.fromkeys(out))


def _decode_rot13(s: str) -> list[str]:
    if not re.fullmatch(r"[A-Za-z]{6,}", s):
        return []
    
    letters = sum(c.isalpha() for c in s)
    if letters < len(s) * 0.6:
        return []

    try:
        dec = codecs.decode(s, "rot_13")
    except Exception:
        return []

    if dec == s:
        return []

    printable = sum(c.isprintable() for c in dec)
    if printable / max(len(dec), 1) < 0.9:
        return []

    return [dec]


def _transforms(s: str, max_out: int) -> list[tuple[str, str]]:
    """
    Возвращает список (название_преобразования, результат).
    """
    results: list[tuple[str, str]] = []
    results.extend(("base64", x) for x in _decode_base64(s, max_out))

    if _PERCENT_RE.search(s):
        results.extend(("url", x) for x in _decode_url(s))

    if _HTML_ENTITY_RE.search(s):
        results.extend(("html", x) for x in _decode_html_entities(s))

    if "\\" in s:
        results.extend(("unicode_escape", x) for x in _decode_unicode_escapes(s))
        results.extend(("hex_escape_blob", x) for x in _decode_hex_escapes_blob(s))

    results.extend(("base32", x) for x in _decode_base32(s, max_out))
    results.extend(("base85", x) for x in _decode_base85(s, max_out))
    results.extend(("hex", x) for x in _decode_hex_blob(s, max_out))

    if any(ch.isalpha() for ch in s):
        results.extend(("rot13", x) for x in _decode_rot13(s))

    dedup: list[tuple[str, str]] = []
    seen = set()
    for name, val in results:
        key = (name, val)
        if key not in seen and val != s:
            seen.add(key)
            dedup.append((name, val))

    return dedup


def generate_normalization_candidates(
    text: str,
    *,
    lowercase: bool = True,
    nfkc: bool = True,
    strip_zero_width: bool = True,
    strip_controls: bool = True,
    collapse_whitespace: bool = True,
    max_len: int = 8192,
    max_decode_depth: int = 6,
    max_generated_nodes: int = 200,
    max_out_per_transform: int = 4096,
    include_original: bool = True,
) -> list[dict]:
    """
    Генерирует все разумные варианты нормализации/декодирования.

    Возвращает список словарей:
    {
        "text": ...,
        "score": ...,
        "depth": ...,
        "path": ["base64", "url", ...]
    }
    """
    raw = "" if text is None else str(text)
    raw = _truncate(raw, max_len)

    def _prepare_pipeline_text(value: str) -> str:
        return _basic_cleanup(
            value,
            lowercase=False,
            nfkc=nfkc,
            strip_zero_width=strip_zero_width,
            strip_controls=strip_controls,
            collapse_whitespace=collapse_whitespace,
            max_len=max_len,
        )

    def _prepare_result_text(value: str) -> str:
        return _basic_cleanup(
            value,
            lowercase=lowercase,
            nfkc=nfkc,
            strip_zero_width=strip_zero_width,
            strip_controls=strip_controls,
            collapse_whitespace=collapse_whitespace,
            max_len=max_len,
        )

    start = _prepare_pipeline_text(raw)

    start_result = _prepare_result_text(start)

    queue = deque()
    queue.append((start, 0, []))

    visited = {start}
    results = []

    if include_original:
        results.append({
            "text": start_result,
            "score": _signal_score(start_result),
            "depth": 0,
            "path": [],
        })

    generated = 0

    while queue and generated < max_generated_nodes:
        current, depth, path = queue.popleft()

        if depth >= max_decode_depth:
            continue

        for transform_name, transformed in _transforms(current, max_out=max_out_per_transform):
            pipeline_candidate = _prepare_pipeline_text(transformed)

            if not pipeline_candidate or pipeline_candidate in visited:
                continue

            visited.add(pipeline_candidate)
            new_path = path + [transform_name]
            generated += 1
            candidate = _prepare_result_text(pipeline_candidate)

            results.append({
                "text": candidate,
                "score": _signal_score(candidate),
                "depth": depth + 1,
                "path": new_path,
            })

            queue.append((pipeline_candidate, depth + 1, new_path))

            if generated >= max_generated_nodes:
                break

    results.sort(key=lambda x: (-x["score"], x["depth"], -len(x["text"])))

    return results


def normalize_input(
    text: str,
    *,
    lowercase: bool = True,
    nfkc: bool = True,
    strip_zero_width: bool = True,
    strip_controls: bool = True,
    collapse_whitespace: bool = True,
    max_len: int = 8192,
    max_decode_depth: int = 6,
    max_generated_nodes: int = 200,
    max_out_per_transform: int = 4096,
    return_all_candidates: bool = False,
    join_candidates: bool = False,
    top_k: int = 5,
) -> str | list[dict]:
    """
    Основная функция нормализации.

    Режимы:
    - return_all_candidates=True  -> вернуть все кандидаты
    - join_candidates=True        -> вернуть строку из top_k кандидатов через ' || '
    - иначе                       -> вернуть лучший кандидат
    """
    candidates = generate_normalization_candidates(
        text,
        lowercase=lowercase,
        nfkc=nfkc,
        strip_zero_width=strip_zero_width,
        strip_controls=strip_controls,
        collapse_whitespace=collapse_whitespace,
        max_len=max_len,
        max_decode_depth=max_decode_depth,
        max_generated_nodes=max_generated_nodes,
        max_out_per_transform=max_out_per_transform,
        include_original=True,
    )

    if return_all_candidates:
        return candidates

    if not candidates:
        return ""

    if join_candidates:
        uniq = []
        seen = set()
        for item in candidates[:top_k]:
            t = item["text"]
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        return " || ".join(uniq)

    return candidates[0]["text"]


if __name__ == "__main__":
    samples = [
        "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "JTNDc2NyaXB0JTNFYWxlcnQoMSklM0Mvc2NyaXB0JTNF",
        "UEhOamNtbHdkRDVoYkdWeWRDZ3hLVHd2YzJOeWFYQjBQZz09",
        "%2555%256e%2569%256f%256e%2520%2553%2545%254c%2545%2543%2554",
        "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3ealert(1)\\x3c\\x2f\\x73\\x63\\x72\\x69\\x70\\x74\\x3e",
    ]

    for s in samples:
        print("=" * 80)
        print("RAW:", s)
        all_candidates = normalize_input(s, return_all_candidates=True)
        for item in all_candidates[:5]:
            print(f"[depth={item['depth']}, score={item['score']:.2f}, path={item['path']}] {item['text']}")
