#!/usr/bin/env python3
"""jev_hook_guard: the checks a Claude Code hook runs before it sends text to an external judgment API.

A hook that asks a remote judge (TypeSafe Jev ``/v1/systemone``, or any HTTP judge) about a prompt, a tool call or the
last assistant message sends text from the session off the machine. Call these, in this order, before that send:

  1. kill switch       the caller checks a file first and stops (no log line, no network)
  2. Exclude.hit()     exclusion words from a file, matched on normalized text and once more with all whitespace
                       removed; on a hit, SessionPins.pin() so the rest of the session is not sent either
  3. refuse()          refuse the whole input when it looks like a secret dump: URL credentials, a secret label,
                       a pasted .env file, a street address
  4. mask()            env-file values, key and token shapes, personal data, values next to labels, names, home path
  5. (cut)             mask() returns at most `limit` characters, cut after masking so no half key is left behind
  6. leftover()        last check of the exact text that will be sent; a rule name means: do not send
  7. append_jsonl()    write a pending log line first; if it cannot be written, do not send
  8. post_json()       https only (http only on loopback, see endpoint_ok()), every 3xx refused, wall-clock deadline
  9. classify_error()  timeout | billing (402) | redirect-refused | auth-error | rate-limited | http-error | network

Nothing in this module prints, logs or returns a secret value. Standard library only, Python 3.9+.
"""
import json
import os
import re
import signal
import threading
import time
import unicodedata

try:
    import fcntl
except ImportError:                      # Windows: append_jsonl writes without a lock
    fcntl = None

__version__ = "0.1.1"
__all__ = ["normalize", "load_env_values", "mask", "refuse", "leftover", "Exclude", "SessionPins", "endpoint_ok",
           "post_json", "classify_error", "ensure_private_dir", "append_jsonl", "Deadline"]

MASK = "<redacted>"
SCREEN_CHARS = 4000      # mask() and refuse() read this many normalized characters
ENV_PREFIX = 12          # env values of 12+ characters also match by their first 12 (from 16 characters, last 12) characters


# ---------------------------------------------------------------------------------------------------------------------
# Normalization

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_FULLWIDTH = dict([(c, c - 0xFEE0) for c in range(0xFF01, 0xFF5F)] + [(0x3000, 0x20)])
_FULLWIDTH_ANY = re.compile("[！-～　]")
# Dash variants, and Cyrillic or Greek letters that render exactly like Latin ones ("ѕk-ant-..." with a Cyrillic s).
_CONFUSABLE = re.compile("[‐-―−﹘﹣Ͱ-ϿЀ-ԯ]")
_CONF_MAP = {c: "-" for c in (0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xFE58, 0xFE63)}
for _a, _b in (("аеорсухѕіјԁһԛԝ", "aeopcyxsijdhqw"), ("АВЕКМНОРСТХЅІЈ", "ABEKMHOPCTXSIJ"),
               ("αορτυνικ", "aoptuvik"), ("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧ", "ABEZHIKMNOPTYX")):
    _CONF_MAP.update({ord(x): y for x, y in zip(_a, _b)})
del _a, _b
_WS = re.compile(r"\s+")


def _text(x):
    return x if isinstance(x, str) else ""


def _fold(t):
    """Fullwidth ASCII (U+FF01-FF5E) and the ideographic space to ASCII; zero-width characters removed. Circled digits,
    units and compatibility jamo stay: full NFKC turned "①②③" into "123" and changed what the text says."""
    if _FULLWIDTH_ANY.search(t):         # translate only when needed: on a multi-megabyte text it costs hundreds of ms
        t = t.translate(_FULLWIDTH)
    return _ZERO_WIDTH.sub("", t) if _ZERO_WIDTH.search(t) else t


def normalize(text):
    """The text every check sees: fullwidth ASCII folded, zero-width characters removed, NFC (Korean pasted from a macOS
    file name arrives as NFD), dash variants to "-", Cyrillic and Greek lookalikes to Latin. Non-string input gives ""."""
    t = unicodedata.normalize("NFC", _fold(_text(text)))
    return t.translate(_CONF_MAP) if _CONFUSABLE.search(t) else t


# ---------------------------------------------------------------------------------------------------------------------
# Env-file values

_ENV_ASSIGN = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(.*)$")


def _env_value(raw):
    """Value of a KEY=value line: up to the matching quote when quoted (a trailing comment is ignored), otherwise up to
    the first whitespace that is followed by #."""
    v = raw.strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    return re.split(r"\s+#", v, maxsplit=1)[0].strip()


def load_env_values(path, min_len=6):
    """Values of an env file (KEY=value lines, optional `export`, quotes, # comments), longest first, so a value that
    contains another one is masked whole. Values shorter than `min_len` are skipped: true, false and 8080 would mask
    ordinary text. A missing file gives []. Keep the list in memory: never log it."""
    if not path or not os.path.isfile(path):
        return []
    vals = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = _ENV_ASSIGN.match(line.rstrip("\n"))
            if m:
                v = _env_value(m.group(1))
                if len(v) >= min_len:
                    vals.add(v)
    return sorted(vals, key=lambda v: (-len(v), v))


def _needles(env_values):
    """Values as given plus their normalized form (the text is normalized before matching), longest first."""
    out = set()
    for v in env_values or ():
        if isinstance(v, str) and v:
            out.add(v)
            out.add(normalize(v))
    out.discard("")
    return sorted(out, key=lambda v: (-len(v), v))


# Masking a value only by its first and last 12 characters left the middle of real values behind (7 to 8 characters in
# 19 of the items checked). Any token that touches a masked span is therefore replaced whole.
_ENV_TOKEN = re.compile(r"[A-Za-z0-9_+/=.:-]*" + re.escape(MASK) + r"[A-Za-z0-9_+/=.:-]*")


def _mask_env_values(t, values):
    """Mask each place a value occurs. Matching runs on the text with all whitespace removed, so a value split across
    lines or spaces is still found; the span is mapped back to the original positions."""
    if not values:
        return t
    idx = [i for i, ch in enumerate(t) if not ch.isspace()]
    flat = "".join(t[i] for i in idx)
    spans = []
    for v in values:
        vf = "".join(v.split())
        needles = {vf, vf[:ENV_PREFIX], "".join(v[:ENV_PREFIX].split())} if len(v) >= ENV_PREFIX else {vf}
        if len(vf) >= 16:
            needles.add(vf[-ENV_PREFIX:])                   # only the end of a value was pasted
        for nd in needles:
            k = flat.find(nd) if nd else -1
            while k >= 0:
                spans.append((idx[k], idx[k + len(nd) - 1] + 1))
                k = flat.find(nd, k + 1)
    if not spans:
        return t
    merged = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    out, last = [], 0
    for a, b in merged:
        out += [t[last:a], MASK]
        last = b
    out.append(t[last:])
    return "".join(out)


# ---------------------------------------------------------------------------------------------------------------------
# Shape rules

# Between digit groups: a hyphen, dot or slash (spaces allowed around it), or spaces only. Never a line break, so a table
# with a 4-digit number on each line is not read as a card number.
_NUM_SEP = r"(?:[ \t]*[-./][ \t]*|[ \t]+)"
# Edges of a number or a key prefix: no ASCII letter or digit right before or after. Not \b: Python's \b counts a Korean
# letter as a word character, so "010-1234-5678이야" had no \b after the 8 and went out unmasked. Not re.ASCII either: it
# would also narrow \s and \d, and a number spaced with no-break spaces would no longer match.
_START = r"(?<![0-9A-Za-z])"
_END = r"(?![0-9A-Za-z])"
# A leading date: real month and day, no digit right after the day (3333-01-1234567 is a 4-2-7 account, not a date).
_DATE_START = re.compile(r"\d{4}[-./](?:0[1-9]|1[0-2])[-./](?:0[1-9]|[12]\d|3[01])(?!\d)")
_BANK_CONTEXT = re.compile(r"(?i)계좌|은행|입금|송금|이체|예금주|뱅크|bank|account|acct|농협|신한|새마을금고|우체국|수협|신협")
_FILE_EXTS = frozenset("md py js ts tsx jsx mjs cjs json jsonl txt sh zsh yml yaml toml lock log csv tsv html css swift kt "
                       "java rb go rs c h cpp png jpg jpeg gif webp pdf mp4 mov wav mp3 zip env plist xml sql ipynb docx "
                       "xlsx pptx hwp hwpx".split())


def _account_or_keep(m):
    """Mask a bank-account shape (3 to 4 digit groups, 10+ digits). A leading date (2026-10-01-..., month 01-12 and day
    01-31 with no digit right after the day) is kept. With a separator other than a hyphen (space, dot, slash) the longest
    group must have 6+ digits, or a bank word must appear in the 20 characters before: "ports 3000 8080 5432" and
    "15000 20000 25000" stay, while the common Korean layouts 6-2-6, 3-3-6 and 4-2-7 have a 6+ digit group (3-4-4-2 and
    4-4-4 need a bank word)."""
    s = m.group(0)
    if _DATE_START.match(s) or sum(c.isdigit() for c in s) < 10:
        return s
    if not re.fullmatch(r"\d+(?:-\d+)+", s) and max(len(x) for x in re.findall(r"\d+", s)) < 6 \
            and not _BANK_CONTEXT.search(m.string, max(0, m.start() - 20), m.start()):
        return s
    return "<account>"


def _email_at_or_keep(m):
    """"kim.minsu at example.com": when the last part is a file extension ("look at README.md") it is not an address."""
    return m.group(0) if m.group(1).lower() in _FILE_EXTS else "<email>"


def _spaced_key_or_keep(m):
    """Five or more 4-character groups ("9rTy U2iO pA5s DfG8 hJkL") are a key only when at least two groups mix letters
    and digits or have a lowercase letter followed by an uppercase one; a run of words or of years stays."""
    keyish = sum(1 for g in m.group(0).split()
                 if (re.search(r"[A-Za-z]", g) and re.search(r"\d", g)) or re.search(r"[a-z][A-Z]", g))
    return MASK if keyish >= 2 else m.group(0)


# (pattern, replacement, checked by leftover). "all": the rule also holds on a JSON body; "text": only on the masked
# text (label and assignment rules: in a JSON body the escape "\n" counts as a letter and stops valid sends); False: not
# checked. A rule whose replacement is a function counts in leftover() only where that function would mask the match.
# leftover() reports a hit as "shape-<index>", so keep the order and append new rules at the end.
_SHAPES = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), MASK, "all"),
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:basic|bearer|token)?\s*\S+"), r"\1" + MASK, "all"),
    (re.compile(r"(?i)\b(bearer\s+)[\w.~+/=-]{8,}"), r"\1" + MASK, "all"),
    (re.compile(_START + r"sk-[A-Za-z0-9_-]{8,}"), MASK, "all"),
    (re.compile(_START + r"[sr]k_(?:live|test)_[A-Za-z0-9]{10,}"), MASK, "all"),
    (re.compile(_START + r"eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*){0,2}"), MASK, "all"),
    (re.compile(_START + r"gh[pousr]_[A-Za-z0-9]{20,}"), MASK, "all"),
    (re.compile(_START + r"github_pat_[A-Za-z0-9_]{20,}"), MASK, "all"),
    (re.compile(_START + r"xox[abposr]-[A-Za-z0-9-]{10,}"), MASK, "all"),
    (re.compile(_START + r"AKIA[0-9A-Z]{16}" + _END), MASK, "all"),
    (re.compile(_START + r"AIza[0-9A-Za-z_-]{30,}"), MASK, "all"),
    (re.compile(_START + r"sb_secret_[A-Za-z0-9_-]+"), MASK, "all"),
    (re.compile(_START + r"sbp_[A-Za-z0-9]{20,}"), MASK, "all"),
    (re.compile(_START + r"npm_[A-Za-z0-9]{30,}"), MASK, "all"),
    (re.compile(_START + r"\d{8,10}:[A-Za-z0-9_-]{35}" + _END), MASK, "all"),            # Telegram bot token
    # Any assignment (= or :, any case, JSON quotes) whose name ends in KEY, TOKEN, SECRET, PASS(WORD) or PWD: the name
    # stays, the value goes. A bare PASS is handled by the next rule.
    (re.compile(r"(?i)(?<![A-Za-z0-9_])([A-Z0-9_]{0,40}(?:KEY|TOKEN|SECRET|PASS\s*WORD|(?<=[A-Z0-9_])PASS|PWD))\b"
                r"([\"']?\s*[:=]\s*)(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;)}]+)"), r"\1\2" + MASK, "text"),
    # A bare "pass:". A value of digits and ratios only is a test result ("Pass: 128/128, Fail: 0").
    (re.compile(r"(?i)(?<![A-Za-z0-9_])(pass)\b([\"']?\s*[:=]\s*)(?![\d,./:%]+(?:[\s\"',;)}]|$))"
                r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;)}]+)"), r"\1\2" + MASK, "text"),
    # Settings whose name has a part (split on _ or -) that is session, sid, auth, sign or cred (webhook_signing=...,
    # "auth": "Basic ..."). Whole parts only: design and consideration are not touched.
    (re.compile(r"(?i)(?<![A-Za-z0-9_])((?:[A-Za-z0-9]{1,40}[_-]){0,6}(?:session|sid|auth(?:orization|entication)?|"
                r"sign(?:ing|ature)?|cred(?:ential|entials)?)(?:[_-][A-Za-z0-9]{1,40}){0,6})(?![A-Za-z0-9])"
                r"([\"']?\s*[:=]\s*)(?:\"[^\"\n]*\"|'[^'\n]*'|\S{6,})"), r"\1\2" + MASK, "text"),
    (re.compile(r"(?i)\b(basic|digest)\s+[A-Za-z0-9+/=._-]{8,}"), r"\1 " + MASK, "text"),          # HTTP Basic / Digest
    (re.compile(r"(?<![\w.%+-])[\w.%+-]{1,64}:[^\s@/]{3,128}@[\w.-]{1,253}"), MASK, "text"),      # user:pw@host, no scheme
    (re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s*=\s*(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']+)"), r"\1=" + MASK, "text"),  # KEY=value
    (re.compile(r"(?i)\b((?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|"
                r"passw(?:or)?d|passphrase|token|secret)[a-z0-9_-]{0,40}[\"']?\s*[:=]\s*[\"']?)[^\s\"'&;,)]{6,}"),
     r"\1" + MASK, "text"),
    # Personal data: phone (spaces allowed around separators), resident registration number, card, account, email.
    # Separators: hyphen, dot, slash, space. leftover() checks the phone, ID, card and account rules, not the email ones.
    (re.compile(r"\+82\s*[-./]?\s*(?:\(\s*0\s*\)\s*[-./]?\s*|0\s*)?1[016789]\s*[-./]?\s*\d{3,4}\s*[-./]?\s*\d{4}" + _END),
     "<phone>", "all"),
    (re.compile(_START + r"01[016789]\s*[-./]?\s*\d{3,4}\s*[-./]?\s*\d{4}" + _END), "<phone>", "all"),
    (re.compile(_START + r"0\d{1,2}\s*[-./]\s*\d{3,4}\s*[-./]\s*\d{4}" + _END), "<phone>", "all"),
    # Only when the first 6 digits are a date. Second part starting 1-4: resident registration number, 5-8: foreigner
    # registration number.
    (re.compile(_START + r"\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\s*-?\s*[1-8]\d{6}" + _END), "<id-number>", "all"),
    (re.compile(_START + r"(?:\d{4}" + _NUM_SEP + r"?){3}\d{4}" + _END), "<card>", "all"),
    (re.compile(_START + r"\d{2,6}(?:" + _NUM_SEP + r"\d{2,8}){2,3}" + _END), _account_or_keep, "all"),
    (re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@(?!\d)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+"), "<email>", False),
    # "kim@ example.com": a space after the @ only. The local part is ASCII only, so a handle mention ("account
    # @shop.example") or a Korean word before it is not swallowed.
    (re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}[ \t]*@[ \t]+(?!\d)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}"
                r"(?![A-Za-z0-9-])"), "<email>", False),
    (re.compile(r"(?i)[\w.+-]{1,64}\s*(?:\(at\)|\[at\]|\sat\s|골뱅이)\s*[\w-]{1,63}"
                r"(?:\s*(?:\(dot\)|\[dot\]|\sdot\s|점)\s*[\w-]{1,63})+"), "<email>", False),      # kim at example dot com
    (re.compile(r"(?i)(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}[ \t]+(?:at|\(at\)|\[at\])[ \t]+(?:[A-Za-z0-9-]{1,63}\.)+"
                r"([A-Za-z]{2,24})(?![A-Za-z0-9-])"), _email_at_or_keep, False),                     # kim.minsu at example.com
    (re.compile(_START + r"3[47]\d{2}" + _NUM_SEP + r"?\d{6}" + _NUM_SEP + r"?\d{5}" + _END), "<card>", "all"),  # Amex 4-6-5
    (re.compile(r"\(\s*0\d{1,2}\s*\)\s*\d{3,4}\s*[-./]?\s*\d{4}" + _END), "<phone>", "all"),          # (02) 1234-5678
    (re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9]{4}(?:[ \t]+[A-Za-z0-9]{4}){4,}(?![A-Za-z0-9])"), _spaced_key_or_keep, False),
    # URL query values: a parameter whose name contains key, token, auth, sig, pass, pwd, pw or secret is masked whatever
    # its value looks like (no digit needed); any other parameter only when its value has 12+ characters with both cases.
    (re.compile(r"(?i)([?&][\w.-]{0,40}?(?:key|token|auth|sig|pass|pwd|pw|secret)[\w.-]{0,40}=)[^&#\s]+"),
     r"\1" + MASK, "text"),
    (re.compile(r"([?&][\w.-]{1,40}=)(?=[A-Za-z0-9_~.%+/=-]{12,})(?=[A-Za-z0-9_~.%+/=-]*[A-Z])"
                r"(?=[A-Za-z0-9_~.%+/=-]*[a-z])[A-Za-z0-9_~.%+/=-]+"), r"\1" + MASK, False),
]

# Letters and digits mixed in 8 to 64 characters: a key with no name in front of it.
_MIXED_TOKEN = re.compile(r"(?<![A-Za-z0-9_+/=-])(?=[A-Za-z0-9_+/=-]{0,64}[A-Za-z])"
                          r"(?=[A-Za-z0-9_+/=-]{0,64}\d)[A-Za-z0-9_+/=-]{8,64}(?![A-Za-z0-9_+/=-])")
_NAME_SEGMENTS = re.compile(r"[A-Za-z]+|\d{1,8}")     # name parts: letters only, or 8 digits or fewer
# Secret labels, English and Korean (비번 = password, 비밀번호 = password, 암호 = password or cipher, 패스워드 = password,
# 인증번호 = verification code, 시크릿 = secret, 키체인 = keychain, ...키 = ... key, 토큰 = token). A spaced "비 번" counts
# only when no Korean letter precedes it and a particle, a non-Korean character or the end follows ("준비 번호표" = a
# queue ticket does not).
_SECRET_LABEL = re.compile(r"(?i)(?<![A-Za-z])(?:password|passwd|passphrase|pwd|p\s*/\s*w|pw|api[\s._-]?key|token|secret"
                           r"|auth|otp|pin)(?![A-Za-z])"
                           r"|(?<=[A-Za-z0-9][_-])pass(?![A-Za-z])"
                           r"|비번|(?<![가-힣])비\s+번(?=[은는이가을를도만요값로와과랑의에입인임였예라야면]|[^가-힣]|$)"
                           r"|비밀\s*번호|패스워드|인증\s*번호|시크릿|키체인"
                           r"|(?:암호|[가-힣]{0,4}키|토큰)(?=[은는이가을를도만요값로와과랑의에입인임였예라야면]|[^가-힣]|$)")
_NOT_LABEL = re.compile(r"단축키$")                  # "단축키 Cmd+Shift+4" = keyboard shortcut
_STRONG_LABEL = re.compile(r"(?i)^(?:password|passwd|passphrase|pwd|pw|p\s*/\s*w|pass|비\s*번|비밀\s*번호|암호|패스워드"
                           r"|인증\s*번호)$")
_SPAN_LABEL = re.compile(r"(?i)^(?:password|passwd|passphrase|pwd|pw|p\s*/\s*w|pass|secret|비\s*번|비밀\s*번호|암호|패스워드"
                         r"|인증\s*번호|시크릿)$")
_NUMERIC_LABEL = re.compile(r"(?i)^(?:password|passwd|passphrase|pwd|pw|p\s*/\s*w|pass|otp|pin|비\s*번|비밀\s*번호|암호"
                            r"|패스워드|인증\s*번호)$")       # labels after which a digits-only value is masked too
# After a strong Korean label, a line holding only particles or separators ("비번은" then a line break) means the first
# token of the next line is the value.
_LABEL_TAIL = re.compile(r"[\s은는이가을를도만요값로와과랑의에입인임였예라야면:=：→-]*")
_VALUE_SPAN = re.compile(r"\s*[\"']?\s*[:=]\s*([^\s가-힣]+(?:[ \t][^\s가-힣]+)*)")   # label, separator, value (spaces too)
# Between a strong English label and its value: an attached Korean particle, a separator, or is/was/are. A blank alone
# does not count.
_EN_INTRO = re.compile(r"(?i)(?:[가-힣]{1,4}[\s:=]*|\s*(?:[:=→(\[「『\"'–—-]|->)+\s*|\s+(?:is|was|are)\s+)")
_PLACEHOLDER = re.compile(r"<(?:redacted|phone|id-number|card|account|email|hash)>")
_PLAIN_NUMBER = re.compile(r"^(?:\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d{4}-\d{2}-\d{2}\S*|v?\d+(?:\.\d+){1,3}"
                           r"|\d{1,2}:\d{2}(?::\d{2})?|\d+/\d+|\d+(?:\.\d+)?[kKmM])$")
_FILE_LIKE = re.compile(r"(?i)^[\w.-]+\.(?:env|local|example|sample|json|ya?ml|toml|ini|conf|txt|md)$")
_EDGE = "\"'`()[]{}<>.,;:!?→=|*"
_PROX_GAP = 30
_STRONG_GAP = 60                         # a strong Korean label reaches the first non-Korean 4+ character token within 60
_SENTENCE_END = re.compile(r"[.!?。]$")
_HEXID = re.compile(r"\b(?=[0-9a-f]{0,64}[a-f])(?=[0-9a-f]{0,64}\d)[0-9a-f]{7,}\b")     # commit SHAs, hashes, hex keys
_TOKENISH = re.compile(r"(?<![A-Za-z0-9_+/=-])(?=[A-Za-z0-9_+/=-]{0,200}[A-Za-z])(?=[A-Za-z0-9_+/=-]{0,200}\d)"
                       r"[A-Za-z0-9_+/=-]{32,}")


def _near_label_value(core, label, sep):
    if not core or not re.search(r"[A-Za-z0-9]", core) or _PLAIN_NUMBER.match(core):
        return False                     # Korean-only words, 1,234,567, dates, versions and times are not values
    if core.isdigit():
        return len(core) >= 4 and (sep or bool(_NUMERIC_LABEL.match(label)))   # "토큰 12000개" (12000 tokens) stays
    if any(ch.isdigit() for ch in core) and len(core) >= 4:
        return True
    return len(core) >= 6 and bool(re.search(r"[A-Za-z]", core)) and (
        bool(re.search(r"[a-z]", core) and re.search(r"[A-Z]", core)) or bool(re.search(r"[^A-Za-z0-9]", core)))


def _sentence_like(span):
    """Three or more lowercase English words ("Auth: fixed the login redirect ...") are a status line, not a value."""
    return sum(1 for w in span.split() if re.fullmatch(r"[a-z]+", w.strip(_EDGE))) >= 3


def _strong_value(t, end, label):
    """Value after a strong label -> (start, end) or None. Any non-Korean token of 4+ characters counts, whatever its
    letters. A Korean label reaches the first such token in the same line and sentence within 60 characters; an English
    label only the one token right after an attached particle, a separator or is/was. English words are all non-Korean,
    so reaching further would mask any word ("password reset flow" stays)."""
    korean = bool(re.search(r"[가-힣]", label))
    if not korean:
        m = _EN_INTRO.match(t, end)
        if not m or m.end() == end:
            return None
        end = m.end()
    for tm in re.finditer(r"\S+", t[end:end + _STRONG_GAP]):
        gap = t[end:end + tm.start()]
        nxt = "\n" in gap                # a Korean label line with only particles: look at the next line's first token
        if nxt and not (korean and gap.count("\n") == 1 and _LABEL_TAIL.fullmatch(gap[:gap.index("\n")])):
            return None
        tok = tm.group(0)
        if _PLACEHOLDER.search(tok):
            return None
        core = re.sub(r"[가-힣]+$", "", tok.strip(_EDGE)).strip(_EDGE)
        if len(re.sub(r"[가-힣]", "", core)) >= 4 and not _PLAIN_NUMBER.match(core) and not _FILE_LIKE.match(core):
            off = end + tm.start() + tok.find(core)
            return off, off + len(core)
        if nxt or not korean or _SENTENCE_END.search(tok):
            return None
    return None


def _mask_near_labels(t):
    """Mask the value after a secret label. Label plus ":" or "=": the following non-Korean run, spaced values included;
    for a weak label (token, auth, pin, ...키) whose run reads like an English sentence, only the first token by the
    usual rule. A strong label (password, 비번, ...): the first non-Korean 4+ character token whatever its letters.
    Otherwise: the first value-like token within 30 characters. File names such as .env.local are not values."""
    spans = []
    for m in _SECRET_LABEL.finditer(t):
        label, end = m.group(0), m.end()
        if _NOT_LABEL.search(label):
            continue
        v = _VALUE_SPAN.match(t, end)
        if v:
            if _PLACEHOLDER.search(v.group(1)):
                continue                 # an earlier rule already masked it
            core = v.group(1).strip(_EDGE)
            if len(core) >= 4 and not _PLAIN_NUMBER.match(core) and not _FILE_LIKE.match(core) and (
                    _SPAN_LABEL.match(label) or not _sentence_like(v.group(1))):
                spans.append((v.start(1), v.end(1)))
                continue
        if _STRONG_LABEL.match(label):
            s = _strong_value(t, end, label)
            if s:
                spans.append(s)
                continue
        sep = v is not None
        for tm in re.finditer(r"\S+", t[end:end + _PROX_GAP + 80]):
            if tm.start() > _PROX_GAP:
                break
            tok = tm.group(0)
            if _PLACEHOLDER.search(tok):
                break
            core = re.sub(r"[가-힣]+$", "", tok.strip(_EDGE)).strip(_EDGE)
            if _FILE_LIKE.match(core):
                continue
            if _near_label_value(core, label, sep):
                off = end + tm.start() + tok.find(core)
                spans.append((off, off + len(core)))
                break
    if not spans:
        return t
    out, last = [], 0
    for a, b in sorted(spans):
        if a < last:
            continue
        out += [t[last:a], MASK]
        last = b
    out.append(t[last:])
    return "".join(out)


def _mixed_mask(m):
    """A token whose parts (split on -, _ and +) are each letters only or 8 digits or fewer is a name and stays
    (claude-sonnet-5-5, gpt-image-2, Cmd+Shift+4). A part mixing letters and digits, or a single part, is masked."""
    s = m.group(0)
    segs = re.split(r"[-_+]", s)
    if len(segs) >= 2 and all(_NAME_SEGMENTS.fullmatch(x) for x in segs):
        return s
    return MASK


# Korean names before the honorifics 님 and 씨 ("김철수님", "홍길동씨"): common surname plus one or two letters.
_SURNAMES = "김이박최정강조윤장임한오서신권황안송류유전홍고문양손배백허남"
_NAME_HON = re.compile(r"(?<![가-힣])[" + _SURNAMES + r"][가-힣]{1,2}(?=님|씨)")
# Words of that shape that are titles or relations, not names (customer, director, doctor, in-laws, ...).
_NAME_STOP = {"고객", "이사", "박사", "장모", "장인", "전무", "조교", "강사", "임금", "신부", "남편", "서방", "양반",
              "조카", "손자", "손녀", "고모", "이모", "정부", "유저"}


def _name_mask(m):
    return m.group(0) if m.group(0) in _NAME_STOP else "<name>"


def _self_names_rx(names):
    """Your own names and handles. A name made of ASCII letters only matches as a whole word (so "dan" leaves "danger"
    alone); any other name matches anywhere. Whitespace inside a name matches any run of whitespace."""
    if isinstance(names, str):
        names = [names]
    keep = {normalize(n).strip() for n in names or () if isinstance(n, str) and n.strip()}
    parts = []
    for n in sorted(keep, key=lambda s: (-len(s), s)):
        p = r"\s+".join(re.escape(w) for w in n.split())
        if re.fullmatch(r"[A-Za-z]+", "".join(n.split())):
            p = r"(?<![A-Za-z])" + p + r"(?![A-Za-z])"
        parts.append(p)
    return re.compile("|".join(parts), re.I) if parts else None


def mask(text, env_values=(), limit=600, home=None, self_names=()):
    """Masked text, at most `limit` characters. Order: normalize -> home path to "~" -> env values (whole token,
    first/last 12 characters, whitespace-split) -> shape rules -> values next to labels -> hex ids -> mixed letter-digit
    tokens (8-64 characters, then 32+ that are still left) -> Korean honorific names -> `self_names` -> collapse
    spaces -> cut to `limit`.

    The first 4,000 normalized characters (2 x limit when that is larger) are masked before the cut, so a key that
    crosses the cut is already masked. `home`: None means the current user's home directory, "" skips this step.
    Placeholders: <redacted> <phone> <id-number> <card> <account> <email> <hash> <name>. Non-string input gives ""."""
    limit = int(limit)
    if limit <= 0:
        return ""
    screen = max(SCREEN_CHARS, 2 * limit)
    t = normalize(_text(text)[:screen * 2])[:screen]
    home = os.path.expanduser("~") if home is None else _text(home)
    home = normalize(home).rstrip("/\\")
    if len(home) > 1:
        t = re.sub(re.escape(home) + r"(?![\w.-])", "~", t)
    t = _ENV_TOKEN.sub(MASK, _mask_env_values(t, _needles(env_values)))
    for rx, rep, _check in _SHAPES:
        t = rx.sub(rep, t)
    t = _mask_near_labels(t)
    t = _HEXID.sub("<hash>", t)
    t = _MIXED_TOKEN.sub(_mixed_mask, t)
    # Letter-digit tokens of 32+ characters that the 8-64 rule leaves (longer than 64, such as base64 of a key, or made
    # of name-like parts): leftover() would stop the whole send on them, so they are masked here instead.
    t = _TOKENISH.sub(MASK, t)
    t = _NAME_HON.sub(_name_mask, t)
    names = _self_names_rx(self_names)
    if names is not None:
        t = names.sub("<name>", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()[:limit]


# ---------------------------------------------------------------------------------------------------------------------
# Refuse the whole input

# Secret label words. Korean: 비번 / 비밀번호 / 패스워드 = password, 암호 = password or cipher, 인증키 = API key. A
# passphrase is plain words, which no shape rule recognises, so the word alone refuses the input.
_SECRET_WORDS = re.compile(r"비번|(?<![가-힣])비\s+번(?=[은는이가을를도만요값로와과랑의에입인임였예라야면]|[^가-힣]|$)"
                           r"|비밀\s*번호|암호|인증키|패스워드"
                           r"|password|passwd|passphrase|\bpw\b|\bp\s*/\s*w\b|pass\s+is|secret|token|api.?key|credential",
                           re.I)
_ENV_LINE = re.compile(r"^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]+=\S", re.M)   # NAME=value with no space around =
_URL_CRED = re.compile(r"://[^/\s]+:[^@\s]+@")
# Korean street address (시/도 + 구/군/시 + 로/길/동/읍/면 + number) or an apartment unit (101동 202호).
_ADDRESS = re.compile(r"[가-힣]{1,6}(?:시|도)\s*[가-힣]{1,6}(?:구|군|시)\s*[가-힣0-9]{1,10}(?:로|길|동|읍|면)\s*\d"
                      r"|\d{1,4}\s*동\s*\d{1,4}\s*호")


def refuse(text):
    """Reason to send nothing at all, or None. Reads the first 4,000 normalized characters. Returns 'url-credential'
    (scheme://user:pw@), 'secret-label' (password, passwd, passphrase, pw, P/W, "pass is", secret, token, api key,
    credential, 비번, 비밀번호, 암호, 인증키, 패스워드), 'env-file' (two or more NAME=value lines) or 'address' (a Korean
    street address or apartment unit). Never returns the value."""
    t = normalize(_text(text)[:SCREEN_CHARS * 2])[:SCREEN_CHARS]
    if _URL_CRED.search(t):
        return "url-credential"
    if _SECRET_WORDS.search(t):
        return "secret-label"
    if len(_ENV_LINE.findall(t)) >= 2:
        return "env-file"
    if _ADDRESS.search(t):
        return "address"
    return None


# ---------------------------------------------------------------------------------------------------------------------
# Last check before the send

def leftover(text, env_values=()):
    """Run on the exact text that is about to be sent (the variable part of the request; fixed local text such as a
    question list can trip the KEY=value and long-token rules by itself). Checks env values, the key, label and
    assignment rules, phone, ID, card and account numbers (not email addresses) and long tokens. Returns the name of
    the rule that still matches ('credential-value', 'credential-prefix', 'credential-suffix', 'shape-<n>',
    'long-token') or None. Never returns the value."""
    t = _text(text)
    for v in _needles(env_values):
        if v in t:
            return "credential-value"
        if len(v) >= ENV_PREFIX and v[:ENV_PREFIX] in t:
            return "credential-prefix"
        if len(v) >= 16 and v[-ENV_PREFIX:] in t:
            return "credential-suffix"
    for i, (rx, rep, check) in enumerate(_SHAPES):
        if not check:
            continue
        for m in rx.finditer(t):
            hit = m.group(0)
            masks = rep(m) != hit if callable(rep) else MASK not in hit     # a function rule counts where it masks
            if masks:
                return "shape-%d" % i
    if _TOKENISH.search(t):
        return "long-token"
    return None


# ---------------------------------------------------------------------------------------------------------------------
# Exclusion words

class Exclude(object):
    """Exclusion patterns: one regular expression per line, # comments and blank lines ignored, matched
    case-insensitively. `path` that exists with no pattern lines sets `empty_file` (the caller should log it) and
    falls back to `default`; a missing file uses `default`. The default list is empty: nothing is excluded until you
    list it. A pattern that does not compile raises re.error."""

    def __init__(self, path=None, default=()):
        self.path = path
        self.empty_file = False
        patterns = []
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                patterns = [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]
            self.empty_file = not patterns
        if not patterns:
            if isinstance(default, str):
                default = [default]
            patterns = [p for p in default or () if isinstance(p, str) and p.strip()]
        self.patterns = patterns
        self._rx = re.compile("|".join(patterns), re.I) if patterns else None

    def hit(self, text):
        """True when a pattern matches the normalized text, or the normalized text with all whitespace removed
        ("Acme  Corp", "ac me" style spacing). Non-string or empty text is False."""
        if self._rx is None or not text or not isinstance(text, str):
            return False
        n = normalize(text)
        return bool(self._rx.search(n) or self._rx.search(_WS.sub("", n)))


# ---------------------------------------------------------------------------------------------------------------------
# Private files

def ensure_private_dir(path):
    """Create `path` one level at a time, each new level 0700 (os.makedirs applies its mode to the last level only). If
    `path` already exists and belongs to the current user, group and other bits are removed. Existing parents are left
    as they are. Returns the absolute path."""
    path = os.path.abspath(path)
    if os.path.isdir(path):
        _tighten(path, 0o700)
        return path
    parent = os.path.dirname(path)
    if parent != path and not os.path.isdir(parent):
        ensure_private_dir(parent)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        if not os.path.isdir(path):
            raise
    os.chmod(path, 0o700)
    return path


def _tighten(path, mode):
    st = os.stat(path)
    if hasattr(os, "getuid") and st.st_uid == os.getuid() and st.st_mode & 0o077:
        os.chmod(path, mode)


def _rotate(path, keep):
    for i in range(keep - 1, 0, -1):
        src = "%s.%d" % (path, i)
        if os.path.exists(src):
            os.replace(src, "%s.%d" % (path, i + 1))
    os.replace(path, path + ".1")


def append_jsonl(path, obj, max_bytes=5 * 1024 * 1024, keep=4):
    """Append one JSON line. The file is created 0600 (an existing file of yours loses group and other bits); missing
    directories are created 0700, an existing directory is left as it is (call ensure_private_dir() on your state
    directory). When the file is over `max_bytes` it becomes path.1 (path.1 -> path.2 ... up to path.<keep>; older
    generations are dropped). Rotation and write happen under a lock on path.lock, so concurrent writers do not
    interleave lines. Errors are raised: the caller decides that a failed pending line means no send."""
    keep = max(1, int(keep))
    parent = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(parent):
        ensure_private_dir(parent)
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    lock = None
    if fcntl is not None:
        lock = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        for _ in range(200):              # wait up to about 1 s, then write without the lock (a lost line is worse)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                time.sleep(0.005)
    try:
        if os.path.exists(path) and os.path.getsize(path) > max_bytes:
            _rotate(path, keep)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            st = os.fstat(fd)
            if hasattr(os, "getuid") and st.st_uid == os.getuid() and st.st_mode & 0o077:
                os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
    finally:
        if lock is not None:
            os.close(lock)                # closing releases the lock


# ---------------------------------------------------------------------------------------------------------------------
# Session pins

def _safe_name(s):
    n = re.sub(r"[^\w.-]", "_", str(s))[:120]
    return re.sub(r"^\.+", lambda m: "_" * len(m.group(0)), n) or "_"     # never "", "." or ".."


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class SessionPins(object):
    """Per-session pins: once a session is pinned, nothing more from it is sent, for the rest of its life.

    A hit pins the session only when it came from a source the session owns: user text, assistant text, the working
    directory or the transcript path. A hit that only appears in tool input, tool output, an attachment or the raw
    transcript tail skips that one send and does not pin (one directory listing that showed a matching file name used to
    pin a whole session). A source in neither list pins: an unknown source fails closed.

    Marker file: <dir>/<session id>, content "<UTC timestamp> <source>", mode 0600 in a 0700 directory. Markers are
    never cleaned, so a resumed session stays pinned. A marker without a source, or one that cannot be read, pins.
    A caller that sends tool text itself can pass skip_only_sources=() to follow every marker."""

    def __init__(self, dir, pin_sources=("user", "assistant", "cwd", "transcript-path"),
                 skip_only_sources=("tool-input", "tool-result", "attachment", "raw-tail")):
        self.dir = dir
        self.pin_sources = tuple(pin_sources)
        self.skip_only_sources = tuple(skip_only_sources)
        both = set(self.pin_sources) & set(self.skip_only_sources)
        if both:
            raise ValueError("a source cannot both pin and only skip: %s" % ", ".join(sorted(both)))

    def _path(self, session_id):
        return os.path.join(self.dir, _safe_name(session_id))

    def note(self, session_id):
        """Source word in the marker: None when there is no marker, "" when it has no source or cannot be read."""
        if not session_id:
            return None
        p = self._path(session_id)
        if not os.path.exists(p):
            return None
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                words = f.read(256).split()
        except OSError:
            return ""
        return words[1] if len(words) >= 2 else ""

    def pinned(self, session_id):
        """True when a marker exists whose source is not skip-only. An empty session id is never pinned."""
        note = self.note(session_id)
        return note is not None and note not in self.skip_only_sources

    def pin(self, session_id, source):
        """Pin the session for a hit from `source`. Returns True when the session is pinned after the call, False for a
        skip-only source (skip this send only) or an empty session id (nothing to write; skip this send)."""
        if not session_id or source in self.skip_only_sources:
            return False
        if self.pinned(session_id):
            return True                   # keep the first source
        ensure_private_dir(self.dir)
        src = re.sub(r"\s+", "-", _text(source).strip()) or "unknown"
        p = self._path(session_id)
        tmp = "%s.%d.%s.tmp" % (p, os.getpid(), os.urandom(4).hex())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, ("%s %s" % (_now_iso(), src)).encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.replace(tmp, p)            # also replaces a marker written for a skip-only source by an older writer
        except OSError:
            os.unlink(tmp)
            raise
        return True

    def writable(self):
        """False when a pin could not be written. Do not send then: a hit later in the session could not be pinned."""
        try:
            ensure_private_dir(self.dir)
        except OSError:
            return False
        return os.access(self.dir, os.W_OK)


# ---------------------------------------------------------------------------------------------------------------------
# HTTP

def endpoint_ok(url):
    """https, or plain http to 127.0.0.1, localhost or [::1] only. Anything else would carry the key in clear text."""
    url = _text(url)
    return url.startswith("https://") or bool(re.match(r"^http://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?(?:/|$)", url))


class Deadline(Exception):
    """post_json() ran past its wall-clock deadline."""


_OPENER = []


def _opener():
    if not _OPENER:
        import urllib.error
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            """Refuse every 3xx: following one would send the Authorization header to another origin."""

            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)
        _OPENER.append(urllib.request.build_opener(_NoRedirect))
    return _OPENER[0]


def _open(req, timeout):
    """Tests replace this function."""
    return _opener().open(req, timeout=timeout)


def post_json(url, body, key, timeout):
    """POST `body` as JSON with "Authorization: Bearer <key>". Returns (response dict, milliseconds).

    Every 3xx is refused (HTTPError with the 3xx code). `timeout` is a socket timeout and, in the main thread on a
    platform with SIGALRM, also a wall-clock deadline for the whole call (Deadline); a previously installed SIGALRM
    handler and timer are restored. Raises ValueError for an endpoint that endpoint_ok() refuses, a key that is not
    printable ASCII, or a response that is not a JSON object. No exception carries the key."""
    import urllib.request
    if not endpoint_ok(url):
        raise ValueError("endpoint refused: https, or http on loopback only")
    if not isinstance(key, str) or not re.fullmatch(r"[\x21-\x7e]+", key):
        raise ValueError("key must be printable ASCII without spaces")
    timeout = max(float(timeout), 0.01)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    alarm = hasattr(signal, "SIGALRM") and threading.current_thread() is threading.main_thread()
    t0 = time.perf_counter()
    if alarm:
        def _expired(*_):
            raise Deadline("%.1fs deadline" % timeout)
        old_handler = signal.signal(signal.SIGALRM, _expired)
        old_timer = signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        try:
            with _open(req, timeout) as r:
                raw = r.read()
        except Exception as e:
            close = getattr(e, "close", None)    # an HTTPError holds the response socket
            if callable(close):
                try:
                    close()
                except Exception:
                    pass
            raise
    finally:
        if alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
            if old_timer[0] > 0:          # re-arm a timer that was running before this call
                left = old_timer[0] - (time.perf_counter() - t0)
                signal.setitimer(signal.ITIMER_REAL, max(left, 0.001), old_timer[1])
    ms = round((time.perf_counter() - t0) * 1000)
    resp = json.loads(raw.decode("utf-8"))
    if not isinstance(resp, dict):
        raise ValueError("response is not a JSON object")
    return resp, ms


def _err_kind(e):
    """Type name (and HTTP code) only: an exception message can carry headers or the key."""
    import urllib.error
    return type(e).__name__ + (" %d" % e.code if isinstance(e, urllib.error.HTTPError) else "")


def classify_error(exc):
    """Exception from post_json() -> (status, extra). Status: 'timeout', 'billing' (402: credits ran out; make it loud,
    a judge that stops answering looks like a judge that says no), 'redirect-refused' (3xx), 'auth-error' (401, 403),
    'rate-limited' (429), 'http-error' (other HTTP codes, or a response that is not a JSON object), 'network'.
    `extra` holds only {'http': code} or {'err': type name}: never headers, messages or the key."""
    import socket
    import urllib.error
    if isinstance(exc, (Deadline, socket.timeout, TimeoutError)):
        return "timeout", {}
    if isinstance(exc, urllib.error.HTTPError):
        c = exc.code
        if c == 402:
            return "billing", {"http": c}
        if 300 <= c < 400:
            return "redirect-refused", {"http": c}
        if c in (401, 403):
            return "auth-error", {"http": c}
        if c == 429:
            return "rate-limited", {"http": c}
        return "http-error", {"http": c}
    if isinstance(exc, urllib.error.URLError):
        if isinstance(getattr(exc, "reason", None), (socket.timeout, TimeoutError)):
            return "timeout", {}
        return "network", {"err": _err_kind(exc)}
    if isinstance(exc, ValueError):
        return "http-error", {"err": _err_kind(exc)}
    return "network", {"err": _err_kind(exc)}
