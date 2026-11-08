"""Shared text normalization primitives.

Both D2 and the harness checks start from these, but the checks go much
further (harness/checks.py), so a way around a defense registers as a success
(rule 16).
"""

from __future__ import annotations

import unicodedata

# Characters that render as nothing but can split tokens. Category Cf covers
# zero-width space/joiners, bidi controls, word joiner, BOM, soft hyphen, etc.
_EXTRA_INVISIBLE = {
    "͏",  # combining grapheme joiner
    "ᅟ",
    "ᅠ",
    "ㅤ",  # hangul fillers
    "ﾠ",
    "᠎",  # mongolian vowel separator
}


def is_invisible(ch: str) -> bool:
    return unicodedata.category(ch) == "Cf" or ch in _EXTRA_INVISIBLE


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if not is_invisible(ch))


def nfkc_clean(text: str) -> str:
    """NFKC-normalize and remove zero-width and other invisible format characters."""
    return strip_invisible(unicodedata.normalize("NFKC", strip_invisible(text)))


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")
