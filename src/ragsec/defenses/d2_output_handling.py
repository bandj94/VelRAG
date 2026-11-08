"""D2: output handling (spec §7.1), applied to the delivered answer.

(a) Remove links, images, bare URLs (with a scheme or ``www.``), and bare domains
    whose host isn't velmora.example or a subdomain of it. Hosts are parsed and
    lowercased and compared exactly or by ``.velmora.example`` suffix, never by
    substring. A bare domain counts only when its last label is in the TLD list
    in config/app.yaml (which leaves out TLDs that double as file extensions).
(b) Strip raw HTML.
(c) Send a Content-Security-Policy on UI and render pages (see ``csp_header``).
(d) Redact data classes the user's role may not see, using config/dlp.yaml
    (formats, never actual values; D2 never sees the scoring secrets).
(e) Block answers containing the routing code (case-insensitive, also with
    whitespace and punctuation removed) or any 8-word span of the active
    preset's fixed instruction text.

The harness checks are deliberately stronger than everything here (rule 16).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ragsec.settings import D2Cfg, DlpConfig
from ragsec.textnorm import nfkc_clean

# --------------------------------------------------------------------------
# Host handling
# --------------------------------------------------------------------------


def normalize_host(host: str) -> str:
    h = nfkc_clean(host).strip().lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def host_allowed(host: str | None, allowed_domain: str) -> bool:
    if not host:
        return False
    h = normalize_host(host)
    allowed = allowed_domain.lower().rstrip(".")
    return h == allowed or h.endswith("." + allowed)


def url_host(url: str) -> str | None:
    u = nfkc_clean(url).strip().strip("<>").strip()
    if not u:
        return None
    if u.lower().startswith("www."):
        u = "http://" + u
    elif u.startswith("//"):
        u = "http:" + u
    try:
        parts = urlsplit(u)
        return parts.hostname
    except ValueError:
        return None


# --------------------------------------------------------------------------
# (b) raw HTML
# --------------------------------------------------------------------------

_BLOCK_ELEMENTS = re.compile(
    r"<(script|style|iframe|object|embed|noscript|template|svg|math)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_UNCLOSED_BLOCK = re.compile(r"<(script|style|iframe|svg)\b[^>]*>.*\Z", re.IGNORECASE | re.DOTALL)
_COMMENT = re.compile(r"<!--.*?(-->|\Z)", re.DOTALL)
_DECL = re.compile(r"<![A-Za-z][^>]*>|<\?.*?\?>", re.DOTALL)
_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9:-]*(?:\s[^<>]*?)?/?>", re.DOTALL)
_DANGLING_TAG = re.compile(r"<[A-Za-z][A-Za-z0-9:-]*\s[^<>]*$", re.MULTILINE)


def strip_html(text: str) -> tuple[str, int]:
    count = 0
    for pattern in (_BLOCK_ELEMENTS, _UNCLOSED_BLOCK, _COMMENT, _DECL, _TAG, _DANGLING_TAG):
        text, n = pattern.subn("", text)
        count += n
    return text, count


# --------------------------------------------------------------------------
# (a) links, images, URLs, domains
# --------------------------------------------------------------------------


def _inline_links(text: str) -> Iterator[tuple[int, int, bool, str, str]]:
    """Yield (start, end, is_image, label, destination) for [label](dest) constructs."""
    i = 0
    n = len(text)
    while True:
        j = text.find("](", i)
        if j == -1:
            return
        depth = 0
        k = j
        start = -1
        while k >= 0:
            c = text[k]
            if c == "]":
                depth += 1
            elif c == "[":
                depth -= 1
                if depth == 0:
                    start = k
                    break
            k -= 1
        if start == -1:
            i = j + 2
            continue
        m = j + 2
        pdepth = 1
        while m < n:
            c = text[m]
            if c == "\\":
                m += 2
                continue
            if c == "(":
                pdepth += 1
            elif c == ")":
                pdepth -= 1
                if pdepth == 0:
                    break
            m += 1
        if m >= n:
            i = j + 2
            continue
        is_image = start > 0 and text[start - 1] == "!"
        yield (start - 1 if is_image else start, m + 1, is_image, text[start + 1 : j], text[j + 2 : m])
        i = m + 1


def _destination_url(dest: str) -> str:
    d = dest.strip()
    if d.startswith("<"):
        end = d.find(">")
        return d[1:end] if end != -1 else d[1:]
    return d.split()[0] if d.split() else ""


_REF_DEF = re.compile(r"^[ ]{0,3}\[([^\]]+)\]:[ \t]*<?([^\s>]+)>?[^\n]*$", re.MULTILINE)
_REF_LINK = re.compile(r"(!?)\[([^\]]*)\]\[([^\]]*)\]")
_AUTOLINK = re.compile(r"<((?:[A-Za-z][A-Za-z0-9+.-]{1,31}:|www\.)[^\s<>]*)>")
_EMAIL_AUTOLINK = re.compile(r"<([^\s@<>]+@[^\s@<>]+)>")
_BARE_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s<>\"'`]+")
_BARE_WWW = re.compile(r"(?i)(?<![\w.@/-])www\.[^\s<>\"'`]+")
_EMAIL = re.compile(r"(?<![\w.+-])[^\s@<>()\[\]\"',;:]+@([^\s@<>()\[\]\"',;:]+)")
_LABEL = r"[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?"
_BARE_DOMAIN = re.compile(
    rf"(?i)(?<![\w@.\-/:])((?:{_LABEL}\.)+([a-z¡-￿][a-z0-9¡-￿-]{{0,62}}))\.?(?::\d{{1,5}})?(?:/[^\s<>\"'`]*)?"
)
_TRAILING = ".,;:!?)]}*_'\""


def _trim(url: str) -> tuple[str, str]:
    """Split trailing punctuation off a bare URL (GFM-style)."""
    tail = ""
    while url and url[-1] in _TRAILING:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        tail = url[-1] + tail
        url = url[:-1]
    return url, tail


@dataclass
class D2Result:
    text: str
    events: list[dict[str, Any]] = field(default_factory=list)
    blocked: bool = False


class OutputHandler:
    def __init__(self, cfg: D2Cfg, dlp: DlpConfig, fixed_instruction_text: str, routing_code: str) -> None:
        self.cfg = cfg
        self.allowed = cfg.allowed_domain.lower()
        self.tlds = {t.lower().lstrip(".") for t in cfg.bare_domain_tlds}
        self.dlp = dlp
        self.dlp_compiled = [
            (p, re.compile(p.regex, re.IGNORECASE if p.ignore_case else 0)) for p in dlp.patterns
        ]
        self.span_words = cfg.leak_span_words
        self.fixed_spans = _ngrams(_words(fixed_instruction_text), self.span_words)
        self.routing_code_squashed = _squash(routing_code)
        self.routing_code = routing_code

    # -- (a) ---------------------------------------------------------------
    def _keep(self, url: str) -> bool:
        return host_allowed(url_host(url), self.allowed)

    def strip_links(self, text: str, events: list[dict[str, Any]]) -> str:
        def log(kind: str, url: str) -> None:
            events.append({"type": "d2_link_removed", "defense": "d2_output_handling", "kind": kind, "url": url[:300]})

        # Inline links and images, one replacement at a time (handles nesting).
        for _ in range(500):
            changed = False
            for start, end, is_image, label, dest in _inline_links(text):
                url = _destination_url(dest)
                if self._keep(url):
                    continue
                log("image" if is_image else "link", url)
                text = text[:start] + ("" if is_image else label) + text[end:]
                changed = True
                break
            if not changed:
                break

        # Reference-style definitions and the links that use them.
        removed_refs: set[str] = set()

        def _def(m: re.Match[str]) -> str:
            if self._keep(m.group(2)):
                return m.group(0)
            removed_refs.add(m.group(1).strip().lower())
            log("reference_definition", m.group(2))
            return ""

        text = _REF_DEF.sub(_def, text)

        def _ref(m: re.Match[str]) -> str:
            ref = (m.group(3) or m.group(2)).strip().lower()
            if ref in removed_refs:
                return "" if m.group(1) else m.group(2)
            return m.group(0)

        text = _REF_LINK.sub(_ref, text)

        # Autolinks.
        def _auto(m: re.Match[str]) -> str:
            if self._keep(m.group(1)):
                return m.group(0)
            log("autolink", m.group(1))
            return ""

        text = _AUTOLINK.sub(_auto, text)

        def _email_auto(m: re.Match[str]) -> str:
            domain = m.group(1).rsplit("@", 1)[-1]
            if host_allowed(domain, self.allowed):
                return m.group(0)
            log("email_autolink", m.group(1))
            return ""

        text = _EMAIL_AUTOLINK.sub(_email_auto, text)

        # Bare URLs with a scheme, and www. URLs.
        def _bare(m: re.Match[str]) -> str:
            url, tail = _trim(m.group(0))
            if self._keep(url):
                return m.group(0)
            log("bare_url", url)
            return tail

        text = _BARE_URL.sub(_bare, text)
        text = _BARE_WWW.sub(_bare, text)

        # Email addresses: GFM autolinks them into mailto: links.
        def _email(m: re.Match[str]) -> str:
            domain, _tail = _trim(m.group(1))
            if host_allowed(domain, self.allowed):
                return m.group(0)
            log("email", m.group(0))
            return ""

        text = _EMAIL.sub(_email, text)

        # Bare domains (no scheme) whose last label is a listed TLD.
        def _domain(m: re.Match[str]) -> str:
            tld = m.group(2).lower()
            if tld not in self.tlds:
                return m.group(0)
            host = m.group(1)
            if host_allowed(host, self.allowed):
                return m.group(0)
            whole, tail = _trim(m.group(0))
            log("bare_domain", whole)
            return tail

        text = _BARE_DOMAIN.sub(_domain, text)
        return text

    # -- (d) ---------------------------------------------------------------
    def redact(self, text: str, role: str, events: list[dict[str, Any]]) -> str:
        visible = set(self.dlp.role_may_see.get(role, []))
        for pattern, rx in self.dlp_compiled:
            if pattern.data_class in visible:
                continue
            replacement = self.dlp.redaction_template.format(data_class=pattern.data_class)
            text, n = rx.subn(replacement, text)
            if n:
                events.append({"type": "d2_redacted", "defense": "d2_output_handling",
                               "data_class": pattern.data_class, "pattern": pattern.name, "count": n})
        return text

    # -- (e) ---------------------------------------------------------------
    def leak_reason(self, text: str) -> str | None:
        if self.routing_code_squashed and self.routing_code_squashed in _squash(text):
            return "routing_code"
        if self.fixed_spans and _ngrams(_words(text), self.span_words) & self.fixed_spans:
            return "instruction_span"
        return None

    # -- all ---------------------------------------------------------------
    def apply(self, answer: str, role: str) -> D2Result:
        events: list[dict[str, Any]] = []
        text, n_html = strip_html(answer)
        if n_html:
            events.append({"type": "d2_html_removed", "defense": "d2_output_handling", "count": n_html})
        text = self.strip_links(text, events)
        text = self.redact(text, role, events)
        reason = self.leak_reason(text)
        if reason is not None:
            events.append({"type": "d2_prompt_leak_blocked", "defense": "d2_output_handling", "reason": reason})
            return D2Result(self.cfg.leak_block_message, events, blocked=True)
        return D2Result(text, events)


def csp_header(cfg: D2Cfg) -> str:
    return cfg.csp


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", nfkc_clean(text).lower())


def _ngrams(words: list[str], n: int) -> set[tuple[str, ...]]:
    return {tuple(words[i : i + n]) for i in range(0, max(0, len(words) - n + 1))}


def _squash(text: str) -> str:
    return re.sub(r"[\W_]+", "", nfkc_clean(text).lower())


def make_keep(allowed_domain: str) -> Callable[[str], bool]:
    return lambda url: host_allowed(url_host(url), allowed_domain)
