"""Inbound meaning processing (WP07, contract C5 step 7 and C7).

The kernel has already authenticated, deduplicated, and applied opt-out or
hold before acknowledging the provider. This module pulls the unprocessed
events from the kernel, classifies each deterministically, and creates the
application-side objects the contract requires:

* date request          → draft commitment (kind customer_date / customer_request) with the
                          message as evidence; never a confirmed date
* product/skin concern  → ExceptionRecord(product_concern) + request a hold on sales
                          follow-up through the kernel (suppression, non-permanent)
* complaint             → ExceptionRecord(complaint)
* wrong number          → ExceptionRecord(wrong_number) + hold
* identity ambiguity    → ExceptionRecord(identity_ambiguity) when the number maps to
                          zero or several customers
* possible opt-out      → ExceptionRecord(ambiguous_opt_out) (kernel already holds)
* ordinary              → recorded on the customer timeline only

Rules first, model never: classification is keyword/pattern based so it is
auditable and evaluable (row A4). An LLM may later *suggest* a class, but the
rule verdict for opt-out and concern classes is never downgraded by a model.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

CLASSES = ("opt_out", "ambiguous_opt_out", "product_concern", "complaint", "wrong_number",
           "date_request", "ordinary")

# Carrier-standard keywords (the kernel suppresses these before we see them;
# kept here so the classifier is complete and evaluable on its own).
_EXPLICIT = {"stop", "stopall", "unsubscribe", "cancel", "end", "quit", "revoke", "optout", "opt-out", "opt out"}
# Clear natural-language requests to stop. Not carrier keywords, but unambiguous:
# treated as explicit (permanent suppression), mirrored in the kernel's detector.
_EXPLICIT_PHRASES = ("stop texting", "stop messaging", "don't text", "dont text", "do not text", "don't message",
                     "do not message", "remove me", "take me off", "no more texts", "no more messages", "unsubscribe me",
                     "stop sending", "stop contacting", "lose my number", "please stop")
# Possibly an opt-out; a hold a human must review.
_POSSIBLE = ("leave me alone", "not interested", "unsub", "stop it", "go away", "no thanks", "no thank you")
_WRONG_NUMBER = re.compile(r"\b(wrong number|who is this|who's this|who dis|don't know you|dont know you|"
                           r"i don't know who you are|not (angela|her|him|them)|you have the wrong)\b", re.I)
_CONCERN = re.compile(r"\b(rash(es)?|burn(ing|ed|s)?|sting(ing|s)?|itch(y|ing|es)?|hives|swell(ing|ed|s)?|swollen|"
                      r"break(ing)? out|broke out|breakout|allerg(y|ic|ies)|reaction|irritat(ed|ion|ing)|"
                      r"redness|blister(s|ed|ing)?|peeling|infect(ion|ions|ed)|pain(ful)?|hurt(s|ing)?|doctor|dermatologist|er\b|"
                      r"emergency|hospital|made my (skin|face) worse)\b", re.I)
_COMPLAINT = re.compile(r"\b(never (arrived|came|got|received)|didn't (arrive|come|get|receive)|did not (arrive|receive)|"
                        r"broken|damaged|leaking|wrong (item|product|shade|color|colour|order)|missing|refund|"
                        r"charged twice|overcharged|disappointed|unacceptable|terrible|awful|rip ?off|scam|"
                        r"complain(t|ing)?|unhappy|not happy)\b", re.I)
_DATE = re.compile(r"\b(next (week|month|monday|tuesday|wednesday|thursday|friday|saturday|sunday)|"
                   r"(this|next) (weekend|wknd)|tomorrow|after (the )?(holidays?|christmas|thanksgiving|wedding|trip|vacation)|"
                   r"in (a|two|three|\d+) (days?|weeks?|months?)|(on|by|around) (monday|tuesday|wednesday|thursday|friday|saturday|sunday)|"
                   r"(jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.? \d{1,2}|\d{1,2}/\d{1,2}|"
                   r"(later|another time|not (right )?now|busy (this|next) week|check back|reach out|try (me )?again|"
                   r"get back to (you|me)|circle back|remind me|follow up (with me )?(later|next)|when i get back))\b", re.I)

_PUNCT = re.compile(r"[.!?,\"'“”]")
# A stop keyword that opens the message and is followed by a sentence break
# ("STOP. this gave me a rash", "Stop! who is this", "STOP\nsent from my phone"):
# the customer said STOP; what follows does not soften it. Mirrored in the kernel
# (`mk_adapters::twilio::detect_opt_out`).
# "stop" as a word (also "stopp", "stooop", "stopping", "stops"); not "stopped" or
# "nonstop". "bus stop" is still a hold — over-holding is safe, a missed stop is not.
_STOP_WORD = re.compile(r"\b(sto+p+|stopping|stops)\b")
_KEYWORD_THEN_BREAK = re.compile(r"^\s*(stop|stopall|unsubscribe|optout|opt[- ]out|revoke)\s*([.!,;:\n]|-\s|–|—)", re.I)


def _canon(text: str) -> str:
    """NFKC (fullwidth/compatibility forms fold: 'ＳＴＯＰ' → 'STOP', '…' → '...') and
    typographic apostrophes/quotes mapped to ASCII (iOS types ’ by default)."""
    t = unicodedata.normalize("NFKC", text)
    return t.translate({0x2019: "'", 0x2018: "'", 0x02BC: "'", 0x201C: '"', 0x201D: '"'})


def _norm(text: str) -> str:
    """Canonical word sequence: lowercase, apostrophes deleted ("don't" → "dont"),
    every other non-alphanumeric character (punctuation, symbols, emoji) a word
    break. Mirrored exactly by the kernel's `detect_opt_out`."""
    t = _canon(text).lower().replace("'", "")
    t = "".join(c if c.isalnum() or c.isspace() else " " for c in t)
    return " ".join(t.split())


def _explicit_phrase(norm: str) -> bool:
    """An explicit stop phrase, also when its words are run together ("stoptexting").
    "please stop" never counts when followed by "by" ("please stop by Friday")."""
    collapsed = norm.replace(" ", "")
    for p in _PHRASES_N:
        if p == "please stop" and "stop by" in norm:
            continue
        if p in norm or p.replace(" ", "") in collapsed:
            return True
    return False


def _is_keyword(word: str) -> bool:
    """A carrier opt-out keyword, including emphatic spellings of stop ("STOPPP", "stooop")."""
    return word in _EXPLICIT or bool(re.fullmatch(r"sto+p+", word))


@dataclass(frozen=True)
class InboundClass:
    label: str
    evidence: str   # the matched span, verbatim from the message (for the exception/commitment record)


def classify_inbound(text: str) -> InboundClass:
    """Deterministic classification. Order encodes the contract's priorities:
    safety (opt-out, concern) before business (complaint, date) before ordinary."""
    norm = _norm(text)
    text = _canon(text)
    if not norm:
        return InboundClass("ordinary", "")
    if norm in _EXPLICIT:
        return InboundClass("opt_out", text.strip())
    words = norm.split(" ")
    first = words[0]
    if _is_keyword(first) and len(words) <= 2 and not norm.startswith("stop by"):
        return InboundClass("opt_out", text.strip())
    if all(_is_keyword(w) for w in words):                     # "STOP STOP STOP"
        return InboundClass("opt_out", text.strip())
    if _KEYWORD_THEN_BREAK.search(text):
        return InboundClass("opt_out", text.strip())
    # Wrong number outranks a natural-language stop phrase *here*: the kernel has
    # already suppressed the number permanently (its detector treats the phrase as
    # explicit), and the business outcome is "this customer's number is wrong",
    # not "this customer opted out".
    if _WRONG_NUMBER.search(text):
        return InboundClass("wrong_number", _WRONG_NUMBER.search(text).group(0))
    if _explicit_phrase(norm):
        return InboundClass("opt_out", text.strip())
    if any(p in norm for p in _POSSIBLE_N) or (_STOP_WORD.search(norm) and "stop by" not in norm and "non stop" not in norm):
        return InboundClass("ambiguous_opt_out", text.strip())
    m = _CONCERN.search(text)
    if m:
        return InboundClass("product_concern", m.group(0))
    m = _COMPLAINT.search(text)
    if m:
        return InboundClass("complaint", m.group(0))
    m = _DATE.search(text)
    if m:
        return InboundClass("date_request", m.group(0))
    return InboundClass("ordinary", "")


# Classes that must stop ordinary sales follow-up until a human looks (C7).
STOPS_SALES_FOLLOW_UP = {"opt_out", "ambiguous_opt_out", "product_concern", "wrong_number"}
# Classes that surface as visible exceptions.
EXCEPTION_KIND = {"product_concern": "product_concern", "complaint": "complaint", "wrong_number": "wrong_number",
                  "ambiguous_opt_out": "ambiguous_opt_out"}


_PHRASES_N = tuple(dict.fromkeys(_norm(p) for p in _EXPLICIT_PHRASES))
_POSSIBLE_N = tuple(dict.fromkeys(_norm(p) for p in _POSSIBLE))
