"""Mask payment card data before a request is recorded.

With an application behind the HTTP decoy (HONEYPOT_HTTP_UPSTREAM) a checkout
form can be reachable, and anyone who finds it might type a real card. The
engine keeps request lines and bodies, so card data is masked before either
reaches a transcript or an event:

* a run of 13-19 digits (spaces or dashes allowed between them) that passes
  the Luhn check keeps only its last four digits;
* the value of any field named like a card security code is replaced.

The forwarded request is untouched; only what the honeypot stores is masked.
A Luhn-valid digit run that is not a card (one in ten random runs, e.g. a
millisecond timestamp) is masked too, which costs nothing worth keeping.
"""

import re

_DIGIT_RUN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

_SECURITY_CODE = re.compile(
    r"""(?ix)
    (?<![a-z0-9_])
    (["']?(?:cvc|cvv2?|csc|cid|security_?code|card_?code)["']?\s*[:=]\s*)
    ("[^"]*"|'[^']*'|[^&,}\s]*)
    """
)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _mask_number(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    if _luhn(digits):
        return f"[card ****{digits[-4:]}]"
    return match.group(0)


def _mask_code(match: re.Match) -> str:
    value = match.group(2)
    quote = value[0] if value[:1] in ("'", '"') else ""
    return f"{match.group(1)}{quote}[redacted]{quote}"


def redact_card_data(text: str) -> str:
    if not text:
        return text
    return _SECURITY_CODE.sub(_mask_code, _DIGIT_RUN.sub(_mask_number, text))
