import math
import re
from collections import Counter

# Labels that announce sensitive data; the value next to them is often
# unrecognisable on its own (a password or a short account number).
# OCR merges and garbles words ("CREDITCARDCODE", "PASSWORDI", "BANK. ACCOUNT"),
# so phrases allow any separator and have no trailing word boundary
SENSITIVE_KEYWORDS = re.compile(
    r"\b(password|passwd|api\W*key|secret\W*key|private\W*key|bank\W*account"
    r"|social\W*security|credit\W*card|diagnosis)"
    # Short words keep strict boundaries so they don't match inside other words
    r"|\b(iban|ssn|cvv|cvc)\b",
    re.IGNORECASE,
)

CARD_NUMBER = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
US_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
BELGIAN_NATIONAL_NUMBER = re.compile(r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b")
API_KEY_PREFIXES = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}"
    r"|xox[abps]-[A-Za-z0-9-]{10,})"
)

MIN_SECRET_LENGTH = 24
MIN_SECRET_ENTROPY = 3.5


def _passes_luhn(digits: str) -> bool:
    """Checks the Luhn checksum that every payment card number carries."""
    total = 0
    for i, char in enumerate(reversed(digits)):
        digit = int(char)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _is_valid_iban(candidate: str) -> bool:
    """Checks the ISO 13616 mod-97 checksum of an IBAN."""
    rearranged = candidate[4:] + candidate[:4]
    as_number = "".join(str(int(char, 36)) for char in rearranged)
    return int(as_number) % 97 == 1


def _shannon_entropy(token: str) -> float:
    """Returns the average number of bits of information per character."""
    counts = Counter(token)
    return -sum(
        count / len(token) * math.log2(count / len(token)) for count in counts.values()
    )


def _looks_like_secret(token: str) -> bool:
    """Detects long random tokens such as API keys without a known prefix."""
    # Mixed case and digits are required so hex hashes and ordinary words pass
    return (
        len(token) >= MIN_SECRET_LENGTH
        and any(char.islower() for char in token)
        and any(char.isupper() for char in token)
        and any(char.isdigit() for char in token)
        and _shannon_entropy(token) >= MIN_SECRET_ENTROPY
    )


def contains_sensitive_info(text: str) -> bool:
    """Checks whether OCR text contains data that must never be recorded.

    Args:
        text: The text extracted from a screenshot.

    Returns:
        True if the text holds credentials, payment, identity or medical data.
    """
    if SENSITIVE_KEYWORDS.search(text):
        return True
    if US_SSN.search(text) or BELGIAN_NATIONAL_NUMBER.search(text):
        return True
    if API_KEY_PREFIXES.search(text):
        return True
    for match in CARD_NUMBER.finditer(text):
        if _passes_luhn(re.sub(r"\D", "", match.group())):
            return True
    for match in IBAN.finditer(text):
        if _is_valid_iban(match.group().replace(" ", "")):
            return True
    return any(_looks_like_secret(token) for token in text.split())
