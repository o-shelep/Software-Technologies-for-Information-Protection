"""Шифр Гронсфельда (розділ 4.7).

    C_i = (P_i + d[j(i) mod t]) mod m
    P_i = (C_i - d[j(i) mod t]) mod m

j(i) — номер обробленої літери алфавіту без урахування сторонніх символів:
пробіли, цифри та розділові знаки не змінюються і не споживають цифру ключа.
"""

import re

from .alphabets import Alphabet
from .errors import CipherError
from .text import nfc, prepare_text

_DIGITS_RE = re.compile(r"[0-9]+")  # лише ASCII-цифри, без інших Unicode-цифр


def parse_key(key: str) -> tuple[int, ...]:
    """Ключ зберігається як рядок, тому початкові нулі не втрачаються."""
    key = nfc(key)
    if key == "":
        raise CipherError("Цифровий ключ не може бути порожнім.")
    if not _DIGITS_RE.fullmatch(key):
        raise CipherError(
            f"Цифровий ключ '{key}' має містити лише цифри 0-9 "
            f"(без пробілів, знаків і літер)."
        )
    if set(key) == {"0"}:
        raise CipherError("Цифровий ключ не може складатися лише з нулів.")
    return tuple(int(d) for d in key)


def encrypt(alphabet: Alphabet, key: str, plaintext: str) -> str:
    return _apply(alphabet, parse_key(key), plaintext, +1)


def decrypt(alphabet: Alphabet, key: str, ciphertext: str) -> str:
    return _apply(alphabet, parse_key(key), ciphertext, -1)


def _apply(alphabet: Alphabet, digits: tuple[int, ...], text: str, sign: int) -> str:
    index_of = {letter: i for i, letter in enumerate(alphabet.letters)}
    m, t = alphabet.size, len(digits)
    j = 0  # лічильник лише для літер алфавіту
    result = []
    for ch in prepare_text(text, alphabet.letters):
        if ch in index_of:
            shift = digits[j % t]
            result.append(alphabet.letters[(index_of[ch] + sign * shift) % m])
            j += 1
        else:
            result.append(ch)
    return "".join(result)
