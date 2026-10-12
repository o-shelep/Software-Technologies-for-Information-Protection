"""Блокова перестановка за перестановкою індексів.

Для кожного повного блока довжини n: y_j = x_(perm[j]).
Неповний останній блок залишається без змін (задокументована політика).
Режими: "preserve" — переставляється весь нормалізований текст разом із
пробілами (зворотний); "letters" — спочатку лишаються тільки літери.
"""

from .common import CipherError, inverse_permutation, letters_only, parse_permutation, prepare_text

MODES = ("preserve", "letters")


def _prepare(text: str, mode: str) -> str:
    if mode not in MODES:
        raise CipherError(f"Невідомий режим '{mode}'. Допустимі: {', '.join(MODES)}.")
    text = prepare_text(text)
    return letters_only(text) if mode == "letters" else text


def _permute(text: str, perm: tuple) -> str:
    n = len(perm)
    out = []
    for start in range(0, len(text), n):
        block = text[start:start + n]
        if len(block) < n:
            out.append(block)  # неповний залишок — без змін
        else:
            out.append("".join(block[p - 1] for p in perm))
    return "".join(out)


def encrypt(text: str, key, mode: str = "preserve") -> str:
    perm = parse_permutation(key)
    return _permute(_prepare(text, mode), perm)


def decrypt(text: str, key, mode: str = "preserve") -> str:
    perm = parse_permutation(key)
    # Обернену перестановку рахуємо один раз і застосовуємо той самий прохід.
    return _permute(_prepare(text, mode), inverse_permutation(perm))
