"""Два різні алгоритми на основі квадрата Полібія (розділи 4.4 та 4.5).

* coordinates — координатне кодування: символ -> "рядок стовпець";
* row shift   — одноалфавітна підстановка символом з наступного рядка.
"""

import re

from .errors import CipherError
from .square import SIZE, PolybiusSquare
from .text import prepare_text

TOKEN_SEPARATOR = " "
_TOKEN_RE = re.compile(rf"[1-{SIZE}][1-{SIZE}]")


# ---------------------------------------------------------------- coordinates

def encrypt_coordinates(square: PolybiusSquare, plaintext: str) -> str:
    """Strict-режим: приймає лише символи квадрата. Пробіли теж є помилкою —
    їх потрібно вилучити окремою операцією підготовки (remove_whitespace)."""
    text = prepare_text(plaintext, square.symbols)
    _reject_foreign(square, text)
    return TOKEN_SEPARATOR.join(
        f"{r}{c}" for r, c in (square.position[ch] for ch in text)
    )


def decrypt_coordinates(square: PolybiusSquare, ciphertext: str) -> str:
    tokens = parse_coordinates(ciphertext)
    return "".join(square.symbol_at[token] for token in tokens)


def parse_coordinates(ciphertext: str) -> list[tuple[int, int]]:
    """Суворий розбір: токени з двох цифр 1..6, розділені рівно одним пробілом.
    Увесь текст перевіряється до початку декодування; нічого не пропускається."""
    if ciphertext == "":
        return []
    tokens = ciphertext.split(TOKEN_SEPARATOR)
    for index, token in enumerate(tokens, start=1):
        if token == "":
            raise CipherError(
                f"Координатний текст: порожній токен №{index} "
                f"(подвійний, початковий або кінцевий пробіл)."
            )
        if not _TOKEN_RE.fullmatch(token):
            raise CipherError(
                f"Координатний текст: некоректний токен №{index} '{token}'. "
                f"Очікуються дві цифри від 1 до {SIZE} (рядок, стовпець)."
            )
    return [(int(t[0]), int(t[1])) for t in tokens]


def _reject_foreign(square: PolybiusSquare, text: str) -> None:
    for index, ch in enumerate(text, start=1):
        if ch not in square.position:
            hint = " Використайте опцію вилучення пробілів." if ch.isspace() else ""
            raise CipherError(
                f"Символ {ch!r} у позиції {index} не входить до квадрата "
                f"({square.alphabet.title.lower()} набір).{hint}"
            )


# ------------------------------------------------------------------ row shift

def encrypt_row_shift(square: PolybiusSquare, plaintext: str) -> str:
    return _shift_rows(square, plaintext, +1)


def decrypt_row_shift(square: PolybiusSquare, ciphertext: str) -> str:
    return _shift_rows(square, ciphertext, -1)


def _shift_rows(square: PolybiusSquare, text: str, step: int) -> str:
    """Зсув на рядок униз (+1) або вгору (-1) із циклічним переходом 6 <-> 1.
    Символи поза квадратом зберігаються без змін."""
    result = []
    for ch in prepare_text(text, square.symbols):
        if ch in square.position:
            r, c = square.position[ch]
            new_row = (r - 1 + step) % SIZE + 1
            result.append(square.symbol_at[(new_row, c)])
        else:
            result.append(ch)
    return "".join(result)
