"""Побудова ключового квадрата 6x6 (розділ 4.3)."""

from dataclasses import dataclass, field

from .alphabets import Alphabet
from .errors import CipherError
from .text import nfc

SIZE = 6


def unique_in_order(symbols: str) -> str:
    """Вилучає повтори, зберігаючи першу появу: БЕЗПЕКА -> БЕЗПКА."""
    return "".join(dict.fromkeys(symbols))


def normalize_keyword(keyword: str, alphabet: Alphabet) -> str:
    """NFC + верхній регістр + перевірка ключового слова (розділ 6.2)."""
    key = nfc(nfc(keyword).upper())
    if not key:
        raise CipherError("Ключове слово не може бути порожнім.")
    allowed = set(alphabet.square_symbols)
    bad = sorted({ch for ch in key if ch not in allowed})
    if bad:
        shown = ", ".join(repr(ch) for ch in bad)
        raise CipherError(
            f"Ключове слово містить символи поза квадратом "
            f"({alphabet.title.lower()} набір): {shown}."
        )
    if not any(ch in alphabet.letters for ch in key):
        raise CipherError("Ключове слово має містити щонайменше одну літеру.")
    return key


@dataclass(frozen=True)
class PolybiusSquare:
    alphabet: Alphabet
    keyword: str
    rows: tuple[str, ...]
    # Таблиці пошуку будуються один раз: символ -> (рядок, стовпець) і навпаки.
    position: dict[str, tuple[int, int]] = field(repr=False)
    symbol_at: dict[tuple[int, int], str] = field(repr=False)

    @classmethod
    def build(cls, alphabet: Alphabet, keyword: str) -> "PolybiusSquare":
        key = normalize_keyword(keyword, alphabet)
        sequence = unique_in_order(key)
        sequence += "".join(s for s in alphabet.square_symbols if s not in sequence)

        if len(sequence) != SIZE * SIZE or len(set(sequence)) != SIZE * SIZE:
            raise CipherError("Квадрат має містити рівно 36 унікальних символів.")
        if set(sequence) != set(alphabet.square_symbols):
            raise CipherError("Квадрат має містити кожен символ базового набору рівно один раз.")

        rows = tuple(sequence[i:i + SIZE] for i in range(0, SIZE * SIZE, SIZE))
        position = {}
        symbol_at = {}
        for r, row in enumerate(rows, start=1):
            for c, symbol in enumerate(row, start=1):
                position[symbol] = (r, c)
                symbol_at[(r, c)] = symbol
        return cls(alphabet, key, rows, position, symbol_at)

    @property
    def symbols(self) -> str:
        return "".join(self.rows)

    def render(self) -> str:
        """Текстове подання квадрата з номерами рядків і стовпців."""
        header = "Рядок | " + " ".join(str(c) for c in range(1, SIZE + 1))
        lines = [header, "-" * len(header)]
        for r, row in enumerate(self.rows, start=1):
            lines.append(f"{r:>5} | " + " ".join(row))
        return "\n".join(lines)
