"""Узгоджені набори символів (розділ 4.1 методички).

Набір символів є частиною специфікації: він має бути однаковим
під час шифрування і розшифрування. Мова завжди обирається явно.
"""

from dataclasses import dataclass

from .errors import CipherError


@dataclass(frozen=True)
class Alphabet:
    code: str            # "uk" або "en"
    title: str           # назва для інтерфейсу
    letters: str         # базовий алфавіт для Гронсфельда
    square_symbols: str  # 36 символів для квадрата Полібія

    @property
    def size(self) -> int:
        """Потужність алфавіту m для формул Гронсфельда."""
        return len(self.letters)


UKRAINIAN = Alphabet(
    code="uk",
    title="Український",
    letters="АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ",
    square_symbols="АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ012",
)

LATIN = Alphabet(
    code="en",
    title="Латинський",
    letters="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    square_symbols="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
)

ALPHABETS = {UKRAINIAN.code: UKRAINIAN, LATIN.code: LATIN}


def get_alphabet(code: str) -> Alphabet:
    """Повертає алфавіт за явним кодом; автоматичного вгадування немає."""
    try:
        return ALPHABETS[code]
    except KeyError:
        supported = ", ".join(ALPHABETS)
        raise CipherError(
            f"Непідтримуваний алфавіт '{code}'. Допустимі значення: {supported}."
        ) from None


def _self_check() -> None:
    for alphabet in ALPHABETS.values():
        assert len(alphabet.square_symbols) == 36, alphabet.code
        assert len(set(alphabet.square_symbols)) == 36, alphabet.code
        assert alphabet.square_symbols.startswith(alphabet.letters), alphabet.code
    assert UKRAINIAN.size == 33 and LATIN.size == 26


_self_check()
