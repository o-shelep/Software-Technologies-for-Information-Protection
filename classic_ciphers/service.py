"""Єдина точка входу для інтерфейсу: перевіряє режим і викликає алгоритм.

Інтерфейс (CLI) не містить криптографічної логіки і звертається лише сюди.
"""

from dataclasses import dataclass

from . import gronsfeld, polybius
from .alphabets import get_alphabet
from .errors import CipherError
from .square import PolybiusSquare
from .text import remove_whitespace

OPERATIONS = ("encrypt", "decrypt")
ALGORITHMS = ("coordinates", "row-shift", "gronsfeld")
SQUARE_ALGORITHMS = ("coordinates", "row-shift")


@dataclass(frozen=True)
class Request:
    operation: str
    algorithm: str
    alphabet: str
    key: str
    text: str
    strip_whitespace: bool = False


def validate_mode(operation: str, algorithm: str) -> None:
    if operation not in OPERATIONS:
        raise CipherError(f"Непідтримувана операція '{operation}'. Допустимі: {', '.join(OPERATIONS)}.")
    if algorithm not in ALGORITHMS:
        raise CipherError(f"Непідтримуваний алгоритм '{algorithm}'. Допустимі: {', '.join(ALGORITHMS)}.")


def build_square(alphabet_code: str, keyword: str) -> PolybiusSquare:
    return PolybiusSquare.build(get_alphabet(alphabet_code), keyword)


def process(request: Request) -> str:
    """Усі перевірки (режим, алфавіт, ключ) виконуються до обробки тексту."""
    validate_mode(request.operation, request.algorithm)
    alphabet = get_alphabet(request.alphabet)

    if request.strip_whitespace and not (
        request.algorithm == "coordinates" and request.operation == "encrypt"
    ):
        raise CipherError("Вилучення пробілів застосовується лише до координатного шифрування.")

    if request.algorithm == "gronsfeld":
        gronsfeld.parse_key(request.key)  # рання перевірка ключа
        action = gronsfeld.encrypt if request.operation == "encrypt" else gronsfeld.decrypt
        return action(alphabet, request.key, request.text)

    square = PolybiusSquare.build(alphabet, request.key)
    if request.algorithm == "coordinates":
        if request.operation == "encrypt":
            text = remove_whitespace(request.text) if request.strip_whitespace else request.text
            return polybius.encrypt_coordinates(square, text)
        return polybius.decrypt_coordinates(square, request.text)

    action = polybius.encrypt_row_shift if request.operation == "encrypt" else polybius.decrypt_row_shift
    return action(square, request.text)
