"""Вертикальна (стовпцева) перестановка.

Текст записується в таблицю по рядках, кількість стовпців = довжина ключа.
Ключ задає порядок читання стовпців: (3, 1, 4, 2) — спочатку стовпець 3,
потім 1, 4, 2. Неповний останній рядок доповнюється PAD_CHAR, кількість
доданих символів повертається окремо й потрібна для розшифрування.
"""

from .common import CipherError, letters_only, parse_permutation, prepare_text

PAD_CHAR = "_"
MODES = ("preserve", "letters")


def _prepare(text: str, mode: str) -> str:
    if mode not in MODES:
        raise CipherError(f"Невідомий режим '{mode}'. Допустимі: {', '.join(MODES)}.")
    text = prepare_text(text)
    return letters_only(text) if mode == "letters" else text


def encrypt(text: str, key, mode: str = "preserve") -> tuple:
    """Повертає (шифротекст, кількість_доповнення)."""
    order = parse_permutation(key)
    k = len(order)
    text = _prepare(text, mode)
    pad = (-len(text)) % k
    text += PAD_CHAR * pad
    rows = [text[i:i + k] for i in range(0, len(text), k)]
    cipher = "".join("".join(row[col - 1] for row in rows) for col in order)
    return cipher, pad


def decrypt(text: str, key, pad: int = 0, mode: str = "preserve") -> str:
    order = parse_permutation(key)
    k = len(order)
    text = _prepare(text, mode)
    if not isinstance(pad, int) or isinstance(pad, bool) or not 0 <= pad < k:
        raise CipherError(f"Кількість доповнення має бути цілим числом від 0 до {k - 1}.")
    if len(text) % k:
        raise CipherError(
            f"Довжина шифротексту ({len(text)}) не кратна кількості стовпців ({k})."
        )
    n_rows = len(text) // k
    if pad and n_rows == 0:
        raise CipherError("Доповнення не може бути більшим за довжину шифротексту.")
    columns = {}
    for i, col in enumerate(order):
        columns[col] = text[i * n_rows:(i + 1) * n_rows]
    plain = "".join(columns[c][r] for r in range(n_rows) for c in range(1, k + 1))
    if pad:
        tail = plain[-pad:]
        if tail != PAD_CHAR * pad:
            raise CipherError("Неправильний ключ або кількість доповнення: службові символи не знайдено.")
        plain = plain[:-pad]  # видаляємо рівно стільки, скільки додали
    return plain
