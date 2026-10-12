"""Проста одноалфавітна підстановка (за ключовим словом або за готовою таблицею)."""

from .common import ALPHABET, M, CipherError, prepare_key_word, prepare_text


def table_from_keyword(keyword: str) -> str:
    """Ключове слово без повторів (перша поява) + невикористані літери алфавіту."""
    word = prepare_key_word(keyword, "Ключове слово")
    seen = []
    for ch in word + ALPHABET:
        if ch not in seen:
            seen.append(ch)
    return "".join(seen)


def validate_table(table: str) -> str:
    """Таблиця B має довжину 33, містить лише літери A і не має повторів."""
    if not isinstance(table, str) or not table:
        raise CipherError("Таблиця підстановки не може бути порожньою.")
    table = prepare_key_word(table, "Таблиця підстановки")
    if len(table) != M:
        raise CipherError(f"Таблиця підстановки має містити {M} літери, а містить {len(table)}.")
    if len(set(table)) != M:
        dup = next(ch for ch in table if table.count(ch) > 1)
        missing = next(ch for ch in ALPHABET if ch not in table)
        raise CipherError(f"У таблиці літера '{dup}' повторюється, а '{missing}' відсутня.")
    return table


def _apply(text: str, source: str, target: str) -> str:
    mapping = dict(zip(source, target))
    # Символи поза алфавітом (пробіли, цифри, розділові знаки) не змінюються.
    return "".join(mapping.get(ch, ch) for ch in text)


def encrypt(text: str, table: str) -> str:
    table = validate_table(table)
    return _apply(prepare_text(text), ALPHABET, table)


def decrypt(text: str, table: str) -> str:
    table = validate_table(table)
    return _apply(prepare_text(text), table, ALPHABET)


def encrypt_keyword(text: str, keyword: str) -> str:
    return encrypt(text, table_from_keyword(keyword))


def decrypt_keyword(text: str, keyword: str) -> str:
    return decrypt(text, table_from_keyword(keyword))
