"""Підготовка тексту: Unicode NFC і політика регістру (розділ 5)."""

import unicodedata


def nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def prepare_text(text: str, supported: str) -> str:
    """Нормалізує текст у NFC і переводить у верхній регістр лише ті символи,
    чия велика форма належить до підтримуваного набору.

    Решта символів (пробіли, розділові знаки, літери іншої мови) не
    змінюється, тому довжина і структура тексту зберігаються.
    """
    allowed = set(supported)
    result = []
    for ch in nfc(text):
        upper = ch.upper()
        result.append(upper if upper in allowed else ch)
    return "".join(result)


def remove_whitespace(text: str) -> str:
    """Окрема, видима операція підготовки для координатного режиму:
    вилучає пробіли, табуляції та переноси рядків."""
    return "".join(ch for ch in text if not ch.isspace())
