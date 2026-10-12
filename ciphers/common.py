"""Спільні правила обробки тексту і перевірки ключів для всіх шифрів."""

import unicodedata

# Базовий український алфавіт (33 літери) у порядку з розділу 4.1 методички.
ALPHABET = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"
M = len(ALPHABET)  # 33
INDEX = {ch: i for i, ch in enumerate(ALPHABET)}


class CipherError(ValueError):
    """Помилка некоректного ключа або вхідних даних (зрозуміле повідомлення)."""


def prepare_text(text: str) -> str:
    """NFC-нормалізація + верхній регістр + перевірка підтримуваних символів.

    Пробіли, цифри, розділові знаки й переноси рядків залишаються.
    Літера не з українського алфавіту (латиниця, Ы, Э, Ё...) або
    "висячий" комбінований діакритичний знак вважаються помилкою.
    """
    if not isinstance(text, str):
        raise CipherError("Текст має бути рядком Unicode, а не байтами.")
    prepared = unicodedata.normalize("NFC", text).upper()
    for pos, ch in enumerate(prepared, start=1):
        category = unicodedata.category(ch)
        if (category.startswith("L") and ch not in INDEX) or category.startswith("M"):
            raise CipherError(
                f"Непідтримуваний символ '{ch}' (U+{ord(ch):04X}) на позиції {pos}: "
                "дозволені лише українські літери, пробіли, цифри та розділові знаки."
            )
    return prepared


def letters_only(text: str) -> str:
    """Режим letters only: лишає тільки літери алфавіту (незворотний щодо пробілів)."""
    return "".join(ch for ch in text if ch in INDEX)


def prepare_key_word(key: str, what: str = "Ключ") -> str:
    """Нормалізує ключове слово і перевіряє, що воно складається лише з літер алфавіту."""
    if not isinstance(key, str) or not key.strip():
        raise CipherError(f"{what} не може бути порожнім.")
    word = unicodedata.normalize("NFC", key.strip()).upper()
    bad = [ch for ch in word if ch not in INDEX]
    if bad:
        raise CipherError(
            f"{what} містить символ '{bad[0]}', якого немає в алфавіті: "
            "допускаються лише українські літери без пробілів."
        )
    return word


def parse_permutation(key) -> tuple:
    """Приймає '3 2 5 1 4', '3,2,5,1,4' або послідовність чисел; повертає кортеж int."""
    if isinstance(key, str):
        parts = key.replace(",", " ").split()
        if not parts:
            raise CipherError("Ключ-перестановка не може бути порожнім.")
        try:
            key = [int(p) for p in parts]
        except ValueError:
            raise CipherError(
                "Ключ-перестановка має складатися з цілих чисел, напр. '3 2 5 1 4'."
            ) from None
    perm = tuple(key)
    validate_permutation(perm)
    return perm


def validate_permutation(perm) -> None:
    """Ключ довжини n має містити кожне число від 1 до n рівно один раз."""
    n = len(perm)
    if n == 0:
        raise CipherError("Ключ-перестановка не може бути порожнім.")
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in perm):
        raise CipherError("Елементи перестановки мають бути цілими числами.")
    out_of_range = [x for x in perm if not 1 <= x <= n]
    if out_of_range:
        raise CipherError(
            f"Число {out_of_range[0]} поза діапазоном 1..{n} для ключа довжини {n}."
        )
    if len(set(perm)) != n:
        dup = next(x for x in perm if perm.count(x) > 1)
        raise CipherError(f"Число {dup} повторюється в перестановці.")


def inverse_permutation(perm: tuple) -> tuple:
    """Обернена перестановка: якщо y[j] = x[perm[j]], то x[i] = y[inv[i]]."""
    inv = [0] * len(perm)
    for j, src in enumerate(perm, start=1):
        inv[src - 1] = j
    return tuple(inv)
