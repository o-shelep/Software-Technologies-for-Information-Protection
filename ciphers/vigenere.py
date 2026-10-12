"""Шифр Віженера за модулем 33.

C_i = (P_i + K_(i mod l)) mod 33,  P_i = (C_i - K_(i mod l)) mod 33.
Позиція ключа просувається лише на літерах алфавіту; пробіли, цифри
й розділові знаки копіюються без змін і ключ не зсувають.
"""

from .common import ALPHABET, INDEX, M, prepare_key_word, prepare_text


def _shift(text: str, key: str, sign: int) -> str:
    shifts = [INDEX[ch] for ch in prepare_key_word(key, "Ключ Віженера")]
    result = []
    k = 0  # лічильник лише оброблених літер
    for ch in prepare_text(text):
        if ch in INDEX:
            # Оператор % у Python завжди дає 0..M-1, навіть для від'ємного числа.
            result.append(ALPHABET[(INDEX[ch] + sign * shifts[k % len(shifts)]) % M])
            k += 1
        else:
            result.append(ch)
    return "".join(result)


def encrypt(text: str, key: str) -> str:
    return _shift(text, key, +1)


def decrypt(text: str, key: str) -> str:
    return _shift(text, key, -1)
