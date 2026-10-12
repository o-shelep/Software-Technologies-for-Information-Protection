"""Зворотність D_k(E_k(x)) == x щонайменше для 10 різних повідомлень кожним алгоритмом."""

import pytest

from ciphers import block, columnar, prepare_text, substitution, vigenere

MESSAGES = [
    "Слава Україні!",
    "Ґанок, їжак, єнот, ідея — усі літери на місці.",
    "Шифр Віженера: 33 літери, модуль 33.",
    "Пам'ятай: ключ не можна повторювати.",
    "Київ — столиця України.\nДругий рядок.\n",
    "Щастя є, його не може не бути.",
    "Ї",
    "ЮЯ АБ",
    "Тест 2026 року, версія 1.0 (бета)?",
    "Обережно: класичні шифри не захищають дані!",
    "ґ є і ї Ґ Є І Ї",
    "   пробіли на початку і в кінці   ",
]

WORD_KEYS = ["КЛЮЧ", "захист", "Ґ", "ЇЖАКЄНОТ"]
PERM_KEYS = ["1", "2 1", "3 1 4 2", "3 2 5 1 4", "5 4 3 2 1 7 6"]


@pytest.mark.parametrize("msg", MESSAGES)
@pytest.mark.parametrize("key", WORD_KEYS)
def test_substitution_roundtrip(msg, key):
    assert substitution.decrypt_keyword(substitution.encrypt_keyword(msg, key), key) == prepare_text(msg)


@pytest.mark.parametrize("msg", MESSAGES)
@pytest.mark.parametrize("key", WORD_KEYS)
def test_vigenere_roundtrip(msg, key):
    assert vigenere.decrypt(vigenere.encrypt(msg, key), key) == prepare_text(msg)


@pytest.mark.parametrize("msg", MESSAGES)
@pytest.mark.parametrize("key", PERM_KEYS)
def test_block_roundtrip(msg, key):
    assert block.decrypt(block.encrypt(msg, key), key) == prepare_text(msg)


@pytest.mark.parametrize("msg", MESSAGES)
@pytest.mark.parametrize("key", PERM_KEYS)
def test_columnar_roundtrip(msg, key):
    cipher, pad = columnar.encrypt(msg, key)
    assert columnar.decrypt(cipher, key, pad) == prepare_text(msg)


def test_vigenere_skips_non_letters_for_key_position():
    # Пробіл і кома не зсувають ключ: "А А" з ключем "БВ" -> "Б В".
    assert vigenere.encrypt("А, А", "БВ") == "Б, В"
