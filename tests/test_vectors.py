"""Контрольні тестові вектори з розділу 7 методички: прямий результат і відновлення."""

import pytest

from classic_ciphers.service import Request, process

VECTORS = [
    # (алгоритм, алфавіт, ключ, відкритий текст, очікуваний результат)
    ("coordinates", "uk", "БЕЗПЕКА", "СЛАВА", "44 35 16 21 16"),
    ("coordinates", "en", "SECURITY", "HELLO", "32 12 35 35 42"),
    ("row-shift", "uk", "БЕЗПЕКА", "СЛАВА", "ЧТЖИЖ"),
    ("row-shift", "en", "SECURITY", "HELLO", "OYVVZ"),
    ("gronsfeld", "uk", "31415", "СЛАВА УКРАЇНІ", "ФМҐГД ЦЛФБНРЇ"),
    ("gronsfeld", "en", "2718", "HELLO WORLD", "JLMTQ DPZNK"),
]
IDS = [f"{v[0]}-{v[1]}" for v in VECTORS]


@pytest.mark.parametrize("algo, lang, key, plain, cipher", VECTORS, ids=IDS)
def test_vector_encrypt(algo, lang, key, plain, cipher):
    assert process(Request("encrypt", algo, lang, key, plain)) == cipher


@pytest.mark.parametrize("algo, lang, key, plain, cipher", VECTORS, ids=IDS)
def test_vector_decrypt(algo, lang, key, plain, cipher):
    assert process(Request("decrypt", algo, lang, key, cipher)) == plain
