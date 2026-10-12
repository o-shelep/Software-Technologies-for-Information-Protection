"""Негативні тести: некоректні ключі та дані дають CipherError, а не аварію."""

import pytest

from ciphers import ALPHABET, CipherError, block, columnar, substitution, vigenere


@pytest.mark.parametrize("key", ["", "   ", "KEY", "КЛЮЧ1", "КЛ ЮЧ", "ЁЖ", "ЫЭ"])
def test_vigenere_bad_keys(key):
    with pytest.raises(CipherError):
        vigenere.encrypt("ТЕКСТ", key)


@pytest.mark.parametrize("key", ["", "ABC", "СЛОВО!"])
def test_substitution_bad_keywords(key):
    with pytest.raises(CipherError):
        substitution.encrypt_keyword("ТЕКСТ", key)


@pytest.mark.parametrize("table", [
    ALPHABET[:-1],                 # 32 літери
    ALPHABET + "А",                # 34 літери
    "А" + ALPHABET[1:-1] + "А",    # повтор А, немає Я
    ALPHABET[:-1] + "Z",           # стороння літера
])
def test_substitution_bad_tables(table):
    with pytest.raises(CipherError):
        substitution.encrypt("ТЕКСТ", table)


@pytest.mark.parametrize("key", ["", "1 1 2", "0 1 2", "1 2 4", "3 2 x", "-1 1", (1, 2.5), (True, 2)])
def test_bad_permutations(key):
    with pytest.raises(CipherError):
        block.encrypt("ТЕКСТ", key)
    with pytest.raises(CipherError):
        columnar.encrypt("ТЕКСТ", key)


@pytest.mark.parametrize("pad", [-1, 4, 10])
def test_columnar_bad_pad(pad):
    cipher, _ = columnar.encrypt("КРИП", "3 1 4 2")
    with pytest.raises(CipherError):
        columnar.decrypt(cipher, "3 1 4 2", pad)


def test_columnar_bad_length():
    with pytest.raises(CipherError):
        columnar.decrypt("АБВ", "3 1 4 2", 0)


def test_columnar_wrong_pad_detected():
    cipher, pad = columnar.encrypt("КРИПТО", "3 1 4 2")
    assert pad == 2
    # Завелике доповнення виявляється: на його місці немає службових символів.
    with pytest.raises(CipherError):
        columnar.decrypt(cipher, "3 1 4 2", 3)


@pytest.mark.parametrize("text", ["Hello", "Привет, мир — ЫЭ", "Ё", "\u0301А"])
def test_unsupported_text_symbols(text):
    with pytest.raises(CipherError):
        vigenere.encrypt(text, "КЛЮЧ")


def test_bad_mode():
    with pytest.raises(CipherError):
        block.encrypt("ТЕКСТ", "2 1", mode="random")
