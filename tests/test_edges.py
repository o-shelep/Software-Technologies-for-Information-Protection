"""Граничні випадки, українські літери, Unicode NFC, доповнення."""

import unicodedata

import pytest

from ciphers import ALPHABET, block, columnar, prepare_text, substitution, vigenere

KEY5 = "3 2 5 1 4"


def test_alphabet_has_33_letters():
    assert len(ALPHABET) == 33 and len(set(ALPHABET)) == 33


def test_nfc_decomposed_yi():
    decomposed = "\u0456\u0308"  # "і" + комбінована діереза
    assert unicodedata.normalize("NFC", decomposed) == "ї"
    assert prepare_text(decomposed) == "Ї"
    assert vigenere.encrypt(decomposed, "А") == "Ї"


@pytest.mark.parametrize("letter", "ҐЄІЇґєії")
def test_ukrainian_letters_not_damaged(letter):
    out = substitution.encrypt_keyword(letter, "КЛЮЧ")
    assert len(out) == 1 and out in ALPHABET
    assert substitution.decrypt_keyword(out, "КЛЮЧ") == letter.upper()


@pytest.mark.parametrize("func", [
    lambda t: substitution.encrypt_keyword(t, "КЛЮЧ"),
    lambda t: vigenere.encrypt(t, "КЛЮЧ"),
    lambda t: block.encrypt(t, KEY5),
    lambda t: columnar.encrypt(t, KEY5)[0],
])
def test_empty_text(func):
    assert func("") == ""


def test_single_char():
    assert block.encrypt("а", KEY5) == "А"  # неповний блок не змінюється
    cipher, pad = columnar.encrypt("а", KEY5)
    assert pad == 4 and columnar.decrypt(cipher, KEY5, pad) == "А"


@pytest.mark.parametrize("length", [4, 5, 6, 9, 10, 11])
def test_block_lengths_around_block_size(length):
    text = ALPHABET[:length]
    cipher = block.encrypt(text, KEY5)
    full = length - length % 5
    assert cipher[full:] == text[full:]  # хвіст без змін
    assert block.decrypt(cipher, KEY5) == text


@pytest.mark.parametrize("length", [3, 4, 5, 7, 8, 9])
def test_columnar_padding_removed_exactly(length):
    text = ALPHABET[:length]
    cipher, pad = columnar.encrypt(text, "3 1 4 2")
    assert pad == (-length) % 4
    assert cipher.count(columnar.PAD_CHAR) == pad
    assert columnar.decrypt(cipher, "3 1 4 2", pad) == text


def test_columnar_keeps_text_ending_with_pad_char():
    # Текст сам закінчується на '_': видаляється лише відома кількість доповнення.
    text = "КІНЕЦЬ__"
    cipher, pad = columnar.encrypt(text, "3 1 4 2 5")
    assert columnar.decrypt(cipher, "3 1 4 2 5", pad) == text


def test_formatting_preserved_in_substitutions():
    text = "Рядок 1, рядок 2!\nДругий: 3.\n"
    assert vigenere.decrypt(vigenere.encrypt(text, "КЛЮЧ"), "КЛЮЧ") == prepare_text(text)
    enc = substitution.encrypt_keyword(text, "КЛЮЧ")
    assert [c for c in enc if c not in ALPHABET] == [c for c in prepare_text(text) if c not in ALPHABET]


def test_letters_mode_removes_spaces():
    assert block.encrypt("а б, в!", "1", mode="letters") == "АБВ"
