import pytest

from classic_ciphers import LATIN, UKRAINIAN, CipherError
from classic_ciphers.gronsfeld import decrypt, encrypt, parse_key


def test_key_keeps_leading_zero():
    assert parse_key("0123") == (0, 1, 2, 3)
    # "0123" і "123" — різні ключі
    assert encrypt(LATIN, "0123", "AAAA") == "ABCD"
    assert encrypt(LATIN, "123", "AAAA") == "BCDB"


def test_single_digit_key_9():
    assert encrypt(LATIN, "9", "ABC XYZ") == "JKL GHI"
    assert decrypt(LATIN, "9", "JKL GHI") == "ABC XYZ"


def test_long_key_longer_than_text():
    key = "98765432109876543210"
    assert encrypt(LATIN, key, "AAA") == "JIH"
    assert decrypt(UKRAINIAN, key, encrypt(UKRAINIAN, key, "ЇЖАК")) == "ЇЖАК"


@pytest.mark.parametrize("key, fragment", [
    ("", "порожнім"),
    ("0", "лише з нулів"),
    ("0000", "лише з нулів"),
    ("12a3", "лише цифри"),
    ("12 3", "лише цифри"),
    ("-123", "лише цифри"),
    ("1.5", "лише цифри"),
    ("١٢٣", "лише цифри"),  # арабсько-індійські цифри не приймаються
])
def test_invalid_keys_rejected(key, fragment):
    with pytest.raises(CipherError, match=fragment):
        parse_key(key)


def test_wraparound_mod_m():
    assert encrypt(UKRAINIAN, "1", "Я") == "А"   # m = 33
    assert encrypt(LATIN, "1", "Z") == "A"       # m = 26
    assert decrypt(UKRAINIAN, "1", "А") == "Я"


def test_foreign_symbols_do_not_advance_key():
    # Ключ 12: A+1, B+2, C+1. Пробіл, цифри й знаки між літерами ключ не споживають.
    assert encrypt(LATIN, "12", "A B, 7C!") == "B D, 7D!"
    assert encrypt(LATIN, "12", "ABC") == "BDD"


def test_other_language_letters_are_foreign():
    assert encrypt(UKRAINIAN, "1", "А-Z") == "Б-Z"
    assert encrypt(LATIN, "1", "Ї A") == "Ї B"


def test_ukrainian_special_letters():
    assert encrypt(UKRAINIAN, "1", "ГЄІЇ") == "ҐЖЇЙ"
    assert decrypt(UKRAINIAN, "1", "ҐЖЇЙ") == "ГЄІЇ"


def test_lowercase_and_nfc_input():
    ukr_decomposed = "Ї"  # українська І + діерезис -> у NFC це Ї (U+0407)
    lat_decomposed = "Ï"       # латинська I + діерезис -> у NFC це Ï (U+00CF)
    assert encrypt(UKRAINIAN, "1", ukr_decomposed) == "Й"
    assert encrypt(UKRAINIAN, "31415", "слава україні") == "ФМҐГД ЦЛФБНРЇ"
    # Ï не входить до латинського алфавіту, тому зберігається і не просуває ключ
    assert encrypt(LATIN, "12", lat_decomposed + "AA") == "ÏBC"


def test_newlines_and_formatting_preserved():
    text = "СЛАВА\nУКРАЇНІ\n\n  2026!\n"
    cipher = encrypt(UKRAINIAN, "31415", text)
    assert cipher == "ФМҐГД\nЦЛФБНРЇ\n\n  2026!\n"
    assert decrypt(UKRAINIAN, "31415", cipher) == text
