import pytest

from classic_ciphers import LATIN, UKRAINIAN, CipherError, PolybiusSquare
from classic_ciphers.polybius import (
    decrypt_coordinates, decrypt_row_shift, encrypt_coordinates,
    encrypt_row_shift, parse_coordinates,
)

UK = PolybiusSquare.build(UKRAINIAN, "БЕЗПЕКА")
EN = PolybiusSquare.build(LATIN, "SECURITY")


# --------------------------------------------------------------- coordinates

def test_first_and_last_cells_11_and_66():
    assert encrypt_coordinates(UK, "Б") == "11"
    assert encrypt_coordinates(UK, "2") == "66"
    assert decrypt_coordinates(UK, "11 66") == "Б2"


def test_first_and_last_rows_whole():
    assert encrypt_coordinates(UK, "БЕЗПКА") == "11 12 13 14 15 16"
    assert decrypt_coordinates(UK, "61 62 63 64 65 66") == "ЬЮЯ012"


def test_ukrainian_special_letters():
    for letter in "ҐЄІЇ":
        assert decrypt_coordinates(UK, encrypt_coordinates(UK, letter)) == letter
    assert encrypt_coordinates(UK, "ґєії") == "23 25 32 33"


def test_latin_a_and_z():
    assert encrypt_coordinates(EN, "az") == "23 52"


def test_lowercase_is_uppercased():
    assert encrypt_coordinates(UK, "слава") == "44 35 16 21 16"


def test_empty_text():
    assert encrypt_coordinates(UK, "") == ""
    assert decrypt_coordinates(UK, "") == ""


@pytest.mark.parametrize("token", ["00", "17", "61x", "67", "70", "1", "123", "ab", "1 ", "٤٤"])
def test_invalid_tokens_rejected(token):
    with pytest.raises(CipherError):
        parse_coordinates(token)


@pytest.mark.parametrize("token", ["00", "17", "67"])
def test_required_error_tokens_inside_text(token):
    with pytest.raises(CipherError, match=f"'{token}'"):
        decrypt_coordinates(UK, f"11 {token} 22")


def test_61_is_valid_but_out_of_range_tokens_are_not():
    # 61 — коректна клітинка (рядок 6, стовпець 1), 67 і 17 — ні.
    assert decrypt_coordinates(UK, "61") == "Ь"


@pytest.mark.parametrize("text", ["11  12", " 11 12", "11 12 ", "11\t12", "11,12", "1112"])
def test_bad_separators_rejected(text):
    with pytest.raises(CipherError):
        decrypt_coordinates(UK, text)


def test_spaces_and_foreign_symbols_rejected_in_strict_mode():
    with pytest.raises(CipherError, match="вилучення пробілів"):
        encrypt_coordinates(UK, "СЛАВА УКРАЇНІ")
    with pytest.raises(CipherError, match="'!'"):
        encrypt_coordinates(UK, "СЛАВА!")
    with pytest.raises(CipherError, match="'5'"):
        encrypt_coordinates(UK, "КЛАС5")


# ----------------------------------------------------------------- row shift

def test_shift_from_sixth_row_wraps_to_first():
    # Рядок 6: Ь Ю Я 0 1 2  -> рядок 1: Б Е З П К А
    assert encrypt_row_shift(UK, "ЬЮЯ012") == "БЕЗПКА"
    assert decrypt_row_shift(UK, "БЕЗПКА") == "ЬЮЯ012"


def test_shift_down_and_back_up_for_every_symbol():
    for square in (UK, EN):
        for symbol in square.symbols:
            r, c = square.position[symbol]
            shifted = encrypt_row_shift(square, symbol)
            assert square.position[shifted] == (r % 6 + 1, c)
            assert decrypt_row_shift(square, shifted) == symbol


def test_row_shift_keeps_foreign_symbols():
    assert encrypt_row_shift(UK, "СЛАВА, УКРАЇНО!\n") == "ЧТЖИЖ, ЩЄЦЖРФХ!\n"
    # Цифри 0-9 входять до латинського квадрата, тому вони теж зсуваються: 4 -> S, 2 -> 8
    assert encrypt_row_shift(EN, "HELLO, WORLD 42!") == "OYVVZ, 3ZDVL S8!"


def test_row_shift_is_simple_substitution():
    """Одна й та сама буква завжди дає ту саму заміну (одноалфавітна підстановка)."""
    assert encrypt_row_shift(UK, "ААААА") == "ЖЖЖЖЖ"
