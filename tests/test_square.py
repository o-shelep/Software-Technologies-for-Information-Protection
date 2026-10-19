import pytest

from classic_ciphers import LATIN, UKRAINIAN, CipherError, PolybiusSquare
from classic_ciphers.square import unique_in_order


def test_unique_in_order_keeps_first_occurrence():
    assert unique_in_order("БЕЗПЕКА") == "БЕЗПКА"
    assert unique_in_order("SECURITY") == "SECURITY"


@pytest.mark.parametrize("alphabet, key", [(UKRAINIAN, "БЕЗПЕКА"), (LATIN, "SECURITY"), (UKRAINIAN, "ЯЯЯ")])
def test_square_is_6x6_with_36_unique_symbols(alphabet, key):
    square = PolybiusSquare.build(alphabet, key)
    assert len(square.rows) == 6 and all(len(row) == 6 for row in square.rows)
    assert len(set(square.symbols)) == 36
    assert set(square.symbols) == set(alphabet.square_symbols)


def test_ukrainian_square_matches_methodical_example():
    square = PolybiusSquare.build(UKRAINIAN, "БЕЗПЕКА")
    assert square.rows == ("БЕЗПКА", "ВГҐДЄЖ", "ИІЇЙЛМ", "НОРСТУ", "ФХЦЧШЩ", "ЬЮЯ012")


def test_latin_square_matches_methodical_example():
    square = PolybiusSquare.build(LATIN, "SECURITY")
    assert square.rows == ("SECURI", "TYABDF", "GHJKLM", "NOPQVW", "XZ0123", "456789")


def test_lookup_tables_are_inverse():
    square = PolybiusSquare.build(UKRAINIAN, "БЕЗПЕКА")
    for symbol, pos in square.position.items():
        assert square.symbol_at[pos] == symbol
    assert square.symbol_at[(1, 1)] == "Б" and square.symbol_at[(6, 6)] == "2"


def test_keyword_is_case_insensitive_and_nfc_normalized():
    assert PolybiusSquare.build(UKRAINIAN, "безпека").rows == PolybiusSquare.build(UKRAINIAN, "БЕЗПЕКА").rows
    # "И" + U+0306 (бреве) у NFC перетворюється на одну літеру "Й"
    assert PolybiusSquare.build(UKRAINIAN, "кйїв").keyword == "КЙЇВ"


def test_keyword_may_contain_square_digits():
    assert PolybiusSquare.build(UKRAINIAN, "КЛЮЧ2").rows[0] == "КЛЮЧ2А"
    assert PolybiusSquare.build(LATIN, "AGENT007").rows[0] == "AGENT0"


@pytest.mark.parametrize("alphabet, key, fragment", [
    (UKRAINIAN, "", "порожнім"),
    (UKRAINIAN, "КЛЮЧ 1", "' '"),
    (UKRAINIAN, "KEY", "'K'"),            # латиниця в українському квадраті
    (UKRAINIAN, "КЛЮЧ5", "'5'"),          # цифри 3-9 відсутні в українському квадраті
    (LATIN, "КЛЮЧ", "'К'"),
    (UKRAINIAN, "012", "щонайменше одну літеру"),
    (LATIN, "2024", "щонайменше одну літеру"),
    (UKRAINIAN, "ПАРОЛЬ!", "'!'"),
])
def test_invalid_keywords_rejected(alphabet, key, fragment):
    with pytest.raises(CipherError, match=fragment):
        PolybiusSquare.build(alphabet, key)


def test_render_shows_rows_and_columns():
    text = PolybiusSquare.build(LATIN, "SECURITY").render()
    assert "1 2 3 4 5 6" in text and "6 | 4 5 6 7 8 9" in text
