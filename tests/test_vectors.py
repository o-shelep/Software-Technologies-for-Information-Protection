"""Обов'язкові контрольні вектори з розділу 7 методички: прямий результат і відновлення."""

from ciphers import ALPHABET, block, columnar, substitution, vigenere

REVERSED = ALPHABET[::-1]


def test_substitution_reversed_alphabet():
    assert substitution.encrypt("СЛАВА УКРАЇНІ", REVERSED) == "ІНЯЬЯ ЗОЇЯРЛС"
    assert substitution.decrypt("ІНЯЬЯ ЗОЇЯРЛС", REVERSED) == "СЛАВА УКРАЇНІ"


def test_vigenere():
    assert vigenere.encrypt("СЛАВА УКРАЇНІ", "КЛЮЧ") == "ВЬЮЩК ДЇККЧЛД"
    assert vigenere.decrypt("ВЬЮЩК ДЇККЧЛД", "КЛЮЧ") == "СЛАВА УКРАЇНІ"


def test_block_permutation_letters_only():
    assert block.encrypt("СЛАВА УКРАЇНІ", "3 2 5 1 4", mode="letters") == "АЛАСВРКЇУАНІ"
    # Еталон зворотності — підготовлений рядок без пробілу.
    assert block.decrypt("АЛАСВРКЇУАНІ", "3 2 5 1 4", mode="letters") == "СЛАВАУКРАЇНІ"


def test_columnar():
    cipher, pad = columnar.encrypt("КРИПТОГРАФІЯ", (3, 1, 4, 2))
    assert (cipher, pad) == ("ИГІКТАПРЯРОФ", 0)
    assert columnar.decrypt(cipher, (3, 1, 4, 2), pad) == "КРИПТОГРАФІЯ"


def test_keyword_table_construction():
    table = substitution.table_from_keyword("шифрування")
    assert table.startswith("ШИФРУВАН")
    assert len(table) == 33 and set(table) == set(ALPHABET)
