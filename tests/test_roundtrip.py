"""Зворотність D_k(E_k(x)) = підготовлений x: фіксовані повідомлення та
генеративні (property-based) тести на випадкових ключах і текстах."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from classic_ciphers import LATIN, UKRAINIAN
from classic_ciphers.service import Request, process
from classic_ciphers.text import prepare_text

MESSAGES_UK = [
    "СЛАВА УКРАЇНІ", "ҐАНОК І ЄНОТ", "Їжак їсть яблука.", "ЩАСТЯ — ЦЕ СВОБОДА!",
    "Київ, Львів, Ужгород", "Шифр Гронсфельда\nдругий рядок\n", "ЮРИДИЧНИЙ ФАКУЛЬТЕТ 2026",
    "Ь Ю Я", "ПРИВІТ!", "Захист інформації — лабораторна №2",
]
MESSAGES_EN = [
    "HELLO WORLD", "The quick brown fox jumps over the lazy dog.", "ATTACK AT DAWN",
    "Zebra & Apple", "agent 007", "Line one\nline two\n", "CRYPTO-2026!", "A", "z y x", "Mixed CASE text",
]
ALL = [("uk", m) for m in MESSAGES_UK] + [("en", m) for m in MESSAGES_EN]
KEYWORDS = {"uk": "БЕЗПЕКА", "en": "SECURITY"}
ALPHABET = {"uk": UKRAINIAN, "en": LATIN}


def roundtrip(algo, lang, key, text, strip=False):
    cipher = process(Request("encrypt", algo, lang, key, text, strip_whitespace=strip))
    return process(Request("decrypt", algo, lang, key, cipher))


@pytest.mark.parametrize("lang, message", ALL)
def test_roundtrip_gronsfeld(lang, message):
    assert roundtrip("gronsfeld", lang, "0271828", message) == prepare_text(message, ALPHABET[lang].letters)


@pytest.mark.parametrize("lang, message", ALL)
def test_roundtrip_row_shift(lang, message):
    expected = prepare_text(message, ALPHABET[lang].square_symbols)
    assert roundtrip("row-shift", lang, KEYWORDS[lang], message) == expected


@pytest.mark.parametrize("lang, message", [
    ("uk", "СЛАВАУКРАЇНІ"), ("uk", "ҐЄІЇ012"), ("uk", "ЖАБАЬЮЯ"), ("uk", "ПРИВІТ СВІТЕ"),
    ("uk", "ЩАСТЯ\nСВОБОДА"), ("en", "HELLO WORLD"), ("en", "AGENT007"), ("en", "ZEBRA 2026"),
    ("en", "attack at dawn"), ("en", "QWERTY0123456789"),
])
def test_roundtrip_coordinates_with_visible_space_removal(lang, message):
    expected = prepare_text("".join(message.split()), ALPHABET[lang].square_symbols)
    assert roundtrip("coordinates", lang, KEYWORDS[lang], message, strip=True) == expected


# ------------------------------------------------------------ property-based

def keyword_strategy(alphabet):
    return st.text(alphabet=alphabet.square_symbols, min_size=1, max_size=15).filter(
        lambda k: any(ch in alphabet.letters for ch in k)
    )


digit_keys = st.text(alphabet="0123456789", min_size=1, max_size=20).filter(lambda k: set(k) != {"0"})
any_text = st.text(max_size=200)


@settings(max_examples=200)
@given(lang=st.sampled_from(["uk", "en"]), key=digit_keys, text=any_text)
def test_property_gronsfeld(lang, key, text):
    assert roundtrip("gronsfeld", lang, key, text) == prepare_text(text, ALPHABET[lang].letters)


@settings(max_examples=200)
@given(data=st.data(), lang=st.sampled_from(["uk", "en"]), text=any_text)
def test_property_row_shift(data, lang, text):
    key = data.draw(keyword_strategy(ALPHABET[lang]))
    assert roundtrip("row-shift", lang, key, text) == prepare_text(text, ALPHABET[lang].square_symbols)


@settings(max_examples=200)
@given(data=st.data(), lang=st.sampled_from(["uk", "en"]))
def test_property_coordinates(data, lang):
    alphabet = ALPHABET[lang]
    key = data.draw(keyword_strategy(alphabet))
    text = data.draw(st.text(alphabet=alphabet.square_symbols, max_size=100))
    cipher = process(Request("encrypt", "coordinates", lang, key, text))
    assert len(cipher) == max(0, 3 * len(text) - 1)
    assert process(Request("decrypt", "coordinates", lang, key, cipher)) == text
