"""Генеративні (property-based) тести зворотності на випадкових ключах і текстах."""

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # noqa: E402

from ciphers import ALPHABET, block, columnar, prepare_text, substitution, vigenere  # noqa: E402

texts = st.text(alphabet=ALPHABET + ALPHABET.lower() + " ,.!?-'\n0123456789", max_size=200)
words = st.text(alphabet=ALPHABET, min_size=1, max_size=15)
perms = st.integers(min_value=1, max_value=12).flatmap(
    lambda n: st.permutations(list(range(1, n + 1)))
)


@settings(max_examples=200)
@given(texts, words)
def test_substitution_property(text, key):
    assert substitution.decrypt_keyword(substitution.encrypt_keyword(text, key), key) == prepare_text(text)


@settings(max_examples=200)
@given(texts, words)
def test_vigenere_property(text, key):
    assert vigenere.decrypt(vigenere.encrypt(text, key), key) == prepare_text(text)


@settings(max_examples=200)
@given(texts, perms)
def test_block_property(text, perm):
    assert block.decrypt(block.encrypt(text, perm), perm) == prepare_text(text)


@settings(max_examples=200)
@given(texts, perms)
def test_columnar_property(text, perm):
    cipher, pad = columnar.encrypt(text, perm)
    assert columnar.decrypt(cipher, perm, pad) == prepare_text(text)
