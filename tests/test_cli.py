"""Перевірка інтерфейсу командного рядка, файлів UTF-8 і режимів."""

import pytest

from classic_ciphers.cli import run
from classic_ciphers.errors import CipherError
from classic_ciphers.service import Request, process


def test_cli_encrypt_text(capsys):
    code = run(["encrypt", "--lang", "uk", "--algo", "coordinates", "--key", "БЕЗПЕКА", "--text", "СЛАВА"])
    assert code == 0
    assert capsys.readouterr().out == "44 35 16 21 16\n"


def test_cli_error_has_nonzero_exit_and_message(capsys):
    code = run(["decrypt", "--lang", "uk", "--algo", "coordinates", "--key", "БЕЗПЕКА", "--text", "11 00"])
    err = capsys.readouterr().err
    assert code == 1 and "Помилка" in err and "'00'" in err


def test_cli_unknown_algorithm_is_rejected():
    with pytest.raises(SystemExit) as exc:
        run(["encrypt", "--lang", "uk", "--algo", "vigenere", "--key", "1", "--text", "А"])
    assert exc.value.code == 2


def test_cli_language_is_required():
    with pytest.raises(SystemExit) as exc:
        run(["encrypt", "--algo", "gronsfeld", "--key", "1", "--text", "А"])
    assert exc.value.code == 2


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        run(["--help"])
    assert exc.value.code == 0 and "encrypt" in capsys.readouterr().out


def test_cli_square(capsys):
    assert run(["square", "--lang", "en", "--key", "SECURITY"]) == 0
    assert "1 | S E C U R I" in capsys.readouterr().out


def test_file_roundtrip_multiline_with_trailing_newline(tmp_path):
    source = tmp_path / "plain.txt"
    cipher = tmp_path / "cipher.txt"
    restored = tmp_path / "restored.txt"
    text = "Слава Україні!\nГероям слава.\n"
    source.write_text(text, encoding="utf-8")

    base = ["--lang", "uk", "--algo", "gronsfeld", "--key", "31415"]
    assert run(["encrypt", *base, "--input", str(source), "--output", str(cipher)]) == 0
    assert run(["decrypt", *base, "--input", str(cipher), "--output", str(restored)]) == 0
    assert cipher.read_text(encoding="utf-8").startswith("ФМҐГД ЦЛФБНРЇ!\n")
    assert restored.read_text(encoding="utf-8") == "СЛАВА УКРАЇНІ!\nГЕРОЯМ СЛАВА.\n"


def test_file_coordinates_with_strip_whitespace(tmp_path):
    source = tmp_path / "plain.txt"
    cipher = tmp_path / "cipher.txt"
    restored = tmp_path / "restored.txt"
    source.write_text("слава\nукраїні\n", encoding="utf-8")

    base = ["--lang", "uk", "--algo", "coordinates", "--key", "БЕЗПЕКА"]
    assert run(["encrypt", *base, "--strip-whitespace", "--input", str(source), "--output", str(cipher)]) == 0
    assert cipher.read_text(encoding="utf-8").endswith("\n")
    assert run(["decrypt", *base, "--input", str(cipher), "--output", str(restored)]) == 0
    assert restored.read_text(encoding="utf-8") == "СЛАВАУКРАЇНІ\n"


def test_failed_operation_leaves_no_output_file(tmp_path):
    source = tmp_path / "bad.txt"
    out = tmp_path / "out.txt"
    source.write_text("11 22 77\n", encoding="utf-8")
    code = run(["decrypt", "--lang", "uk", "--algo", "coordinates", "--key", "БЕЗПЕКА",
                "--input", str(source), "--output", str(out)])
    assert code == 1
    assert not out.exists()
    assert list(tmp_path.iterdir()) == [source]  # жодних тимчасових файлів


def test_invalid_utf8_file(tmp_path, capsys):
    source = tmp_path / "cp1251.txt"
    source.write_bytes("Слава".encode("cp1251"))
    code = run(["encrypt", "--lang", "uk", "--algo", "gronsfeld", "--key", "1", "--input", str(source)])
    assert code == 1 and "UTF-8" in capsys.readouterr().err


def test_missing_file(capsys):
    code = run(["encrypt", "--lang", "uk", "--algo", "gronsfeld", "--key", "1", "--input", "no_such_file.txt"])
    assert code == 1 and "не знайдено" in capsys.readouterr().err


@pytest.mark.parametrize("request_", [
    Request("encode", "gronsfeld", "uk", "1", "А"),
    Request("encrypt", "caesar", "uk", "1", "А"),
    Request("encrypt", "gronsfeld", "auto", "1", "А"),
    Request("decrypt", "row-shift", "uk", "БЕЗПЕКА", "А", strip_whitespace=True),
])
def test_unsupported_modes_rejected(request_):
    with pytest.raises(CipherError):
        process(request_)


def test_key_is_validated_before_processing():
    # Помилка ключа повідомляється навіть для порожнього тексту.
    with pytest.raises(CipherError, match="нулів"):
        process(Request("encrypt", "gronsfeld", "uk", "000", ""))
