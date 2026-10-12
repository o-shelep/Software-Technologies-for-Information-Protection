"""Робота з UTF-8 файлами та консольним інтерфейсом."""

import cli


def test_file_roundtrip_multiline(tmp_path):
    src = tmp_path / "plain.txt"
    enc = tmp_path / "cipher.txt"
    dec = tmp_path / "decoded.txt"
    text = "Перший рядок: Ґанок.\nДругий рядок — їжак, єнот.\n"
    src.write_text(text, encoding="utf-8", newline="")

    assert cli.main(["encrypt", "-a", "vigenere", "-k", "КЛЮЧ", "-i", str(src), "-o", str(enc)]) == 0
    assert cli.main(["decrypt", "-a", "vigenere", "-k", "КЛЮЧ", "-i", str(enc), "-o", str(dec)]) == 0
    result = dec.read_text(encoding="utf-8", newline="")
    assert result == text.upper()
    assert result.endswith("\n")  # завершальний перенос збережено


def test_file_columnar_with_pad(tmp_path, capsys):
    src = tmp_path / "plain.txt"
    enc = tmp_path / "cipher.txt"
    src.write_text("Рядок один\nрядок два\n", encoding="utf-8", newline="")
    assert cli.main(["encrypt", "-a", "columnar", "-k", "3 1 4 2", "-i", str(src), "-o", str(enc)]) == 0
    pad = int(capsys.readouterr().err.split("Доповнення: ")[1].split()[0])
    assert cli.main(["decrypt", "-a", "columnar", "-k", "3 1 4 2", "--pad", str(pad), "-i", str(enc)]) == 0
    assert capsys.readouterr().out == "РЯДОК ОДИН\nРЯДОК ДВА\n\n"  # print додає ще один \n


def test_file_not_utf8(tmp_path, capsys):
    src = tmp_path / "cp1251.txt"
    src.write_bytes("Привіт".encode("cp1251"))
    assert cli.main(["encrypt", "-a", "vigenere", "-k", "КЛЮЧ", "-i", str(src)]) == 1
    assert "UTF-8" in capsys.readouterr().err


def test_missing_file(tmp_path, capsys):
    assert cli.main(["encrypt", "-a", "vigenere", "-k", "КЛЮЧ", "-i", str(tmp_path / "nope.txt")]) == 1
    assert "Помилка файлу" in capsys.readouterr().err


def test_error_leaves_no_output_file(tmp_path):
    out = tmp_path / "out.txt"
    assert cli.main(["encrypt", "-a", "block", "-k", "1 1", "-t", "ТЕКСТ", "-o", str(out)]) == 1
    assert not out.exists()


def test_cli_text_vector(capsys):
    assert cli.main(["encrypt", "-a", "vigenere", "-k", "ключ", "-t", "Слава Україні"]) == 0
    assert capsys.readouterr().out.strip() == "ВЬЮЩК ДЇККЧЛД"
