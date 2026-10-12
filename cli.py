"""Консольний інтерфейс до навчальних шифрів (ЛР 1).

Приклади:
  python cli.py encrypt -a vigenere -k КЛЮЧ -t "Слава Україні"
  python cli.py decrypt -a columnar -k "3 1 4 2" --pad 0 -i cipher.txt -o plain.txt
  python cli.py rules
"""

import argparse
import os
import sys
import tempfile

from ciphers import ALPHABET, CipherError, block, columnar, substitution, vigenere

ALGORITHMS = ("substitution", "vigenere", "block", "columnar")

RULES = f"""Правила підготовки тексту:
  * кодування файлів: UTF-8; програма працює з рядками Unicode;
  * нормалізація Unicode NFC, потім переведення у верхній регістр;
  * алфавіт ({len(ALPHABET)} літери): {ALPHABET};
  * пробіли, цифри, розділові знаки й переноси рядків зберігаються;
    у Віженері вони не просувають позицію ключа;
  * літери інших алфавітів (латиниця, Ы, Э, Ё) — помилка;
  * перестановки: режим preserve (за замовчуванням) переставляє весь
    текст разом із пробілами; режим letters спершу лишає тільки літери;
  * блокова перестановка: неповний останній блок не змінюється;
  * вертикальна перестановка: останній рядок доповнюється символом
    '{columnar.PAD_CHAR}', кількість доповнення виводиться окремо і
    передається при розшифруванні через --pad.
"""


def run(command: str, algorithm: str, key: str, text: str, mode: str = "preserve", pad: int = 0):
    """Вся логіка вибору шифру — тут; повертає (результат, доповнення або None)."""
    enc = command == "encrypt"
    if algorithm == "substitution":
        # Готова таблиця з 33 різних літер — теж ключове слово: побудова поверне її ж.
        f = substitution.encrypt_keyword if enc else substitution.decrypt_keyword
        return f(text, key), None
    if algorithm == "vigenere":
        return (vigenere.encrypt if enc else vigenere.decrypt)(text, key), None
    if algorithm == "block":
        return (block.encrypt if enc else block.decrypt)(text, key, mode), None
    if algorithm == "columnar":
        if enc:
            return columnar.encrypt(text, key, mode)
        return columnar.decrypt(text, key, pad, mode), None
    raise CipherError(f"Невідомий алгоритм '{algorithm}'.")


def read_input(args) -> str:
    if args.text is not None:
        return args.text
    if args.input:
        # newline="" — зберігаємо переноси рядків точно такими, як у файлі.
        with open(args.input, encoding="utf-8", newline="") as fh:
            return fh.read()
    if sys.stdin.isatty():
        return input("Введіть текст: ")
    return sys.stdin.read()


def write_atomic(path: str, data: str) -> None:
    """Пишемо у тимчасовий файл і лише потім перейменовуємо: без частково записаних результатів."""
    folder = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=folder, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Навчальні шифри заміни та перестановки (не для реального захисту даних)."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("rules", help="показати правила підготовки тексту")
    for name, title in (("encrypt", "зашифрувати"), ("decrypt", "розшифрувати")):
        p = sub.add_parser(name, help=title)
        p.add_argument("-a", "--algorithm", required=True, choices=ALGORITHMS, help="алгоритм")
        p.add_argument("-k", "--key", required=True,
                       help="ключ: слово (substitution/vigenere), таблиця з 33 літер "
                            "(substitution) або перестановка '3 2 5 1 4' (block/columnar)")
        src = p.add_mutually_exclusive_group()
        src.add_argument("-t", "--text", help="текст у командному рядку")
        src.add_argument("-i", "--input", help="вхідний файл UTF-8")
        p.add_argument("-o", "--output", help="вихідний файл UTF-8 (інакше — екран)")
        p.add_argument("-m", "--mode", choices=block.MODES, default="preserve",
                       help="режим для перестановок (default: preserve)")
        if name == "decrypt":
            p.add_argument("--pad", type=int, default=0,
                           help="кількість доповнення (лише для columnar)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        print(RULES)
        return 0
    try:
        text = read_input(args)
        result, pad = run(args.command, args.algorithm, args.key, text,
                          args.mode, getattr(args, "pad", 0))
        if args.output:
            write_atomic(args.output, result)
            print(f"Результат записано у файл {args.output}", file=sys.stderr)
        else:
            print(result)
        if pad is not None:
            print(f"Доповнення: {pad} (передайте --pad {pad} при розшифруванні)", file=sys.stderr)
        return 0
    except CipherError as exc:
        print(f"Помилка: {exc}", file=sys.stderr)
    except UnicodeDecodeError:
        print("Помилка: вхідний файл не в кодуванні UTF-8.", file=sys.stderr)
    except OSError as exc:
        print(f"Помилка файлу: {exc.strerror}: {exc.filename}", file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("Помилка: введення перервано.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
