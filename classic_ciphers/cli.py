"""Консольний інтерфейс: команди encrypt, decrypt, square.

Коди завершення: 0 — успіх, 1 — некоректні дані (ключ, текст, координати),
2 — некоректні аргументи командного рядка (argparse).
"""

import argparse
import os
import sys
import tempfile

from .alphabets import ALPHABETS
from .errors import CipherError
from .service import ALGORITHMS, SQUARE_ALGORITHMS, Request, build_square, process

EXIT_OK, EXIT_DATA_ERROR = 0, 1

EPILOG = """приклади:
  python -m classic_ciphers encrypt --lang uk --algo coordinates --key БЕЗПЕКА --text "СЛАВА"
  python -m classic_ciphers decrypt --lang uk --algo coordinates --key БЕЗПЕКА --text "44 35 16 21 16"
  python -m classic_ciphers encrypt --lang en --algo gronsfeld --key 2718 --input in.txt --output out.txt
  python -m classic_ciphers square  --lang uk --key БЕЗПЕКА
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="classic_ciphers",
        description="Навчальні шифри: квадрат Полібія (coordinates, row-shift) і шифр Гронсфельда. "
                    "Не застосовувати для реального захисту даних.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="КОМАНДА")

    for name, help_text in (("encrypt", "зашифрувати текст"), ("decrypt", "розшифрувати текст")):
        cmd = sub.add_parser(name, help=help_text, description=help_text.capitalize() + ".")
        _add_common(cmd)
        cmd.add_argument("--algo", required=True, choices=ALGORITHMS,
                         help="алгоритм: coordinates | row-shift | gronsfeld")
        source = cmd.add_mutually_exclusive_group()
        source.add_argument("--text", help="текст, введений вручну")
        source.add_argument("--input", metavar="ФАЙЛ", help="вхідний файл UTF-8")
        cmd.add_argument("--output", metavar="ФАЙЛ", help="вихідний файл UTF-8 (інакше — екран)")
        cmd.add_argument("--show-square", action="store_true",
                         help="показати активний квадрат (для coordinates і row-shift)")
        if name == "encrypt":
            cmd.add_argument("--strip-whitespace", action="store_true",
                             help="coordinates: явно вилучити пробіли й переноси перед шифруванням")

    sq = sub.add_parser("square", help="показати ключовий квадрат 6x6",
                        description="Показати ключовий квадрат 6x6.")
    _add_common(sq)
    return parser


def _add_common(cmd: argparse.ArgumentParser) -> None:
    cmd.add_argument("--lang", required=True, choices=sorted(ALPHABETS),
                     help="алфавіт: uk — український, en — латинський (обирається явно)")
    cmd.add_argument("--key", required=True,
                     help="ключове слово (Полібій) або рядок цифр (Гронсфельд)")


def read_text(args: argparse.Namespace) -> tuple[str, bool]:
    """Повертає текст і ознаку, що він прочитаний з файлу або потоку."""
    if args.text is not None:
        return args.text, False
    if args.input:
        with open(args.input, encoding="utf-8", newline="") as f:
            return f.read(), True
    if sys.stdin.isatty():
        print("Введіть текст (завершення: Ctrl+D, у Windows Ctrl+Z і Enter):", file=sys.stderr)
    return sys.stdin.read(), True


def write_atomically(path: str, content: str) -> None:
    """Запис через тимчасовий файл: при помилці частковий результат не з'являється."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def _strip_final_newline(text: str) -> str:
    for ending in ("\r\n", "\n"):
        if text.endswith(ending):
            return text[: -len(ending)]
    return text


def run(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    args = build_parser().parse_args(argv)
    try:
        if args.command == "square":
            print(build_square(args.lang, args.key).render())
            return EXIT_OK

        text, from_stream = read_text(args)
        coordinates = args.algo == "coordinates"
        if coordinates and from_stream:
            # Завершальний перенос рядка у файлі є оформленням файлу, а не даними.
            text = _strip_final_newline(text)

        result = process(Request(
            operation=args.command,
            algorithm=args.algo,
            alphabet=args.lang,
            key=args.key,
            text=text,
            strip_whitespace=getattr(args, "strip_whitespace", False),
        ))

        if args.show_square and args.algo in SQUARE_ALGORITHMS:
            print(build_square(args.lang, args.key).render(), end="\n\n", file=sys.stderr)

        if args.output:
            write_atomically(args.output, result + "\n" if coordinates else result)
            print(f"Результат записано у файл: {args.output}", file=sys.stderr)
        else:
            print(result, end="" if result.endswith("\n") else "\n")
        return EXIT_OK
    except CipherError as exc:
        print(f"Помилка: {exc}", file=sys.stderr)
        return EXIT_DATA_ERROR
    except FileNotFoundError as exc:
        print(f"Помилка: файл не знайдено: {exc.filename}", file=sys.stderr)
        return EXIT_DATA_ERROR
    except UnicodeDecodeError:
        print("Помилка: вхідний файл не є коректним текстом UTF-8.", file=sys.stderr)
        return EXIT_DATA_ERROR
