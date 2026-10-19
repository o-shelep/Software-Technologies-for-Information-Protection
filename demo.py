"""Генерує відтворювані результати для звіту: results/report_data.md.

Запуск:  python demo.py
Містить: власні квадрати 6x6, таблицю контрольних векторів (очікуване / фактичне /
статус) та власні приклади шифрування і розшифрування для всіх трьох режимів.
Щоб використати свої дані, змініть константи OWN_* нижче.
"""

from pathlib import Path

from classic_ciphers.service import Request, build_square, process
from tests.test_vectors import VECTORS

OWN_KEYWORD = {"uk": "КРИПТОГРАФІЯ", "en": "CRYPTOGRAPHY"}
OWN_DIGIT_KEY = {"uk": "0271", "en": "1945"}
OWN_TEXT = {
    "uk": "Захист інформації — це наука, а не магія!",
    "en": "Classic ciphers are for learning only.",
}
ALGO_TITLE = {"coordinates": "Полібій coordinates", "row-shift": "Полібій row shift", "gronsfeld": "Гронсфельд"}
LANG_TITLE = {"uk": "український", "en": "латинський"}


def md_square(lang: str, key: str) -> str:
    square = build_square(lang, key)
    lines = ["| Рядок | 1 | 2 | 3 | 4 | 5 | 6 |", "|---|---|---|---|---|---|---|"]
    for r, row in enumerate(square.rows, start=1):
        lines.append(f"| **{r}** | " + " | ".join(row) + " |")
    return "\n".join(lines)


def vectors_table() -> str:
    lines = [
        "| Алгоритм, алфавіт | Ключ | Вхід | Очікувано | Фактично (E) | D(E(x)) | Статус |",
        "|---|---|---|---|---|---|---|",
    ]
    for algo, lang, key, plain, expected in VECTORS:
        actual = process(Request("encrypt", algo, lang, key, plain))
        restored = process(Request("decrypt", algo, lang, key, actual))
        ok = actual == expected and restored == plain
        lines.append(
            f"| {ALGO_TITLE[algo]}, {LANG_TITLE[lang]} | {key} | {plain} | `{expected}` | "
            f"`{actual}` | {restored} | {'OK' if ok else 'FAIL'} |"
        )
    return "\n".join(lines)


def own_examples() -> str:
    lines = [
        "| Режим | Алфавіт | Ключ | Відкритий текст (вхід) | Шифротекст | Розшифровано |",
        "|---|---|---|---|---|---|",
    ]
    for lang in ("uk", "en"):
        for algo in ("coordinates", "row-shift", "gronsfeld"):
            key = OWN_DIGIT_KEY[lang] if algo == "gronsfeld" else OWN_KEYWORD[lang]
            text = OWN_TEXT[lang]
            if algo == "coordinates":
                # Координатний режим приймає лише символи квадрата:
                # підготовка тексту — окрема видима операція.
                text = "".join(ch for ch in text if ch.isalnum())
            cipher = process(Request("encrypt", algo, lang, key, text, strip_whitespace=algo == "coordinates"))
            plain = process(Request("decrypt", algo, lang, key, cipher))
            lines.append(f"| {ALGO_TITLE[algo]} | {LANG_TITLE[lang]} | {key} | {text} | `{cipher}` | {plain} |")
    return "\n".join(lines)


def main() -> None:
    parts = [
        "# Дані для звіту (згенеровано demo.py)\n",
        f"## Власний український квадрат, ключ {OWN_KEYWORD['uk']}\n\n{md_square('uk', OWN_KEYWORD['uk'])}\n",
        f"## Власний латинський квадрат, ключ {OWN_KEYWORD['en']}\n\n{md_square('en', OWN_KEYWORD['en'])}\n",
        f"## Контрольні вектори (розділ 7)\n\n{vectors_table()}\n",
        "## Власні приклади\n",
        "Для координатного режиму пробіли та розділові знаки вилучено окремою операцією "
        "підготовки; розшифрування повертає підготовлений текст (верхній регістр).\n",
        own_examples() + "\n",
    ]
    out = Path(__file__).parent / "results" / "report_data.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(parts), encoding="utf-8")
    print(f"Збережено: {out}")


if __name__ == "__main__":
    main()
