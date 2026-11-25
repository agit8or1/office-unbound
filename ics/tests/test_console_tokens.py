"""Console (ics/frontend/src/style.css) tokens added by the UI audit that test_brand.py does not cover yet: the form-field border is the
shared --ou-field (WCAG 1.4.11, 3:1 against every surface a field sits on), in both themes and in the forced dark theme."""
import re
from pathlib import Path

from ics.deploy import brand

ROOT = Path(__file__).resolve().parents[2]
CSS = (ROOT / "ics/frontend/src/style.css").read_text()
TOK = re.compile(r"--([a-z0-9-]+):\s*([^;]+);")


def _blocks():
    light = dict(TOK.findall(CSS.split(":root {", 1)[1].split("}", 1)[0]))
    media = dict(TOK.findall(CSS.split(':root:not([data-theme="light"]) {', 1)[1].split("}", 1)[0]))
    forced = dict(TOK.findall(CSS.split(':root[data-theme="dark"] {', 1)[1].split("}", 1)[0]))
    return light, {**light, **media}, {**light, **forced}


def _lum(h: str) -> float:
    h = h.lstrip("#")
    c = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def _contrast(a: str, b: str) -> float:
    x, y = sorted((_lum(a), _lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


def test_the_console_field_border_is_the_shared_field_token_in_both_themes():
    light, dark, forced = _blocks()
    sl, sd = brand.tokens()
    assert light["field"] == sl["field"]
    assert dark["field"] == sd["field"] == forced["field"]


def test_console_field_borders_reach_3_to_1_on_every_console_surface():
    for c in _blocks():
        for bg in ("bg", "surface", "surface2", "sunken"):
            assert _contrast(c["field"], c[bg]) >= 3, (bg, c["field"], c[bg])


def test_inputs_and_wizard_fields_use_the_field_token():
    assert "select, textarea { background: var(--surface); border: 1px solid var(--field);" in CSS
    kit = (ROOT / "ics/frontend/src/wizards/kit/kit.css").read_text()
    assert "border: 1px solid var(--field, #90856f)" in kit
