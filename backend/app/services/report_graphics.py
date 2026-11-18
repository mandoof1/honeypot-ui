"""Vector figures for the investigation report, and raster copies for Word.

Every figure is a ReportLab ``Drawing`` built from a handful of primitive
shapes (rectangles, lines, polygons, circles, text). The PDF embeds them as
vectors; the Word document gets a PNG painted from the same drawing by
``to_png``, so the two formats cannot drift apart.
"""

from __future__ import annotations

import math
from io import BytesIO
from pathlib import Path

from reportlab.graphics.shapes import (
    Circle,
    Drawing,
    Ellipse,
    Group,
    Line,
    Polygon,
    PolyLine,
    Rect,
    String,
    UserNode,
    mmult,
    transformPoint,
)
from reportlab.lib import colors
from reportlab.lib.fonts import addMapping
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from app.services.report_analytics import LEVELS, SCALE, TACTICS

FONT_DIR = Path(__file__).parent / "report_assets" / "fonts"

#: Registered name -> file. Plex for text and data, Space Grotesk for display.
FONTS = {
    "HS-Sans": "IBMPlexSans-Regular.ttf",
    "HS-Sans-Medium": "IBMPlexSans-Medium.ttf",
    "HS-Sans-SemiBold": "IBMPlexSans-SemiBold.ttf",
    "HS-Sans-Bold": "IBMPlexSans-Bold.ttf",
    "HS-Sans-Italic": "IBMPlexSans-Italic.ttf",
    "HS-Mono": "IBMPlexMono-Regular.ttf",
    "HS-Mono-SemiBold": "IBMPlexMono-SemiBold.ttf",
    "HS-Display": "SpaceGrotesk-Bold.ttf",
    "HS-Display-Medium": "SpaceGrotesk-Medium.ttf",
}

INK0 = "#0a0a0c"
INK1 = "#101014"
INK2 = "#17171d"
INK3 = "#1f1f27"
LINE = "#2a2a34"
LINE2 = "#3a3a46"
PAPER = "#f2f0ea"
PAPER2 = "#9b9aa3"
PAPER3 = "#7d7c86"
SHEET = "#ffffff"
SHEET2 = "#f6f5f1"
RULE = "#dddcd6"
TEXT = "#101014"
MUTED = "#5d5c66"

TLP_COLOURS = {"TLP:RED": "#ff2b2b", "TLP:AMBER": "#ffc000", "TLP:GREEN": "#33ff00", "TLP:CLEAR": "#ffffff"}


def register_fonts() -> None:
    registered = set(pdfmetrics.getRegisteredFontNames())
    for name, file in FONTS.items():
        if name not in registered:
            pdfmetrics.registerFont(TTFont(name, str(FONT_DIR / file)))
    addMapping("HS-Sans", 0, 0, "HS-Sans")
    addMapping("HS-Sans", 1, 0, "HS-Sans-SemiBold")
    addMapping("HS-Sans", 0, 1, "HS-Sans-Italic")
    addMapping("HS-Sans", 1, 1, "HS-Sans-SemiBold")
    addMapping("HS-Mono", 0, 0, "HS-Mono")
    addMapping("HS-Mono", 1, 0, "HS-Mono-SemiBold")
    addMapping("HS-Mono", 0, 1, "HS-Mono")
    addMapping("HS-Mono", 1, 1, "HS-Mono-SemiBold")


def hexcolour(value):
    return colors.HexColor(value) if isinstance(value, str) else value


def mix(a: str, b: str, amount: float) -> str:
    """``amount`` of colour ``b`` over colour ``a``."""
    ca, cb = colors.HexColor(a), colors.HexColor(b)
    channels = [
        int(round(255 * (x + (y - x) * amount)))
        for x, y in zip((ca.red, ca.green, ca.blue), (cb.red, cb.green, cb.blue))
    ]
    return "#%02x%02x%02x" % tuple(channels)


def width_of(text, font, size) -> float:
    return pdfmetrics.stringWidth(str(text), font, size)


def wrap(text, font, size, width, limit=None) -> list[str]:
    words = str(text).split()
    lines, line = [], ""
    for word in words:
        candidate = (line + " " + word).strip()
        if width_of(candidate, font, size) <= width or not line:
            line = candidate
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    if limit and len(lines) > limit:
        lines = lines[:limit]
        while lines[-1] and width_of(lines[-1] + " ...", font, size) > width:
            lines[-1] = lines[-1].rsplit(" ", 1)[0] if " " in lines[-1] else lines[-1][:-1]
        lines[-1] += " ..."
    return lines


def fit(text, font, size, width) -> str:
    text = str(text)
    if width_of(text, font, size) <= width:
        return text
    while text and width_of(text + "...", font, size) > width:
        text = text[:-1]
    return text + "..."


# -- primitives -------------------------------------------------------------


def rect(x, y, w, h, fill=None, stroke=None, stroke_width=0.6, radius=0):
    return Rect(
        x, y, w, h, rx=radius, ry=radius,
        fillColor=hexcolour(fill) if fill else None,
        strokeColor=hexcolour(stroke) if stroke else None,
        strokeWidth=stroke_width,
    )


def text(x, y, value, font="HS-Sans", size=8, fill=TEXT, anchor="start"):
    return String(x, y, str(value), fontName=font, fontSize=size, fillColor=hexcolour(fill), textAnchor=anchor)


def line(x1, y1, x2, y2, stroke=RULE, width=0.6):
    return Line(x1, y1, x2, y2, strokeColor=hexcolour(stroke), strokeWidth=width)


def arc_polygon(cx, cy, outer, inner, start, end, fill, steps=None):
    """An annular sector from ``start`` to ``end`` degrees, as one polygon."""
    steps = steps or max(6, int(abs(end - start) / 2))
    points = []
    for i in range(steps + 1):
        a = math.radians(start + (end - start) * i / steps)
        points += [cx + outer * math.cos(a), cy + outer * math.sin(a)]
    for i in range(steps, -1, -1):
        a = math.radians(start + (end - start) * i / steps)
        points += [cx + inner * math.cos(a), cy + inner * math.sin(a)]
    return Polygon(points, fillColor=hexcolour(fill), strokeColor=None, strokeWidth=0)


def logo(x, y, size, colour=PAPER):
    """The hexagon mark, ``size`` points across, lower-left corner at x, y."""
    k = size / 24.0
    group = Group()

    def hexagon(points, filled):
        flat = []
        for px, py in points:
            flat += [x + px * k, y + (24 - py) * k]
        return Polygon(
            flat,
            fillColor=hexcolour(colour) if filled else None,
            strokeColor=None if filled else hexcolour(colour),
            strokeWidth=1.3 * k,
        )

    group.add(hexagon([(12, 2.4), (20.8, 7.2), (20.8, 16.8), (12, 21.6), (3.2, 16.8), (3.2, 7.2)], False))
    group.add(hexagon([(12, 8), (16.4, 10.4), (16.4, 15.2), (12, 17.6), (7.6, 15.2), (7.6, 10.4)], True))
    return group


def brackets(x, y, w, h, colour=LINE2, length=14, width=0.9):
    """HUD corner brackets around a box."""
    group = Group()
    for cx, cy, dx, dy in [(x, y, 1, 1), (x + w, y, -1, 1), (x, y + h, 1, -1), (x + w, y + h, -1, -1)]:
        group.add(line(cx, cy, cx + dx * length, cy, colour, width))
        group.add(line(cx, cy, cx, cy + dy * length, colour, width))
    return group


# -- the threat gauge -------------------------------------------------------


def gauge_group(cx, cy, radius, index, level, dark=True, labels=True):
    """A half-circle dial in four coloured bands, filled up to the level."""
    group = Group()
    back = INK0 if dark else SHEET
    thickness = radius * 0.19
    inner = radius - thickness
    current = LEVELS.index(level)
    gap = 1.6
    for i, name in enumerate(LEVELS):
        start = 180 - i * 45 - gap / 2
        end = 180 - (i + 1) * 45 + gap / 2
        colour = SCALE[name]["colour"]
        fill = colour if i <= current else mix(back, colour, 0.22)
        group.add(arc_polygon(cx, cy, radius, inner, start, end, fill))
    # The reading: a thin bright arc just inside the bands, from 0 to the index.
    reading = 180 - 180 * index / 100
    group.add(arc_polygon(cx, cy, inner - 4, inner - 6.5, 180, reading, SCALE[level]["colour"]))
    tick_colour = PAPER3 if dark else MUTED
    for value in range(0, 101, 5):
        a = math.radians(180 - 1.8 * value)
        major = value % 25 == 0
        r1, r2 = radius + 5, radius + (12 if major else 8)
        group.add(
            line(cx + r1 * math.cos(a), cy + r1 * math.sin(a), cx + r2 * math.cos(a), cy + r2 * math.sin(a),
                 PAPER2 if (major and dark) else tick_colour, 1.1 if major else 0.6)
        )
        if major and labels:
            r3 = radius + 22
            group.add(text(cx + r3 * math.cos(a), cy + r3 * math.sin(a) - 3, str(value),
                           "HS-Mono", 7.5, PAPER2 if dark else MUTED, "middle"))
    # Needle.
    a = math.radians(reading)
    length = inner - 14
    perp = a + math.pi / 2
    base = radius * 0.035
    group.add(Polygon(
        [cx + base * math.cos(perp), cy + base * math.sin(perp),
         cx + length * math.cos(a), cy + length * math.sin(a),
         cx - base * math.cos(perp), cy - base * math.sin(perp)],
        fillColor=hexcolour(PAPER if dark else TEXT), strokeColor=None, strokeWidth=0,
    ))
    group.add(Circle(cx, cy, radius * 0.075, fillColor=hexcolour(back), strokeColor=hexcolour(PAPER if dark else TEXT), strokeWidth=1.4))
    group.add(Circle(cx, cy, radius * 0.03, fillColor=hexcolour(SCALE[level]["colour"]), strokeColor=None))
    return group


def level_scale(width, level, dark=False, height=34):
    """The four levels side by side, the current one outlined."""
    d = Drawing(width, height)
    gap = 6
    w = (width - 3 * gap) / 4
    for i, name in enumerate(LEVELS):
        x = i * (w + gap)
        info = SCALE[name]
        active = name == level
        d.add(rect(x, height - 8, w, 5, info["colour"] if active or dark else mix(SHEET, info["colour"], 0.55)))
        label_colour = (PAPER if active else PAPER3) if dark else (TEXT if active else MUTED)
        d.add(text(x, height - 21, info["name"], "HS-Display" if active else "HS-Display-Medium", 9, label_colour))
        d.add(text(x + w, height - 21, f"{info['band'][0]}-{info['band'][1]}", "HS-Mono", 7, label_colour, "end"))
        d.add(text(x, height - 31, info["colour_name"].upper(), "HS-Mono", 6, PAPER3 if dark else MUTED))
        if active:
            d.add(brackets(x - 3, 0, w + 6, height, info["colour"], 6, 1))
    return d


def gauge_badge(width, assessment, height=150):
    """A compact light-page gauge with the index and level beside it."""
    d = Drawing(width, height)
    radius = 62
    cx, cy = radius + 26, 30
    d.add(gauge_group(cx, cy, radius, assessment["index"], assessment["level"], dark=False))
    x = cx + radius + 44
    d.add(text(x, 112, "THREAT INDEX", "HS-Mono", 7, MUTED))
    d.add(text(x, 72, str(assessment["index"]), "HS-Display", 40, TEXT))
    d.add(text(x + width_of(str(assessment["index"]), "HS-Display", 40) + 4, 72, "/ 100", "HS-Mono", 9, MUTED))
    chip_w = width_of(assessment["name"], "HS-Display", 12) + 22
    d.add(rect(x, 38, chip_w, 20, assessment["colour"], radius=3))
    d.add(text(x + chip_w / 2, 44, assessment["name"], "HS-Display", 12, INK1, "middle"))
    d.add(text(x + chip_w + 8, 44, f"Level {assessment['level_number']} of 4 / {assessment['colour_name']}", "HS-Sans", 8.5, MUTED))
    d.add(text(x, 20, f"Band {assessment['band'][0]}-{assessment['band'][1]}  /  base {25 * (assessment['level_number'] - 1)} + factors {assessment['bonus']:.1f}", "HS-Mono", 7, MUTED))
    return d


def factor_bar(fraction, width=90, colour=TEXT, height=9):
    d = Drawing(width, height)
    d.add(rect(0, 2, width, 5, "#ecebe6"))
    if fraction > 0:
        d.add(rect(0, 2, max(1.5, width * fraction), 5, colour))
    return d


def chip(label, colour, font_size=7, height=12, text_colour=INK1):
    w = width_of(label, "HS-Display", font_size) + 10
    d = Drawing(w, height)
    d.add(rect(0, 0, w, height, colour, radius=2))
    d.add(text(w / 2, (height - font_size) / 2 + 1.2, label, "HS-Display", font_size, text_colour, "middle"))
    return d


# -- dashboard figures ------------------------------------------------------


def kpi_grid(items, width, columns=4, tile_height=58, gap=8, accent=None):
    """Tiles of (label, value, note)."""
    rows = math.ceil(len(items) / columns)
    height = rows * tile_height + (rows - 1) * gap
    d = Drawing(width, height)
    w = (width - (columns - 1) * gap) / columns
    for i, (label, value, note) in enumerate(items):
        row, col = divmod(i, columns)
        x = col * (w + gap)
        y = height - (row + 1) * tile_height - row * gap
        d.add(rect(x, y, w, tile_height, SHEET2, RULE, 0.6))
        d.add(rect(x, y + tile_height - 2, w, 2, accent or TEXT))
        d.add(text(x + 9, y + tile_height - 15, fit(str(label).upper(), "HS-Mono", 6.5, w - 18), "HS-Mono", 6.5, MUTED))
        size = 19
        value = str(value)
        while size > 10 and width_of(value, "HS-Display", size) > w - 18:
            size -= 1
        d.add(text(x + 9, y + 20, fit(value, "HS-Display", size, w - 18), "HS-Display", size, TEXT))
        if note:
            d.add(text(x + 9, y + 8, fit(note, "HS-Sans", 6.8, w - 18), "HS-Sans", 6.8, MUTED))
    return d


def rings(items, width, height=96):
    """Progress rings for rates: (label, fraction or None, note)."""
    d = Drawing(width, height)
    w = width / len(items)
    for i, (label, fraction, note) in enumerate(items):
        cx, cy, r = i * w + w / 2, height - 38, 26
        d.add(arc_polygon(cx, cy, r, r - 5, 0, 360, "#ecebe6", 90))
        if fraction is not None and fraction > 0:
            d.add(arc_polygon(cx, cy, r, r - 5, 90, 90 - 360 * min(1.0, fraction), TEXT, max(8, int(180 * fraction))))
        value = "n/a" if fraction is None else f"{fraction:.0%}"
        d.add(text(cx, cy - 4, value, "HS-Display", 12, TEXT if fraction is not None else MUTED, "middle"))
        d.add(text(cx, 16, fit(label, "HS-Sans-SemiBold", 7.5, w - 6), "HS-Sans-SemiBold", 7.5, TEXT, "middle"))
        d.add(text(cx, 6, fit(note, "HS-Sans", 6.5, w - 6), "HS-Sans", 6.5, MUTED, "middle"))
    return d


def hbars(rows, width, label_width=110, bar_height=11, gap=7, total=None):
    """Horizontal bars: (label, count, colour)."""
    rows = list(rows)
    height = max(1, len(rows)) * (bar_height + gap) + 4
    d = Drawing(width, height)
    total = total or max([r[1] for r in rows] + [1])
    span = width - label_width - 40
    for i, (label, count, colour) in enumerate(rows):
        y = height - (i + 1) * (bar_height + gap)
        d.add(text(0, y + 2.5, fit(label, "HS-Sans", 8, label_width - 8), "HS-Sans", 8, TEXT))
        d.add(rect(label_width, y, span, bar_height, "#efeeea"))
        d.add(rect(label_width, y, max(1.5, span * count / total), bar_height, colour))
        d.add(text(width, y + 2.5, str(count), "HS-Mono-SemiBold", 8, TEXT, "end"))
    return d


def stacked_bar(segments, width, height=40):
    """One bar split into (label, count, colour) segments, with a legend."""
    d = Drawing(width, height)
    total = sum(count for _, count, _ in segments) or 1
    x = 0
    for label, count, colour in segments:
        if count:
            w = width * count / total
            d.add(rect(x, height - 14, w, 14, colour))
            x += w
    lx = 0
    for label, count, colour in segments:
        d.add(rect(lx, 4, 8, 8, colour))
        caption = f"{label} {count}"
        d.add(text(lx + 12, 5, caption, "HS-Sans", 7.5, TEXT))
        lx += width_of(caption, "HS-Sans", 7.5) + 28
    return d


def timeline_chart(timeline, width, height=118):
    buckets = timeline.get("buckets") or []
    d = Drawing(width, height)
    if not buckets:
        d.add(text(0, height / 2, "No start times recorded.", "HS-Sans", 8, MUTED))
        return d
    left, bottom, top = 26, 22, 10
    plot_w, plot_h = width - left, height - bottom - top
    peak = max(b["count"] for b in buckets) or 1
    for frac in (0, 0.5, 1):
        y = bottom + plot_h * frac
        d.add(line(left, y, width, y, "#e6e5e0", 0.5))
        d.add(text(left - 5, y - 2.5, str(round(peak * frac)), "HS-Mono", 6.5, MUTED, "end"))
    slot = plot_w / len(buckets)
    bar = max(1.2, slot * 0.68)
    for i, b in enumerate(buckets):
        if b["count"]:
            h = max(1.5, plot_h * b["count"] / peak)
            d.add(rect(left + i * slot + (slot - bar) / 2, bottom, bar, h, SCALE[b["level"]]["colour"]))
    d.add(line(left, bottom, width, bottom, TEXT, 0.8))
    fmt = "%d %b %H:%M" if timeline["size"].total_seconds() < 86400 else "%d %b %Y"
    first, last = buckets[0]["start"], buckets[-1]["start"]
    d.add(text(left, 8, first.strftime(fmt) + " UTC", "HS-Mono", 6.5, MUTED))
    if len(buckets) > 1:
        d.add(text(width, 8, last.strftime(fmt) + " UTC", "HS-Mono", 6.5, MUTED, "end"))
    d.add(text(left + plot_w / 2, 8, f"{len(buckets)} {timeline['label']} intervals", "HS-Mono", 6.5, MUTED, "middle"))
    return d


def tactic_strip(tactic_counts, width, colour, height=74):
    """The ATT&CK tactics in kill-chain order, two rows, lit where observed."""
    d = Drawing(width, height)
    columns = math.ceil(len(TACTICS) / 2)
    gap = 4
    w = (width - (columns - 1) * gap) / columns
    h = (height - gap) / 2
    for i, (tid, name) in enumerate(TACTICS):
        row, col = divmod(i, columns)
        x = col * (w + gap)
        y = height - (row + 1) * h - row * gap
        count = tactic_counts.get(tid, 0)
        lit = count > 0
        d.add(rect(x, y, w, h, INK1 if lit else SHEET2, None if lit else RULE, 0.6))
        if lit:
            d.add(rect(x, y + h - 2.5, w, 2.5, colour))
        lines = wrap(name, "HS-Sans-SemiBold", 7, w - 10, 2)
        for j, part in enumerate(lines):
            d.add(text(x + 5, y + h - 13 - j * 8.5, part, "HS-Sans-SemiBold", 7, PAPER if lit else MUTED))
        d.add(text(x + 5, y + 5, tid, "HS-Mono", 6, PAPER2 if lit else "#a3a2aa"))
        if lit:
            d.add(text(x + w - 5, y + 5, f"x{count}", "HS-Mono-SemiBold", 6.5, colour, "end"))
    return d


def pipeline_diagram(stages, width, columns=3):
    """Analysis stages in reading order, three to a row: (title, subtitle, stat)."""
    rows = math.ceil(len(stages) / columns)
    gap, row_gap, h = 22, 22, 92
    height = rows * h + (rows - 1) * row_gap
    d = Drawing(width, height)
    w = (width - (columns - 1) * gap) / columns

    def arrow(x1, y1, x2, y2):
        d.add(line(x1, y1, x2, y2, MUTED, 0.9))
        if x2 > x1:
            points = [x2 - 4, y2 + 2.6, x2, y2, x2 - 4, y2 - 2.6]
        else:
            points = [x2 - 2.6, y2 + 4, x2, y2, x2 + 2.6, y2 + 4]
        d.add(Polygon(points, fillColor=hexcolour(MUTED), strokeColor=None, strokeWidth=0))

    for i, (title, subtitle, stat) in enumerate(stages):
        row, col = divmod(i, columns)
        x = col * (w + gap)
        y = height - (row + 1) * h - row * row_gap
        d.add(rect(x, y, w, h, INK1, radius=3))
        d.add(rect(x, y + h - 2, w, 2, PAPER3))
        d.add(text(x + 10, y + h - 16, f"{i + 1:02d}", "HS-Mono", 7, PAPER3))
        d.add(text(x + 28, y + h - 16, fit(title, "HS-Display", 10, w - 38), "HS-Display", 10, PAPER))
        for j, part in enumerate(wrap(subtitle, "HS-Sans", 7.3, w - 20, 3)):
            d.add(text(x + 10, y + h - 33 - j * 9.5, part, "HS-Sans", 7.3, PAPER2))
        d.add(line(x + 10, y + 22, x + w - 10, y + 22, LINE2, 0.5))
        d.add(text(x + 10, y + 9, fit(stat, "HS-Mono", 7, w - 20), "HS-Mono", 7, PAPER))
        if col < columns - 1 and i < len(stages) - 1:
            arrow(x + w + 3, y + h / 2, x + w + gap - 3, y + h / 2)
        elif i < len(stages) - 1:
            # Wrap to the next row: down, back to the left, down again.
            mid = y - row_gap / 2
            d.add(line(x + w / 2, y - 2, x + w / 2, mid, MUTED, 0.9))
            d.add(line(x + w / 2, mid, w / 2, mid, MUTED, 0.9))
            arrow(w / 2, mid, w / 2, y - row_gap + 3)
    return d


def qr_group(data, x, y, size, dark=INK1, light=PAPER):
    from reportlab.graphics.barcode.qr import QrCodeWidget

    widget = QrCodeWidget(data, barLevel="M", barBorder=2)
    x0, y0, x1, y1 = widget.getBounds()
    group = Group(transform=[size / (x1 - x0), 0, 0, size / (y1 - y0), x, y])
    widget.barFillColor = hexcolour(dark)
    widget.barStrokeWidth = 0
    widget.barStrokeColor = hexcolour(dark)
    group.add(Rect(x0, y0, x1 - x0, y1 - y0, fillColor=hexcolour(light), strokeColor=None))
    group.add(widget)
    return group


# -- the cover --------------------------------------------------------------


def cover_duration_position(page_width, page_height):
    """Where the cover's "time to generate" value sits, baseline left."""
    m = 42
    return m + (page_width - 2 * m) / 3, page_height - 150 - 70


def cover(page_width, page_height, info):
    """The first page: classification, title, the gauge and the key figures."""
    d = Drawing(page_width, page_height)
    a = info["assessment"]
    accent = a["colour"]
    W, H = page_width, page_height
    m = 42
    d.add(rect(0, 0, W, H, INK0))
    for gx in range(0, int(W) + 1, 24):
        d.add(line(gx, 0, gx, H, "#121217", 0.4))
    for gy in range(0, int(H) + 1, 24):
        d.add(line(0, gy, W, gy, "#121217", 0.4))
    d.add(brackets(22, 22, W - 44, H - 44, LINE2, 18, 1))
    d.add(rect(0, H - 4, W, 4, accent))

    # Masthead.
    d.add(logo(m, H - 74, 26))
    d.add(text(m + 34, H - 59, "HONEYSENTINEL", "HS-Display", 13, PAPER))
    d.add(text(m + 34, H - 71, "DECEPTION AND THREAT ANALYSIS PLATFORM", "HS-Mono", 6.3, PAPER3))
    tlp = info["classification"]
    tlp_colour = TLP_COLOURS.get(tlp, PAPER)
    tw = width_of(tlp, "HS-Mono-SemiBold", 8) + 16
    d.add(rect(W - m - tw, H - 68, tw, 16, INK0, tlp_colour, 0.9, 2))
    d.add(text(W - m - tw / 2, H - 63, tlp, "HS-Mono-SemiBold", 8, tlp_colour, "middle"))
    d.add(text(W - m, H - 82, info["report_id"], "HS-Mono", 7.5, PAPER2, "end"))

    # Title block.
    y = H - 150
    d.add(text(m, y + 26, "// AI-ASSISTED THREAT INVESTIGATION", "HS-Mono", 8, accent))
    d.add(text(m, y - 6, "Threat Investigation Report", "HS-Display", 31, PAPER))
    sub = info.get("subtitle")
    if sub:
        d.add(text(m, y - 26, fit(sub, "HS-Sans", 10, W - 2 * m), "HS-Sans", 10, PAPER2))
    d.add(line(m, y - 40, W - m, y - 40, LINE, 0.7))
    meta = [
        ("GENERATED", info["generated"]),
        # Known only once the document is finished: the PDF canvas writes it
        # at cover_duration_position when it saves; Word passes it in.
        ("TIME TO GENERATE", info.get("duration")),
        ("SCOPE", info["scope"]),
    ]
    col = (W - 2 * m) / 3
    for i, (label, value) in enumerate(meta):
        x = m + i * col
        d.add(text(x, y - 56, label, "HS-Mono", 6.5, PAPER3))
        if value:
            d.add(text(x, y - 70, fit(value, "HS-Sans-Medium", 9, col - 10), "HS-Sans-Medium", 9, PAPER))

    # Gauge.
    cx, cy, radius = W / 2, 400, 148
    d.add(gauge_group(cx, cy, radius, a["index"], a["level"], dark=True))
    d.add(text(cx, cy - 58, str(a["index"]), "HS-Display", 50, PAPER, "middle"))
    d.add(text(cx + width_of(str(a["index"]), "HS-Display", 50) / 2 + 6, cy - 58, "/100", "HS-Mono", 9, PAPER3))
    d.add(text(cx, cy - 86, a["name"], "HS-Display", 24, accent, "middle"))
    d.add(text(cx, cy - 102, f"LEVEL {a['level_number']} OF 4  /  {a['colour_name'].upper()}", "HS-Mono", 7.5, PAPER2, "middle"))
    if a.get("simulated") or a.get("any_simulated"):
        label = "SIMULATED DATA IN SCOPE" if not a.get("simulated") else "SIMULATED DATA ONLY"
        lw = width_of(label, "HS-Mono-SemiBold", 7.5) + 18
        d.add(rect(cx - lw / 2, cy + 64, lw, 15, INK0, SCALE["medium"]["colour"], 0.9, 2))
        d.add(text(cx, cy + 68.5, label, "HS-Mono-SemiBold", 7.5, SCALE["medium"]["colour"], "middle"))

    # Level scale.
    scale = level_scale(W - 2 * m - 60, a["level"], dark=True)
    group = Group(transform=[1, 0, 0, 1, m + 30, 240])
    for item in scale.contents:
        group.add(item)
    d.add(group)

    # Verdict.
    for i, part in enumerate(wrap(info["verdict"], "HS-Sans", 9, W - 2 * m - 60, 3)):
        d.add(text(W / 2, 218 - i * 12.5, part, "HS-Sans", 9, PAPER2, "middle"))

    # Key figures.
    figures = info["figures"]
    fw = (W - 2 * m) / len(figures)
    top = 172
    d.add(line(m, top, W - m, top, LINE, 0.7))
    for i, (label, value) in enumerate(figures):
        x = m + i * fw
        if i:
            d.add(line(x, top - 44, x, top - 6, LINE, 0.6))
        d.add(text(x + 8, top - 16, label, "HS-Mono", 6.3, PAPER3))
        size = 17
        while size > 10 and width_of(value, "HS-Display", size) > fw - 14:
            size -= 0.5
        d.add(text(x + 8, top - 38, fit(value, "HS-Display", size, fw - 14), "HS-Display", size, PAPER))
    d.add(line(m, top - 52, W - m, top - 52, LINE, 0.7))

    # Prepared by / for, and the verification code.
    y = 98
    blocks = info["parties"]
    bw = (W - 2 * m - 92) / max(1, len(blocks))
    for i, (label, name, detail) in enumerate(blocks):
        x = m + i * bw
        d.add(text(x, y, label, "HS-Mono", 6.3, PAPER3))
        d.add(text(x, y - 14, fit(name, "HS-Sans-SemiBold", 9, bw - 10), "HS-Sans-SemiBold", 9, PAPER))
        if detail:
            d.add(text(x, y - 26, fit(detail, "HS-Mono", 7, bw - 10), "HS-Mono", 7, PAPER2))
    d.add(qr_group(info["qr"], W - m - 72, 38, 72))
    d.add(text(W - m - 80, 104, "VERIFY", "HS-Mono", 6.3, PAPER3, "end"))
    d.add(text(W - m - 80, 94, "Scan for report ID", "HS-Sans", 6.5, PAPER2, "end"))
    d.add(text(W - m - 80, 85, "and evidence hash", "HS-Sans", 6.5, PAPER2, "end"))
    d.add(text(m, 40, "EVIDENCE SHA-256  " + info["evidence_hash"], "HS-Mono", 6.2, PAPER3))
    return d


# -- raster copy for Word ---------------------------------------------------


def _rgb(colour):
    if colour is None:
        return None
    colour = hexcolour(colour)
    return (int(round(colour.red * 255)), int(round(colour.green * 255)), int(round(colour.blue * 255)), 255)


def to_png(drawing: Drawing, scale: float = 3.0, background: str | None = None) -> BytesIO:
    """Paint a drawing made of this module's primitives into a PNG."""
    from PIL import Image, ImageDraw, ImageFont

    width, height = int(round(drawing.width * scale)), int(round(drawing.height * scale))
    image = Image.new("RGBA", (max(1, width), max(1, height)), _rgb(background) if background else (255, 255, 255, 0))
    draw = ImageDraw.Draw(image)
    fonts = {}

    def font(name, size):
        key = (name, round(size * scale, 1))
        if key not in fonts:
            fonts[key] = ImageFont.truetype(str(FONT_DIR / FONTS.get(name, FONTS["HS-Sans"])), max(1, int(round(size * scale))))
        return fonts[key]

    def point(m, x, y):
        px, py = transformPoint(m, (x, y))
        return px * scale, (drawing.height - py) * scale

    def box(m, x, y, w, h):
        (x0, y0), (x1, y1) = point(m, x, y), point(m, x + w, y + h)
        return [min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)]

    def factor(m):
        return math.sqrt(abs(m[0] * m[3] - m[1] * m[2]))

    def walk(node, m):
        if isinstance(node, UserNode):
            node = node.provideNode()
        if isinstance(node, Group):
            inner = mmult(m, node.transform)
            for child in node.contents:
                walk(child, inner)
            return
        fill = _rgb(getattr(node, "fillColor", None))
        stroke = _rgb(getattr(node, "strokeColor", None))
        stroke_width = max(1, int(round((getattr(node, "strokeWidth", 1) or 0) * scale * factor(m)))) if stroke else 0
        if isinstance(node, Rect):
            xy = box(m, node.x, node.y, node.width, node.height)
            if xy[2] - xy[0] < 0.5 or xy[3] - xy[1] < 0.5:
                if fill:
                    draw.rectangle([xy[0], xy[1], max(xy[0] + 1, xy[2]), max(xy[1] + 1, xy[3])], fill=fill)
                return
            radius = (node.rx or 0) * scale * factor(m)
            draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=stroke, width=stroke_width)
        elif isinstance(node, Circle):
            cx, cy = point(m, node.cx, node.cy)
            r = node.r * scale * factor(m)
            draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill, outline=stroke, width=stroke_width)
        elif isinstance(node, Ellipse):
            cx, cy = point(m, node.cx, node.cy)
            rx, ry = node.rx * scale * factor(m), node.ry * scale * factor(m)
            draw.ellipse([cx - rx, cy - ry, cx + rx, cy + ry], fill=fill, outline=stroke, width=stroke_width)
        elif isinstance(node, Line):
            if stroke:
                draw.line([point(m, node.x1, node.y1), point(m, node.x2, node.y2)], fill=stroke, width=stroke_width)
        elif isinstance(node, (Polygon, PolyLine)):
            pts = [point(m, node.points[i], node.points[i + 1]) for i in range(0, len(node.points) - 1, 2)]
            if len(pts) < 2:
                return
            if isinstance(node, Polygon):
                draw.polygon(pts, fill=fill, outline=stroke, width=stroke_width if stroke else 0)
            elif stroke:
                draw.line(pts, fill=stroke, width=stroke_width, joint="curve")
        elif isinstance(node, String):
            x, y = point(m, node.x, node.y)
            anchor = {"start": "ls", "middle": "ms", "end": "rs"}.get(node.textAnchor, "ls")
            draw.text((x, y), node.text, fill=fill or (0, 0, 0, 255), font=font(node.fontName, node.fontSize * factor(m)), anchor=anchor)

    walk(drawing, (1, 0, 0, 1, 0, 0))
    output = BytesIO()
    image.save(output, format="PNG", optimize=True)
    output.seek(0)
    return output
