"""The investigation report, as PDF and Word. Renders stored findings; never executes telemetry.

Layout, top to bottom:

* a cover with the threat level gauge, classification and key figures;
* document control, a transmittal memo and the contents;
* ten numbered sections: threat level, key metrics, the model's summary,
  findings and assessment, ATT&CK mapping, indicators, the model and the
  analysis pipeline, method and limitations, review and approval;
* appendices: the session inventory, one page per evidence case, and the
  record of how long the report took to generate.

Every number is computed from the evidence snapshot (``report_analytics``)
or measured while the report is made; nothing is estimated for display.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from time import perf_counter
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    ActionFlowable,
    BaseDocTemplate,
    CondPageBreak,
    Flowable,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.graphics.shapes import Drawing

from app.services import report_graphics as g
from app.services.report_analytics import (
    LEVELS,
    SCALE,
    ATTACK_VERSION,
    TACTIC_NAMES,
    TACTICS,
    analytic_confidence,
    distinct,
    format_ms,
    format_span,
    format_time,
    group_level,
    level_reason,
    report_metrics,
    threat_assessment,
)

MAX_PDF_SESSIONS = 100
PAGE_W, PAGE_H = A4
MARGIN = 42
CONTENT_W = PAGE_W - 2 * MARGIN
HEADER_H = 50
INK = colors.HexColor(g.INK1)
PAPER = colors.HexColor(g.PAPER)
MUTED = colors.HexColor(g.MUTED)


def text(value, limit=6000):
    """Bound untrusted strings and escape ReportLab's XML-like paragraph syntax."""
    value = str(value) if value is not None else "Not recorded"
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
    if len(value) > limit:
        value = value[:limit] + " [excerpt truncated]"
    return escape(value).replace("\n", "<br/>")


def _technique_state(item: dict) -> str:
    """How far a mapped technique was confirmed, in the report's words."""
    if item.get("confirmed") is False or item.get("unconfirmed"):
        return "Unconfirmed"
    if item.get("confirmed") is True:
        return "Confirmed"
    if item.get("support") is not None:
        return "Checker support: " + str(item["support"])
    return "Confirmation not recorded"


# -- styles -----------------------------------------------------------------


def _styles():
    g.register_fonts()
    base = ParagraphStyle(
        "body", fontName="HS-Sans", fontSize=9.3, leading=14.2, spaceAfter=7,
        textColor=INK, alignment=TA_LEFT,
    )
    s = {
        "body": base,
        "lead": ParagraphStyle("lead", parent=base, fontSize=10.5, leading=16, spaceAfter=9),
        "muted": ParagraphStyle("muted", parent=base, fontSize=8.2, leading=12, textColor=MUTED),
        "small": ParagraphStyle("small", parent=base, fontSize=7.6, leading=10.5, textColor=MUTED, spaceAfter=4),
        "h1": ParagraphStyle(
            "h1", parent=base, fontName="HS-Display", fontSize=18, leading=23,
            spaceBefore=2, spaceAfter=11, keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base, fontName="HS-Sans-SemiBold", fontSize=11, leading=15,
            spaceBefore=12, spaceAfter=6, keepWithNext=True,
        ),
        "label": ParagraphStyle(
            "label", parent=base, fontName="HS-Mono-SemiBold", fontSize=7, leading=10,
            textColor=MUTED, spaceBefore=8, spaceAfter=5, keepWithNext=True,
        ),
        "title": ParagraphStyle("title", parent=base, fontName="HS-Display", fontSize=22, leading=27, spaceAfter=4),
        "cell": ParagraphStyle("cell", parent=base, fontSize=8, leading=11, spaceAfter=0),
        "cell_muted": ParagraphStyle("cell_muted", parent=base, fontSize=7.8, leading=10.8, spaceAfter=0, textColor=MUTED),
        "cell_label": ParagraphStyle(
            "cell_label", parent=base, fontName="HS-Sans-Medium", fontSize=7.8, leading=10.8,
            spaceAfter=0, textColor=MUTED,
        ),
        "cell_head": ParagraphStyle(
            "cell_head", parent=base, fontName="HS-Mono-SemiBold", fontSize=6.6, leading=9,
            spaceAfter=0, textColor=PAPER,
        ),
        "cell_mono": ParagraphStyle("cell_mono", parent=base, fontName="HS-Mono", fontSize=7.3, leading=10, spaceAfter=0),
        # Fits a 36-character session UUID on one line in the inventory.
        "cell_mono_small": ParagraphStyle("cell_mono_small", parent=base, fontName="HS-Mono", fontSize=6.1, leading=9, spaceAfter=0),
        "term": ParagraphStyle(
            "term", parent=base, fontName="HS-Mono", fontSize=7.3, leading=10.2, spaceAfter=0,
            textColor=PAPER,
        ),
        "term_ref": ParagraphStyle(
            "term_ref", parent=base, fontName="HS-Mono", fontSize=6.8, leading=10.2, spaceAfter=0,
            textColor=colors.HexColor(g.PAPER3),
        ),
        "term_bar": ParagraphStyle(
            "term_bar", parent=base, fontName="HS-Mono", fontSize=6.8, leading=9, spaceAfter=0,
            textColor=colors.HexColor(g.PAPER2),
        ),
        "card_title": ParagraphStyle(
            "card_title", parent=base, fontName="HS-Sans-SemiBold", fontSize=10.5, leading=14, spaceAfter=4,
        ),
        "badge": ParagraphStyle("badge", parent=base, fontName="HS-Display", fontSize=17, leading=20, spaceAfter=0),
        "toc0": ParagraphStyle("toc0", parent=base, fontName="HS-Sans-Medium", fontSize=9.3, leading=17, spaceAfter=0),
        "toc1": ParagraphStyle("toc1", parent=base, fontSize=8.5, leading=14, leftIndent=14, spaceAfter=0, textColor=MUTED),
    }
    return s


# -- context ----------------------------------------------------------------


@dataclass
class Context:
    records: list
    narrative: dict | None
    sensitive: bool
    meta: dict
    started: float
    assessment: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    groups: list = field(default_factory=list)
    settings: object = None
    report_id: str = ""
    evidence_hash: str = ""
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    classification: str = "TLP:AMBER"
    slots: dict = field(default_factory=dict)
    finished: dict | None = None

    @property
    def accent(self):
        return self.assessment["colour"]

    def finish(self):
        """Render and total time, fixed the first time they are asked for."""
        if self.finished is None:
            render_ms = (perf_counter() - self.started) * 1000
            timings = self.meta.get("timings") or {}
            parts = [timings.get(k) for k in ("snapshot_ms", "queue_ms", "narrative_ms")]
            total = sum(p for p in parts if isinstance(p, (int, float))) + render_ms
            self.finished = {
                "render_ms": render_ms,
                "total_ms": total,
                "render": format_ms(render_ms),
                "total": format_ms(total),
            }
        return self.finished


def _requester(ctx):
    person = ctx.meta.get("requester") or {}
    name = person.get("name") or (person.get("email") or "").split("@")[0] or "Not recorded"
    return name, person.get("email"), person.get("role")


def _parties(value: str) -> list[tuple[str, str | None]]:
    """``Name <mail>; Name <mail>`` (or bare addresses) as (name, email) pairs."""
    result = []
    for part in re.split(r"[;\n]", value or ""):
        part = part.strip()
        if not part:
            continue
        match = re.match(r"^(.*?)\s*<([^>]+)>$", part)
        if match:
            result.append((match.group(1).strip() or match.group(2).strip(), match.group(2).strip()))
        elif "@" in part:
            result.append((part, part))
        else:
            result.append((part, None))
    return result


def _party_text(parties):
    return "; ".join(f"{n} <{e}>" if e and e != n else n for n, e in parties)


def _settings():
    try:
        from app.core.config import get_settings

        return get_settings()
    except Exception:  # pragma: no cover - settings always load in the app
        return None


def _setting(ctx, name, default=""):
    return str(getattr(ctx.settings, name, default) or default).strip()


def _revision():
    try:
        from app.ai.provenance import git_revision

        revision = git_revision()
    except Exception:
        revision = "unknown"
    return revision[:12] if revision and revision != "unknown" else "not recorded"


# -- building blocks --------------------------------------------------------


class Builder:
    def __init__(self, ctx, styles):
        self.ctx = ctx
        self.s = styles
        self.story = []
        self.section = 0

    def add(self, *items):
        self.story.extend(items)

    def p(self, value, style="body", raw=False):
        self.story.append(Paragraph(value if raw else text(value), self.s[style]))

    def para(self, value, style="body", raw=False):
        return Paragraph(value if raw else text(value), self.s[style])

    def paragraphs(self, value, style="body"):
        for part in str(value).split("\n"):
            if part.strip():
                self.p(part.strip(), style)

    def h1(self, title, numbered=True, appendix=None, new_page="soft"):
        """A section heading. ``new_page``: True always starts a page; "soft"
        starts one only when less than about 40% of the page is left."""
        if new_page == "soft":
            self.story.append(CondPageBreak(300))
            self.story.append(Spacer(1, 26))
        elif new_page:
            self.story.append(PageBreak())
        if appendix:
            prefix, toc = f"APPENDIX {appendix}", f"Appendix {appendix}. {title}"
        elif numbered:
            self.section += 1
            prefix, toc = f"{self.section:02d}", f"{self.section}. {title}"
        else:
            prefix, toc = None, title
        label = (
            f'<font name="HS-Mono" size="8.5" color="{g.MUTED}">{escape(prefix)}&nbsp;&nbsp;/&nbsp;&nbsp;</font>'
            if prefix
            else ""
        )
        paragraph = Paragraph(label + text(title), self.s["h1"])
        paragraph._hs_toc = (0, toc, f"s{len(self.story)}")
        self.story.append(paragraph)

    def h2(self, title, toc=False):
        paragraph = Paragraph(text(title), self.s["h2"])
        if toc:
            paragraph._hs_toc = (1, title, f"s{len(self.story)}")
        self.story.append(paragraph)

    def label(self, value):
        self.p(str(value).upper(), "label")

    def cell(self, value, style="cell"):
        if isinstance(value, (Flowable, list)):
            return value
        return Paragraph(text("Not recorded" if value is None else str(value)[:1500]), self.s[style])

    def grid(self, rows, widths, mono=(), highlight=None, kind="grid", font=None, mono_style="cell_mono"):
        """A table with a dark header row."""
        data = []
        for r, row in enumerate(rows):
            cells = []
            for c, value in enumerate(row):
                if r == 0:
                    cells.append(self.cell(str(value).upper(), "cell_head"))
                else:
                    cells.append(self.cell(value, mono_style if c in mono else (font or "cell")))
            data.append(cells)
        table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(g.SHEET2)]),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor(g.RULE)),
            ("LINEBELOW", (0, 0), (-1, 0), 1.6, colors.HexColor(self.ctx.accent)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ]
        if highlight is not None:
            style.append(("BACKGROUND", (0, highlight), (-1, highlight), colors.HexColor(g.mix(g.SHEET, self.ctx.accent, 0.16))))
        table.setStyle(TableStyle(style))
        table._hs_kind = kind
        self.story.append(table)
        self.story.append(Spacer(1, 9))
        return table

    def kv(self, rows, widths=None, kind="kv"):
        """Label / value rows without a header."""
        widths = widths or [CONTENT_W * 0.3, CONTENT_W * 0.7]
        data = [
            [self.cell(label, "cell_label"), self.cell(value, "cell_mono" if mono else "cell")]
            for label, value, *rest in rows
            for mono in [bool(rest and rest[0])]
        ]
        table = Table(data, colWidths=widths, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(g.RULE)),
            ("LINEABOVE", (0, 0), (-1, 0), 0.9, INK),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4.2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4.2),
        ]))
        table._hs_kind = kind
        self.story.append(table)
        self.story.append(Spacer(1, 9))
        return table

    def terminal(self, title, lines, accent=None, add=True, width=CONTENT_W):
        """Captured text in a dark, monospaced block, one row per line."""
        accent = accent or self.ctx.accent
        data = [[Paragraph(text("● ● ●   " + title), self.s["term_bar"]), ""]]
        for ref, value in lines:
            data.append([Paragraph(text(ref), self.s["term_ref"]), Paragraph(text(value), self.s["term"])])
        if len(data) == 1:
            data.append(["", Paragraph("No text recorded.", self.s["term"])])
        table = Table(data, colWidths=[46, width - 46], repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("SPAN", (0, 0), (-1, 0)),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(g.INK3)),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor(g.INK0)),
            ("LINEBEFORE", (0, 0), (0, -1), 2.4, colors.HexColor(accent)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 2.2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
            ("TOPPADDING", (0, 0), (-1, 0), 5),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
        ]))
        table._hs_kind = "terminal"
        if add:
            self.story.append(table)
            self.story.append(Spacer(1, 9))
        return table

    def figure(self, drawing, space_after=8):
        self.story.append(drawing)
        if space_after:
            self.story.append(Spacer(1, space_after))

    def side_by_side(self, left, right, gap=18):
        w = (CONTENT_W - gap) / 2
        table = Table([[left, "", right]], colWidths=[w, gap, w], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        table._hs_kind = "layout"
        self.story.append(table)


class Slot(Flowable):
    """A value known only when the document is finished (render time).

    It records where it was laid out; the canvas writes the value there when
    it saves, after every page is complete.
    """

    def __init__(self, ctx, key, style):
        super().__init__()
        self.ctx, self.key, self.style = ctx, key, style

    def wrap(self, available_width, available_height):
        return available_width, self.style.leading

    def draw(self):
        x, y = self.canv.absolutePosition(0, 0)
        self.ctx.slots.setdefault(self.canv.getPageNumber(), []).append((self.key, x, y + 2.5, self.style))


class Toc(TableOfContents):
    pass


# -- page furniture ---------------------------------------------------------


def _chrome(ctx):
    """Header band and footer of every page after the cover."""

    def draw(canvas, document):
        a = ctx.assessment
        canvas.saveState()
        canvas.setFillColor(colors.HexColor(g.INK1))
        canvas.rect(0, PAGE_H - HEADER_H, PAGE_W, HEADER_H, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor(ctx.accent))
        canvas.rect(0, PAGE_H - HEADER_H - 2, PAGE_W, 2, fill=1, stroke=0)
        mark = g.logo(MARGIN, PAGE_H - 37, 22)
        drawing = Drawing(PAGE_W, PAGE_H)
        drawing.add(mark)
        drawing.drawOn(canvas, 0, 0)
        canvas.setFillColor(PAPER)
        canvas.setFont("HS-Display", 10.5)
        canvas.drawString(MARGIN + 30, PAGE_H - 24, "HONEYSENTINEL")
        canvas.setFillColor(colors.HexColor(g.PAPER2))
        canvas.setFont("HS-Mono", 6.6)
        canvas.drawString(MARGIN + 30, PAGE_H - 35, "THREAT INVESTIGATION REPORT  /  " + ctx.report_id)
        label = f"{a['name']}  {a['index']}/100"
        width = g.width_of(label, "HS-Display", 8) + 16
        x = PAGE_W - MARGIN - width
        canvas.setFillColor(colors.HexColor(ctx.accent))
        canvas.roundRect(x, PAGE_H - 34, width, 16, 2, fill=1, stroke=0)
        canvas.setFillColor(INK)
        canvas.setFont("HS-Display", 8)
        canvas.drawCentredString(x + width / 2, PAGE_H - 28.5, label)
        canvas.setFillColor(colors.HexColor(g.PAPER2))
        canvas.setFont("HS-Mono", 6.4)
        canvas.drawRightString(x - 10, PAGE_H - 28.5, "THREAT LEVEL")
        # Footer.
        canvas.setStrokeColor(colors.HexColor(g.RULE))
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 36, PAGE_W - MARGIN, 36)
        tlp = ctx.classification
        tw = g.width_of(tlp, "HS-Mono-SemiBold", 6.6) + 10
        canvas.setFillColor(colors.HexColor(g.INK0))
        canvas.roundRect(MARGIN, 18, tw, 12, 1.5, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor(g.TLP_COLOURS.get(tlp, g.PAPER)))
        canvas.setFont("HS-Mono-SemiBold", 6.6)
        canvas.drawCentredString(MARGIN + tw / 2, 21.6, tlp)
        canvas.setFillColor(MUTED)
        canvas.setFont("HS-Mono", 6.4)
        canvas.drawString(MARGIN + tw + 8, 21.6, "EVIDENCE SHA-256 " + ctx.evidence_hash[:24] + "...")
        canvas.restoreState()

    return draw


def _canvas_class(ctx):
    class ReportCanvas(Canvas):
        """Holds pages back until the end so each can say "of N"."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            done = ctx.finish()
            total = len(self._pages)
            for number, state in enumerate(self._pages, 1):
                self.__dict__.update(state)
                self.saveState()
                if number == 1:
                    x, y = g.cover_duration_position(PAGE_W, PAGE_H)
                    self.setFillColor(PAPER)
                    self.setFont("HS-Sans-Medium", 9)
                    self.drawString(x, y, done["total"])
                else:
                    self.setFillColor(MUTED)
                    self.setFont("HS-Mono", 6.6)
                    self.drawRightString(PAGE_W - MARGIN, 21.6, f"PAGE {number} OF {total}")
                for key, x, y, style in ctx.slots.get(number, []):
                    self.setFillColor(style.textColor)
                    self.setFont(style.fontName, style.fontSize)
                    self.drawString(x, y, done[key])
                self.restoreState()
                Canvas.showPage(self)
            Canvas.save(self)

    return ReportCanvas


class ReportDoc(BaseDocTemplate):
    def __init__(self, buffer, ctx, **kwargs):
        super().__init__(buffer, pagesize=A4, **kwargs)
        self._ctx = ctx
        cover = Frame(0, 0, PAGE_W, PAGE_H, 0, 0, 0, 0, id="cover")
        body = Frame(MARGIN, 46, CONTENT_W, PAGE_H - HEADER_H - 46 - 22, 0, 0, 0, 0, id="body")
        self.addPageTemplates([
            PageTemplate("cover", [cover]),
            PageTemplate("body", [body], onPage=_chrome(ctx)),
        ])

    def beforeDocument(self):
        # multiBuild lays the document out more than once (the contents need
        # page numbers); only the last pass's positions and times count.
        self._ctx.slots.clear()
        self._ctx.finished = None

    def afterFlowable(self, flowable):
        toc = getattr(flowable, "_hs_toc", None)
        if toc:
            level, title, key = toc
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, level=level, closed=False)
            self.notify("TOCEntry", (level, title, self.page, key))


# -- the report -------------------------------------------------------------


def generate_pdf_report(
    records: list[tuple[dict, dict]],
    output_format="pdf",
    narrative=None,
    include_sensitive=False,
    meta=None,
) -> bytes:
    if len(records) > MAX_PDF_SESSIONS:
        raise ValueError(f"PDF reports support at most {MAX_PDF_SESSIONS} sessions")
    started = perf_counter()
    meta = dict(meta or {})
    styles = _styles()
    from app.services.investigation_narrative import evidence_groups

    ctx = Context(records=records, narrative=narrative, sensitive=bool(include_sensitive), meta=meta, started=started)
    ctx.settings = _settings()
    ctx.evidence_hash = meta.get("evidence_sha256") or hashlib.sha256(
        json.dumps([records, bool(include_sensitive)], sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()
    requested = meta.get("requested_at")
    ctx.generated = datetime.now(timezone.utc)
    ctx.report_id = meta.get("report_id") or "HS-IR-{}-{}".format(
        ctx.generated.strftime("%Y%m%d"), ctx.evidence_hash[:8].upper()
    )
    if requested is None:
        meta["requested_at"] = ctx.generated
    configured = _setting(ctx, "REPORT_CLASSIFICATION")
    ctx.classification = configured or ("TLP:RED" if ctx.sensitive else "TLP:AMBER")
    ctx.assessment = threat_assessment(records)
    ctx.metrics = report_metrics(records, ctx.assessment, narrative)
    ctx.groups = evidence_groups(records)

    b = Builder(ctx, styles)
    cover_info = _cover_info(ctx)
    cover = g.cover(PAGE_W, PAGE_H, cover_info)
    cover._hs_cover = True
    b.add(cover, NextPageTemplate("body"), PageBreak())
    _front_matter(b)
    _threat_section(b)
    _metrics_section(b)
    _narrative_sections(b)
    _attack_section(b)
    _ioc_section(b)
    _model_section(b)
    _method_section(b)
    _approval_section(b)
    _inventory_appendix(b)
    _case_appendix(b)
    _record_appendix(b)

    if output_format == "docx":
        return _word_document(b.story, ctx, cover_info, styles)
    buffer = BytesIO()
    doc = ReportDoc(
        buffer,
        ctx,
        title=f"HoneySentinel Threat Investigation Report {ctx.report_id}",
        author="HoneySentinel AI",
        subject=f"Threat level {ctx.assessment['name']} ({ctx.assessment['index']}/100), {len(records)} session(s)",
        creator=f"HoneySentinel {_setting(ctx, 'VERSION', 'unknown')}",
        keywords=["honeypot", "threat investigation", ctx.classification, ctx.report_id],
    )
    doc.multiBuild(b.story, canvasmaker=_canvas_class(ctx))
    return buffer.getvalue()


def _cover_info(ctx, duration=None):
    a, m = ctx.assessment, ctx.metrics
    name, email, _ = _requester(ctx)
    organisation = _setting(ctx, "REPORT_ORGANISATION")
    project = _setting(ctx, "REPORT_PROJECT")
    prepared_for = _setting(ctx, "REPORT_PREPARED_FOR")
    recipients = _parties(_setting(ctx, "REPORT_RECIPIENTS"))
    subtitle = " / ".join(x for x in [organisation, project] if x) or "Evidence captured by the HoneySentinel decoy network"
    parties = [("PREPARED BY", name, email)]
    if prepared_for or recipients:
        first = recipients[0] if recipients else (prepared_for, None)
        parties.append(("PREPARED FOR", prepared_for or first[0], first[1] if recipients else None))
    contact = _setting(ctx, "REPORT_CONTACT_EMAIL") or email
    if contact:
        parties.append(("CONTACT", contact, None))
    narrative_ms = (ctx.meta.get("timings") or {}).get("narrative_ms")
    figures = [
        ("SESSIONS", str(m["sessions"])),
        ("SOURCES", str(m["sources"])),
        ("WINDOW", format_span(m["span_seconds"]) if m["span_seconds"] is not None else "n/a"),
        ("ATT&CK TACTICS", str(len(a["tactics"]))),
        ("INDICATORS", str(len(m["iocs"]))),
        ("AI ANALYSIS", format_ms(narrative_ms) if narrative_ms is not None else "n/a"),
    ]
    scope = f"{m['sessions']} session(s), {m['sources']} source(s)"
    qr = (
        f"HoneySentinel report {ctx.report_id}\nThreat level {a['name']} {a['index']}/100\n"
        f"Generated {ctx.generated.strftime('%Y-%m-%dT%H:%M:%SZ')}\nEvidence SHA-256 {ctx.evidence_hash}"
    )
    verdict = level_reason(a) + " " + SCALE[a["level"]]["handling"]
    return {
        "assessment": a,
        "classification": ctx.classification,
        "report_id": ctx.report_id,
        "subtitle": subtitle,
        "generated": format_time(ctx.generated, seconds=False),
        "duration": duration,
        "scope": scope,
        "verdict": verdict,
        "figures": figures,
        "parties": parties[:3],
        "qr": qr,
        "evidence_hash": ctx.evidence_hash,
    }


# -- front matter -----------------------------------------------------------


def _front_matter(b):
    ctx, a, m = b.ctx, b.ctx.assessment, b.ctx.metrics
    name, email, role = _requester(ctx)
    contact = _setting(ctx, "REPORT_CONTACT_EMAIL") or email
    organisation = _setting(ctx, "REPORT_ORGANISATION")
    project = _setting(ctx, "REPORT_PROJECT")
    prepared_for = _setting(ctx, "REPORT_PREPARED_FOR")
    recipients = _parties(_setting(ctx, "REPORT_RECIPIENTS"))
    cc = _parties(_setting(ctx, "REPORT_CC"))
    model = (ctx.narrative or {}).get("model")
    card = (ctx.narrative or {}).get("model_card") or {}

    b.h1("Document control", numbered=False, new_page=False)
    window = (
        f"{format_time(m['first'], False)} to {format_time(m['last'], False)}" if m["first"] else "Not recorded"
    )
    scope = f"{m['sessions']} session(s) from {m['sources']} source address(es); {window}"
    if ctx.meta.get("truncated"):
        scope += f". The selection matched more sessions; the {MAX_PDF_SESSIONS} most recent are included."
    rows = [
        ("Report ID", ctx.report_id, True),
        ("Version / status", "1.0 / Generated by the platform; pending analyst review"),
        ("Classification", f"{ctx.classification} ({'contains original credentials, administrator export' if ctx.sensitive else 'captured secrets redacted, analyst export'})"),
        ("Threat level", f"{a['name']} ({a['colour_name']}), index {a['index']} of 100, level {a['level_number']} of 4"),
        ("Generated", format_time(ctx.generated)),
        ("Requested by", " ".join(x for x in [name, f"<{email}>" if email else "", f"({role})" if role else ""] if x)),
    ]
    if organisation:
        rows.append(("Organisation", organisation))
    if project:
        rows.append(("Project", project))
    if prepared_for:
        rows.append(("Prepared for", prepared_for))
    if contact:
        rows.append(("Point of contact", contact, True))
    rows += [
        ("Evidence scope", scope),
        ("Evidence SHA-256", ctx.evidence_hash, True),
        ("Platform", f"HoneySentinel {_setting(ctx, 'VERSION', 'unknown')}, revision {_revision()}"),
        ("Narrative model", f"{model} ({card.get('quantization') or 'quantization not reported'}, local inference)" if model else "No AI narrative in this export"),
    ]
    b.kv(rows)

    b.h2("Transmittal")
    subject = f"[{ctx.classification}] Threat investigation {ctx.report_id}: {a['name']} ({a['index']}/100)"
    to = _party_text(recipients) or prepared_for or "Authorised recipients under the handling marking below"
    memo = [
        ("TO", to),
        ("FROM", " ".join(x for x in [name, f"<{email}>" if email else ""] if x)),
    ]
    if cc:
        memo.append(("CC", _party_text(cc)))
    memo += [("DATE", format_time(ctx.generated, seconds=False)), ("SUBJECT", subject)]
    rows = [[b.cell(k, "cell_head"), b.cell(v, "cell_mono")] for k, v in memo]
    body = (
        f"Please find attached threat investigation report {ctx.report_id} for review. The selected evidence "
        f"({m['sessions']} session(s), {m['sources']} source address(es)) is rated {a['name']} at {a['index']} of 100. "
        "The findings were written by the platform's local language model from the captured evidence and checked "
        "against it automatically; they have not yet been reviewed by an analyst."
        + (f" Questions about this report can be sent to {contact}." if contact else "")
    )
    rows.append([b.para(body, "cell"), ""])
    table = Table(rows, colWidths=[62, CONTENT_W - 62], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -2), INK),
        ("BACKGROUND", (1, 0), (1, -2), colors.HexColor(g.SHEET2)),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor(g.RULE)),
        ("LINEBEFORE", (0, 0), (0, -1), 2.4, colors.HexColor(ctx.accent)),
        ("SPAN", (0, -1), (-1, -1)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, -1), (-1, -1), 9),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 9),
    ]))
    table._hs_kind = "email"
    b.add(table)

    b.h2("Handling")
    if ctx.classification == "TLP:RED":
        handling = (
            "TLP:RED. For the named recipients only; do not share further. This administrator export contains the "
            "original captured activity and the credentials attackers tried."
        )
    elif ctx.classification == "TLP:AMBER":
        handling = (
            "TLP:AMBER. Limited disclosure: recipients may share it on a need-to-know basis within their organisation "
            "and with those who need it to act on it. Captured secrets are masked in this analyst export."
        )
    else:
        handling = f"{ctx.classification}. Handle according to the organisation's policy for this marking."
    b.p(handling, "muted")

    b.add(PageBreak())
    b.h2("Contents")
    toc = Toc()
    toc.levelStyles = [b.s["toc0"], b.s["toc1"]]
    toc.dotsMinLevel = 0
    b.add(toc)


# -- 1 threat level ---------------------------------------------------------


def _threat_section(b):
    ctx, a = b.ctx, b.ctx.assessment
    b.h1("Threat level assessment", new_page=True)
    b.figure(g.gauge_badge(CONTENT_W, a), 6)
    info = SCALE[a["level"]]
    b.p(
        f"This evidence is rated <b>{a['name']}</b> ({a['colour_name'].lower()}), with a threat index of "
        f"<b>{a['index']} out of 100</b>. " + text(level_reason(a)) + " "
        f"A report takes the level of its most severe session, using the same definition the console uses for "
        f"every session. Within the {a['name']} band ({a['band'][0]} to {a['band'][1]}) the index is the band's base "
        f"of {25 * (a['level_number'] - 1)} plus {a['bonus']:.1f} points from the six factors below.",
        "lead",
        raw=True,
    )
    b.p(f"<b>What {a['name']} means.</b> " + text(info["meaning"]), raw=True)
    b.p(f"<b>Suggested handling.</b> " + text(info["handling"]), raw=True)
    if a["simulated"]:
        b.p("All selected sessions are labelled simulations. The level describes the fixture data, not live attacks.", "muted")
    elif a["any_simulated"]:
        b.p("Some selected sessions are labelled simulations and count toward the level.", "muted")
    if a["controlled"]:
        b.p(
            f"{a['controlled']} selected session(s) come from the controlled-test sensor (traffic generated by the "
            "project team for testing), not from outside attackers.",
            "muted",
        )

    b.h2("Scoring factors")
    rows = [["Factor", "Observed in this evidence", "Contribution", "Points"]]
    for f in a["factors"]:
        rows.append([
            f["title"],
            f["observed"],
            g.factor_bar(f["fraction"], 82, a["colour"]),
            f"{f['points']:.1f} / {f['weight']}",
        ])
    rows.append(["Level base", f"{a['name']} band starts at {25 * (a['level_number'] - 1)}", "", str(25 * (a["level_number"] - 1))])
    rows.append(["Threat index", "Base plus factors, kept inside the level's band", "", f"{a['index']} / 100"])
    table = b.grid(rows, [CONTENT_W * 0.25, CONTENT_W * 0.42, 94, CONTENT_W * 0.33 - 94], mono=(3,))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor(g.mix(g.SHEET, a["colour"], 0.2))),
    ]))

    b.h2("Session severity distribution")
    b.figure(g.stacked_bar(
        [(SCALE[level]["name"].title(), a["distribution"][level], SCALE[level]["colour"]) for level in LEVELS],
        CONTENT_W,
    ), 4)

    b.add(CondPageBreak(200))
    b.h2("Threat level scale")
    rows = [["Level", "Index", "Meaning", "Suggested handling"]]
    for level in LEVELS:
        info = SCALE[level]
        rows.append([
            g.chip(f"{info['name']} / {info['colour_name'].upper()}", info["colour"], 6.5),
            f"{info['band'][0]}-{info['band'][1]}",
            info["meaning"],
            info["handling"],
        ])
    b.grid(rows, [92, 40, (CONTENT_W - 132) * 0.55, (CONTENT_W - 132) * 0.45], mono=(1,),
           highlight=LEVELS.index(a["level"]) + 1)
    b.p(
        "How a session is rated: its recorded stage (benign 0, reconnaissance 2, exploitation 4, exfiltration 5) plus "
        "up to 2 for the rule layer's confidence, 3 for a critical offensive tool, 2 to 3 for high-impact goals and 1 "
        "for an anomaly from a calibrated detector. A score of 3 or more is medium, 5 high and 8 critical. The level "
        "and index rank recorded behaviour; they are not a probability that a real system was compromised.",
        "small",
    )


# -- 2 metrics --------------------------------------------------------------


def _metrics_section(b):
    ctx, a, m = b.ctx, b.ctx.assessment, b.ctx.metrics
    b.h1("Key metrics")
    confirmed = sum(1 for t in m["techniques"] if t["state"] != "unconfirmed")
    latency = m["analysis_ms"]
    items = [
        ("Sessions", m["sessions"], f"{m['enriched']} with AI explanation"),
        ("Unique sources", m["sources"], f"{len(m['countries'])} countr{'y' if len(m['countries']) == 1 else 'ies'}"),
        ("Protocols", ", ".join(sorted(m["protocols"])) if len(m["protocols"]) <= 2 else len(m["protocols"]),
         (", ".join(sorted(m["protocols"])) if len(m["protocols"]) > 2 else f"{len(m['sensors'])} sensor(s)")),
        ("Observation window", format_span(m["span_seconds"]) if m["span_seconds"] is not None else "n/a",
         format_time(m["first"], False) if m["first"] else ""),
        ("Commands captured", m["commands"], f"{m['keystrokes']} keystrokes recorded"),
        ("Credential attempts", m["credential_attempts"], f"{m['decoy_accepts']} accepted by the decoy"),
        ("Indicators", len(m["iocs"]), f"{m['uploads']} upload record(s)"),
        ("ATT&CK techniques", f"{confirmed} / {len(m['techniques'])}", "confirmed / proposed"),
        ("ATT&CK tactics", len(a["tactics"]), f"of {len(TACTICS)} in ATT&CK"),
        ("Highest severity", a["name"], f"{a['distribution']['high'] + a['distribution']['critical']} session(s) high or above"),
        ("Pipeline latency", format_ms(latency["mean"]) if latency["mean"] is not None else "n/a",
         f"mean per session, max {format_ms(latency['max'])}" if latency["max"] is not None else "not recorded"),
        ("Decider triage", f"{m['triaged']} / {m['sessions']}", f"mean {format_ms(m['triage_ms_mean'])}" if m["triage_ms_mean"] else "sessions triaged"),
    ]
    b.figure(g.kpi_grid(items, CONTENT_W, 4, accent=a["colour"]), 6)

    b.h2("Analysis quality")
    rates = m["rates"]
    b.figure(g.rings([
        ("AI evidence coverage", rates["evidence_coverage"],
         f"{m['reviewed_groups']} of {m['groups']} activity groups" if m["groups"] else "no narrative"),
        ("AI enrichment coverage", rates["enrichment_coverage"], f"{m['enriched']} of {m['sessions']} sessions"),
        ("Rules / AI agreement", rates["agreement"],
         f"{m['agreements']} of {m['agreement_total']} triaged" if m["agreement_total"] else "no triage recorded"),
        ("Mean rule confidence", rates["rule_confidence"], "rule-decided sessions"),
    ], CONTENT_W), 2)
    level, reason = analytic_confidence(m)
    b.p(f"<b>Analytic confidence: {escape(level)}.</b> " + text(reason[0].upper() + reason[1:]), raw=True)

    b.add(CondPageBreak(170))
    b.h2("Activity timeline")
    b.figure(g.timeline_chart(m["timeline"], CONTENT_W), 2)
    b.p("Bars are coloured by the most severe session that started in each interval.", "small")

    b.add(CondPageBreak(150))
    half = (CONTENT_W - 18) / 2
    category_colour = {"benign": SCALE["low"]["colour"], "reconnaissance": SCALE["medium"]["colour"],
                       "exploitation": SCALE["high"]["colour"], "exfiltration": SCALE["critical"]["colour"]}
    left = [b.para("RECORDED CATEGORY", "label"), g.hbars(
        [(k.title(), v, category_colour.get(k, g.PAPER3)) for k, v in sorted(m["categories"].items(), key=lambda x: -x[1])],
        half, 90)]
    right = [b.para("PROTOCOL", "label"), g.hbars(
        [(k, v, g.INK1) for k, v in sorted(m["protocols"].items(), key=lambda x: -x[1])], half, 60)]
    b.side_by_side(left, right)

    b.add(CondPageBreak(160))
    b.h2("Most active sources")
    rows = [["Source address", "Country", "Sessions", "Protocols", "Peak level", "Recorded categories"]]
    ordered = sorted(m["per_source"].items(), key=lambda kv: (-LEVELS.index(kv[1]["level"]), -kv[1]["sessions"]))
    for source, info in ordered[:10]:
        rows.append([
            source, info["country"] or "Unknown", str(info["sessions"]), ", ".join(sorted(info["protocols"])),
            g.chip(SCALE[info["level"]]["name"], SCALE[info["level"]]["colour"], 6.2, 11),
            ", ".join(f"{k} {v}" for k, v in info["categories"].most_common()),
        ])
    b.grid(rows, [92, 70, 44, 58, 62, CONTENT_W - 326], mono=(0, 2))
    if len(ordered) > 10:
        b.p(f"Showing 10 of {len(ordered)} sources; every source is listed in Appendix A.", "small")

    if m["usernames"]:
        b.add(CondPageBreak(140))
        b.h2("Usernames tried")
        rows = [["Username", "Attempts", "Share"]]
        total = sum(m["usernames"].values()) or 1
        for name, count in m["usernames"].most_common(10):
            rows.append([name, str(count), f"{count / total:.0%}"])
        b.grid(rows, [CONTENT_W * 0.5, CONTENT_W * 0.25, CONTENT_W * 0.25], mono=(0, 1, 2))
        b.p("Usernames only. Passwords appear solely in the administrator export.", "small")


# -- 3-5 the model's narrative ---------------------------------------------


def _narrative_sections(b):
    ctx, a = b.ctx, b.ctx.assessment
    narrative = ctx.narrative
    b.h1("Executive summary")
    if narrative is None:
        m = ctx.metrics
        b.p(
            f"This export contains {m['sessions']} session(s) from {m['sources']} recorded source address(es) "
            f"using {', '.join(sorted(m['protocols'])) or 'no recorded protocols'}. No AI narrative was written for "
            "it; the sections below report the stored findings only.",
            "lead",
        )
        return
    model = narrative.get("model")
    b.p(
        f'<font name="HS-Mono" size="7" color="{g.MUTED}">WRITTEN BY THE LOCAL MODEL {escape(str(model).upper())} '
        f"FROM THE EVIDENCE PACKET / {escape(format_time(narrative.get('generated_at')))}</font>",
        raw=True,
    )
    parts = [x.strip() for x in str(narrative["summary"]).split("\n") if x.strip()]
    for i, part in enumerate(parts):
        b.p(part, "lead" if i == 0 else "body")
    scope = narrative.get("scope") or {}
    b.kv([
        ("Selected sessions", len(ctx.records)),
        ("Recorded source addresses", ", ".join(sorted({str(s.get("attacker_ip") or "Not recorded") for s, _ in ctx.records}))),
        ("Stored categories", "; ".join(f"{k}: {v}" for k, v in sorted(ctx.metrics["categories"].items()))),
        ("AI evidence coverage",
         f"{scope.get('model_reviewed_groups')} representative activity groups of {scope.get('unique_activity_groups')} unique groups"),
        ("Threat level", f"{a['name']} ({a['index']}/100)"),
    ])

    b.h1("Findings")
    b.p(
        "Each finding was written by the model and cites the captured evidence lines that support it. The quoted "
        "excerpt is inserted by the report from the evidence itself, not by the model.",
        "muted",
    )
    levels = {g_["reference"]: group_level(g_, a) for g_ in ctx.groups}
    for i, finding in enumerate(narrative["findings"], 1):
        refs = finding.get("references") or []
        level = max((levels.get(r, "low") for r in refs), key=LEVELS.index, default="low")
        colour = SCALE[level]["colour"]
        content = [
            b.para(finding["title"], "card_title"),
            g.chip(f"CASE {', '.join(refs)}  /  {SCALE[level]['name']}", colour, 6.2, 11),
            Spacer(1, 6),
        ]
        for part in str(finding["paragraph"]).split("\n"):
            if part.strip():
                content.append(b.para(part.strip()))
        lines = finding.get("evidence_lines") or []
        quotes = str(finding.get("quote") or "").split("\n")
        # One row per cited line when they correspond; otherwise the quotation
        # is kept whole, exactly as it was inserted from the evidence.
        if len(lines) == len(quotes):
            pairs = list(zip(lines, quotes))
        else:
            pairs = [(", ".join(lines or refs), str(finding.get("quote") or ""))]
        content.append(b.terminal("supporting evidence  /  " + ", ".join(lines or refs), pairs, colour, add=False,
                                  width=CONTENT_W - 60))
        card = Table([[b.para(f"F{i}", "badge"), content]], colWidths=[40, CONTENT_W - 40], hAlign="LEFT")
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(g.SHEET2)),
            ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(colour)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        card._hs_kind = "card"
        b.add(card, Spacer(1, 10))

    b.h1("Assessment and recommended actions")
    b.h2("Assessment and uncertainty")
    b.paragraphs(narrative["assessment"])
    b.h2("Recommended follow-up")
    b.paragraphs(narrative["next_steps"])
    b.h2(f"Handling for a {a['name']} rating")
    b.p(SCALE[a["level"]]["handling"])
    b.h2("Scope of the model review")
    b.p(
        "The local model interpreted the referenced representative groups using the captured command and request "
        "excerpts supplied to it. The complete selected-session inventory and the captured activity are preserved in "
        "the appendices. Repeated identical activity is grouped for readability. Groups outside the stated AI coverage "
        "remain recorded evidence, not additional model conclusions. Source addresses identify recorded network "
        "endpoints. Interpretations and attempted actions do not prove changes to a real host.",
        "muted",
    )


# -- 6 ATT&CK ---------------------------------------------------------------


def _attack_section(b):
    ctx, m = b.ctx, b.ctx.metrics
    b.h1("MITRE ATT&CK mapping")
    b.p(
        f"MITRE ATT&CK Enterprise{' ' + ATTACK_VERSION if ATTACK_VERSION else ''}, {len(TACTICS)} tactics. "
        "Tactics are lit where at least one technique was detected by a rule or proposed by the model and supported "
        "by the checker; the number is the count of session observations. Unconfirmed proposals are listed but not lit.",
        "muted",
    )
    b.figure(g.tactic_strip(m["tactic_counts"], CONTENT_W, ctx.accent), 10)
    if not m["techniques"]:
        b.p("No ATT&CK techniques were mapped for the selected sessions.")
        return
    rows = [["ID", "Technique", "Tactic", "Sessions", "Established by"]]
    for t in m["techniques"][:40]:
        if t["state"] == "rule":
            how = "Rule detection"
        elif t["state"] == "supported":
            how = f"Model, checker support {t['max_support']:.2f}" if t["max_support"] is not None else "Model, supported"
        else:
            how = "Unconfirmed model proposal"
        rows.append([
            t["id"], t["name"] or "Not recorded",
            ", ".join(TACTIC_NAMES.get(x, x) for x in t["tactics"]) or "Not recorded",
            str(t["sessions"]), how,
        ])
    b.grid(rows, [58, CONTENT_W * 0.33, CONTENT_W * 0.22, 48, CONTENT_W - 106 - CONTENT_W * 0.55], mono=(0, 3))
    if len(m["techniques"]) > 40:
        b.p(f"Showing 40 of {len(m['techniques'])} techniques.", "small")


# -- 7 indicators -----------------------------------------------------------


def _ioc_section(b):
    m = b.ctx.metrics
    b.h1("Indicators of compromise")
    if not m["iocs"]:
        b.p("No indicators were recorded for the selected sessions.")
        return
    types = {}
    for item in m["iocs"]:
        types[item["type"]] = types.get(item["type"], 0) + 1
    b.p(
        f"{len(m['iocs'])} distinct indicator(s): " + ", ".join(f"{v} {k}" for k, v in sorted(types.items())) + ". "
        "Values are as the attacker supplied them; check them in an isolated environment before visiting or resolving.",
    )
    rows = [["Type", "Observed value", "Sessions", "First seen"]]
    for item in m["iocs"][:60]:
        rows.append([item["type"], item["value"], str(item["sessions"]), format_time(item["first_seen"], False)])
    b.grid(rows, [56, CONTENT_W - 56 - 50 - 104, 50, 104], mono=(1, 2))
    if len(m["iocs"]) > 60:
        b.p(f"Showing 60 of {len(m['iocs'])} indicators.", "small")


# -- 8 model and pipeline ---------------------------------------------------


def _model_section(b):
    ctx, m = b.ctx, b.ctx.metrics
    narrative = ctx.narrative or {}
    card = narrative.get("model_card") or {}
    telemetry = narrative.get("telemetry") or {}
    validation = narrative.get("validation") or {}
    b.h1("AI model and analysis pipeline")
    b.p(
        "Every session passes through the stages below as it is captured. The report reads what each stage stored "
        "for the selected sessions; the narrative stage runs when the report is requested.",
        "muted",
    )
    flow = ", ".join(m["flow_models"]) or "not recorded"
    triage_model = ", ".join(m["triage_models"]) or "decider"
    enrich_model = ", ".join(m["enrichment_models"]) or "enrichment model"
    agreement = m["rates"]["agreement"]
    b.figure(g.pipeline_diagram([
        ("Sensor capture", "Emulated SSH, Telnet, FTP and HTTP(S) services record each session",
         f"{m['sessions']} sessions / {len(m['sensors'])} sensor(s)"),
        ("Rule engine", "Deterministic detections and ATT&CK mapping set the category",
         f"mean conf {m['rates']['rule_confidence']:.2f}" if m["rates"]["rule_confidence"] is not None else "no rule verdicts"),
        ("ML models", "Flow forest (advisory), Isolation Forest, k-means clusters",
         f"{m['clusters']} clusters / {m['cluster_outliers']} outliers"),
        ("AI triage", f"{triage_model} reads each transcript and estimates compromise",
         f"{m['triaged']} triaged / {agreement:.0%} agree" if agreement is not None else f"{m['triaged']} triaged"),
        ("AI enrichment", f"{enrich_model} explains intent per session",
         f"{m['enriched']} of {m['sessions']} explained"),
        ("Report narrative", f"{narrative.get('model') or 'model'} writes, a validator checks citations",
         f"{telemetry.get('completion_tokens') or 'n/a'} tokens written"),
    ], CONTENT_W), 8)

    b.h2("Narrative model card", toc=True)
    if narrative:
        def number(value, unit=""):
            return f"{value:,}{unit}" if isinstance(value, int) else "Not reported"

        params = card.get("parameters")
        size = card.get("size_bytes")
        b.kv([
            ("Model", f"{narrative.get('model')} (served as '{card.get('alias') or narrative.get('model')}')"),
            ("Model file", card.get("file") or "Not reported", True),
            ("Inference runtime", f"llama.cpp, build {card['runtime_build']}" if card.get("runtime_build") else "OpenAI-compatible local server"),
            ("Quantization", card.get("quantization") or "Not reported"),
            ("Parameters", f"{params / 1e9:.2f} billion" if isinstance(params, (int, float)) else "Not reported"),
            ("Size on disk", f"{size / 1024 ** 3:.2f} GiB" if isinstance(size, (int, float)) else "Not reported"),
            ("Context window", f"{number(card.get('context_deployed'))} tokens deployed / {number(card.get('context_trained'))} trained"),
            ("Vocabulary", f"{number(card.get('vocabulary'))} tokens"),
            ("Decoding", "Temperature {t}, at most {mx} new tokens, output constrained to a strict JSON schema, reasoning mode off".format(
                t=(narrative.get("decoding") or {}).get("temperature", 0.15),
                mx=(narrative.get("decoding") or {}).get("max_tokens", 1300))),
            ("Prompt fingerprint", (narrative.get("prompt_sha256") or "Not recorded")[:16], True),
            ("Network access", "None. The model runs on the platform's own host; no evidence leaves it."),
        ])
    else:
        b.p("No AI narrative was written for this export.")

    b.h2("Generation telemetry", toc=True)
    if telemetry:
        def rate(value):
            return f"{value:.1f} tokens/s" if isinstance(value, (int, float)) else "Not reported"

        compute = None
        if isinstance(telemetry.get("prompt_ms"), (int, float)) and isinstance(telemetry.get("predicted_ms"), (int, float)):
            compute = telemetry["prompt_ms"] + telemetry["predicted_ms"]
        dropped = telemetry.get("cases_dropped") or 0
        b.kv([
            ("Evidence packet", f"{telemetry.get('packet_tokens', 'n/a')} tokens, {telemetry.get('cases', 'n/a')} case(s)"
             + (f", {dropped} dropped to fit the context window" if dropped else "")),
            ("Prompt tokens", telemetry.get("prompt_tokens") or "Not reported"),
            ("Completion tokens", telemetry.get("completion_tokens") or "Not reported"),
            ("Prompt processing", rate(telemetry.get("prompt_per_second"))),
            ("Generation speed", rate(telemetry.get("predicted_per_second"))),
            ("Model compute time", format_ms(compute)),
            ("Narrative wall time", format_ms(telemetry.get("wall_ms"))),
            ("Finish reason", telemetry.get("finish_reason") or "Not reported"),
        ])
    else:
        b.p("No generation telemetry was recorded for this narrative.", "muted")

    b.h2("Validation gates", toc=True)
    if narrative:
        rows = [["Gate", "What it checks", "Checked", "Result"]]
        for name, what, count in [
            ("Schema", "The reply is one JSON object with summary, findings, assessment and next steps", 1),
            ("Citations", "Every finding cites evidence-line identifiers that exist in the packet", validation.get("citations")),
            ("References", "Every [E#] reference in the prose names a case that was supplied", validation.get("references")),
            ("Addresses", "No IP address appears that is absent from the evidence", validation.get("addresses")),
            ("URLs", "No URL appears that is absent from the evidence", validation.get("urls")),
            ("Quotations", "Quoted excerpts are inserted from the evidence, never from the model", validation.get("findings")),
        ]:
            rows.append([name, what, "n/a" if count is None else str(count), "PASS"])
        b.grid(rows, [64, CONTENT_W - 64 - 52 - 46, 52, 46], mono=(2, 3))
        b.p("A reply that fails any gate is rejected and no report is produced; this report passed all of them.", "small")

    b.h2("Analysis modules on the selected sessions", toc=True)
    calibrated = m["anomaly_calibrated"]
    rows = [["Module", "Method", "On this evidence"]]
    rows.append(["Rule engine", "Deterministic patterns over commands and requests",
                 f"Set the category of {sum(1 for _, x in ctx.records if x.get('model_source') == 'rules')} session(s)"])
    rows.append(["Flow classifier", f"Random forest ({flow}); advisory only",
                 f"Disagreed with the rules on {m['flow_disagreements']} of {m['flow_total']} session(s)" if m["flow_total"] else "No flow verdicts stored"])
    rows.append(["Anomaly detector", "Isolation Forest (" + (", ".join(m["anomaly_sources"]) or "not recorded") + ")",
                 (f"Calibrated; {m['anomalous']} session(s) flagged" if calibrated
                  else "Not yet calibrated on real sessions; its flags do not affect severity")])
    rows.append(["Behavioural clustering", "Mini-batch k-means over session features",
                 f"{m['clusters']} cluster(s), {m['cluster_outliers']} outlier(s)"])
    rows.append(["Triage decider", triage_model,
                 f"{m['triaged']} session(s), mean {format_ms(m['triage_ms_mean'])}" if m["triaged"] else "No session triaged"])
    rows.append(["Enrichment", enrich_model, f"{m['enriched']} session(s) explained"])
    rows.append(["Client fingerprinting", "HASSH, JA3/JA4 and HTTP header order where available",
                 ", ".join(f"{k} {v}" for k, v in m["fingerprints"].items()) or "None recorded"])
    latency = m["analysis_ms"]
    rows.append(["Pipeline latency", "Time the analysis took per session at ingest",
                 f"Mean {format_ms(latency['mean'])}, median {format_ms(latency['median'])}, max {format_ms(latency['max'])}"
                 if latency["count"] else "Not recorded"])
    b.grid(rows, [92, CONTENT_W * 0.38, CONTENT_W - 92 - CONTENT_W * 0.38])


# -- 9 method, 10 approval --------------------------------------------------


def _method_section(b):
    b.h1("Methodology and limitations")
    b.h2("How the evidence was collected")
    b.p(
        "HoneySentinel exposes emulated services that have no legitimate users, so every connection is unsolicited. "
        "Each session's commands, requests and login attempts are recorded, encrypted at rest and analysed as they "
        "arrive. This report is a snapshot of that stored evidence at the time of the request; it does not replay or "
        "execute anything that was captured."
    )
    b.h2("How the report was produced")
    b.p(
        "The threat level, metrics, ATT&CK mapping and indicator lists are computed directly from the stored records. "
        "The executive summary, findings and recommendations are written by a local language model from a bounded "
        "packet of evidence lines; an automatic validator rejects any reply that cites a line, address or URL that is "
        "not in that packet, and the quoted excerpts are inserted from the evidence by the report itself."
    )
    b.h2("Limitations")
    for item in [
        "Commands typed into a decoy are attempts. They do not prove that a download, persistence or theft succeeded.",
        "A source address is a network endpoint, possibly a proxy or a shared gateway, not an identified person.",
        "Model interpretations can be wrong. Treat them as leads to check against the preserved evidence.",
        "Redaction is pattern based and may miss unusual secret formats; the administrator export holds the original.",
        "The threat index ranks recorded behaviour. It is not a probability of compromise and is not calibrated against incident outcomes.",
    ]:
        b.p("•  " + item)
    b.h2("Glossary")
    rows = [["Term", "Meaning"]]
    for term, meaning in [
        ("Decoy / honeypot", "A service built to be attacked, with no production data or users behind it."),
        ("Session", "One connection from a source to a decoy, from first packet to disconnect."),
        ("Evidence case (E1, E2 ...)", "Sessions that share the same protocol, category and captured activity."),
        ("ATT&CK", "MITRE's public catalogue of adversary tactics (goals) and techniques (methods)."),
        ("Indicator (IoC)", "An observable such as an address, URL or file name worth searching for elsewhere."),
        ("TLP", "Traffic Light Protocol, the FIRST standard marking for how far a document may be shared."),
        ("HASSH / JA3 / JA4", "Fingerprints of an SSH or TLS client's handshake, used to link sessions from the same tool."),
        ("Isolation Forest", "An anomaly detector that flags sessions unlike the ones it was fitted on."),
        ("Evidence SHA-256", "A hash of the exact evidence snapshot; any change to the evidence changes it."),
    ]:
        rows.append([term, meaning])
    b.grid(rows, [CONTENT_W * 0.28, CONTENT_W * 0.72])


def _approval_section(b):
    ctx = b.ctx
    name, email, _ = _requester(ctx)
    b.h1("Review and approval", new_page=True)
    b.p(
        "This report was generated automatically. It becomes a reviewed record once the people below have checked "
        "the findings against the evidence appendices and signed.",
        "muted",
    )
    prepared_for = _setting(ctx, "REPORT_PREPARED_FOR")
    rows = [["Role", "Name", "Email", "Signature", "Date"]]
    rows.append(["Prepared by", name, email or "", "", format_time(ctx.generated, seconds=False)])
    rows.append(["Technical reviewer", "", "", "", ""])
    for party_name, party_email in _parties(_setting(ctx, "REPORT_RECIPIENTS"))[:3]:
        rows.append([prepared_for or "Recipient", party_name, party_email or "", "", ""])
    if len(rows) == 3:
        rows.append([prepared_for or "Supervisor / committee", "", "", "", ""])
    table = b.grid(rows, [96, 108, CONTENT_W - 96 - 108 - 100 - 82, 100, 82], mono=(2,))
    table.setStyle(TableStyle([
        ("TOPPADDING", (0, 1), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 1), (-1, -1), 14),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white]),
    ]))
    b.h2("Reviewer notes")
    lines = Table([[""] for _ in range(6)], colWidths=[CONTENT_W], rowHeights=[22] * 6, hAlign="LEFT")
    lines.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor(g.RULE))]))
    lines._hs_kind = "lines"
    b.add(lines)


# -- appendices -------------------------------------------------------------


def _inventory_appendix(b):
    ctx, a = b.ctx, b.ctx.assessment
    b.h1("Session inventory", appendix="A", new_page=True)
    rows = [["Case", "Session UUID", "Source", "Proto", "Started (UTC)", "Category", "Level"]]
    for group in ctx.groups:
        for s in group["sessions"]:
            level = a["by_uuid"].get(str(s["uuid"]), ("low", 0))[0]
            rows.append([
                group["reference"], s["uuid"], s["source"], str(group["protocol"] or "").upper(),
                format_time(s["started_at"]).replace(" UTC", ""), group["category"],
                g.chip(SCALE[level]["name"], SCALE[level]["colour"], 5.8, 10),
            ])
    b.grid(rows, [28, 150, 74, 34, 94, 72, CONTENT_W - 452], mono=(0, 1, 2, 3, 4), mono_style="cell_mono_small")


def _case_appendix(b):
    ctx, a = b.ctx, b.ctx.assessment
    reviewed = set((ctx.narrative or {}).get("reviewed_references") or [])
    from app.services.investigation_narrative import redact

    for index, group in enumerate(ctx.groups):
        level = group_level(group, a)
        colour = SCALE[level]["colour"]
        title = f"{group['reference']} / {str(group['protocol']).upper()} / {group['category']}"
        if index == 0:
            b.h1("Evidence cases", appendix="B", new_page=True)
        else:
            b.add(PageBreak())
        heading = b.para(title, "title")
        heading._hs_toc = (1, title, f"c{index}")
        b.add(heading, g.chip(f"THREAT LEVEL  {SCALE[level]['name']} / {SCALE[level]['colour_name'].upper()}", colour, 7, 14), Spacer(1, 10))
        sources = sorted({str(s["source"]) for s in group["sessions"]})
        first = min(str(s["started_at"]) for s in group["sessions"])
        last = max(str(s["ended_at"] or s["started_at"]) for s in group["sessions"])
        usernames = sorted(group.get("credential_usernames", {}).items(), key=lambda x: -x[1])[:6]
        b.kv([
            ("Source address(es)", ", ".join(sources), True),
            ("Sessions sharing this activity", len(group["sessions"])),
            ("First observed", format_time(first)),
            ("Last observed", format_time(last)),
            ("Stored category", group["category"]),
            ("Threat level", f"{SCALE[level]['name']} ({SCALE[level]['colour_name']})"),
            ("Captured authentication attempts",
             f"{group.get('credential_attempts', 0)} ({group.get('decoy_accepts', 0)} accepted by the decoy)"),
            ("Usernames tried", ", ".join(f"{n} x{c}" for n, c in usernames) or "None recorded", True),
            ("Evidence source", group.get("evidence_source", "Stored activity")),
            ("AI review", "Included in the model evidence packet" if group["reference"] in reviewed
             else "Recorded here; not interpreted by the model in this report"),
        ])
        if all(str(s["uuid"]).startswith("demo-") for s in group["sessions"]):
            b.p("SIMULATED DEMONSTRATION: prepared fixture data; no attack commands were executed.", "h2")
        if group.get("rule_reason"):
            b.p("<b>Stored rule evidence.</b> " + text(group["rule_reason"]), raw=True)
        if group.get("prior_explanation"):
            b.p("<b>Stored per-session explanation.</b> " + text(group["prior_explanation"]), raw=True)
        b.label("Captured command / request evidence")
        commands = str(group["commands"] or "No command/request text recorded.")
        if not ctx.sensitive:
            commands = redact(commands)
        lines = commands.splitlines()
        b.terminal(
            f"{group['reference']}  /  {str(group['protocol']).upper()}  /  {group.get('evidence_source', 'stored activity')}",
            [(f"{group['reference']}.{i}", line[:1000] + (" [line shortened]" if len(line) > 1000 else ""))
             for i, line in enumerate(lines[:40], 1)],
            colour,
        )
        if len(lines) > 40:
            b.p(f"Excerpt shortened: showing 40 of {len(lines)} captured activity lines.", "small")
        for s in group["sessions"]:
            if s.get("evidence_error"):
                b.p(f"Session {s['uuid']}: {s['evidence_error']}", "small")
        # The stored rows repeat an indicator once per session (with its own
        # timestamp); the case lists each type and value once.
        case_iocs = distinct((str(x.get("type")), str(x.get("value"))) for x in group.get("iocs") or [])
        if case_iocs:
            b.label("Recorded indicators")
            b.grid([["Type", "Observed value"]] + [list(x) for x in case_iocs[:40]],
                   [70, CONTENT_W - 70], mono=(1,))
            if len(case_iocs) > 40:
                b.p("Indicator excerpt shortened to the first 40 values.", "small")
        prints = []
        for s, _ in ctx.records:
            if str(s.get("session_uuid")) in {str(x["uuid"]) for x in group["sessions"]}:
                fp = s.get("fingerprints") if isinstance(s.get("fingerprints"), dict) else {}
                for key in ("hassh", "hassh_server", "ja3", "ja4", "http_header_order"):
                    if fp.get(key):
                        prints.append((key.upper().replace("_", " "), str(fp[key])))
        prints = distinct(prints)
        if prints:
            b.label("Client fingerprints")
            b.kv([(k, v, True) for k, v in prints[:8]])
        if ctx.sensitive:
            credential_rows = [["Session / source", "Username", "Captured password", "Result"]]
            total = 0
            for s in group["sessions"]:
                total += s.get("credentials_total", 0)
                for c in s.get("credentials") or []:
                    if len(credential_rows) <= 100:
                        credential_rows.append([
                            f"{s['uuid']} / {s['source']}", c.get("username", ""), c.get("password", ""),
                            str(c.get("success", c.get("accepted", "Not recorded"))),
                        ])
                if s.get("credential_error"):
                    b.p(f"Session {s['uuid']}: {s['credential_error']}", "small")
            if len(credential_rows) > 1:
                b.label("Captured credential evidence (admin)")
                b.grid(credential_rows, [CONTENT_W * 0.38, CONTENT_W * 0.18, CONTENT_W * 0.26, CONTENT_W * 0.18], mono=(1, 2))
                if total > len(credential_rows) - 1:
                    b.p(f"Credential excerpt: {len(credential_rows) - 1} of {total} recorded attempts shown for this case.", "small")


def _record_appendix(b):
    ctx = b.ctx
    timings = ctx.meta.get("timings") or {}
    narrative = ctx.narrative or {}
    b.h1("Report generation record", appendix="C", new_page=True)
    b.p(
        "When this report was generated and how long each step took. Times are measured by the platform while the "
        "report is made; the document rendering time is taken when the last page is complete.",
        "muted",
    )
    requested = ctx.meta.get("requested_at")
    rows = [
        ("Report requested", format_time(requested)),
        ("Findings written by the model", format_time(narrative.get("generated_at")) if narrative else "No narrative"),
        ("Document generated", format_time(ctx.generated)),
    ]
    b.kv(rows)
    b.h2("Time taken")
    style = b.s["cell_mono"]
    data = [
        [b.cell("Evidence snapshot", "cell_label"), b.cell(format_ms(timings.get("snapshot_ms")), "cell_mono"),
         b.cell("Selected sessions read and decrypted, secrets redacted", "cell_muted")],
        [b.cell("Waiting for the model", "cell_label"), b.cell(format_ms(timings.get("queue_ms")), "cell_mono"),
         b.cell("Queued behind background analysis using the same model", "cell_muted")],
        [b.cell("AI analysis", "cell_label"), b.cell(format_ms(timings.get("narrative_ms")), "cell_mono"),
         b.cell("The local model writing and the validator checking the findings", "cell_muted")],
        [b.cell("Document rendering", "cell_label"), Slot(ctx, "render", style),
         b.cell("Charts, tables and page layout of this document", "cell_muted")],
        [b.cell("Total time to generate", "cell_label"), Slot(ctx, "total", ParagraphStyle("total", parent=style, fontName="HS-Mono-SemiBold")),
         b.cell("Sum of the steps above", "cell_muted")],
    ]
    table = Table(data, colWidths=[CONTENT_W * 0.3, 90, CONTENT_W * 0.7 - 90], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(g.RULE)),
        ("LINEABOVE", (0, 0), (-1, 0), 0.9, INK),
        ("LINEABOVE", (0, -1), (-1, -1), 0.9, INK),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor(g.mix(g.SHEET, ctx.accent, 0.16))),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    table._hs_kind = "kv"
    b.add(table)
    b.h2("Integrity")
    b.kv([
        ("Report ID", ctx.report_id, True),
        ("Evidence SHA-256", ctx.evidence_hash, True),
        ("Sessions in snapshot", len(ctx.records)),
        ("Renderer", f"ReportLab {reportlab.Version} (PDF), python-docx (Word); IBM Plex and Space Grotesk typefaces (SIL OFL)"),
    ])
    b.add(Spacer(1, 18))
    b.p(f'<font name="HS-Mono" size="7" color="{g.MUTED}">END OF REPORT  /  {escape(ctx.report_id)}</font>', raw=True)


# -- Word -------------------------------------------------------------------


def _word_document(story, ctx, cover_info, styles):
    from docx import Document
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor

    d = Document()
    section = d.sections[0]
    section.page_width, section.page_height = Inches(8.27), Inches(11.69)
    section.top_margin, section.bottom_margin = Inches(0.8), Inches(0.7)
    section.left_margin = section.right_margin = Inches(0.6)
    section.different_first_page_header_footer = True
    normal = d.styles["Normal"]
    normal.font.name, normal.font.size = "Arial", Pt(9.5)
    normal.paragraph_format.line_spacing = 1.15
    normal.paragraph_format.space_after = Pt(6)
    for name, size in [("Title", 22), ("Heading 1", 16), ("Heading 2", 11.5)]:
        style = d.styles[name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor.from_string("101014")
        properties = style.element.get_or_add_pPr()
        borders = OxmlElement("w:pBdr")
        for edge in ["top", "left", "bottom", "right", "between"]:
            border = OxmlElement("w:" + edge)
            border.set(qn("w:val"), "nil")
            borders.append(border)
        properties.append(borders)
    content_width = 8.27 - 1.2

    def shade(cell, colour):
        item = OxmlElement("w:shd")
        item.set(qn("w:val"), "clear")
        item.set(qn("w:fill"), colour.lstrip("#"))
        cell._tc.get_or_add_tcPr().append(item)

    def field(paragraph, instruction):
        element = OxmlElement("w:fldSimple")
        element.set(qn("w:instr"), instruction)
        run = OxmlElement("w:r")
        t = OxmlElement("w:t")
        t.text = "1"
        run.append(t)
        element.append(run)
        paragraph._p.append(element)

    def plain(paragraph):
        return "".join(
            "\n" if getattr(frag, "lineBreak", False) else getattr(frag, "text", "") for frag in paragraph.frags
        ).strip()

    def picture(run, drawing, scale=3):
        run.add_picture(g.to_png(drawing, scale), width=Inches(drawing.width / 72))

    # Header and footer of the pages after the cover.
    a = ctx.assessment
    header = section.header.add_table(rows=1, cols=2, width=Inches(content_width))
    for cell in header.rows[0].cells:
        shade(cell, g.INK1)
    run = header.cell(0, 0).paragraphs[0].add_run()
    run.add_picture(g.to_png(_logo_drawing(), 4), width=Inches(0.28))
    run = header.cell(0, 0).paragraphs[0].add_run("  HONEYSENTINEL  /  " + ctx.report_id)
    run.bold = True
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor.from_string("F2F0EA")
    run = header.cell(0, 1).paragraphs[0].add_run(f"THREAT LEVEL {a['name']}  {a['index']}/100")
    run.bold = True
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor.from_string(a["colour"].lstrip("#").upper())
    footer = section.footer.paragraphs[0]
    footer.add_run(f"{ctx.classification}  |  Evidence SHA-256 {ctx.evidence_hash[:24]}...  |  Page ").font.size = Pt(7.5)
    field(footer, "PAGE")
    footer.add_run(" of ").font.size = Pt(7.5)
    field(footer, "NUMPAGES")

    cover_paragraph = None
    slots = []
    pending_break = False

    def new_paragraph(style=None):
        """A body paragraph that starts a page if a break is pending.

        A break written as its own paragraph lands on the next page by itself
        whenever the previous page is exactly full, leaving a blank page.
        """
        nonlocal pending_break
        paragraph = d.add_paragraph(style=style)
        if pending_break:
            paragraph.paragraph_format.page_break_before = True
            pending_break = False
        return paragraph
    headings = [plain(x) for x in story if isinstance(x, Paragraph) and x.style.name == "h1"]

    def add_paragraph(container, item):
        value = plain(item)
        name = item.style.name
        style = {"title": "Title", "h1": "Heading 1", "h2": "Heading 2", "card_title": "Heading 2"}.get(name, "Normal")
        paragraph = new_paragraph(style)
        run = paragraph.add_run(value)
        if name in {"small", "muted", "label", "cell_muted", "cell_label"}:
            run.font.size = Pt(8)
            run.font.color.rgb = RGBColor.from_string("5D5C66")
        if name in {"label"}:
            run.bold = True
        if name in {"cell_mono", "term", "term_ref", "term_bar"}:
            run.font.name = "Courier New"
            run.font.size = Pt(8)
        if name == "lead":
            run.font.size = Pt(10.5)
        if name == "badge":
            run.bold = True
            run.font.size = Pt(14)

    def fill_cell(cell, value, kind, header_row):
        cell.paragraphs[0].text = ""
        items = value if isinstance(value, list) else [value]
        first = True
        for item in items:
            if isinstance(item, Drawing):
                paragraph = cell.paragraphs[0] if first else cell.add_paragraph()
                picture(paragraph.add_run(), item)
            elif isinstance(item, Paragraph):
                if first:
                    paragraph = cell.paragraphs[0]
                    run = paragraph.add_run(plain(item))
                else:
                    paragraph = cell.add_paragraph()
                    run = paragraph.add_run(plain(item))
                run.font.size = Pt(8)
                if item.style.fontName.startswith("HS-Mono"):
                    run.font.name = "Courier New"
                    run.font.size = Pt(7.5)
                if item.style.fontName in {"HS-Display", "HS-Sans-SemiBold", "HS-Mono-SemiBold"} or header_row:
                    run.bold = True
                if header_row or kind == "terminal" or (kind == "email" and item.style.name == "cell_head"):
                    run.font.color.rgb = RGBColor.from_string("F2F0EA")
                if item.style.name in {"cell_muted", "cell_label"}:
                    run.font.color.rgb = RGBColor.from_string("5D5C66")
            elif isinstance(item, Table):
                nested = cell.add_table(rows=0, cols=len(item._cellvalues[0]))
                add_table_rows(nested, item, getattr(item, "_hs_kind", "grid"))
            elif isinstance(item, Slot):
                paragraph = cell.paragraphs[0] if first else cell.add_paragraph()
                run = paragraph.add_run("")
                run.font.name = "Courier New"
                run.font.size = Pt(8)
                slots.append((run, item.key))
            elif isinstance(item, str) and item:
                cell.paragraphs[0].add_run(item).font.size = Pt(8)
            else:
                continue
            first = False

    def add_table_rows(table, item, kind):
        rows = item._cellvalues
        for i, row in enumerate(rows):
            cells = table.add_row().cells
            header_row = i == 0 and kind == "grid"
            for j, (cell, value) in enumerate(zip(cells, row)):
                fill_cell(cell, value, kind, header_row)
                if header_row:
                    shade(cell, g.INK1)
                elif kind == "terminal":
                    shade(cell, g.INK3 if i == 0 else g.INK0)
                elif kind == "email":
                    shade(cell, g.INK1 if j == 0 and i < len(rows) - 1 else g.SHEET2)
                elif kind in {"card"}:
                    shade(cell, g.SHEET2)
                elif kind == "grid" and i % 2 == 0:
                    shade(cell, g.SHEET2)
            if header_row:
                table.rows[i]._tr.get_or_add_trPr().append(OxmlElement("w:tblHeader"))
        if kind in {"grid", "kv", "terminal", "email", "card", "lines"}:
            table.style = "Table Grid"

    def walk(items):
        nonlocal cover_paragraph, pending_break
        for item in items:
            if getattr(item, "_hs_cover", False):
                cover_paragraph = d.add_paragraph()
                cover_paragraph.paragraph_format.space_after = Pt(0)
            elif isinstance(item, Paragraph):
                add_paragraph(d, item)
            elif isinstance(item, PageBreak):
                pending_break = True
            elif isinstance(item, Toc):
                for title in headings:
                    paragraph = new_paragraph()
                    paragraph.add_run(title)
                    paragraph.paragraph_format.space_after = Pt(2)
            elif isinstance(item, KeepTogether):
                walk(item._content)
            elif isinstance(item, Table):
                if getattr(item, "_hs_kind", None) == "card":
                    # Word gets the finding as ordinary paragraphs and a
                    # top-level evidence table, which stay editable there.
                    badge, content = item._cellvalues[0]
                    walk([badge])
                    walk(content if isinstance(content, list) else [content])
                    continue
                if getattr(item, "_hs_kind", None) == "layout":
                    row = item._cellvalues[0]
                    for value in (row[0], row[-1]):
                        for part in value if isinstance(value, list) else [value]:
                            walk([part])
                    continue
                if pending_break:
                    spacer = new_paragraph()
                    spacer.paragraph_format.space_after = Pt(0)
                columns = len(item._cellvalues[0])
                table = d.add_table(rows=0, cols=columns)
                add_table_rows(table, item, getattr(item, "_hs_kind", "grid"))
                d.add_paragraph().paragraph_format.space_after = Pt(2)
            elif isinstance(item, Drawing):
                picture(new_paragraph().add_run(), item)
            elif isinstance(item, (ActionFlowable, Spacer, CondPageBreak)):
                continue

    walk(story)
    done = ctx.finish()
    for run, key in slots:
        run.text = done[key]
    if cover_paragraph is not None:
        cover = g.cover(PAGE_W, PAGE_H, {**cover_info, "duration": done["total"]})
        height = 9.3
        cover_paragraph.add_run().add_picture(g.to_png(cover, 2.2), width=Inches(height * PAGE_W / PAGE_H), height=Inches(height))
        cover_paragraph.alignment = 1
    d.core_properties.author = "HoneySentinel AI"
    d.core_properties.title = f"HoneySentinel Threat Investigation Report {ctx.report_id}"
    d.core_properties.subject = f"Threat level {a['name']} ({a['index']}/100)"
    d.core_properties.keywords = f"{ctx.classification}, {ctx.report_id}"
    d.core_properties.last_modified_by = "HoneySentinel AI"
    output = BytesIO()
    d.save(output)
    return output.getvalue()


def _logo_drawing():
    drawing = Drawing(24, 24)
    drawing.add(g.logo(0, 0, 24))
    return drawing
