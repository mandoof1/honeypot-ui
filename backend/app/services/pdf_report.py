"""Human-readable evidence reports. Render stored findings; never execute telemetry."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import re
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.graphics.shapes import Drawing, Rect, String

MAX_PDF_SESSIONS = 100
INK = colors.HexColor('#101014')
PAPER = colors.HexColor('#f2f0ea')
MUTED = colors.HexColor('#696874')
RAMP = {'benign': '#19b287', 'reconnaissance': '#fab219', 'exploitation': '#ec835a', 'exfiltration': '#d5405f'}


def text(value, limit=6000):
    """Bound untrusted strings and escape ReportLab's XML-like paragraph syntax."""
    value = str(value) if value is not None else 'Not recorded'
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)
    if len(value) > limit:
        value = value[:limit] + ' [excerpt truncated]'
    return escape(value).replace('\n', '<br/>')


def generate_pdf_report(records: list[tuple[dict, dict]], output_format="pdf", narrative=None, include_sensitive=False) -> bytes:
    if len(records) > MAX_PDF_SESSIONS:
        raise ValueError(f'PDF reports support at most {MAX_PDF_SESSIONS} sessions')
    fonts = Path(reportlab.__file__).parent / 'fonts'
    for name, file in [('HSBody', 'Vera.ttf'), ('HSBold', 'VeraBd.ttf')]:
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts / file)))
    normal = ParagraphStyle('body', fontName='HSBody', fontSize=9, leading=14, spaceAfter=9,
                            textColor=INK, wordWrap='LTR', alignment=TA_LEFT)
    heading = ParagraphStyle('heading', parent=normal, fontName='HSBold', fontSize=13, leading=18,
                             spaceBefore=14, spaceAfter=8, keepWithNext=True)
    small = ParagraphStyle('small', parent=normal, fontSize=8, leading=11, textColor=MUTED)
    title = ParagraphStyle('title', parent=heading, fontSize=27, leading=33)
    p = lambda value, style=normal: Paragraph(text(value), style)
    story = []
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=42, rightMargin=42,
                           topMargin=79, bottomMargin=48, title='HoneySentinel AI Investigation Report',
                           author='HoneySentinel AI')
    width = A4[0] - 84

    def table(rows, widths=None, log=False):
        head_style = ParagraphStyle('table_head', parent=small, textColor=PAPER, fontName='HSBold')
        cell_style = ParagraphStyle('log_cell', parent=small, fontName='Courier', fontSize=7.5) if log else small
        data = [[p('Not recorded' if cell is None else str(cell)[:1200], head_style if i == 0 else cell_style) for cell in row] for i, row in enumerate(rows)]
        result = Table(data, colWidths=widths or [width * .31, width * .69], repeatRows=1, hAlign='LEFT')
        result.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), INK),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#eeedf0')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10), ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, 0), 2, colors.HexColor('#7d7c86')),
        ]))
        story.append(result)

    def frame(canvas, document):
        canvas.saveState()
        canvas.setFillColor(INK)
        canvas.rect(0, A4[1]-59, A4[0], 59, fill=1, stroke=0)
        canvas.setFillColor(PAPER)
        canvas.setFont('HSBold', 13)
        canvas.saveState()
        canvas.translate(42, A4[1]-46)
        canvas.scale(1.15, 1.15)
        def mark(points, filled=False):
            path = canvas.beginPath()
            for i, (x, y) in enumerate(points):
                (path.moveTo if i == 0 else path.lineTo)(x, 24-y)
            path.close()
            canvas.setStrokeColor(PAPER)
            canvas.setLineWidth(1.3)
            canvas.drawPath(path, fill=int(filled), stroke=int(not filled))
        mark([(12,2.4),(20.8,7.2),(20.8,16.8),(12,21.6),(3.2,16.8),(3.2,7.2)])
        mark([(12,8),(16.4,10.4),(16.4,15.2),(12,17.6),(7.6,15.2),(7.6,10.4)], True)
        canvas.restoreState()
        canvas.drawString(80, A4[1]-29, 'HoneySentinel AI')
        canvas.setFont('HSBody', 8)
        canvas.drawRightString(A4[0]-42, A4[1]-25, 'INVESTIGATION / EVIDENCE REPORT')
        canvas.drawRightString(A4[0]-42, A4[1]-42, now)
        canvas.setFillColor(MUTED)
        canvas.setFont('HSBody', 8)
        canvas.drawString(42, 28, 'Sensitive security telemetry | Authorised analyst export')
        canvas.drawRightString(A4[0]-42, 28, f'{document.page}')
        canvas.restoreState()

    now = datetime.now(timezone.utc).strftime('%d %B %Y, %H:%M UTC')
    if narrative is not None:
        _investigation_content(story, p, table, heading, small, title, width, records, narrative, include_sensitive)
        if output_format == 'docx':
            return _word_document(story, Counter(str(a.get('category') or 'unknown') for _, a in records), now)
        doc.build(story, onFirstPage=frame, onLaterPages=frame)
        return buffer.getvalue()
    story += [p('Investigation report', title), p(f'Generated {now}', small),
              p('Introduction', heading),
              p(f'This report brings together {len(records)} selected honeypot session(s), their source information, '
                'recorded activity and available AI analysis. It explains what was observed and why the system '
                'assigned its findings. The report is a snapshot of stored evidence, not a new attack simulation '
                'or an independently verified attribution of a person.'),
              p('Assessment at a glance', heading)]
    counts = Counter(str(a.get('category') or 'unknown') for _, a in records)
    sources = {str(s['attacker_ip']) for s, _ in records if s.get('attacker_ip')}
    protocols = sorted({str(s.get('protocol') or 'unknown').upper() for s, _ in records})
    explained = sum(bool(isinstance(a.get('enrichment'), dict) and a['enrichment'].get('intent')) for _, a in records)
    demos = sum(str(s.get('session_uuid', '')).startswith('demo-') for s, _ in records)
    summary = (f'The selected evidence contains {len(records)} session(s) from {len(sources)} recorded source address(es), '
               f'using {", ".join(protocols) or "no recorded protocols"}. '
               + 'Stored categories: '+(', '.join(f'{name}: {count}' for name, count in sorted(counts.items())) or 'none')+'. '
               +f'{explained} session(s) contain a stored explanation. Session-by-session details below describe the observed activity and its available interpretation.')
    story.append(p(summary))
    if demos:
        story.append(p(f'DEMONSTRATION DATA: {demos} selected session(s) are labelled simulations, not live attack captures.', small))

    table([['Recorded category', 'Session count']] + [[key.replace('_', ' ').title(), str(value)] for key, value in sorted(counts.items())] if counts else [['Recorded category', 'Session count'], ['No matching sessions', '0']])
    chart = Drawing(width, max(42, len(counts)*27+12))
    for i, (category, count) in enumerate(sorted(counts.items())):
        y = chart.height-25-i*27
        chart.add(String(0, y+2, category.title(), fontName='HSBody', fontSize=8, fillColor=INK))
        chart.add(Rect(115, y-2, max(2, (width-155)*count/max(1,len(records))), 13,
                       fillColor=colors.HexColor(RAMP.get(category, '#7d7c86')), strokeColor=None))
        chart.add(String(width-28, y+2, str(count), fontName='HSBold', fontSize=9))
    story += [Spacer(1, 14), chart,
              p('Reading the findings', heading),
              p('Source addresses identify the network endpoint recorded by the sensor, not a named attacker. '
                'Private or translated addresses may represent a gateway. Model confidence is not a verified '
                'probability of an attack. Anomaly and operator-profile estimates may be unvalidated. '
                'Confirm important conclusions against the preserved session evidence.')]
    for index, (s, a) in enumerate(records, 1):
        story.append(PageBreak())
        if str(s.get('session_uuid', '')).startswith('demo-'):
            story.append(p('SIMULATED DEMONSTRATION: prepared test data, not a live attack capture.', heading))
        story += [p(f'Session {index:02d} / {s.get("protocol", "unknown").upper()}', title),
                  p(s.get('session_uuid'), small), p('Attacker / source information', heading)]
        geo = s.get('geo') or {}
        table([['Field', 'Recorded value'], ['Source address', s.get('attacker_ip')],
               ['Source port', s.get('attacker_port')], ['Country / city', f'{geo.get("country_name") or geo.get("country") or "Not recorded"} / {geo.get("city") or "Not recorded"}'],
               ['First observed (stored time)', s.get('started_at')], ['Last observed (stored time)', s.get('ended_at')],
               ['Duration (seconds)', s.get('duration_seconds')], ['Session status', s.get('status')],
               ['Research scanner attribution', a.get('scanner_operator') or 'Not attributed']])
        story += [p('What happened', heading),
                  p(f'The sensor recorded a {s.get("protocol", "unknown")} interaction from '
                    f'{s.get("attacker_ip", "an unrecorded address")}. The stored session runs from '
                    f'{s.get("started_at") or "an unknown start time"} to {s.get("ended_at") or "an unrecorded end time"}. '
                    f'It contains {a.get("command_count") or 0} recorded commands and {len(s.get("uploads") or [])} upload records. '
                    f'The recorded category is {a.get("category") or "unknown"}, decided by '
                    f'{a.get("model_source") or "an unrecorded analysis source"}.'),
                  p('The stored command/activity summary is reproduced in the log excerpt below. Missing events are not reconstructed.'),
                  p('Explanation and AI analysis', heading)]
        enrichment = a.get('enrichment') if isinstance(a.get('enrichment'), dict) else {}
        status = a.get('enrichment_status') or 'not recorded'
        story.append(p(f'Local-model analysis status: {status}.'))
        if enrichment.get('intent'):
            story.append(p(enrichment['intent']))
        if a.get('rule_reason'):
            story.append(p('Rule evidence: '+str(a['rule_reason'])))
        else:
            story.append(p('No stored local-model explanation is available for this session. The report retains '
                           'the recorded findings above rather than inventing an explanation.'))
        for objective in (enrichment.get('objectives') or [])[:12]:
            story.append(p('Objective inferred by model: '+str(objective)))
        table([['Analysis field', 'Recorded finding'], ['Verdict source', a.get('model_source')],
               ['Classification confidence', a.get('confidence')],
               ['Model / checked by', f'{enrichment.get("model") or "Not recorded"} / {enrichment.get("checked_by") or "Not recorded"}'],
               ['Explanation generated at', enrichment.get('analysed_at')],
               ['Detected tools', ', '.join(str(x.get('name', '')) if isinstance(x,dict) else str(x) for x in (a.get('detected_tools') or [])[:30]) or 'None recorded'],
               ['Detected intents', ', '.join(map(str, (a.get('detected_intents') or [])[:30])) or 'None recorded']])
        story.append(p('ATT&CK techniques and supporting context', heading))
        techniques = list((a.get('mitre') or {}).get('techniques') or [])
        techniques += list(enrichment.get('mitre_techniques') or [])
        if techniques:
            rows = [['Technique', 'Evidence / confirmation']]
            for item in techniques[:40]:
                if isinstance(item, dict):
                    state = 'Unconfirmed' if item.get('confirmed') is False or item.get('unconfirmed') else 'Confirmed' if item.get('confirmed') is True else ('Checker support: '+str(item['support']) if item.get('support') is not None else 'Confirmation not recorded')
                    rows.append([f'{item.get("id", "Unknown")} / {item.get("name", "")}', f'{state}. {item.get("evidence") or item.get("description") or "No supporting text recorded"}'])
            table(rows, [width*.4, width*.6])
        else:
            story.append(p('No mapped techniques were recorded.'))
        dropped = enrichment.get('dropped_techniques') or []
        if dropped:
            story.append(p('Technique candidates rejected by the checker: '+', '.join(str(x.get('id', 'unknown')) if isinstance(x,dict) else str(x) for x in dropped[:30])))
        if a.get('iocs'):
            story.append(p('Indicators to investigate', heading))
            table([['Type', 'Observed value']] + [[x.get('type') or 'Unknown', x.get('value') or 'Not recorded'] for x in a['iocs'][:20] if isinstance(x,dict)])
        story.append(p('Recorded activity log excerpt', heading))
        summary = str(a.get('command_summary') or 'No command/activity summary was recorded.')
        summary = re.sub(r'(?i)\b(password|passwd|pwd|token|secret|api_key)\s*[:=]\s*[^\s&;]+', r'\1=[REDACTED]', summary)
        summary = re.sub(r'(?im)Authorization:[^\n]+', 'Authorization: [REDACTED]', summary)
        all_lines = summary.splitlines()
        lines = all_lines[:20]
        table([['Line', 'Stored activity summary']] + [[str(i), line[:1000] + (' [excerpt truncated]' if len(line)>1000 else '')] for i, line in enumerate(lines,1)], [45,width-45], log=True)
        if len(all_lines) > 20:
            story.append(p(f'Activity excerpt truncated: showing 20 of {len(all_lines)} stored summary lines.', small))
        story.append(p('This is a bounded excerpt of the stored summary, not a complete packet capture or decrypted credential log.', small))
        story += [p('Investigation notes', heading), p('Review the recorded activity and explanation before escalating the finding. '
                  'This download does not include stored credentials or execute captured files. It does not establish '
                  'attacker identity, successful compromise, data theft, or intent beyond the evidence recorded here.')]
    if output_format == 'docx':
        return _word_document(story, counts, now)
    doc.build(story, onFirstPage=frame, onLaterPages=frame)
    return buffer.getvalue()


def _investigation_content(story, p, table, heading, small, title, width, records, narrative, include_sensitive):
    from app.services.investigation_narrative import evidence_groups
    groups = evidence_groups(records)
    counts = Counter(a.get('category') or 'unknown' for _, a in records)
    story += [p('Investigation report', title), p('Written by our local '+str(narrative.get('model'))+' model | '+str(narrative.get('generated_at')), small)]
    if include_sensitive:
        story.append(p('ADMIN EXPORT: includes original captured activity and available captured credentials.', small))
    demos = sum(str(s.get('session_uuid','')).startswith('demo-') for s, _ in records)
    if demos:
        story.append(p(f'DEMONSTRATION DATA: {demos} selected sessions are labelled simulations, not live captures.', heading))
    story.append(p('Executive summary', heading))
    def paragraphs(value):
        for part in str(value).split('\n'):
            if part.strip(): story.append(p(part.strip()))
    paragraphs(narrative['summary'])
    scope = narrative['scope']
    table([['Investigation scope', 'Recorded value'], ['Selected sessions', len(records)],
           ['Recorded source addresses', ', '.join(sorted({s.get('attacker_ip') or 'Not recorded' for s, _ in records}))],
           ['Stored categories', '; '.join(f'{k}: {v}' for k,v in sorted(counts.items()))],
           ['AI evidence coverage', f"{scope['model_reviewed_groups']} representative activity groups of {scope['unique_activity_groups']} unique groups"],
           ['Evidence included', 'All selected sessions and activity groups are listed in the appendix below.']])
    story.append(p('What happened: findings from the captured evidence', heading))
    for i, finding in enumerate(narrative['findings'], 1):
        story.append(p(f'{i}. '+finding['title'], heading))
        paragraphs(finding['paragraph'])
        story.append(p('Evidence references: '+', '.join(finding['references']), small))
        table([['Captured evidence', 'Exact supporting excerpt'], [', '.join(finding['references']), finding['quote']]], log=True)
    story.append(p('Assessment and uncertainty', heading));paragraphs(narrative['assessment'])
    story.append(p('Recommended follow-up', heading));paragraphs(narrative['next_steps'])
    story.append(p('Scope of the model review', heading))
    story.append(p('The local model interpreted the referenced representative groups using the captured command/request excerpts supplied to it. '
                   'The complete selected-session inventory and available captured activity are preserved below. '
                   'Repeated identical activity is grouped for readability. Groups outside the stated AI coverage remain recorded evidence, not additional model conclusions. '
                   'Source addresses identify recorded network endpoints. Interpretations and attempted actions do not prove changes to a real host.'))
    story.append(PageBreak());story.append(p('Selected-session inventory', title))
    rows = [['Case', 'Session UUID', 'Source', 'Protocol', 'Started (stored time)', 'Category']]
    for g in groups:
        for s in g['sessions']:
            rows.append([g['reference'], s['uuid'], s['source'], g['protocol'], s['started_at'], g['category']])
    table(rows, [width*x for x in [.06,.25,.17,.09,.26,.17]])
    reviewed = set(narrative.get('reviewed_references') or [])
    for group in groups:
        story.append(PageBreak());story.append(p(group['reference']+' / '+str(group['protocol']).upper(), title))
        sources=sorted({s['source'] for s in group['sessions']})
        first=min(str(s['started_at']) for s in group['sessions'])
        last=max(str(s['ended_at'] or s['started_at']) for s in group['sessions'])
        table([['Evidence field', 'Recorded value'], ['Source address(es)', ', '.join(sources)],
               ['Sessions sharing this activity', len(group['sessions'])], ['First observed', first], ['Last observed', last],
               ['Stored category', group['category']], ['Captured authentication attempts', group.get('credential_attempts',0)], ['Evidence source', group.get('evidence_source','Stored activity')], ['AI review', 'Included in model evidence packet' if group['reference'] in reviewed else 'Recorded in appendix; not model-interpreted in this report']])
        if all(str(s['uuid']).startswith('demo-') for s in group['sessions']):story.append(p('SIMULATED DEMONSTRATION: prepared fixture data; no attack commands were executed.', heading))
        if group.get('rule_reason'):story.append(p('Stored rule evidence: '+str(group['rule_reason'])))
        story.append(p('Captured command / request evidence', heading))
        commands=str(group['commands'] or 'No command/request text recorded.')
        if not include_sensitive:
            from app.services.investigation_narrative import redact
            commands=redact(commands)
        lines=commands.splitlines();shown=lines[:40]
        table([['Line', 'Captured command / request']] + [[f"{group['reference']}.{i}", line[:1000]+(' [line shortened]' if len(line)>1000 else '')] for i,line in enumerate(shown,1)], [58,width-58], log=True)
        if len(lines)>40:story.append(p(f'Excerpt shortened: showing 40 of {len(lines)} captured activity lines.', small))
        for s in group['sessions']:
            if s.get('evidence_error'):story.append(p(f"Session {s['uuid']}: {s['evidence_error']}", small))
        if group.get('iocs'):
            story.append(p('Recorded indicators', heading))
            table([['Type', 'Observed value']] + [[x.get('type'),x.get('value')] for x in group['iocs'][:40]])
            if len(group['iocs'])>40:story.append(p('Indicator excerpt shortened to the first 40 values.', small))
        if include_sensitive:
            credential_rows=[['Session / source', 'Username', 'Captured password', 'Recorded result']]
            total=0
            for s in group['sessions']:
                total+=s.get('credentials_total',0)
                for c in s.get('credentials') or []:
                    if len(credential_rows)<=100:
                        credential_rows.append([str(s['uuid'])+' / '+str(s['source']),c.get('username',''),c.get('password',''),str(c.get('success',c.get('accepted','Not recorded')))])
                if s.get('credential_error'):story.append(p(f"Session {s['uuid']}: {s['credential_error']}",small))
            if len(credential_rows)>1:
                story.append(p('Captured credential evidence (admin)', heading))
                table(credential_rows,[width*x for x in [.38,.18,.26,.18]])
                if total>len(credential_rows)-1:story.append(p(f'Credential excerpt: {len(credential_rows)-1} of {total} recorded attempts shown for this case.',small))
    story.append(p('Report provenance', heading))
    story.append(p('Narrative model: '+str(narrative.get('model'))+'. Generated: '+str(narrative.get('generated_at'))+'. '
                   'Finding references and quoted excerpts were checked against the selected model evidence packet. '
                   'This check verifies citation and quotation consistency; it does not independently prove every model interpretation. '+
                   ('Original captured credentials are included for this authorised admin export.' if include_sensitive else 'Captured credential values are omitted from this analyst export.'),small))


def _word_document(story, counts, stamp):
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from PIL import Image, ImageDraw, ImageFont
    from reportlab.platypus import PageBreak as Break
    d = Document()
    section = d.sections[0]
    section.page_width, section.page_height = Inches(8.27), Inches(11.69)
    section.top_margin, section.bottom_margin = Inches(.85), Inches(.7)
    section.left_margin = section.right_margin = Inches(.65)
    normal = d.styles['Normal']
    normal.font.name, normal.font.size = 'Arial', Pt(10)
    normal.paragraph_format.line_spacing = 1.15
    normal.paragraph_format.space_after = Pt(8)
    for name, size in [('Title',26),('Heading 1',14)]:
        d.styles[name].font.name='Arial'
        d.styles[name].font.size=Pt(size)
        d.styles[name].font.color.rgb=RGBColor.from_string('101014')
        properties=d.styles[name].element.get_or_add_pPr()
        borders=OxmlElement('w:pBdr')
        for edge in ['top','left','bottom','right','between']:
            border=OxmlElement('w:'+edge);border.set(qn('w:val'),'nil');borders.append(border)
        properties.append(borders)
    def shade(cell, color):
        item=OxmlElement('w:shd');item.set(qn('w:fill'),color)
        cell._tc.get_or_add_tcPr().append(item)
    def picture_logo():
        image=Image.new('RGBA',(240,240),(0,0,0,0));draw=ImageDraw.Draw(image)
        outer=[(x*10,y*10) for x,y in [(12,2.4),(20.8,7.2),(20.8,16.8),(12,21.6),(3.2,16.8),(3.2,7.2)]]
        inner=[(x*10,y*10) for x,y in [(12,8),(16.4,10.4),(16.4,15.2),(12,17.6),(7.6,15.2),(7.6,10.4)]]
        draw.line(outer+[outer[0]],fill='#f2f0ea',width=13,joint='curve');draw.polygon(inner,fill='#f2f0ea')
        image_buffer=BytesIO();image.save(image_buffer,format='PNG');image_buffer.seek(0)
        return image_buffer
    header=section.header.add_table(rows=1,cols=2,width=Inches(6.97))
    for cell in header.rows[0].cells:shade(cell,'101014')
    paragraph=header.cell(0,0).paragraphs[0]
    paragraph.add_run().add_picture(picture_logo(),width=Inches(.35))
    run=paragraph.add_run('  HoneySentinel AI');run.bold=True;run.font.color.rgb=RGBColor.from_string('F2F0EA')
    run=header.cell(0,1).paragraphs[0].add_run('INVESTIGATION REPORT\n'+stamp)
    run.font.size=Pt(8);run.font.color.rgb=RGBColor.from_string('F2F0EA')
    footer=section.footer.paragraphs[0]
    footer.add_run('Sensitive security telemetry | Authorised analyst export | Page ').font.size=Pt(8)
    field=OxmlElement('w:fldSimple');field.set(qn('w:instr'),'PAGE');footer._p.append(field)
    def plain(paragraph):
        return ''.join('\n' if getattr(frag, 'lineBreak', False) else getattr(frag, 'text', '') for frag in paragraph.frags)
    for item in story:
        if isinstance(item, Paragraph):
            value=plain(item)
            style='Title' if item.style.name=='title' else 'Heading 1' if item.style.name=='heading' else 'Normal'
            d.add_paragraph(value,style)
        elif isinstance(item, Break):d.add_page_break()
        elif isinstance(item, Table):
            rows=item._cellvalues
            table=d.add_table(rows=0,cols=len(rows[0]));table.style='Table Grid'
            for i,row in enumerate(rows):
                cells=table.add_row().cells
                for cell,value in zip(cells,row):
                    cell.text=plain(value) if isinstance(value,Paragraph) else str(value)
                    shade(cell,'101014' if i==0 else 'F2F0EA' if i%2==0 else 'FFFFFF')
                    for run in cell.paragraphs[0].runs:
                        run.font.size=Pt(9)
                        if isinstance(value,Paragraph) and value.style.fontName=='Courier':
                            run.font.name='Courier New';run.font.size=Pt(8)
                        if i==0:run.bold=True;run.font.color.rgb=RGBColor.from_string('F2F0EA')
                if i==0:
                    repeat=OxmlElement('w:tblHeader');table.rows[0]._tr.get_or_add_trPr().append(repeat)
        elif isinstance(item, Drawing) and counts:
            image=Image.new('RGB',(1200,70*len(counts)+30),'white');draw=ImageDraw.Draw(image)
            chart_font=ImageFont.truetype(str(Path(reportlab.__file__).parent/'fonts/Vera.ttf'),28)
            for i,(category,count) in enumerate(sorted(counts.items())):
                y=20+i*70;draw.text((5,y),category.title(),fill='#101014',font=chart_font)
                draw.rectangle((340,y,340+int(730*count/sum(counts.values())),y+30),fill=RAMP.get(category,'#7d7c86'))
                draw.text((1100,y),str(count),fill='#101014',font=chart_font)
            image_buffer=BytesIO();image.save(image_buffer,format='PNG');image_buffer.seek(0)
            d.add_picture(image_buffer,width=Inches(6.5))
    d.core_properties.author='HoneySentinel AI'
    d.core_properties.title='HoneySentinel AI Investigation Report'
    d.core_properties.last_modified_by='HoneySentinel AI'
    output=BytesIO();d.save(output);return output.getvalue()
