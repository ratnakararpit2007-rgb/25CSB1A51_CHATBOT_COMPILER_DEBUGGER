"""
Compile PROJECT_DOCUMENTATION_PAPER.md into:
1. Multi_Language_Compiler_Debugger_Documentation.docx (python-docx)
2. Multi_Language_Compiler_Debugger_Documentation.pdf (reportlab)
"""

import os
import re
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
)
from reportlab.pdfgen import canvas

MD_PATH = "/Users/arpit/toa_project/PROJECT_DOCUMENTATION_PAPER.md"
DOCX_OUT = "/Users/arpit/toa_project/Multi_Language_Compiler_Debugger_Documentation.docx"
PDF_OUT = "/Users/arpit/toa_project/Multi_Language_Compiler_Debugger_Documentation.pdf"


def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{fill_hex}"/>')
    tcPr.append(shd)


def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)


def build_docx(md_text):
    print("Generating DOCX...")
    doc = Document()

    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(10.5)
    normal_style.font.color.rgb = RGBColor(30, 30, 30)

    lines = md_text.split('\n')
    i = 0
    in_code_block = False
    code_lines = []

    while i < len(lines):
        line = lines[i]

        if line.strip().startswith('```'):
            if in_code_block:
                in_code_block = False
                code_text = '\n'.join(code_lines)
                code_lines = []
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Inches(0.25)
                p.paragraph_format.right_indent = Inches(0.25)
                p.paragraph_format.space_before = Pt(4)
                p.paragraph_format.space_after = Pt(6)
                run = p.add_run(code_text)
                run.font.name = 'Courier New'
                run.font.size = Pt(8.5)
                run.font.color.rgb = RGBColor(40, 40, 40)
            else:
                in_code_block = True
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        if line.strip().startswith('|') and '|' in line[1:]:
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                table_lines.append(lines[i].strip())
                i += 1
            
            rows_data = []
            for tl in table_lines:
                cells = [c.strip() for c in tl.split('|')[1:-1]]
                if all(re.match(r'^:?-+:?$', c) for c in cells if c):
                    continue
                rows_data.append(cells)
            
            if rows_data:
                num_cols = max(len(r) for r in rows_data)
                norm_rows = [r + [''] * (num_cols - len(r)) for r in rows_data]
                
                table = doc.add_table(rows=len(norm_rows), cols=num_cols)
                table.alignment = WD_TABLE_ALIGNMENT.CENTER
                table.autofit = True

                for r_idx, row_cells in enumerate(norm_rows):
                    for c_idx, cell_value in enumerate(row_cells):
                        cell = table.cell(r_idx, c_idx)
                        set_cell_margins(cell, top=100, bottom=100, left=120, right=120)
                        cp = cell.paragraphs[0]
                        cp.paragraph_format.space_before = Pt(2)
                        cp.paragraph_format.space_after = Pt(2)
                        
                        clean_text = cell_value.replace('**', '').replace('`', '')
                        c_run = cp.add_run(clean_text)
                        c_run.font.name = 'Times New Roman'
                        
                        if r_idx == 0:
                            set_cell_background(cell, 'EAEAEA')
                            c_run.font.bold = True
                            c_run.font.size = Pt(9.5)
                            cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        else:
                            if r_idx % 2 == 1:
                                set_cell_background(cell, 'F9F9F9')
                            else:
                                set_cell_background(cell, 'FFFFFF')
                            c_run.font.size = Pt(9)
                            cp.alignment = WD_ALIGN_PARAGRAPH.LEFT
                
                sp = doc.add_paragraph()
                sp.paragraph_format.space_after = Pt(6)
            continue

        if line.strip().startswith('!['):
            m = re.match(r'!\[(.*?)\]\((.*?)\)', line.strip())
            if m:
                img_path = m.group(2).strip()
                if os.path.exists(img_path):
                    p = doc.add_paragraph()
                    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p.paragraph_format.space_before = Pt(8)
                    p.paragraph_format.space_after = Pt(4)
                    run = p.add_run()
                    run.add_picture(img_path, width=Inches(6.2))
            i += 1
            continue

        if line.startswith('# '):
            title_text = line[2:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(12)
            p.paragraph_format.space_after = Pt(6)
            run = p.add_run(title_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(18)
            run.font.bold = True
            run.font.color.rgb = RGBColor(20, 20, 80)
            i += 1
            continue

        if line.startswith('## '):
            heading_text = line[3:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(16)
            p.paragraph_format.space_after = Pt(6)
            p.paragraph_format.keep_with_next = True
            
            run = p.add_run(heading_text.upper())
            run.font.name = 'Times New Roman'
            run.font.size = Pt(12)
            run.font.bold = True
            run.font.underline = True
            run.font.color.rgb = RGBColor(0, 0, 0)
            i += 1
            continue

        if line.startswith('### '):
            sub_text = line[4:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(sub_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(11)
            run.font.bold = True
            run.font.color.rgb = RGBColor(30, 30, 30)
            i += 1
            continue

        if line.startswith('#### '):
            sub_sub_text = line[5:].strip()
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(8)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.keep_with_next = True
            run = p.add_run(sub_sub_text)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(10.5)
            run.font.bold = True
            run.font.italic = True
            run.font.color.rgb = RGBColor(40, 40, 40)
            i += 1
            continue

        if line.strip() == '---':
            i += 1
            continue

        stripped = line.strip()
        if not stripped:
            i += 1
            continue

        if stripped.startswith('**TABLE ') or stripped.startswith('**Figure '):
            p = doc.add_paragraph()
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(10)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.keep_with_next = True
            caption_clean = stripped.replace('**', '')
            run = p.add_run(caption_clean)
            run.font.name = 'Times New Roman'
            run.font.size = Pt(9.5)
            run.font.bold = True
            i += 1
            continue

        if stripped.startswith('**Authors:**') or stripped.startswith('**Project Guide:**') or stripped.startswith('**Department') or stripped.startswith('**Date:**'):
            p = doc.add_paragraph()
            p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            clean_meta = stripped.replace('**', '')
            parts = clean_meta.split(':', 1)
            if len(parts) == 2:
                r1 = p.add_run(parts[0] + ':')
                r1.font.bold = True
                r1.font.size = Pt(10)
                r2 = p.add_run(parts[1])
                r2.font.size = Pt(10)
            else:
                r = p.add_run(clean_meta)
                r.font.size = Pt(10)
            i += 1
            continue

        p = doc.add_paragraph()
        p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(5)
        p.paragraph_format.line_spacing = 1.15

        tokens = re.split(r'(\*\*.*?\*\*|\*.*?\*|`.*?`)', line)
        for token in tokens:
            if not token:
                continue
            if token.startswith('**') and token.endswith('**'):
                r = p.add_run(token[2:-2])
                r.font.bold = True
            elif token.startswith('*') and token.endswith('*'):
                r = p.add_run(token[1:-1])
                r.font.italic = True
            elif token.startswith('`') and token.endswith('`'):
                r = p.add_run(token[1:-1])
                r.font.name = 'Courier New'
                r.font.size = Pt(9.5)
            else:
                r = p.add_run(token)

        i += 1

    doc.save(DOCX_OUT)
    print(f"DOCX successfully saved to {DOCX_OUT}")


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        self.saveState()
        self.setFont("Times-Roman", 8.5)
        self.setFillColor(colors.HexColor("#555555"))

        if self._pageNumber > 1:
            self.drawString(54, 755, "Multi-Language Compiler Debugger: Research Documentation")
            self.setStrokeColor(colors.HexColor("#CCCCCC"))
            self.setLineWidth(0.5)
            self.line(54, 750, 558, 750)

        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, page_str)
        self.drawString(54, 36, "Academic Research Documentation — Compiler Design")
        self.setStrokeColor(colors.HexColor("#CCCCCC"))
        self.setLineWidth(0.5)
        self.line(54, 46, 558, 46)
        self.restoreState()


def format_to_reportlab(text):
    # Escape XML entities first
    t = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    # 1. Extract and protect code spans first
    code_spans = []
    def save_code(m):
        code_spans.append(m.group(1))
        return f"___CODE_SPAN_{len(code_spans)-1}___"
    
    t = re.sub(r'`(.*?)`', save_code, t)

    # 2. Bold: **text**
    t = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', t)
    
    # 3. Italic: *text* (word-boundary aware)
    t = re.sub(r'(?<!\w)\*([^\*\n]+?)\*(?!\w)', r'<i>\1</i>', t)
    
    # 4. Restore code spans
    for idx, c in enumerate(code_spans):
        t = t.replace(f"___CODE_SPAN_{idx}___", f'<font name="Courier" size="8">{c}</font>')
    
    # Strip literal math $ markers for clean text
    t = t.replace('$', '')
    return t


def build_pdf(md_text):
    print("Generating PDF...")
    doc = SimpleDocTemplate(
        PDF_OUT,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Times-Bold',
        fontSize=16,
        leading=21,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#111827'),
        spaceAfter=10
    )

    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Times-Roman',
        fontSize=9.5,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#374151'),
        spaceAfter=3
    )

    h1_style = ParagraphStyle(
        'DocH1',
        parent=styles['Normal'],
        fontName='Times-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#000000'),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'DocH2',
        parent=styles['Normal'],
        fontName='Times-Bold',
        fontSize=10.5,
        leading=14,
        textColor=colors.HexColor('#1f2937'),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        'DocH3',
        parent=styles['Normal'],
        fontName='Times-BoldItalic',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor('#374151'),
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontName='Times-Roman',
        fontSize=9.5,
        leading=13.5,
        alignment=TA_JUSTIFY,
        textColor=colors.HexColor('#1f2937'),
        spaceAfter=5
    )

    caption_style = ParagraphStyle(
        'DocCaption',
        parent=styles['Normal'],
        fontName='Times-Bold',
        fontSize=9,
        leading=12,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#111827'),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    code_style = ParagraphStyle(
        'DocCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=9,
        textColor=colors.HexColor('#1e293b')
    )

    story = []
    lines = md_text.split('\n')
    i = 0
    in_code_block = False
    code_lines = []

    while i < len(lines):
        line = lines[i]

        if line.strip().startswith('```'):
            if in_code_block:
                in_code_block = False
                code_text = '\n'.join(code_lines)
                code_lines = []
                p_code = Preformatted(code_text, code_style)
                t_code = Table([[p_code]], colWidths=[504])
                t_code.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
                    ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('RIGHTPADDING', (0,0), (-1,-1), 8),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(t_code)
                story.append(Spacer(1, 4))
            else:
                in_code_block = True
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        if line.strip().startswith('|') and '|' in line[1:]:
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                table_lines.append(lines[i].strip())
                i += 1
            
            rows_data = []
            for tl in table_lines:
                cells = [c.strip() for c in tl.split('|')[1:-1]]
                if all(re.match(r'^:?-+:?$', c) for c in cells if c):
                    continue
                rows_data.append(cells)
            
            if rows_data:
                num_cols = max(len(r) for r in rows_data)
                col_width = 504.0 / num_cols
                
                table_content = []
                for r_idx, r in enumerate(rows_data):
                    padded_r = r + [''] * (num_cols - len(r))
                    row_content = []
                    for c_idx, c_val in enumerate(padded_r):
                        clean_c = format_to_reportlab(c_val)
                        if r_idx == 0:
                            p_cell = Paragraph(f"<b>{clean_c}</b>", ParagraphStyle('TH', parent=body_style, fontSize=7.5, leading=9.5, alignment=TA_CENTER))
                        else:
                            p_cell = Paragraph(clean_c, ParagraphStyle('TD', parent=body_style, fontSize=7, leading=9, alignment=TA_LEFT))
                        row_content.append(p_cell)
                    table_content.append(row_content)
                
                t = Table(table_content, colWidths=[col_width]*num_cols, repeatRows=1)
                t_style = [
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#e2e8f0')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#0f172a')),
                    ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                    ('LEFTPADDING', (0,0), (-1,-1), 3),
                    ('RIGHTPADDING', (0,0), (-1,-1), 3),
                ]
                for r_i in range(1, len(rows_data)):
                    if r_i % 2 == 1:
                        t_style.append(('BACKGROUND', (0, r_i), (-1, r_i), colors.HexColor('#f8fafc')))
                    else:
                        t_style.append(('BACKGROUND', (0, r_i), (-1, r_i), colors.white))
                t.setStyle(TableStyle(t_style))
                story.append(t)
                story.append(Spacer(1, 6))
            continue

        if line.strip() == '---':
            story.append(Spacer(1, 6))
            i += 1
            continue

        stripped = line.strip()
        if not stripped:
            i += 1
            continue

        if line.strip().startswith('!['):
            m = re.match(r'!\[(.*?)\]\((.*?)\)', line.strip())
            if m:
                img_path = m.group(2).strip()
                if os.path.exists(img_path):
                    from reportlab.platypus import Image as RLImage
                    from PIL import Image as PILImage
                    with PILImage.open(img_path) as p_img:
                        w, h = p_img.size
                        aspect = h / w
                    img_w = 504.0
                    img_h = min(504.0 * aspect, 280.0)
                    story.append(RLImage(img_path, width=img_w, height=img_h))
                    story.append(Spacer(1, 4))
            i += 1
            continue

        if line.startswith('# '):
            story.append(Paragraph(format_to_reportlab(line[2:].strip()), title_style))
            i += 1
            continue

        if line.startswith('## '):
            h_text = line[3:].strip().upper()
            story.append(Paragraph(f"<u><b>{format_to_reportlab(h_text)}</b></u>", h1_style))
            i += 1
            continue

        if line.startswith('### '):
            story.append(Paragraph(f"<b>{format_to_reportlab(line[4:].strip())}</b>", h2_style))
            i += 1
            continue

        if line.startswith('#### '):
            story.append(Paragraph(f"<i><b>{format_to_reportlab(line[5:].strip())}</b></i>", h3_style))
            i += 1
            continue

        if stripped.startswith('**TABLE ') or stripped.startswith('**Figure '):
            clean_cap = format_to_reportlab(stripped.replace('**', ''))
            story.append(Paragraph(f"<b>{clean_cap}</b>", caption_style))
            i += 1
            continue

        if stripped.startswith('**Authors:**') or stripped.startswith('**Project Guide:**') or stripped.startswith('**Department') or stripped.startswith('**Date:**'):
            formatted_m = format_to_reportlab(stripped)
            story.append(Paragraph(formatted_m, meta_style))
            i += 1
            continue

        formatted = format_to_reportlab(line)
        story.append(Paragraph(formatted, body_style))
        i += 1

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully saved to {PDF_OUT}")


def main():
    if not os.path.exists(MD_PATH):
        print(f"Error: {MD_PATH} does not exist.")
        sys.exit(1)
    with open(MD_PATH, 'r', encoding='utf-8') as f:
        md_text = f.read()

    build_docx(md_text)
    build_pdf(md_text)
    print("Compilation completed.")


if __name__ == '__main__':
    main()
