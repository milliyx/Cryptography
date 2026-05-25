"""
generate_pptx.py
================
Genera la presentación final SDDV (Equipo 7) en formato PPTX
con estética "Midnight Pitch" — dark mode + acentos vibrantes.

Uso:
    python3 generate_pptx.py
    # → Final_Presentation.pptx
"""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.oxml.ns import qn
from lxml import etree

# ============================================================================
# PALETA "MIDNIGHT PITCH"
# ============================================================================
BG_DARK    = RGBColor(0x0F, 0x14, 0x19)
BG_CARD    = RGBColor(0x1A, 0x21, 0x29)
BG_CARD2   = RGBColor(0x23, 0x2B, 0x36)
TEXT_MAIN  = RGBColor(0xE8, 0xEE, 0xF2)
TEXT_MUTED = RGBColor(0x8B, 0x96, 0xA3)
ACCENT     = RGBColor(0x00, 0xE5, 0xA8)
ACCENT_DK  = RGBColor(0x00, 0xB3, 0x88)
CORAL      = RGBColor(0xFF, 0x6B, 0x6B)
INDIGO     = RGBColor(0x6C, 0x8E, 0xFF)
AMBER      = RGBColor(0xFF, 0xD1, 0x66)

# 16:9 dimensions
SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)

FONT = "Helvetica Neue"
FONT_MONO = "Menlo"


# ============================================================================
# HELPERS
# ============================================================================
def make_pres():
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H
    return prs


def add_dark_slide(prs):
    """Agrega slide en blanco con fondo oscuro."""
    blank = prs.slide_layouts[6]
    slide = prs.slides.add_slide(blank)
    bg = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, SLIDE_H
    )
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG_DARK
    bg.line.fill.background()
    bg.shadow.inherit = False
    return slide


def add_text(slide, x, y, w, h, text, font_size=18, color=TEXT_MAIN,
             bold=False, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP,
             font_name=FONT, italic=False):
    """Agrega un cuadro de texto con formato."""
    tx = slide.shapes.add_textbox(x, y, w, h)
    tf = tx.text_frame
    tf.word_wrap = True
    tf.margin_left = Emu(0)
    tf.margin_right = Emu(0)
    tf.margin_top = Emu(0)
    tf.margin_bottom = Emu(0)
    tf.vertical_anchor = anchor
    # primera línea(s)
    if isinstance(text, str):
        lines = text.split("\n")
    else:
        lines = text
    first = True
    for line in lines:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        p.alignment = align
        run = p.add_run()
        run.text = line
        run.font.name = font_name
        run.font.size = Pt(font_size)
        run.font.bold = bold
        run.font.italic = italic
        run.font.color.rgb = color
    return tx


def add_card(slide, x, y, w, h, fill=BG_CARD, border=None, border_w=1.0):
    """Agrega un rectángulo redondeado tipo card."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    card.fill.solid()
    card.fill.fore_color.rgb = fill
    if border:
        card.line.color.rgb = border
        card.line.width = Pt(border_w)
    else:
        card.line.fill.background()
    card.shadow.inherit = False
    # rounded corner ratio
    card.adjustments[0] = 0.08
    # quitar el texto default
    card.text_frame.text = ""
    return card


def add_pill(slide, x, y, text, fill=ACCENT, font_color=BG_DARK, font_size=10):
    """Agrega un pill/chip pequeño."""
    # ancho aproximado por número de chars
    w = Inches(0.08 * len(text) + 0.4)
    h = Inches(0.3)
    pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    pill.fill.solid()
    pill.fill.fore_color.rgb = fill
    pill.line.fill.background()
    pill.adjustments[0] = 0.5  # max rounded
    tf = pill.text_frame
    tf.margin_left = Emu(0); tf.margin_right = Emu(0)
    tf.margin_top = Emu(0); tf.margin_bottom = Emu(0)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = text
    r.font.name = FONT
    r.font.size = Pt(font_size)
    r.font.bold = True
    r.font.color.rgb = font_color
    return pill, w


def add_progress_bar(slide, current, total):
    """Barra de progreso en la parte superior (estilo Metropolis)."""
    bar_h = Inches(0.06)
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, SLIDE_W, bar_h)
    bg.fill.solid()
    bg.fill.fore_color.rgb = BG_CARD
    bg.line.fill.background()
    bg.shadow.inherit = False

    pct = current / total
    w = int(SLIDE_W * pct)
    fg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, w, bar_h)
    fg.fill.solid()
    fg.fill.fore_color.rgb = ACCENT
    fg.line.fill.background()
    fg.shadow.inherit = False


def add_footer(slide, current, total, section=""):
    """Footer con número de página y sección."""
    add_text(slide, Inches(0.5), Inches(7.15), Inches(8), Inches(0.3),
             section, font_size=9, color=TEXT_MUTED, italic=True)
    add_text(slide, Inches(11.5), Inches(7.15), Inches(1.5), Inches(0.3),
             f"{current} / {total}", font_size=9, color=TEXT_MUTED,
             align=PP_ALIGN.RIGHT)


# ============================================================================
# SLIDES
# ============================================================================
def slide_title(prs):
    s = add_dark_slide(prs)
    # bloque decorativo lateral
    bar = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                             0, 0, Inches(0.25), SLIDE_H)
    bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background(); bar.shadow.inherit = False

    add_text(s, Inches(0.8), Inches(1.8), Inches(11.5), Inches(1.5),
             "Secure Digital Document Vault",
             font_size=54, color=TEXT_MAIN, bold=True)
    add_text(s, Inches(0.8), Inches(3.2), Inches(11.5), Inches(0.7),
             "Final Presentation · Equipo 7",
             font_size=24, color=ACCENT)
    add_text(s, Inches(0.8), Inches(4.2), Inches(11.5), Inches(0.5),
             "Barrios Aguilar · Caballero Martínez · Contreras Colmenero · Martínez López",
             font_size=14, color=TEXT_MUTED)
    add_text(s, Inches(0.8), Inches(6.5), Inches(11.5), Inches(0.5),
             "Criptografía · Dra. Rocío Aldeco Pérez · UNAM 2026-2 · Mayo 2026",
             font_size=11, color=TEXT_MUTED)


def slide_section(prs, num, title, current, total):
    s = add_dark_slide(prs)
    add_progress_bar(s, current, total)
    add_text(s, Inches(0.8), Inches(2.8), Inches(11), Inches(1),
             f"Sección {num}", font_size=18, color=TEXT_MUTED, italic=True)
    add_text(s, Inches(0.8), Inches(3.4), Inches(11.5), Inches(2),
             title, font_size=60, color=ACCENT, bold=True)


def slide_frame(prs, title, current, total, section=""):
    """Slide vacía con título + footer. Devuelve la slide."""
    s = add_dark_slide(prs)
    add_progress_bar(s, current, total)
    # Frame title
    add_text(s, Inches(0.5), Inches(0.35), Inches(12), Inches(0.6),
             title, font_size=22, color=ACCENT, bold=True)
    # Subtle separator
    sep = s.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                             Inches(0.5), Inches(1.05), Inches(12.3), Inches(0.02))
    sep.fill.solid(); sep.fill.fore_color.rgb = BG_CARD
    sep.line.fill.background(); sep.shadow.inherit = False
    add_footer(s, current, total, section)
    return s


# ----- contenido específico --------------------------------------------------

def slide_problem(prs, c, t):
    s = slide_frame(prs, "El problema", c, t, "1 · System Overview")
    add_text(s, Inches(0.5), Inches(1.6), Inches(12.3), Inches(1.5),
             "Hoy enviamos archivos sensibles\npor canales que no garantizan nada.",
             font_size=36, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    # 3 cards
    cw = Inches(3.7); cy = Inches(4.2); ch = Inches(1.8)
    for i, (label, sub) in enumerate([
        ("Correo", "Sin confidencialidad\nni autenticidad"),
        ("Drive / Dropbox", "El proveedor puede\nleer los archivos"),
        ("WhatsApp", "Cifrado limitado, sin firma\nverificable por terceros"),
    ]):
        cx = Inches(0.6 + i * 4.05)
        add_card(s, cx, cy, cw, ch)
        add_text(s, cx, cy + Inches(0.25), cw, Inches(0.6),
                 label, font_size=22, color=CORAL, bold=True,
                 align=PP_ALIGN.CENTER)
        add_text(s, cx, cy + Inches(0.95), cw, Inches(0.8),
                 sub, font_size=12, color=TEXT_MAIN,
                 align=PP_ALIGN.CENTER)


def slide_propuesta(prs, c, t):
    s = slide_frame(prs, "Nuestra propuesta", c, t, "1 · System Overview")
    # 3 lines hero
    add_text(s, Inches(0.5), Inches(2.0), Inches(12.3), Inches(0.9),
             "La seguridad", font_size=44, color=TEXT_MAIN, bold=True,
             align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(3.0), Inches(12.3), Inches(0.9),
             "no se confía,", font_size=44, color=ACCENT, bold=True,
             align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(4.0), Inches(12.3), Inches(0.9),
             "se demuestra.", font_size=44, color=TEXT_MAIN, bold=True,
             align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(5.4), Inches(12.3), Inches(0.5),
             "Con criptografía formal, no con promesas.",
             font_size=16, color=TEXT_MUTED, italic=True, align=PP_ALIGN.CENTER)


def slide_que_construimos(prs, c, t):
    s = slide_frame(prs, "¿Qué construimos?", c, t, "1 · System Overview")
    add_text(s, Inches(0.5), Inches(1.4), Inches(12.3), Inches(0.7),
             "SDDV — Secure Digital Document Vault",
             font_size=28, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(2.1), Inches(12.3), Inches(0.5),
             "CLI en Python para almacenar y compartir archivos de forma segura",
             font_size=14, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    # 3 stat cards
    for i, (n, lbl) in enumerate([("300", "tests verdes"),
                                   ("32",  "commits"),
                                   ("7",   "vulns resueltas")]):
        cx = Inches(2.0 + i * 3.3); cy = Inches(3.2); cw = Inches(2.8); ch = Inches(2.2)
        add_card(s, cx, cy, cw, ch)
        add_text(s, cx, cy + Inches(0.4), cw, Inches(1.2),
                 n, font_size=64, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
        add_text(s, cx, cy + Inches(1.6), cw, Inches(0.5),
                 lbl, font_size=12, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    # pills
    px = Inches(2.0); py = Inches(6.0)
    for label, col in [("D2 · AEAD", ACCENT),
                       ("D3 · Híbrido", INDIGO),
                       ("D5 · Firma", AMBER),
                       ("D6 · Keystore", CORAL)]:
        _, w = add_pill(s, px, py, label, fill=col, font_color=BG_DARK, font_size=11)
        px += w + Inches(0.15)


def slide_arquitectura(prs, c, t):
    s = slide_frame(prs, "Arquitectura por capas", c, t, "1 · System Overview")
    layers = [
        ("Aplicación · CLI python -m crypto", False),
        ("Composición · secure_send.py", True),
        ("Firma · Ed25519 sobre SDDH", False),
        ("Híbrido · X25519 KEM + AEAD DEM", False),
        ("Simétrico · AES-256-GCM / ChaCha20-Poly1305", False),
        ("Llaves · scrypt + AES-GCM", True),
    ]
    cx = Inches(2.5); cw = Inches(8.3); ch = Inches(0.55)
    for i, (text, trust) in enumerate(layers):
        cy = Inches(1.5 + i * 0.75)
        if trust:
            add_card(s, cx, cy, cw, ch, fill=BG_CARD2, border=ACCENT, border_w=1.5)
            color = ACCENT
            font = 14
            bold = True
            # "confiable" badge
            add_text(s, cx + cw + Inches(0.15), cy, Inches(1.5), ch,
                     "confiable", font_size=10, color=ACCENT, italic=True,
                     anchor=MSO_ANCHOR.MIDDLE)
        else:
            add_card(s, cx, cy, cw, ch, fill=BG_CARD)
            color = TEXT_MAIN
            font = 13
            bold = False
        add_text(s, cx + Inches(0.2), cy, cw, ch,
                 text, font_size=font, color=color, bold=bold,
                 anchor=MSO_ANCHOR.MIDDLE)
    add_text(s, Inches(0.5), Inches(6.5), Inches(12.3), Inches(0.4),
             "Almacenamiento, red y contenedores cifrados se consideran no confiables.",
             font_size=11, color=CORAL, italic=True, align=PP_ALIGN.CENTER)


def slide_activos(prs, c, t):
    s = slide_frame(prs, "Activos a proteger", c, t, "2 · Threat Model")
    items = [
        ("Contenido del archivo", "Información sensible → AEAD (D2)"),
        ("Metadatos",              "Filename, timestamp → AAD del DEM"),
        ("Llaves privadas",        "Ed25519 + X25519 → scrypt + AES-GCM"),
        ("Passwords",              "Solo en memoria · longitud mín. 12"),
        ("Firmas digitales",       "No-repudio → Ed25519 (RFC 8032)"),
        ("Nonces AEAD",            "Reuso = catastrófico → CSPRNG"),
    ]
    cw = Inches(5.8); ch = Inches(1.3)
    for i, (titulo, desc) in enumerate(items):
        col = i % 2
        row = i // 2
        cx = Inches(0.7 + col * 6.1)
        cy = Inches(1.4 + row * 1.55)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=ACCENT, border_w=1)
        add_text(s, cx + Inches(0.25), cy + Inches(0.15), cw, Inches(0.5),
                 titulo, font_size=15, color=ACCENT, bold=True)
        add_text(s, cx + Inches(0.25), cy + Inches(0.65), cw, Inches(0.6),
                 desc, font_size=11, color=TEXT_MAIN)


def slide_adversarios(prs, c, t):
    s = slide_frame(prs, "Adversarios considerados", c, t, "2 · Threat Model")
    advs = [
        ("ADV-1", "Externo",                "Lee y modifica contenedores",      ACCENT, False),
        ("ADV-2", "Destinatario malicioso", "Lee su archivo legítimamente",     ACCENT, False),
        ("ADV-3", "Man-in-the-Middle",      "Sustituye pubkeys",                 ACCENT, False),
        ("ADV-4", "Acceso físico",          "Copia el keystore",                 ACCENT, False),
        ("ADV-5", "Fuerza bruta offline",   "Prueba passwords",                  ACCENT, False),
        ("ADV-6", "Dispositivo comprometido","Keylogger, RAM dump · fuera de scope", CORAL, True),
    ]
    cw = Inches(5.8); ch = Inches(1.3)
    for i, (pid, titulo, desc, color, danger) in enumerate(advs):
        col = i % 2; row = i // 2
        cx = Inches(0.7 + col * 6.1); cy = Inches(1.4 + row * 1.55)
        border = CORAL if danger else None
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=border, border_w=1)
        _, pw = add_pill(s, cx + Inches(0.25), cy + Inches(0.2), pid,
                         fill=color, font_color=BG_DARK, font_size=10)
        add_text(s, cx + Inches(0.25) + pw + Inches(0.2), cy + Inches(0.2),
                 cw, Inches(0.4), titulo, font_size=14, color=TEXT_MAIN, bold=True,
                 anchor=MSO_ANCHOR.MIDDLE)
        add_text(s, cx + Inches(0.25), cy + Inches(0.75), cw, Inches(0.5),
                 desc, font_size=11, color=TEXT_MAIN if not danger else CORAL)


def slide_asunciones(prs, c, t):
    s = slide_frame(prs, "Asunciones explícitas", c, t, "2 · Threat Model")
    add_text(s, Inches(0.5), Inches(1.8), Inches(12.3), Inches(1.2),
             "Lo que SDDV asume\ndel entorno",
             font_size=40, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    items = [
        "CSPRNG del SO es seguro",
        "Pubkeys distribuidas auténticamente",
        "Usuario elige passwords fuertes",
        "Sin malware en ejecución",
    ]
    cw = Inches(5.8); ch = Inches(1.0)
    for i, txt in enumerate(items):
        col = i % 2; row = i // 2
        cx = Inches(0.7 + col * 6.1); cy = Inches(4.3 + row * 1.15)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD)
        add_text(s, cx + Inches(0.25), cy, cw, ch,
                 "● " + txt, font_size=14, color=TEXT_MAIN,
                 anchor=MSO_ANCHOR.MIDDLE)


def slide_d2_algos(prs, c, t):
    s = slide_frame(prs, "Selección del algoritmo", c, t, "3 · D2 — AEAD")
    # 2 cards lado a lado
    info = [
        ("AES-256-GCM", "Default · NIST SP 800-38D",
         ["Acelerado por hardware (AES-NI)",
          "Estándar de la industria",
          "TLS 1.3, IPsec"], ACCENT),
        ("ChaCha20-Poly1305", "RFC 7539",
         ["Sin instrucciones AES",
          "Constant-time por diseño",
          "Ideal para móviles"], INDIGO),
    ]
    cw = Inches(5.8); ch = Inches(3.5)
    for i, (titulo, sub, bullets, col) in enumerate(info):
        cx = Inches(0.7 + i * 6.1); cy = Inches(1.4)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=col, border_w=1.5)
        add_text(s, cx + Inches(0.3), cy + Inches(0.25), cw, Inches(0.6),
                 titulo, font_size=24, color=col, bold=True)
        add_text(s, cx + Inches(0.3), cy + Inches(0.85), cw, Inches(0.4),
                 sub, font_size=11, color=TEXT_MUTED)
        for j, b in enumerate(bullets):
            add_text(s, cx + Inches(0.3), cy + Inches(1.4 + j * 0.5), cw, Inches(0.5),
                     "✓  " + b, font_size=12, color=TEXT_MAIN)
    # alerta abajo
    cy = Inches(5.2); ch = Inches(1.5)
    add_card(s, Inches(1.5), cy, Inches(10.3), ch, fill=BG_CARD, border=CORAL, border_w=1)
    add_text(s, Inches(1.5), cy + Inches(0.2), Inches(10.3), Inches(0.5),
             "¿Por qué AEAD y no «encrypt + MAC»?",
             font_size=15, color=CORAL, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(1.7), cy + Inches(0.7), Inches(9.9), Inches(0.7),
             "Un solo mecanismo garantiza confidencialidad e integridad. Diseñar a mano es donde surgen POODLE, Lucky13, BEAST.",
             font_size=12, color=TEXT_MAIN, align=PP_ALIGN.CENTER)


def slide_d2_aad(prs, c, t):
    s = slide_frame(prs, "El AAD no es opcional", c, t, "3 · D2 — AEAD")
    add_card(s, Inches(2.5), Inches(1.4), Inches(8.3), Inches(3.7),
             fill=BG_CARD2, border=ACCENT, border_w=1)
    diagram = (
        "┌─────────────────────────────────────────────┐\n"
        "│ MAGIC(4) \"SDDV\"                             │\n"
        "│ VERSION(1) = 1                              │   ← Cabecera\n"
        "│ ALGO_ID(1)                                  │     completa pasa\n"
        "│ TIMESTAMP(8)                                │     como AAD\n"
        "│ FNAME_LEN(2) · FILENAME                     │     al DEM\n"
        "├─────────────────────────────────────────────┤\n"
        "│ NONCE(12) · CT_LEN(4) · CIPHERTEXT          │\n"
        "│ TAG(16)                                     │\n"
        "└─────────────────────────────────────────────┘"
    )
    add_text(s, Inches(2.7), Inches(1.6), Inches(7.9), Inches(3.3),
             diagram, font_size=12, color=TEXT_MAIN, font_name=FONT_MONO)
    # alerta
    add_card(s, Inches(1.5), Inches(5.5), Inches(10.3), Inches(1.3),
             fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, Inches(1.5), Inches(5.6), Inches(10.3), Inches(0.5),
             "Propiedad clave",
             font_size=14, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(1.7), Inches(6.1), Inches(9.9), Inches(0.7),
             "Modificar 1 bit del filename, timestamp o algoritmo → InvalidTag al descifrar.",
             font_size=12, color=TEXT_MAIN, align=PP_ALIGN.CENTER)


def slide_d2_nonce(prs, c, t):
    s = slide_frame(prs, "Estrategia de nonce", c, t, "3 · D2 — AEAD")
    add_text(s, Inches(0.5), Inches(1.8), Inches(12.3), Inches(2.5),
             "96", font_size=180, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(4.6), Inches(12.3), Inches(0.5),
             "bits aleatorios · CSPRNG · fresco por archivo",
             font_size=18, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    add_card(s, Inches(2.5), Inches(5.5), Inches(8.3), Inches(1.3),
             fill=BG_CARD, border=CORAL, border_w=1)
    add_text(s, Inches(2.5), Inches(5.65), Inches(8.3), Inches(0.4),
             "Nonce reuse en GCM es CATASTRÓFICO",
             font_size=14, color=CORAL, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(2.7), Inches(6.1), Inches(7.9), Inches(0.7),
             "Expone la authentication key. Cada archivo usa clave fresca → el límite es por-clave, no global.",
             font_size=11, color=TEXT_MAIN, align=PP_ALIGN.CENTER)


def slide_d3_kem(prs, c, t):
    s = slide_frame(prs, "KEM + DEM en una línea", c, t, "3 · D3 — Cifrado Híbrido")
    add_text(s, Inches(0.5), Inches(1.5), Inches(12.3), Inches(1.5),
             "Una llave efímera por destinatario.\nUn archivo cifrado una vez.",
             font_size=30, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_card(s, Inches(1.5), Inches(4.0), Inches(10.3), Inches(2.7),
             fill=BG_CARD)
    add_text(s, Inches(1.7), Inches(4.15), Inches(9.9), Inches(0.5),
             "KEM (Key Encapsulation) — X25519 ECDH:",
             font_size=14, color=ACCENT, bold=True)
    add_text(s, Inches(1.9), Inches(4.55), Inches(9.7), Inches(0.9),
             "• Genera file_key aleatoria de 256 bits\n"
             "• Por cada destinatario: par X25519 efímero → ECDH → HKDF → wrap",
             font_size=12, color=TEXT_MAIN)
    add_text(s, Inches(1.7), Inches(5.55), Inches(9.9), Inches(0.5),
             "DEM (Data Encapsulation) — AES-256-GCM o ChaCha20:",
             font_size=14, color=ACCENT, bold=True)
    add_text(s, Inches(1.9), Inches(5.95), Inches(9.7), Inches(0.6),
             "• Cifra el archivo una sola vez con file_key",
             font_size=12, color=TEXT_MAIN)


def slide_d3_forward(prs, c, t):
    s = slide_frame(prs, "Forward secrecy", c, t, "3 · D3 — Cifrado Híbrido")
    add_text(s, Inches(0.5), Inches(1.8), Inches(12.3), Inches(0.9),
             "Las llaves efímeras", font_size=36, color=TEXT_MAIN, bold=True,
             align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(2.8), Inches(12.3), Inches(0.9),
             "se destruyen", font_size=36, color=ACCENT, bold=True,
             align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(3.8), Inches(12.3), Inches(0.9),
             "tras el wrap.", font_size=36, color=TEXT_MAIN, bold=True,
             align=PP_ALIGN.CENTER)
    add_card(s, Inches(2.5), Inches(5.4), Inches(8.3), Inches(1.4),
             fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, Inches(2.7), Inches(5.55), Inches(7.9), Inches(1.2),
             "Si en el futuro se filtra una recipient_priv, los mensajes pasados quedan protegidos porque las efímeras ya no existen.",
             font_size=12, color=TEXT_MAIN, align=PP_ALIGN.CENTER)


def slide_d3_sddh(prs, c, t):
    s = slide_frame(prs, "Contenedor SDDH", c, t, "3 · D3 — Cifrado Híbrido")
    add_card(s, Inches(1.0), Inches(1.4), Inches(11.3), Inches(3.6),
             fill=BG_CARD2)
    diagram = (
        "MAGIC(4) \"SDDH\" · VERSION · ALGO · TIMESTAMP(8)\n"
        "FNAME_LEN(2) · FILENAME · RCPT_COUNT(2)\n\n"
        "╔═ Por cada destinatario (124 B) ═══════════════════════╗\n"
        "║  FINGERPRINT(32)  SHA-256(raw X25519 pubkey)          ║\n"
        "║  EPH_PUB(32)      clave efímera                       ║\n"
        "║  WRAP_NONCE(12)   nonce del wrap                      ║\n"
        "║  WRAPPED_KEY(48)  file_key cifrada (32 ct + 16 tag)   ║\n"
        "╚═══════════════════════════════════════════════════════╝\n"
        "                                  ← fin del AAD del DEM\n"
        "NONCE(12) · CT_LEN(4) · CIPHERTEXT · TAG(16)"
    )
    add_text(s, Inches(1.3), Inches(1.55), Inches(10.7), Inches(3.3),
             diagram, font_size=10, color=TEXT_MAIN, font_name=FONT_MONO)
    # 2 cards
    cy = Inches(5.5); ch = Inches(1.3); cw = Inches(5.5)
    for i, (titulo, desc, col) in enumerate([
        ("Identidad", "SHA-256(raw X25519 pubkey) — 32 B\nSin PKI", ACCENT),
        ("Hardening", "MAX_RECIPIENTS = 1024\nMitigación CWE-770", ACCENT),
    ]):
        cx = Inches(0.7 + i * 6.1)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD)
        add_text(s, cx, cy + Inches(0.15), cw, Inches(0.5),
                 titulo, font_size=16, color=col, bold=True, align=PP_ALIGN.CENTER)
        add_text(s, cx + Inches(0.25), cy + Inches(0.65), cw, Inches(0.6),
                 desc, font_size=11, color=TEXT_MAIN, align=PP_ALIGN.CENTER)


def slide_d5_ed25519(prs, c, t):
    s = slide_frame(prs, "¿Por qué Ed25519?", c, t, "3 · D5 — Firma Digital")
    # 2 cards
    info = [
        ("Propiedades", ACCENT,
         ["Curve25519 · 128 bits de seguridad",
          "Llaves de 32 B",
          "Firma de 64 B",
          "Constant-time por diseño"]),
        ("Determinismo", INDIGO,
         ["No requiere CSPRNG en cada firma.",
          "",
          "Inmune al ataque PS3 (Sony 2010):",
          "reuso de nonce en ECDSA expuso la llave."]),
    ]
    cw = Inches(5.8); ch = Inches(3.6)
    for i, (titulo, col, bullets) in enumerate(info):
        cx = Inches(0.7 + i * 6.1); cy = Inches(1.4)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=col, border_w=1.5)
        add_text(s, cx + Inches(0.3), cy + Inches(0.25), cw, Inches(0.6),
                 titulo, font_size=22, color=col, bold=True)
        for j, b in enumerate(bullets):
            prefix = "✓  " if b and "(" not in b[:2] else ""
            if not b:
                continue
            add_text(s, cx + Inches(0.3), cy + Inches(1.0 + j * 0.5), cw, Inches(0.5),
                     ("✓  " + b) if i == 0 else b,
                     font_size=12, color=TEXT_MAIN)
    add_card(s, Inches(1.5), Inches(5.3), Inches(10.3), Inches(1.0),
             fill=BG_CARD2)
    add_text(s, Inches(1.5), Inches(5.45), Inches(10.3), Inches(0.7),
             "SIGN_MAGIC(4) + SIGNER_FP(32) + SIGNATURE(64) = 100 B",
             font_size=14, color=ACCENT, align=PP_ALIGN.CENTER, font_name=FONT_MONO)


def slide_d5_verify(prs, c, t):
    s = slide_frame(prs, "Verify-first", c, t, "3 · D5 — Firma Digital")
    # tabla comparativa
    add_text(s, Inches(0.7), Inches(1.4), Inches(5.8), Inches(0.6),
             "Patrón ingenuo", font_size=22, color=CORAL, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(6.8), Inches(1.4), Inches(5.8), Inches(0.6),
             "API SDDV", font_size=22, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    rows = [
        ("decrypt → verify",                 "verify → decrypt"),
        ("expone plaintext si firma falla",  "no toca el descifrado"),
        ("posible timing oracle",            "tiempo uniforme"),
    ]
    for i, (left, right) in enumerate(rows):
        y = Inches(2.2 + i * 0.5)
        add_text(s, Inches(0.7), y, Inches(5.8), Inches(0.4),
                 left, font_size=13, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
        add_text(s, Inches(6.8), y, Inches(5.8), Inches(0.4),
                 right, font_size=13, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    # code
    add_card(s, Inches(1.5), Inches(4.2), Inches(10.3), Inches(2.6),
             fill=BG_CARD2)
    code = (
        "def secure_verify_and_decrypt(signed_container, expected_signer_pub,\n"
        "                              recipient_priv, max_age_seconds):\n"
        "    container = verify_hybrid_container(    # ① VERIFY\n"
        "        signed_container, expected_signer_pub)\n"
        "                                            #   InvalidSignature → STOP\n"
        "    return decrypt_for_recipient(           # ② DECRYPT (solo si verify OK)\n"
        "        container, recipient_priv, max_age_seconds)"
    )
    add_text(s, Inches(1.7), Inches(4.35), Inches(9.9), Inches(2.4),
             code, font_size=10, color=TEXT_MAIN, font_name=FONT_MONO)


def slide_d5_binding(prs, c, t):
    s = slide_frame(prs, "Binding de identidad", c, t, "3 · D5 — Firma Digital")
    add_text(s, Inches(0.5), Inches(2.0), Inches(12.3), Inches(1.8),
             "El fingerprint del firmante\nestá dentro de lo firmado.",
             font_size=36, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_card(s, Inches(2.0), Inches(4.5), Inches(9.3), Inches(2.0),
             fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, Inches(2.0), Inches(4.7), Inches(9.3), Inches(0.7),
             "Un atacante no puede sustituir el firmante por Eve",
             font_size=14, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    add_text(s, Inches(2.0), Inches(5.2), Inches(9.3), Inches(0.6),
             "manteniendo la firma de Alice.",
             font_size=14, color=TEXT_MAIN, align=PP_ALIGN.CENTER)
    add_text(s, Inches(2.0), Inches(5.85), Inches(9.3), Inches(0.5),
             "SIGNATURE = Ed25519(SDDH || \"SIGS\" || SIGNER_FP)",
             font_size=12, color=ACCENT, align=PP_ALIGN.CENTER, font_name=FONT_MONO)


def slide_d6_kdf(prs, c, t):
    s = slide_frame(prs, "Protección de llaves", c, t, "3 · D6 — Key Management")
    add_text(s, Inches(0.5), Inches(1.3), Inches(12.3), Inches(0.7),
             "scrypt + AES-256-GCM",
             font_size=32, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    # card izq — params
    cx = Inches(0.7); cy = Inches(2.3); cw = Inches(5.8); ch = Inches(4.3)
    add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, cx + Inches(0.3), cy + Inches(0.2), cw, Inches(0.5),
             "KDF — scrypt", font_size=18, color=ACCENT, bold=True)
    add_text(s, cx + Inches(0.3), cy + Inches(0.7), cw, Inches(0.4),
             "Memory-hard → penaliza GPU/ASIC",
             font_size=11, color=TEXT_MUTED)
    params = [("n",       "2^15 = 32 768"),
              ("r",       "8"),
              ("p",       "1"),
              ("dklen",   "32 B"),
              ("salt",    "16 B CSPRNG")]
    for j, (k, v) in enumerate(params):
        add_text(s, cx + Inches(0.4), cy + Inches(1.5 + j * 0.5), Inches(1.5), Inches(0.4),
                 k, font_size=14, color=ACCENT, bold=True, font_name=FONT_MONO)
        add_text(s, cx + Inches(2.5), cy + Inches(1.5 + j * 0.5), Inches(3.0), Inches(0.4),
                 v, font_size=14, color=TEXT_MAIN, font_name=FONT_MONO)
    # card der — costo
    cx = Inches(6.7); cy = Inches(2.3); cw = Inches(5.8); ch = Inches(4.3)
    add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, cx + Inches(0.3), cy + Inches(0.3), cw, Inches(0.5),
             "Costo deliberado", font_size=18, color=ACCENT, bold=True,
             align=PP_ALIGN.CENTER)
    add_text(s, cx, cy + Inches(1.1), cw, Inches(0.7),
             "150 ms  y  80 MiB RAM",
             font_size=24, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, cx, cy + Inches(1.85), cw, Inches(0.4),
             "por intento en laptop",
             font_size=12, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    add_text(s, cx, cy + Inches(2.7), cw, Inches(0.4),
             "Con password de 50 bits + 1000 GPUs:",
             font_size=11, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    add_text(s, cx, cy + Inches(3.2), cw, Inches(0.8),
             "≈ 2 700 años",
             font_size=32, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)


def slide_d6_json(prs, c, t):
    s = slide_frame(prs, "Keystore JSON", c, t, "3 · D6 — Key Management")
    add_card(s, Inches(1.0), Inches(1.4), Inches(11.3), Inches(5.4),
             fill=BG_CARD2)
    json_txt = (
        "{\n"
        '  "version": 1, "name": "alice", "status": "active",\n'
        '  "kdf": {\n'
        '    "algorithm": "scrypt", "salt_b64": "...",\n'
        '    "n": 32768, "r": 8, "p": 1, "dklen": 32\n'
        '  },\n'
        '  "encryption": {\n'
        '    "algorithm": "AES-256-GCM",\n'
        '    "nonce_b64": "...", "tag_b64": "..."\n'
        '  },\n'
        '  "encrypted_private_key": "...",\n'
        '  "public_keys":  {"ed25519_pub_b64": "...", "x25519_pub_b64": "..."},\n'
        '  "fingerprints": {"ed25519": "...", "x25519": "..."},\n'
        '  "metadata":     {"expires_at": null, "rotated_from": null}\n'
        "}"
    )
    add_text(s, Inches(1.4), Inches(1.6), Inches(10.5), Inches(5.0),
             json_txt, font_size=12, color=TEXT_MAIN, font_name=FONT_MONO)


def slide_d6_lifecycle(prs, c, t):
    s = slide_frame(prs, "Ciclo de vida", c, t, "3 · D6 — Key Management")
    ops = ["init", "unlock", "change-pwd", "rotate",
           "revoke", "delete", "backup", "restore"]
    cw = Inches(2.4); ch = Inches(0.9)
    for i, op in enumerate(ops):
        col = i % 4; row = i // 4
        cx = Inches(1.4 + col * 2.7); cy = Inches(2.4 + row * 1.2)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=ACCENT, border_w=1)
        add_text(s, cx, cy, cw, ch,
                 op, font_size=18, color=TEXT_MAIN, bold=True,
                 align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE,
                 font_name=FONT_MONO)
    add_card(s, Inches(1.5), Inches(5.5), Inches(10.3), Inches(1.3),
             fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, Inches(1.5), Inches(5.65), Inches(10.3), Inches(0.5),
             "Política de no-caching: cada unlock re-deriva con scrypt.",
             font_size=14, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(1.7), Inches(6.15), Inches(9.9), Inches(0.5),
             "La llave privada vive solo en el frame del caller.",
             font_size=11, color=TEXT_MAIN, align=PP_ALIGN.CENTER)


def slide_practices(prs, c, t):
    s = slide_frame(prs, "Las 4 prácticas que aplicamos", c, t,
                    "4 · Secure Practices")
    practices = [
        ("Input validation", ACCENT, [
            "validate_filename (CWE-22)",
            "validate_timestamp (CWE-294)",
            "ciphertext_length 100 MiB (CWE-770)",
            "MAX_RECIPIENTS = 1024"]),
        ("Fail-closed", ACCENT, [
            "Verify antes de decrypt",
            "unlock bloquea si revoked/expired",
            "AEAD nunca devuelve plaintext si tag falla"]),
        ("Canonicalization", INDIGO, [
            'struct.pack(">Q",...) big-endian',
            'JSON con separators=(",",":")',
            "posixpath.normpath check"]),
        ("Error handling", INDIGO, [
            "InvalidTag · InvalidSignature",
            "IdentityRevokedError",
            "Sin atrapar excepciones genéricas"]),
    ]
    cw = Inches(5.8); ch = Inches(2.6)
    for i, (titulo, col, bullets) in enumerate(practices):
        column = i % 2; row = i // 2
        cx = Inches(0.7 + column * 6.1); cy = Inches(1.4 + row * 2.8)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=col, border_w=1)
        add_text(s, cx + Inches(0.25), cy + Inches(0.2), cw, Inches(0.5),
                 titulo, font_size=16, color=col, bold=True)
        for j, b in enumerate(bullets):
            add_text(s, cx + Inches(0.25), cy + Inches(0.8 + j * 0.4),
                     cw, Inches(0.4), "● " + b,
                     font_size=10, color=TEXT_MAIN)


def slide_leccion(prs, c, t):
    s = slide_frame(prs, "Lección clave", c, t, "4 · Secure Practices")
    add_text(s, Inches(0.5), Inches(1.8), Inches(12.3), Inches(0.9),
             "Si la API es difícil",
             font_size=40, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(2.7), Inches(12.3), Inches(0.9),
             "de usar mal,",
             font_size=40, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(3.8), Inches(12.3), Inches(0.9),
             "los errores de implementación",
             font_size=32, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(4.7), Inches(12.3), Inches(0.9),
             "se reducen drásticamente.",
             font_size=36, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(6.2), Inches(12.3), Inches(0.5),
             "Misuse-resistant design · NaCl · libsodium",
             font_size=14, color=TEXT_MUTED, italic=True, align=PP_ALIGN.CENTER)


def slide_vulns(prs, c, t):
    s = slide_frame(prs, "Vulnerabilidades resueltas", c, t, "5 · Security Audit")
    vulns = [
        ("VULN-001 · ALTA", "Path traversal en filename",
         "CWE-22 · Fix: validate_filename", CORAL),
        ("VULN-002", "Replay sin freshness check",
         "CWE-294 · Fix: validate_timestamp", AMBER),
        ("VULN-003", "DoS por ct_len sin tope",
         "CWE-770 · Fix: 100 MiB cap", AMBER),
        ("VULN-004", "DoS por RCPT_COUNT sin tope",
         "CWE-770 · Fix: 1024 cap", AMBER),
        ("VULN-005", "Type confusion SDDH→SDDV",
         "Fix: detección de magic", AMBER),
        ("VULN-006", "Path traversal al unpacking",
         "CWE-22 · Fix: safe_path_join", AMBER),
        ("VULN-007", "Password débil en PKCS8",
         "CWE-521 · Fix: MIN_LEN=12", AMBER),
    ]
    cw = Inches(5.8); ch = Inches(1.2)
    for i, (pid, titulo, fix, col) in enumerate(vulns):
        column = i % 2; row = i // 2
        cx = Inches(0.7 + column * 6.1); cy = Inches(1.4 + row * 1.3)
        border = col if "ALTA" in pid else None
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=border, border_w=1)
        _, pw = add_pill(s, cx + Inches(0.25), cy + Inches(0.15), pid,
                         fill=col, font_color=BG_DARK, font_size=9)
        add_text(s, cx + Inches(0.25), cy + Inches(0.55), cw, Inches(0.4),
                 titulo, font_size=13, color=TEXT_MAIN, bold=True)
        add_text(s, cx + Inches(0.25), cy + Inches(0.85), cw, Inches(0.3),
                 fix, font_size=10, color=TEXT_MUTED)
    # último card vacío → poner 24 tests
    cx = Inches(6.8); cy = Inches(6.6); cw = Inches(5.8); ch = Inches(0.5)


def slide_limits(prs, c, t):
    s = slide_frame(prs, "Lo que NO protegemos", c, t, "5 · Security Audit")
    limits = [
        ("Dispositivo comprometido",  "Keylogger, RAM dump → requiere HSM"),
        ("Distribución de pubkeys",   "No hay PKI; canal fuera de scope"),
        ("Revocación distribuida",    "Sin CRL/OCSP; revoke local"),
        ("Side-channel físico",       "Cold boot, EMI → hardware"),
        ("Pérdida de pwd + backup",   "Propiedad criptográfica, no bug"),
        ("Quantum adversary",         "Roadmap: hybrid PQ (RFC 9180)"),
    ]
    cw = Inches(5.8); ch = Inches(1.3)
    for i, (titulo, desc) in enumerate(limits):
        column = i % 2; row = i // 2
        cx = Inches(0.7 + column * 6.1); cy = Inches(1.4 + row * 1.55)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=CORAL, border_w=1)
        add_text(s, cx + Inches(0.25), cy + Inches(0.2), cw, Inches(0.4),
                 "✗  " + titulo, font_size=13, color=CORAL, bold=True)
        add_text(s, cx + Inches(0.25), cy + Inches(0.65), cw, Inches(0.5),
                 desc, font_size=10, color=TEXT_MAIN)


def slide_demo(prs, c, t):
    s = slide_frame(prs, "Lo que vamos a mostrar", c, t, "6 · Final Demo")
    items = [
        "1.  Init identidades alice + bob",
        "2.  Alice cifra y firma para Bob",
        "3.  Bob verify + decrypt → plaintext",
        "4.  Password incorrecto → InvalidTag",
        "5.  Contenedor modificado → InvalidSignature",
        "6.  Rotate keys de Alice",
        "7.  Backup → delete → restore",
    ]
    for i, t_ in enumerate(items):
        add_text(s, Inches(2.5), Inches(1.6 + i * 0.55), Inches(9), Inches(0.5),
                 t_, font_size=18, color=TEXT_MAIN)
    add_card(s, Inches(3.5), Inches(6.0), Inches(6.3), Inches(0.9),
             fill=BG_CARD, border=ACCENT, border_w=1)
    add_text(s, Inches(3.5), Inches(6.0), Inches(6.3), Inches(0.9),
             "python demo_d6.py    ·    bash verificar_d6.sh",
             font_size=14, color=ACCENT, align=PP_ALIGN.CENTER,
             anchor=MSO_ANCHOR.MIDDLE, font_name=FONT_MONO)


def slide_estado(prs, c, t):
    s = slide_frame(prs, "Estado final", c, t, "6 · Final Demo")
    add_text(s, Inches(0.5), Inches(1.4), Inches(12.3), Inches(2.5),
             "300 / 300", font_size=120, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(4.4), Inches(12.3), Inches(0.5),
             "tests verdes", font_size=18, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    # stats
    stats = [("4500", "líneas Python"),
             ("4",    "docs de diseño"),
             ("7",    "vulns resueltas"),
             ("32",   "commits")]
    for i, (n, lbl) in enumerate(stats):
        cx = Inches(1.5 + i * 2.6); cy = Inches(5.4); cw = Inches(2.1); ch = Inches(1.4)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD)
        add_text(s, cx, cy + Inches(0.2), cw, Inches(0.7),
                 n, font_size=28, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
        add_text(s, cx, cy + Inches(0.9), cw, Inches(0.4),
                 lbl, font_size=10, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(7.0), Inches(12.3), Inches(0.3),
             "github.com/milliyx/Cryptography",
             font_size=10, color=TEXT_MUTED, align=PP_ALIGN.CENTER, font_name=FONT_MONO)


def slide_refs(prs, c, t):
    s = slide_frame(prs, "Estándares y guías", c, t, "Referencias")
    cards_data = [
        ("Estándares · RFCs", ACCENT, [
            "NIST SP 800-38D — GCM",
            "RFC 7539 — ChaCha20 + Poly1305",
            "RFC 7748 — X25519 (Curve25519)",
            "RFC 7914 — scrypt KDF",
            "RFC 8032 — Ed25519 (EdDSA)",
            "RFC 9180 — HPKE",
            "RFC 5869 — HKDF"]),
        ("Guías · Librerías", INDIGO, [
            "OWASP Password Storage Cheat Sheet",
            "OWASP Cryptographic Storage",
            "libsodium / NaCl misuse-resistant",
            "cryptography (pyca) — primitivas",
            "hashlib.scrypt — stdlib",
            "pytest — testing"]),
    ]
    cw = Inches(5.8); ch = Inches(5.0)
    for i, (titulo, col, bullets) in enumerate(cards_data):
        cx = Inches(0.7 + i * 6.1); cy = Inches(1.4)
        add_card(s, cx, cy, cw, ch, fill=BG_CARD, border=col, border_w=1)
        add_text(s, cx + Inches(0.3), cy + Inches(0.25), cw, Inches(0.5),
                 titulo, font_size=18, color=col, bold=True)
        for j, b in enumerate(bullets):
            add_text(s, cx + Inches(0.3), cy + Inches(0.95 + j * 0.5),
                     cw, Inches(0.4), "● " + b,
                     font_size=12, color=TEXT_MAIN)


def slide_qa(prs, c, t):
    s = slide_frame(prs, "Q&A", c, t, "")
    add_text(s, Inches(0.5), Inches(2.0), Inches(12.3), Inches(2.5),
             "¿Preguntas?", font_size=96, color=ACCENT, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(5.0), Inches(12.3), Inches(0.6),
             "Equipo 7", font_size=24, color=TEXT_MAIN, bold=True, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(5.7), Inches(12.3), Inches(0.5),
             "Barrios · Caballero · Contreras · Martínez",
             font_size=14, color=TEXT_MUTED, align=PP_ALIGN.CENTER)
    add_text(s, Inches(0.5), Inches(6.5), Inches(12.3), Inches(0.4),
             "github.com/milliyx/Cryptography",
             font_size=11, color=TEXT_MUTED, align=PP_ALIGN.CENTER, font_name=FONT_MONO)


# ============================================================================
# BUILD
# ============================================================================
def build():
    prs = make_pres()
    # Pre-cuenta total para el footer
    # 1 portada + 6 secciones + (3+3+3+3+3+3+1+1+1+2 = 23 contenido) + Q&A
    # Hacemos un mapeo manual
    total = 28
    c = 0

    c += 1; slide_title(prs)

    # Sección 1
    c += 1; slide_section(prs, 1, "System Overview", c, total)
    c += 1; slide_problem(prs, c, total)
    c += 1; slide_propuesta(prs, c, total)
    c += 1; slide_que_construimos(prs, c, total)
    c += 1; slide_arquitectura(prs, c, total)

    # Sección 2
    c += 1; slide_section(prs, 2, "Threat Model", c, total)
    c += 1; slide_activos(prs, c, total)
    c += 1; slide_adversarios(prs, c, total)
    c += 1; slide_asunciones(prs, c, total)

    # Sección 3
    c += 1; slide_section(prs, 3, "Cryptographic Design", c, total)
    c += 1; slide_d2_algos(prs, c, total)
    c += 1; slide_d2_aad(prs, c, total)
    c += 1; slide_d2_nonce(prs, c, total)
    c += 1; slide_d3_kem(prs, c, total)
    c += 1; slide_d3_forward(prs, c, total)
    c += 1; slide_d3_sddh(prs, c, total)
    c += 1; slide_d5_ed25519(prs, c, total)
    c += 1; slide_d5_verify(prs, c, total)
    c += 1; slide_d5_binding(prs, c, total)
    c += 1; slide_d6_kdf(prs, c, total)
    c += 1; slide_d6_json(prs, c, total)
    c += 1; slide_d6_lifecycle(prs, c, total)

    # Sección 4
    c += 1; slide_section(prs, 4, "Secure Practices", c, total)
    c += 1; slide_practices(prs, c, total)
    c += 1; slide_leccion(prs, c, total)

    # Sección 5
    c += 1; slide_section(prs, 5, "Security Audit", c, total)
    c += 1; slide_vulns(prs, c, total)
    c += 1; slide_limits(prs, c, total)

    # Sección 6
    c += 1; slide_section(prs, 6, "Final Demo", c, total)
    c += 1; slide_demo(prs, c, total)
    c += 1; slide_estado(prs, c, total)

    # Referencias + Q&A
    c += 1; slide_refs(prs, c, total)
    c += 1; slide_qa(prs, c, total)

    out = "/Users/emiliocontreras/Documents/10Semestre/Cripto/Proyecto/docs/Final_Presentation.pptx"
    prs.save(out)
    print(f"OK · {c} slides escritas en {out}")


if __name__ == "__main__":
    build()
