"""Tiny SVG builder for the SecureMatrix paper figures (hand-placed layout, print-friendly palette)."""
from __future__ import annotations

from xml.sax.saxutils import escape

FONT = "Arial, Helvetica, sans-serif"
INK = "#14202E"
LINE = "#3F4B5B"
MUTED = "#475569"
KINDS = {
    "core": ("#EEF4FB", "#2F5D8A"),
    "data": ("#EEF7F1", "#2E7D4F"),
    "ext": ("#F3F4F6", "#6B7280"),
    "dec": ("#FFF8E6", "#B7791F"),
    "bad": ("#FDECEC", "#B42318"),
    "warn": ("#FDF2E9", "#B54708"),
    "plain": ("#FFFFFF", "#3F4B5B"),
    "planned": ("#FFFFFF", "#94A3B8"),
}


class Fig:
    def __init__(self, width: int, height: int):
        self.w, self.h = width, height
        self.back: list[str] = []   # groups, drawn first
        self.mid: list[str] = []    # edges
        self.front: list[str] = []  # nodes and labels

    # -- primitives -------------------------------------------------------------------
    def text(self, x, y, s, size=12.5, weight="normal", anchor="middle", color=INK, layer=None, italic=False):
        style = ' font-style="italic"' if italic else ""
        (layer if layer is not None else self.front).append(
            f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" text-anchor="{anchor}" '
            f'fill="{color}"{style}>{escape(s)}</text>')

    def _lines(self, cx, top, title, lines, h, title_size=14, size=12.5, lh=17):
        n = (1 if title else 0) + len(lines)
        y = top + h / 2 - (n * lh) / 2 + lh * 0.72
        if title:
            self.text(cx, y, title, size=title_size, weight="bold")
            y += lh + 1
        for ln in lines:
            self.text(cx, y, ln, size=size)
            y += lh

    def group(self, x, y, w, h, label):
        self.back.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="#F8FAFC" stroke="#94A3B8" stroke-width="1.2"/>')
        self.text(x + 14, y + 22, label, size=13.5, weight="bold", anchor="start", color="#334155", layer=self.back)

    def box(self, x, y, w, h, title="", lines=(), kind="core", dashed=False):
        fill, stroke = KINDS[kind]
        dash = ' stroke-dasharray="6 4"' if dashed or kind == "planned" else ""
        self.front.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.4"{dash}/>')
        self._lines(x + w / 2, y, title, list(lines), h)
        return (x, y, w, h)

    def pill(self, x, y, w, h, title, lines=()):
        self.front.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h/2}" fill="#FFFFFF" stroke="{LINE}" stroke-width="1.4"/>')
        self._lines(x + w / 2, y, title, list(lines), h)

    def cyl(self, x, y, w, h, title, lines=(), kind="data"):
        fill, stroke = KINDS[kind]
        ry = 10
        self.front.append(
            f'<path d="M{x},{y+ry} a{w/2},{ry} 0 0,0 {w},0 a{w/2},{ry} 0 0,0 {-w},0 v{h-2*ry} a{w/2},{ry} 0 0,0 {w},0 v{-(h-2*ry)}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
        self._lines(x + w / 2, y + ry, title, list(lines), h - ry)

    def para(self, x, y, w, h, title, lines=(), kind="data"):
        fill, stroke = KINDS[kind]
        s = 14
        self.front.append(f'<path d="M{x+s},{y} H{x+w} L{x+w-s},{y+h} H{x} Z" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
        self._lines(x + w / 2, y, title, list(lines), h)

    def diamond(self, cx, cy, w, h, lines, kind="dec"):
        fill, stroke = KINDS[kind]
        self.front.append(f'<path d="M{cx},{cy-h/2} L{cx+w/2},{cy} L{cx},{cy+h/2} L{cx-w/2},{cy} Z" fill="{fill}" stroke="{stroke}" stroke-width="1.4"/>')
        self._lines(cx, cy - h / 2, "", list(lines), h, size=12.5)

    def edge(self, pts, label=None, at=None, dashed=False, both=False, anchor="middle", color=LINE, lcolor=INK):
        d = "M" + " L".join(f"{x},{y}" for x, y in pts)
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        start = ' marker-start="url(#arrowStart)"' if both else ""
        self.mid.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="1.4"{dash}{start} marker-end="url(#arrow)"/>')
        if label:
            lx, ly = at if at else ((pts[0][0] + pts[-1][0]) / 2, (pts[0][1] + pts[-1][1]) / 2)
            for i, part in enumerate(label.split("\n")):
                self.label(lx, ly + i * 15, part, anchor, lcolor)

    def label(self, x, y, s, anchor="middle", color=INK):
        width = len(s) * 6.3 + 8
        x0 = x - width / 2 if anchor == "middle" else (x - 4 if anchor == "start" else x - width + 4)
        self.front.append(f'<rect x="{x0}" y="{y-11}" width="{width}" height="15" fill="#FFFFFF" opacity="0.92"/>')
        self.text(x, y, s, size=11.5, anchor=anchor, color=color)

    def svg(self) -> str:
        defs = (
            '<defs>'
            f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{LINE}"/></marker>'
            f'<marker id="arrowStart" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{LINE}"/></marker>'
            '</defs>')
        body = "\n".join(self.back + self.mid + self.front)
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" '
                f'font-family="{FONT}">\n<rect width="100%" height="100%" fill="#FFFFFF"/>\n{defs}\n{body}\n</svg>\n')
