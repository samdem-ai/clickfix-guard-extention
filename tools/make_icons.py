#!/usr/bin/env python3
"""Render the extension icons (shield with a blocked prompt) as PNGs.

Standard library only: shapes are rasterised with 4x4 supersampling and
written with zlib. Run from the repo root: python tools/make_icons.py
"""

import os
import struct
import zlib

SIZES = (16, 32, 48, 128)
SS = 4  # supersampling factor per axis

RED = (198, 40, 40)
WHITE = (255, 255, 255)


def in_shield(x, y):
    """Shield in unit coordinates: flat top with rounded corners, pointed bottom."""
    if y < 0.06 or y > 0.96:
        return False
    if y <= 0.55:
        half = 0.40
        if y < 0.16:  # rounded top corners
            r = 0.10
            cx = 0.5 - half + r if x < 0.5 else 0.5 + half - r
            if abs(x - 0.5) > half - r:
                return (x - cx) ** 2 + (y - 0.16) ** 2 <= r * r
        return abs(x - 0.5) <= half
    t = (y - 0.55) / (0.96 - 0.55)
    half = 0.40 * (1 - t ** 1.6)
    return abs(x - 0.5) <= half


def in_glyph(x, y):
    """A '>_' prompt with a slash through it, centred in the shield."""
    # chevron '>'
    cx, cy, w, h, th = 0.30, 0.42, 0.16, 0.30, 0.075
    if cx <= x <= cx + w and cy - h / 2 <= y <= cy + h / 2:
        dy = abs(y - cy)
        edge = cx + w * (1 - dy / (h / 2))
        if edge - th * 1.4 <= x <= edge:
            return True
    # underscore '_'
    if 0.50 <= x <= 0.70 and 0.52 <= y <= 0.59:
        return True
    return False


def in_slash(x, y):
    # diagonal bar from top-right to bottom-left
    d = abs((x - 0.5) + (y - 0.48) * 0.9) / (1 + 0.81) ** 0.5
    return d <= 0.045 and 0.22 <= y <= 0.74


def render(size):
    rows = []
    for py in range(size):
        row = bytearray([0])  # filter type 0
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    x = (px + (sx + 0.5) / SS) / size
                    y = (py + (sy + 0.5) / SS) / size
                    if not in_shield(x, y):
                        continue
                    col = WHITE if (in_glyph(x, y) or in_slash(x, y)) and size >= 32 else RED
                    if size < 32 and in_slash(x, y):
                        col = WHITE  # at 16px only the slash stays legible
                    acc[0] += col[0]
                    acc[1] += col[1]
                    acc[2] += col[2]
                    acc[3] += 255
            n = SS * SS
            cov = acc[3] / 255
            if cov:
                row += bytes([round(acc[0] / cov), round(acc[1] / cov), round(acc[2] / cov), round(acc[3] / n)])
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    return b"".join(rows)


def png(size, raw):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main():
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "icons")
    os.makedirs(out, exist_ok=True)
    for s in SIZES:
        with open(os.path.join(out, f"icon-{s}.png"), "wb") as fh:
            fh.write(png(s, render(s)))
        print(f"icons/icon-{s}.png")


if __name__ == "__main__":
    main()
