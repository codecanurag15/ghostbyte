#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostByte 1.0 - advanced steganography toolkit (CLI + GUI, one file)

  python ghostbyte.py                          launch the GUI
  python ghostbyte.py encode cover.png -t "secret" -p hunter2
  python ghostbyte.py encode movie.mp4 -f payload.zip -P        (-P = ask password)
  python ghostbyte.py decode cover_stego.png -p hunter2
  python ghostbyte.py scan suspicious.png      detect appended data / LSB tampering
  python ghostbyte.py clean movie_stego.mp4    strip an appended payload
  python ghostbyte.py capacity cover.wav -b 2
  python ghostbyte.py selftest | themes

Carriers
  PNG / BMP / TIFF (any image Pillow reads is written out as PNG)
                      LSB in pixels, 1/2/4 bits per channel, alpha preserved
  WAV (PCM)           LSB in samples
  anything else       append mode: MP4, MP3, JPG, PDF, ZIP ... (MP4/MOV payloads
                      are wrapped in a valid 'free' box so players stay happy)

Payload: any file or text -> zlib -> optional encryption -> container.
Crypto : PBKDF2-SHA256 (200k) + AES-256-GCM if 'cryptography' is installed,
         otherwise a stdlib SHAKE-256 stream + HMAC-SHA256 (encrypt-then-MAC).

Deps   : pip install pillow   (optional: cryptography).  GUI needs tkinter.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import io
import math
import os
import queue
import random
import re
import shutil
import struct
import sys
import threading
import time
import wave
import zlib

try:
    from PIL import Image
except ImportError:  # images become append-only without Pillow
    Image = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None

if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)
if os.name == "nt":
    os.system("")  # enable ANSI colours in the Windows console

APP, VERSION = "GhostByte", "1.0"
MAGIC, TRAIL = b"GHST", b"GHSTEND!"
HDR_FMT = ">4sBBB16s16sQ"          # magic ver flags cipher salt nonce body_len
HDR_LEN = struct.calcsize(HDR_FMT)
F_ZLIB, F_ENC, F_TEXT = 1, 2, 4
C_NONE, C_SHAKE, C_AES = 0, 1, 2
IMG_LOSSLESS = {".png", ".bmp", ".tif", ".tiff"}
IMG_ANY = IMG_LOSSLESS | {".jpg", ".jpeg", ".webp", ".gif"}
BMFF = {".mp4", ".m4a", ".m4v", ".mov", ".3gp", ".3g2"}


class StegoError(Exception):
    pass


# ════════════════════════════ themes & banner ════════════════════════════
THEMES = {
    "cyberpunk": dict(stops=[(255, 0, 170), (140, 70, 255), (0, 229, 255)], bg=(9, 6, 22), panel=(20, 14, 44),
                      fg=(222, 228, 255), accent=(0, 229, 255), accent2=(255, 0, 170),
                      ok=(57, 255, 140), warn=(255, 200, 0), err=(255, 70, 100)),
    "matrix": dict(stops=[(0, 110, 30), (0, 255, 70), (190, 255, 200)], bg=(2, 10, 3), panel=(6, 22, 9),
                   fg=(170, 255, 190), accent=(0, 255, 70), accent2=(0, 170, 50),
                   ok=(0, 255, 70), warn=(220, 255, 0), err=(255, 80, 80)),
    "sunset": dict(stops=[(255, 70, 110), (255, 150, 70), (255, 220, 120)], bg=(22, 9, 18), panel=(40, 18, 32),
                   fg=(255, 232, 220), accent=(255, 150, 70), accent2=(255, 70, 110),
                   ok=(150, 255, 160), warn=(255, 220, 90), err=(255, 90, 90)),
    "ocean": dict(stops=[(0, 100, 200), (0, 180, 220), (170, 240, 250)], bg=(3, 12, 26), panel=(8, 26, 48),
                  fg=(215, 240, 255), accent=(0, 200, 235), accent2=(70, 130, 255),
                  ok=(80, 255, 190), warn=(255, 215, 90), err=(255, 100, 110)),
    "inferno": dict(stops=[(150, 10, 20), (240, 80, 20), (255, 200, 50)], bg=(14, 5, 5), panel=(30, 12, 10),
                    fg=(255, 226, 205), accent=(255, 110, 30), accent2=(210, 30, 40),
                    ok=(160, 255, 120), warn=(255, 215, 60), err=(255, 90, 90)),
    "vaporwave": dict(stops=[(255, 113, 206), (185, 103, 255), (1, 205, 254), (5, 255, 161)], bg=(20, 8, 38),
                      panel=(36, 16, 62), fg=(245, 225, 255), accent=(1, 205, 254), accent2=(255, 113, 206),
                      ok=(5, 255, 161), warn=(255, 250, 150), err=(255, 100, 130)),
    "mono": dict(stops=[(110, 110, 110), (235, 235, 235)], bg=(14, 14, 14), panel=(28, 28, 28),
                 fg=(225, 225, 225), accent=(240, 240, 240), accent2=(150, 150, 150),
                 ok=(190, 255, 190), warn=(255, 235, 150), err=(255, 150, 150)),
}

GLYPHS = {
    "G": [" ####", "#    ", "# ###", "#   #", " ####"],
    "H": ["#   #", "#   #", "#####", "#   #", "#   #"],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    "S": [" ####", "#    ", " ### ", "    #", "#### "],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "B": ["#### ", "#   #", "#### ", "#   #", "#### "],
    "Y": ["#   #", " # # ", "  #  ", "  #  ", "  #  "],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
}
TAGLINE = "hide anything in anything"


def banner_matrix(word="GHOSTBYTE"):
    return [" ".join(GLYPHS[ch][r] for ch in word) for r in range(5)]


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def grad(stops, t):
    t = max(0.0, min(1.0, t))
    if len(stops) == 1:
        return tuple(stops[0])
    x = t * (len(stops) - 1)
    i = min(int(x), len(stops) - 2)
    return lerp(stops[i], stops[i + 1], x - i)


def hexc(c):
    return "#%02x%02x%02x" % tuple(int(v) for v in c)


# ═════════════════════════════ terminal effects ═════════════════════════════
class T:
    color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    fx = sys.stdout.isatty()
    truecolor = (os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
                 or os.name == "nt" or "WT_SESSION" in os.environ)
    theme = THEMES["cyberpunk"]


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def paint(text, rgb, bold=False):
    if not T.color:
        return text
    if T.truecolor:
        code = "38;2;%d;%d;%d" % tuple(rgb)
    else:
        code = "38;5;%d" % (16 + 36 * round(rgb[0] / 51) + 6 * round(rgb[1] / 51) + round(rgb[2] / 51))
    return "\x1b[%s%sm%s\x1b[0m" % ("1;" if bold else "", code, text)


def gradient_text(s, stops=None, bold=False):
    stops = stops or T.theme["stops"]
    n = max(1, len(s) - 1)
    return "".join(paint(ch, grad(stops, i / n), bold) for i, ch in enumerate(s))


def nap(s):
    if T.fx:
        time.sleep(s)


def rain(lines=7):
    if not (T.color and T.fx):
        return
    w = min(shutil.get_terminal_size((80, 24)).columns, 100) - 1
    chars = "01ABCDEF0123456789<>/\\|=+*#$%&"
    st, bg = T.theme["stops"], T.theme["bg"]
    for _ in range(lines):
        row = "".join(paint(random.choice(chars), lerp(bg, grad(st, random.random()), random.uniform(.25, .9)))
                      if random.random() < .2 else " " for _ in range(w))
        print(row)
        nap(.05)


def show_banner():
    rain()
    rows = banner_matrix()
    width, st = len(rows[0]), T.theme["stops"]
    print()
    for r, row in enumerate(rows):
        print("  " + "".join(paint("█", grad(st, (x + r * 2) / (width + 8)), True) if c == "#" else " "
                             for x, c in enumerate(row)))
        nap(.06)
    print()
    print("  " + gradient_text("◢◤ " + TAGLINE + " ◥◣", bold=True))
    print("  " + paint(f"v{VERSION}  ·  LSB  ·  append  ·  AES-GCM  ·  scan", T.theme["accent2"]))
    print()


def typewrite(text, delay=.012):
    if not T.fx:
        print(text)
        return
    for ch in text:
        sys.stdout.write(paint(ch, T.theme["fg"]))
        sys.stdout.flush()
        time.sleep(delay)
    print()


def say(kind, msg):
    t = T.theme
    icon, col = {"ok": ("[+]", t["ok"]), "err": ("[x]", t["err"]), "warn": ("[!]", t["warn"]),
                 "info": ("[*]", t["accent"])}[kind]
    print(f" {paint(icon, col, True)} {msg}")


def fail(msg, code=1):
    say("err", msg)
    sys.exit(code)


def box(title, rows):
    t = T.theme
    kw = max(len(k) for k, _ in rows)
    cw = max(max(len(str(v)) + kw + 2 for _, v in rows), len(title) + 2)
    inner = cw + 2
    c1, c2 = t["accent"], t["accent2"]
    print(" " + gradient_text("╭─ " + title + " " + "─" * (inner - len(title) - 3) + "╮", [c2, c1], True))
    for k, v in rows:
        pad = " " * (cw - kw - 2 - len(str(v)))
        print(" " + paint("│", c2) + " " + paint(k.ljust(kw), c1, True) + "  " + paint(str(v), t["fg"]) + pad
              + " " + paint("│", c1))
    print(" " + gradient_text("╰" + "─" * inner + "╯", [c2, c1], True))


class Progress:
    def update(self, frac, label=""):
        if not sys.stdout.isatty():
            return
        w, n = 28, int(frac * 28)
        st = T.theme["stops"]
        bar = "".join(paint("█", grad(st, i / (w - 1))) if i < n else paint("░", (70, 70, 80)) for i in range(w))
        sys.stdout.write("\r  %s %3d%%  %-26s" % (bar, int(frac * 100), label))
        sys.stdout.flush()
        if frac >= 1:
            sys.stdout.write("\r" + " " * 70 + "\r")
        else:
            nap(.05)


# ═══════════════════════════ container + crypto ═══════════════════════════
def fmt_size(n):
    if n is None:
        return "unlimited"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def safe_name(name):
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", name).strip(". ")
    return name or "payload.bin"


def unique_path(p):
    if not os.path.exists(p):
        return p
    b, e = os.path.splitext(p)
    i = 1
    while os.path.exists(f"{b}_{i}{e}"):
        i += 1
    return f"{b}_{i}{e}"


def _kdf(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, 64)


def _xor(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def pack_payload(data, name="", password="", compress=True, is_text=False, cipher="auto"):
    nb = safe_name(name).encode("utf-8")[:65535] if name else b""
    inner = struct.pack(">H", len(nb)) + nb + data
    flags = F_TEXT if is_text else 0
    if compress:
        z = zlib.compress(inner, 9)
        if len(z) < len(inner):
            inner, flags = z, flags | F_ZLIB
    salt = nonce = bytes(16)
    cid = C_NONE
    if password:
        if cipher == "aes" and AESGCM is None:
            raise StegoError("AES-GCM needs the 'cryptography' package (pip install cryptography).")
        cid = C_AES if (AESGCM is not None and cipher != "shake") else C_SHAKE
        flags |= F_ENC
        salt, nonce = os.urandom(16), os.urandom(16)
    pre = struct.pack(HDR_FMT[:-1], MAGIC, 1, flags, cid, salt, nonce)
    if cid == C_AES:
        body = AESGCM(_kdf(password, salt)[:32]).encrypt(nonce[:12], inner, pre)
    elif cid == C_SHAKE:
        key = _kdf(password, salt)
        ct = _xor(inner, hashlib.shake_256(key[:32] + nonce).digest(len(inner)))
        body = ct + hmac.new(key[32:], pre + ct, hashlib.sha256).digest()
    else:
        body = inner + struct.pack(">I", zlib.crc32(inner))
    return pre + struct.pack(">Q", len(body)) + body


def parse_header(raw):
    if len(raw) < HDR_LEN:
        raise StegoError("Truncated payload header.")
    magic, ver, flags, cid, salt, nonce, blen = struct.unpack(HDR_FMT, raw[:HDR_LEN])
    if magic != MAGIC:
        raise StegoError("No GhostByte payload found.")
    return ver, flags, cid, salt, nonce, blen


def unpack_payload(blob, password=""):
    ver, flags, cid, salt, nonce, blen = parse_header(blob)
    body = blob[HDR_LEN:HDR_LEN + blen]
    if len(body) != blen:
        raise StegoError("Payload is truncated or corrupted.")
    pre = blob[:HDR_LEN - 8]
    if flags & F_ENC:
        if not password:
            raise StegoError("Payload is encrypted - password required.")
        key = _kdf(password, salt)
        if cid == C_AES:
            if AESGCM is None:
                raise StegoError("Payload uses AES-GCM - install 'cryptography' to decrypt it.")
            try:
                inner = AESGCM(key[:32]).decrypt(nonce[:12], body, pre)
            except Exception:
                raise StegoError("Wrong password or corrupted data.")
        elif cid == C_SHAKE:
            ct, tag = body[:-32], body[-32:]
            if not hmac.compare_digest(tag, hmac.new(key[32:], pre + ct, hashlib.sha256).digest()):
                raise StegoError("Wrong password or corrupted data.")
            inner = _xor(ct, hashlib.shake_256(key[:32] + nonce).digest(len(ct)))
        else:
            raise StegoError("Unknown cipher id.")
    else:
        inner, crc = body[:-4], struct.unpack(">I", body[-4:])[0]
        if zlib.crc32(inner) != crc:
            raise StegoError("Checksum mismatch - data corrupted.")
    if flags & F_ZLIB:
        inner = zlib.decompress(inner)
    n = struct.unpack(">H", inner[:2])[0]
    return inner[2:2 + n].decode("utf-8", "replace"), inner[2 + n:], flags


# ═══════════════════════════════ bit tricks ═══════════════════════════════
_TABLES, _DIG = {}, bytes.maketrans(bytes(range(16)), b"0123456789abcdef")


def _table(k):
    if k not in _TABLES:
        _TABLES[k] = [bytes((b >> (8 - k * (i + 1))) & ((1 << k) - 1) for i in range(8 // k)) for b in range(256)]
    return _TABLES[k]


def embed_symbols(carrier: bytearray, payload: bytes, k: int):
    n = len(payload) * 8 // k
    if n > len(carrier):
        raise StegoError("Carrier too small for payload.")
    tbl = _table(k)
    sym = b"".join([tbl[b] for b in payload])
    keep = (0xFF << k) & 0xFF
    head = int.from_bytes(carrier[:n], "big") & int.from_bytes(bytes([keep]) * n, "big")
    carrier[:n] = (head | int.from_bytes(sym, "big")).to_bytes(n, "big")


def extract_symbols(carrier, k: int, nbytes: int) -> bytes:
    n = nbytes * 8 // k
    if n > len(carrier):
        raise StegoError("Carrier too small.")
    v = int.from_bytes(carrier[:n], "big") & int.from_bytes(bytes([(1 << k) - 1]) * n, "big")
    digits = v.to_bytes(n, "big").translate(_DIG)
    return int(digits, 1 << k).to_bytes(nbytes, "big")


def _scan_lsb(carrier):
    for k in (1, 2, 4):
        if HDR_LEN * 8 // k > len(carrier):
            continue
        h = extract_symbols(carrier, k, HDR_LEN)
        if h[:4] != MAGIC:
            continue
        total = HDR_LEN + struct.unpack(HDR_FMT, h)[-1]
        if total * 8 // k > len(carrier):
            continue
        return extract_symbols(carrier, k, total), k
    return None, None


# ═══════════════════════════════ carriers ═══════════════════════════════
def _img_open(path):
    if Image is None:
        raise StegoError("Pillow is required for images:  pip install pillow")
    try:
        im = Image.open(path)
        im.load()
        return im
    except Exception as e:
        raise StegoError(f"Cannot read image: {e}")


def _wav_read(path):
    try:
        with wave.open(path, "rb") as w:
            return w.getparams(), bytearray(w.readframes(w.getnframes()))
    except (wave.Error, EOFError) as e:
        raise StegoError(f"Unsupported WAV (PCM only): {e}")


def lsb_image_encode(cover, out, env, k):
    im = _img_open(cover)
    alpha = None
    if im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info:
        im = im.convert("RGBA")
        alpha = im.getchannel("A")
    im = im.convert("RGB")
    raw = bytearray(im.tobytes())
    embed_symbols(raw, env, k)
    res = Image.frombytes("RGB", im.size, bytes(raw))
    if alpha is not None:
        res.putalpha(alpha)
    ext = os.path.splitext(out)[1].lower()
    res.save(out, {".bmp": "BMP", ".tif": "TIFF", ".tiff": "TIFF"}.get(ext, "PNG"))


def lsb_wav_encode(cover, out, env, k):
    params, frames = _wav_read(cover)
    sw = params.sampwidth
    carrier = frames[0::sw]  # lowest byte of every little-endian sample
    embed_symbols(carrier, env, k)
    frames[0::sw] = carrier
    with wave.open(out, "wb") as w:
        w.setparams(params)
        w.writeframes(bytes(frames))


def append_encode(cover, out, env):
    foot = TRAIL + struct.pack(">Q", len(env))
    with open(cover, "rb") as src, open(out, "wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
        if os.path.splitext(cover)[1].lower() in BMFF:
            total = 8 + len(env) + len(foot)
            if total < 2 ** 32:
                dst.write(struct.pack(">I4s", total, b"free"))
            else:
                dst.write(struct.pack(">I4sQ", 1, b"free", 16 + len(env) + len(foot)))
        dst.write(env)
        dst.write(foot)


def append_locate(path):
    """-> (payload_start, payload_len) or None"""
    size = os.path.getsize(path)
    if size < 16:
        return None
    with open(path, "rb") as f:
        f.seek(-16, 2)
        foot = f.read(16)
        if foot[:8] != TRAIL:
            return None
        ln = struct.unpack(">Q", foot[8:])[0]
        if ln + 16 > size:
            return None
        return size - 16 - ln, ln


def append_find(path):
    loc = append_locate(path)
    if not loc:
        return None
    with open(path, "rb") as f:
        f.seek(loc[0])
        return f.read(loc[1])


def clean(path, out):
    loc = append_locate(path)
    if not loc:
        raise StegoError("No appended GhostByte payload found (LSB payloads can't be stripped).")
    start, ln = loc
    with open(path, "rb") as f:  # also drop our MP4 'free' box wrapper
        for hdr_len, big in ((8, False), (16, True)):
            if start >= hdr_len:
                f.seek(start - hdr_len)
                h = f.read(hdr_len)
                if not big and struct.unpack(">I4s", h)[1] == b"free" and struct.unpack(">I", h[:4])[0] == 8 + ln + 16:
                    start -= 8
                    break
                if big and h[4:8] == b"free" and struct.unpack(">I", h[:4])[0] == 1 \
                        and struct.unpack(">Q", h[8:])[0] == 16 + ln + 16:
                    start -= 16
                    break
        f.seek(0)
        with open(out, "wb") as dst:
            left = start
            while left:
                chunk = f.read(min(left, 1 << 20))
                dst.write(chunk)
                left -= len(chunk)
    return start


def choose_method(cover, method="auto"):
    ext = os.path.splitext(cover)[1].lower()
    if method == "append":
        return "append"
    if method in ("lsb", "lsb-image", "lsb-wav"):
        if ext == ".wav":
            return "lsb-wav"
        if Image is not None and ext in IMG_ANY:
            return "lsb-image"
        raise StegoError(f"LSB mode supports images and WAV, not '{ext or 'this file'}'. Use method 'append'.")
    if ext == ".wav":
        return "lsb-wav"
    if Image is not None and ext in IMG_LOSSLESS:
        return "lsb-image"
    return "append"


def capacity(cover, method="auto", bits=1):
    m = choose_method(cover, method)
    if m == "append":
        return m, None
    if m == "lsb-wav":
        try:
            with wave.open(cover, "rb") as w:
                n = w.getnframes() * w.getnchannels()
        except (wave.Error, EOFError) as e:
            raise StegoError(f"Unsupported WAV (PCM only): {e}")
    else:
        if Image is None:
            raise StegoError("Pillow is required for images:  pip install pillow")
        w, h = Image.open(cover).size
        n = w * h * 3
    return m, max(0, n * bits // 8 - HDR_LEN)


def default_out(cover, m):
    stem, ext = os.path.splitext(cover)
    if m == "lsb-image" and ext.lower() not in IMG_LOSSLESS:
        ext = ".png"
    return f"{stem}_stego{ext}"


def _fix_out(out, m):
    stem, ext = os.path.splitext(out)
    if m == "lsb-image" and ext.lower() not in IMG_LOSSLESS:
        return stem + ".png"
    if m == "lsb-wav" and ext.lower() != ".wav":
        return stem + ".wav"
    return out


def encode(cover, out, data, name="", password="", method="auto", bits=1, compress=True,
           cipher="auto", is_text=False, cb=None):
    cb = cb or (lambda *_: None)
    if bits not in (1, 2, 4):
        raise StegoError("bits must be 1, 2 or 4.")
    m = choose_method(cover, method)
    out = _fix_out(out, m)
    if os.path.abspath(cover) == os.path.abspath(out):
        raise StegoError("Output must differ from the carrier file.")
    cb(.1, "reading carrier")
    cb(.25, "compress + encrypt")
    env = pack_payload(data, name, password, compress, is_text, cipher)
    _, cap = capacity(cover, m, bits)
    if cap is not None and len(env) > cap + HDR_LEN:
        raise StegoError(f"Payload needs {fmt_size(len(env))} but this carrier holds {fmt_size(cap + HDR_LEN)} "
                         f"at {bits} bit(s)/channel. Try --bits 2/4, a larger carrier, or --method append.")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    cb(.55, "embedding " + m)
    if m == "lsb-image":
        lsb_image_encode(cover, out, env, bits)
    elif m == "lsb-wav":
        lsb_wav_encode(cover, out, env, bits)
    else:
        append_encode(cover, out, env)
    cb(1, "done")
    return dict(method=m, out=out, bits=bits if m != "append" else None, size=len(env),
                capacity=None if cap is None else cap + HDR_LEN, encrypted=bool(password),
                cipher={"auto": "AES-256-GCM" if AESGCM else "SHAKE256+HMAC", "aes": "AES-256-GCM",
                        "shake": "SHAKE256+HMAC"}[cipher] if password else "none")


def read_envelope(path):
    env = append_find(path)
    if env is not None and env[:4] == MAGIC:
        return "append", env, None
    with open(path, "rb") as f:
        head = f.read(12)
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        try:
            params, frames = _wav_read(path)
            env, k = _scan_lsb(frames[0::params.sampwidth])
            if env:
                return "lsb-wav", env, k
        except StegoError:
            pass
    elif Image is not None:
        try:
            env, k = _scan_lsb(_img_open(path).convert("RGB").tobytes())
            if env:
                return "lsb-image", env, k
        except StegoError:
            pass
    raise StegoError("No hidden GhostByte data found in this file.")


def decode(path, password="", cb=None):
    cb = cb or (lambda *_: None)
    cb(.15, "scanning carrier")
    method, env, k = read_envelope(path)
    cb(.6, "decrypting")
    ver, flags, cid, *_ = parse_header(env)
    name, data, flags = unpack_payload(env, password)
    cb(1, "done")
    return dict(method=method, bits=k, name=name, data=data, is_text=bool(flags & F_TEXT),
                encrypted=bool(flags & F_ENC))


# ═══════════════════════════════ steganalysis ═══════════════════════════════
def sniff(head):
    if head.startswith(b"\x89PNG"):
        return "PNG"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
        return "WAV"
    if head[4:8] == b"ftyp":
        return "MP4"
    for sig, k in ((b"GIF8", "GIF"), (b"BM", "BMP"), (b"%PDF", "PDF"), (b"PK\x03\x04", "ZIP"), (b"ID3", "MP3")):
        if head.startswith(sig):
            return k
    return "unknown"


def bmff_boxes(path):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        pos = 0
        while pos + 8 <= size:
            f.seek(pos)
            h = f.read(16)
            sz, typ = struct.unpack(">I4s", h[:8])
            if sz == 1 and len(h) == 16:
                sz = struct.unpack(">Q", h[8:])[0]
            elif sz == 0:
                sz = size - pos
            if sz < 8:
                break
            yield pos, sz, typ
            pos += sz


def lsb_stats(data):
    """Westfeld-Pfitzmann pair-equalisation test on growing prefixes -> (best p, window)."""
    best = (0.0, 0)
    for w in sorted({min(len(data), x) for x in (4096, 32768, 262144, 1 << 20)}):
        h = [data[:w].count(bytes((i,))) for i in range(256)]
        chi, df = 0.0, 0
        for i in range(0, 256, 2):
            m = (h[i] + h[i + 1]) / 2
            if m >= 5:
                chi += (h[i] - m) ** 2 / m
                df += 1
        if df < 16:
            continue
        df -= 1
        z = ((chi / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
        p = 0.5 * math.erfc(z / math.sqrt(2))
        if p > best[0]:
            best = (p, w)
    return best


def scan(path):
    F = []
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(16)
    kind = sniff(head)
    F.append(("info", f"type: {kind}  ·  {size:,} bytes"))
    env = append_find(path)
    if env is not None:
        try:
            _, flags, *_ = parse_header(env)
            F.append(("warn", f"GhostByte payload appended: {len(env):,} bytes "
                              f"({'encrypted' if flags & F_ENC else 'not encrypted'})"))
        except StegoError:
            F.append(("warn", f"trailer marker present with an unknown {len(env):,}-byte block"))
    if kind in ("PNG", "JPEG"):
        data = open(path, "rb").read()
        i = data.rfind(b"IEND\xaeB`\x82") if kind == "PNG" else data.rfind(b"\xff\xd9")
        end = None if i < 0 else i + (8 if kind == "PNG" else 2)
        if end is None:
            F.append(("warn", "no end-of-image marker (truncated or damaged file)"))
        elif size - end > 0:
            F.append(("warn", f"{size - end:,} bytes of data after the end of the image"))
        else:
            F.append(("ok", "no data after end of image"))
    if kind == "MP4":
        sus = [(p, s) for p, s, t in bmff_boxes(path) if t in (b"free", b"skip") and s > 512]
        for p, s in sus:
            F.append(("warn", f"large 'free/skip' box at offset {p:,} ({s:,} bytes) - possible hidden data"))
        if not sus:
            F.append(("ok", "no oversized free/skip boxes"))
    carrier = None
    try:
        if kind == "WAV":
            params, frames = _wav_read(path)
            carrier = bytes(frames[0::params.sampwidth])
        elif kind in ("PNG", "BMP", "GIF") and Image is not None:
            carrier = _img_open(path).convert("RGB").tobytes()
    except StegoError as e:
        F.append(("info", str(e)))
    if carrier:
        env, k = _scan_lsb(carrier)
        if env:
            F.append(("warn", f"GhostByte LSB payload found ({k} bit/channel, {len(env):,} bytes)"))
        p, w = lsb_stats(carrier)
        win = carrier[:1 << 20]
        ones = sum(win.count(bytes((i,))) for i in range(1, 256, 2)) / max(1, len(win))
        verdict = "SUSPICIOUS - LSB pairs look equalised" if p > .85 else "looks natural"
        F.append(("warn" if p > .85 else "ok", f"LSB chi-square p={p:.2f} (window {w:,}), odd-value ratio {ones:.3f} - {verdict}"))
        F.append(("info", "statistical result is a heuristic, not proof"))
    return F


# ═════════════════════════════════ selftest ═════════════════════════════════
def selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="ghostbyte_")
    cases = []
    if Image is not None:
        p = os.path.join(d, "noise.png")
        Image.frombytes("RGB", (200, 200), os.urandom(200 * 200 * 3)).save(p)
        cases += [("PNG   lsb 1-bit", p, "auto", 1), ("PNG   lsb 2-bit", p, "auto", 2), ("PNG   lsb 4-bit", p, "auto", 4)]
        pa = os.path.join(d, "alpha.png")
        Image.merge("RGBA", [Image.frombytes("L", (100, 100), os.urandom(10000)) for _ in range(4)]).save(pa)
        cases.append(("RGBA  lsb 1-bit", pa, "auto", 1))
    pw = os.path.join(d, "tone.wav")
    with wave.open(pw, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(44100)
        w.writeframes(os.urandom(88200))
    cases.append(("WAV   lsb 1-bit", pw, "auto", 1))
    mp4 = os.path.join(d, "clip.mp4")
    open(mp4, "wb").write(struct.pack(">I4s8s", 16, b"ftyp", b"isom\0\0\2\0") + os.urandom(100_000))
    cases.append(("MP4   free box ", mp4, "auto", 1))
    mp3 = os.path.join(d, "song.mp3")
    open(mp3, "wb").write(b"ID3" + os.urandom(50_000))
    cases.append(("MP3   append   ", mp3, "auto", 1))
    bad = 0
    for label, path, method, bits in cases:
        payload = os.urandom(700)
        try:
            for pwd in ("", "s3cret!"):
                out = os.path.join(d, "out_" + os.path.basename(path))
                r = encode(path, out, payload, "blob.bin", pwd, method, bits)
                got = decode(r["out"], pwd)
                assert got["data"] == payload and got["name"] == "blob.bin", "payload mismatch"
                if pwd:
                    try:
                        decode(r["out"], "wrong")
                        raise AssertionError("wrong password accepted")
                    except StegoError:
                        pass
                if r["method"] == "append":
                    clean(r["out"], r["out"] + ".clean")
                    assert open(r["out"] + ".clean", "rb").read() == open(path, "rb").read(), "clean() mismatch"
            say("ok", f"{label}  pass")
        except Exception as e:
            bad += 1
            say("err", f"{label}  FAIL  {type(e).__name__}: {e}")
    try:
        encode(pw, os.path.join(d, "big.wav"), os.urandom(50_000))
        bad += 1
        say("err", "capacity check did not trigger")
    except StegoError:
        say("ok", "capacity guard   pass")
    shutil.rmtree(d, ignore_errors=True)
    return bad


# ═════════════════════════════════════ CLI ═════════════════════════════════════
def cmd_encode(a):
    if not os.path.isfile(a.cover):
        fail(f"carrier not found: {a.cover}")
    if a.text is not None:
        data, name, is_text = a.text.encode("utf-8"), "message.txt", True
    elif a.file:
        if not os.path.isfile(a.file):
            fail(f"payload not found: {a.file}")
        data, name, is_text = open(a.file, "rb").read(), os.path.basename(a.file), False
    else:
        fail("give a payload with -t TEXT or -f FILE")
    pw = a.password or (getpass.getpass("  password: ") if a.ask_pass else os.environ.get("GHOSTBYTE_PASS", ""))
    m = choose_method(a.cover, a.method)
    out = a.out or default_out(a.cover, m)
    res = encode(a.cover, out, data, name, pw, a.method, a.bits, not a.no_compress, a.cipher, is_text, Progress().update)
    box("HIDDEN", [("method", res["method"] + (f" ({res['bits']} bit/ch)" if res["bits"] else "")),
                   ("payload", f"{len(data):,} B  →  {res['size']:,} B packed"),
                   ("crypto", res["cipher"]),
                   ("capacity", fmt_size(res["capacity"]) if res["capacity"] else "unlimited"),
                   ("output", res["out"])])
    if res["method"] == "append":
        say("warn", "append mode is invisible to players but trivial to find with `scan` or a hex editor.")
    if res["bits"] == 4:
        say("warn", "4 bit/channel changes pixels noticeably; prefer 1-2 bits for stealth.")


def cmd_decode(a):
    if not os.path.isfile(a.stego):
        fail(f"file not found: {a.stego}")
    pw = a.password or (getpass.getpass("  password: ") if a.ask_pass else os.environ.get("GHOSTBYTE_PASS", ""))
    r = decode(a.stego, pw, Progress().update)
    if r["is_text"] and not a.out:
        say("ok", f"text message revealed ({r['method']}{'/%d-bit' % r['bits'] if r['bits'] else ''}):")
        print()
        typewrite("  " + r["data"].decode("utf-8", "replace"))
        print()
        return
    target = a.out or safe_name(r["name"])
    if os.path.isdir(target):
        target = os.path.join(target, safe_name(r["name"]))
    target = target if a.force else unique_path(target)
    open(target, "wb").write(r["data"])
    box("REVEALED", [("method", r["method"]), ("encrypted", "yes" if r["encrypted"] else "no"),
                     ("original", r["name"] or "-"), ("size", f"{len(r['data']):,} B"), ("saved", target)])


def cmd_scan(a):
    for p in a.files:
        if not os.path.isfile(p):
            say("err", f"not found: {p}")
            continue
        print(" " + gradient_text("▌ " + p, bold=True))
        for kind, msg in scan(p):
            say(kind, msg)
        print()


def cmd_clean(a):
    stem, ext = os.path.splitext(a.file)
    out = a.out or f"{stem}_clean{ext}"
    n = clean(a.file, out)
    say("ok", f"payload stripped - {n:,} bytes written to {out}")


def cmd_capacity(a):
    m, cap = capacity(a.file, a.method, a.bits)
    box("CAPACITY", [("file", os.path.basename(a.file)), ("method", m),
                     ("bits", a.bits if m != "append" else "-"), ("holds", fmt_size(cap))])


def cmd_themes(_a):
    for name, th in THEMES.items():
        print("  " + paint(f"{name:<10}", th["accent"], True) + gradient_text("█" * 36, th["stops"]))


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--theme", choices=list(THEMES), default=argparse.SUPPRESS, help="colour theme")
    common.add_argument("--no-fx", action="store_true", default=argparse.SUPPRESS, help="disable animations")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS)
    common.add_argument("--no-banner", action="store_true", default=argparse.SUPPRESS)
    ap = argparse.ArgumentParser(prog="ghostbyte", description=f"{APP} - steganography toolkit", parents=[common])
    sub = ap.add_subparsers(dest="cmd")
    e = sub.add_parser("encode", aliases=["hide"], parents=[common], help="hide text/file inside a carrier")
    e.add_argument("cover")
    g = e.add_mutually_exclusive_group()
    g.add_argument("-t", "--text")
    g.add_argument("-f", "--file")
    e.add_argument("-o", "--out")
    e.add_argument("-m", "--method", choices=["auto", "lsb", "append"], default="auto")
    e.add_argument("-b", "--bits", type=int, choices=[1, 2, 4], default=1)
    e.add_argument("-p", "--password", default="")
    e.add_argument("-P", "--ask-pass", action="store_true")
    e.add_argument("--cipher", choices=["auto", "aes", "shake"], default="auto")
    e.add_argument("--no-compress", action="store_true")
    d = sub.add_parser("decode", aliases=["reveal"], parents=[common], help="extract hidden data")
    d.add_argument("stego")
    d.add_argument("-o", "--out", help="file or folder to save to")
    d.add_argument("-p", "--password", default="")
    d.add_argument("-P", "--ask-pass", action="store_true")
    d.add_argument("--force", action="store_true", help="overwrite existing output")
    s = sub.add_parser("scan", parents=[common], help="look for hidden data / anomalies")
    s.add_argument("files", nargs="+")
    c = sub.add_parser("clean", parents=[common], help="strip an appended payload")
    c.add_argument("file")
    c.add_argument("-o", "--out")
    k = sub.add_parser("capacity", parents=[common], help="how much fits in a carrier")
    k.add_argument("file")
    k.add_argument("-m", "--method", choices=["auto", "lsb", "append"], default="auto")
    k.add_argument("-b", "--bits", type=int, choices=[1, 2, 4], default=1)
    sub.add_parser("gui", parents=[common], help="open the graphical interface")
    sub.add_parser("themes", parents=[common], help="preview colour themes")
    sub.add_parser("selftest", parents=[common], help="round-trip tests on generated files")
    return ap


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    T.theme = THEMES[getattr(a, "theme", "cyberpunk")]
    if getattr(a, "no_color", False):
        T.color = False
    if getattr(a, "no_fx", False):
        T.fx = False
    cmd = {"hide": "encode", "reveal": "decode"}.get(a.cmd, a.cmd)
    if cmd in (None, "gui"):
        return launch_gui()
    if not getattr(a, "no_banner", False) and cmd != "selftest" or cmd == "themes":
        show_banner()
    try:
        if cmd == "selftest":
            show_banner()
            bad = selftest()
            say("ok" if not bad else "err", "all tests passed" if not bad else f"{bad} test(s) failed")
            return 1 if bad else 0
        {"encode": cmd_encode, "decode": cmd_decode, "scan": cmd_scan, "clean": cmd_clean,
         "capacity": cmd_capacity, "themes": cmd_themes}[cmd](a)
    except StegoError as e:
        fail(str(e))
    except KeyboardInterrupt:
        print()
        return 130
    return 0


# ═════════════════════════════════════ GUI ═════════════════════════════════════
def launch_gui():
    try:
        import tkinter  # noqa: F401
    except ImportError:
        fail("tkinter is missing (Debian/Ubuntu: sudo apt install python3-tk). The CLI still works.")
    try:
        run_gui()
    except Exception as e:  # no display, etc.
        if type(e).__name__ == "TclError":
            fail(f"cannot open a window here ({e}). Use the CLI: ghostbyte.py --help")
        raise
    return 0


def run_gui():
    import copy
    import colorsys
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, colorchooser, font as tkfont

    ICON = {"ok": "[+]", "err": "[x]", "warn": "[!]", "info": "[*]"}
    RAIN = "01ABCDEF0123456789<>/\\|=+*#$%&"

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"{APP} {VERSION}  ·  steganography toolkit")
            self.geometry("960x920")
            self.minsize(880, 780)
            self.q = queue.Queue()
            self.pal = copy.deepcopy(THEMES["cyberpunk"])
            self.style = ttk.Style(self)
            self.style.theme_use("clam")
            fams = set(tkfont.families())
            self.fonts = [f for f in ("JetBrains Mono", "Fira Code", "Cascadia Code", "Consolas", "Menlo",
                                      "DejaVu Sans Mono", "Courier New", "Helvetica", "Segoe UI", "Georgia")
                          if f in fams] or [tkfont.nametofont("TkFixedFont").actual("family")]
            sv = lambda v="": tk.StringVar(value=v)
            self.v_cover, self.v_mode, self.v_payload, self.v_out = sv(), sv("text"), sv(), sv()
            self.v_method, self.v_bits, self.v_cipher, self.v_pw = sv("auto"), sv("1"), sv("auto"), sv()
            self.v_din, self.v_dpw, self.v_ddir, self.v_sin = sv(), sv(), sv(), sv()
            self.v_theme, self.v_fx, self.v_font = sv("cyberpunk"), sv("rain"), sv(self.fonts[0])
            self.v_compress, self.v_showpw, self.v_shimmer = tk.BooleanVar(value=True), tk.BooleanVar(), tk.BooleanVar(value=True)
            self.v_speed, self.v_size = tk.DoubleVar(value=1.0), tk.IntVar(value=10)
            self.v_status = sv("ready")
            self._auto_out, self.phase, self.pv_img = "", 0.0, None
            self.rain_items, self.stars, self.bcells, self.heads = [], [], [], []

            self.hdr = tk.Canvas(self, height=156, highlightthickness=0, bd=0)
            self.hdr.pack(fill="x")
            self._hdr_job = None
            self.hdr.bind("<Configure>", self._hdr_resized)
            self.nb = ttk.Notebook(self)
            self.nb.pack(fill="both", expand=True, padx=14, pady=(12, 6))
            self._tab_encode()
            self._tab_decode()
            self._tab_scan()
            self._tab_style()
            self.prog = ttk.Progressbar(self, maximum=100)
            self.prog.pack(fill="x", padx=14, pady=(0, 6))
            lf = ttk.Frame(self, style="Bar.TFrame")
            lf.pack(fill="x", padx=14, pady=(0, 4))
            self.log_w = tk.Text(lf, height=8, wrap="word", bd=0, highlightthickness=1, state="disabled")
            sb = ttk.Scrollbar(lf, command=self.log_w.yview)
            self.log_w.configure(yscrollcommand=sb.set)
            self.log_w.pack(side="left", fill="x", expand=True)
            sb.pack(side="right", fill="y")
            ttk.Label(self, textvariable=self.v_status, style="Bar.TLabel").pack(fill="x", padx=14, pady=(0, 8))
            for v in (self.v_cover, self.v_method, self.v_bits):
                v.trace_add("write", self._cover_changed)
            self.v_showpw.trace_add("write", lambda *_: self.e_pw.config(show="" if self.v_showpw.get() else "•"))
            self.apply_theme()
            self.say(f"{APP} ready - " + ("AES-256-GCM available" if AESGCM else "stdlib cipher (pip install cryptography for AES-GCM)")
                     + ("" if Image else "  ·  Pillow missing: images limited to append mode"), "info")
            self.after(50, self._poll)
            self.after(70, self._tick)

        # ── layout helpers ──
        def _row(self, parent, r, text, var, cmd=None, btn="Browse…", show=""):
            ttk.Label(parent, text=text).grid(row=r, column=0, sticky="w", padx=8, pady=5)
            e = ttk.Entry(parent, textvariable=var, show=show)
            e.grid(row=r, column=1, sticky="ew", padx=8, pady=5)
            if cmd:
                ttk.Button(parent, text=btn, command=cmd).grid(row=r, column=2, padx=8, pady=5)
            return e

        def _combo(self, parent, var, values, width=9):
            return ttk.Combobox(parent, textvariable=var, values=values, width=width, state="readonly")

        def _tab_encode(self):
            t = ttk.Frame(self.nb)
            self.nb.add(t, text="   Encode   ")
            t.columnconfigure(1, weight=1)
            self._row(t, 0, "Carrier", self.v_cover, lambda: self._pick(self.v_cover, "Choose carrier file"))
            mf = ttk.Frame(t)
            mf.grid(row=1, column=0, columnspan=3, sticky="w", padx=8)
            ttk.Label(mf, text="Payload").pack(side="left")
            for txt, val in (("Text message", "text"), ("File", "file")):
                ttk.Radiobutton(mf, text=txt, value=val, variable=self.v_mode).pack(side="left", padx=12)
            self.msg = tk.Text(t, height=5, wrap="word", bd=0, highlightthickness=1)
            self.msg.grid(row=2, column=0, columnspan=3, sticky="ew", padx=8, pady=4)
            self._row(t, 3, "Payload file", self.v_payload, lambda: self._pick(self.v_payload, "Choose payload file"))
            self._row(t, 4, "Output", self.v_out, self._save_as, "Save as…")
            of = ttk.Frame(t)
            of.grid(row=5, column=0, columnspan=3, sticky="w", padx=8, pady=4)
            for lbl, var, vals in (("Method", self.v_method, ["auto", "lsb", "append"]),
                                   ("Bits", self.v_bits, ["1", "2", "4"]),
                                   ("Cipher", self.v_cipher, ["auto", "aes", "shake"])):
                ttk.Label(of, text=lbl).pack(side="left", padx=(0, 6))
                self._combo(of, var, vals, 7).pack(side="left", padx=(0, 18))
            ttk.Checkbutton(of, text="Compress", variable=self.v_compress).pack(side="left")
            self.e_pw = self._row(t, 6, "Password", self.v_pw, show="•")
            ttk.Checkbutton(t, text="show", variable=self.v_showpw).grid(row=6, column=2, padx=8)
            self.cap = ttk.Label(t, text="", style="Dim.TLabel")
            self.cap.grid(row=7, column=0, columnspan=3, sticky="w", padx=8, pady=2)
            ttk.Button(t, text="HIDE DATA", style="Accent.TButton", command=self.do_encode)\
                .grid(row=8, column=0, columnspan=3, sticky="ew", padx=8, pady=10)
            self.pv = ttk.Label(t, anchor="n", justify="center", style="Dim.TLabel", width=26)
            self.pv.grid(row=0, column=3, rowspan=8, sticky="n", padx=10, pady=8)

        def _tab_decode(self):
            t = ttk.Frame(self.nb)
            self.nb.add(t, text="   Decode   ")
            t.columnconfigure(1, weight=1)
            self._row(t, 0, "Stego file", self.v_din, lambda: self._pick(self.v_din, "Choose stego file"))
            self._row(t, 1, "Password", self.v_dpw, show="•")
            self._row(t, 2, "Save files to", self.v_ddir, self._pickdir, "Choose…")
            ttk.Button(t, text="REVEAL DATA", style="Accent.TButton", command=self.do_decode)\
                .grid(row=3, column=0, columnspan=3, sticky="ew", padx=8, pady=10)
            self.out_text = tk.Text(t, height=9, wrap="word", bd=0, highlightthickness=1)
            self.out_text.grid(row=4, column=0, columnspan=3, sticky="nsew", padx=8, pady=4)
            ttk.Button(t, text="Copy text", command=self._copy).grid(row=5, column=2, padx=8, pady=4, sticky="e")
            t.rowconfigure(4, weight=1)

        def _tab_scan(self):
            t = ttk.Frame(self.nb)
            self.nb.add(t, text="   Scan   ")
            t.columnconfigure(1, weight=1)
            self._row(t, 0, "File", self.v_sin, lambda: self._pick(self.v_sin, "Choose file to inspect"))
            bf = ttk.Frame(t)
            bf.grid(row=1, column=0, columnspan=3, sticky="w", padx=8, pady=10)
            ttk.Button(bf, text="Analyze", style="Accent.TButton", command=self.do_scan).pack(side="left", padx=(0, 10))
            ttk.Button(bf, text="Strip appended payload…", command=self.do_clean).pack(side="left")
            ttk.Label(t, style="Dim.TLabel", wraplength=700, justify="left",
                      text="Checks for appended GhostByte data, bytes after the image/MP4 structure, "
                           "LSB payload signatures and LSB statistics (chi-square). Results appear in the log below."
                      ).grid(row=2, column=0, columnspan=3, sticky="w", padx=8)

        def _tab_style(self):
            t = ttk.Frame(self.nb)
            self.nb.add(t, text="   Style   ")
            t.columnconfigure(1, weight=1)
            r = 0
            for lbl, var, vals, cb in (("Theme", self.v_theme, list(THEMES), self._on_theme),
                                       ("Header effect", self.v_fx, ["rain", "stars", "none"], lambda *_: self._hdr_build()),
                                       ("Font", self.v_font, self.fonts, lambda *_: self.apply_theme())):
                ttk.Label(t, text=lbl).grid(row=r, column=0, sticky="w", padx=8, pady=6)
                c = self._combo(t, var, vals, 22)
                c.grid(row=r, column=1, sticky="w", padx=8, pady=6)
                c.bind("<<ComboboxSelected>>", cb)
                r += 1
            ttk.Label(t, text="Font size").grid(row=r, column=0, sticky="w", padx=8, pady=6)
            sp = ttk.Spinbox(t, from_=8, to=18, textvariable=self.v_size, width=5, command=self.apply_theme)
            sp.grid(row=r, column=1, sticky="w", padx=8)
            sp.bind("<Return>", lambda e: self.apply_theme())
            r += 1
            ttk.Label(t, text="Effect speed").grid(row=r, column=0, sticky="w", padx=8, pady=6)
            ttk.Scale(t, from_=0.2, to=2.5, variable=self.v_speed, length=220).grid(row=r, column=1, sticky="w", padx=8)
            r += 1
            ttk.Checkbutton(t, text="Shimmer banner", variable=self.v_shimmer).grid(row=r, column=1, sticky="w", padx=8, pady=6)
            r += 1
            cf = ttk.Frame(t)
            cf.grid(row=r, column=0, columnspan=3, sticky="w", padx=8, pady=10)
            for lbl, key in (("Accent", "accent"), ("Second accent", "accent2"), ("Text colour", "fg"),
                             ("Background", "bg"), ("Panel", "panel")):
                ttk.Button(cf, text=lbl, command=lambda k=key: self._pick_color(k)).pack(side="left", padx=(0, 8))
            ttk.Button(cf, text="Randomize", style="Accent.TButton", command=self._randomize).pack(side="left", padx=(8, 0))

        # ── theme engine ──
        def apply_theme(self):
            p, s, hx = self.pal, self.style, hexc
            bg, panel, fg, ac, ac2 = hx(p["bg"]), hx(p["panel"]), hx(p["fg"]), hx(p["accent"]), hx(p["accent2"])
            dim = hx(lerp(p["fg"], p["panel"], .45))
            fam, size = self.v_font.get(), int(self.v_size.get() or 10)
            for n in ("TkDefaultFont", "TkTextFont", "TkFixedFont", "TkMenuFont", "TkHeadingFont"):
                tkfont.nametofont(n).configure(family=fam, size=size)
            self.configure(bg=bg)
            self.hdr.configure(bg=bg)
            s.configure(".", background=panel, foreground=fg, fieldbackground=bg, bordercolor=panel,
                        lightcolor=panel, darkcolor=panel, troughcolor=bg, focuscolor=ac, insertcolor=ac)
            s.configure("TLabel", background=panel, foreground=fg)
            s.configure("Dim.TLabel", background=panel, foreground=dim)
            s.configure("Bar.TLabel", background=bg, foreground=dim)
            s.configure("Bar.TFrame", background=bg)
            s.configure("TButton", background=bg, foreground=ac, bordercolor=ac, lightcolor=bg, darkcolor=bg, padding=7, relief="flat")
            s.map("TButton", background=[("active", ac), ("pressed", ac2)], foreground=[("active", bg), ("pressed", bg)])
            s.configure("Accent.TButton", background=ac2, foreground=bg, padding=10, font=(fam, size, "bold"))
            s.map("Accent.TButton", background=[("active", ac), ("pressed", ac)], foreground=[("active", bg)])
            s.configure("TEntry", fieldbackground=bg, foreground=fg, bordercolor=panel, insertcolor=ac, padding=4)
            s.map("TEntry", bordercolor=[("focus", ac)])
            s.configure("TCombobox", fieldbackground=bg, background=panel, foreground=fg, arrowcolor=ac, bordercolor=panel, padding=3)
            s.map("TCombobox", fieldbackground=[("readonly", bg)], foreground=[("readonly", fg)],
                  selectbackground=[("readonly", bg)], selectforeground=[("readonly", fg)], bordercolor=[("focus", ac)])
            s.configure("TSpinbox", fieldbackground=bg, foreground=fg, arrowcolor=ac, background=panel)
            s.configure("TNotebook", background=bg, bordercolor=bg, tabmargins=(0, 0, 0, 0))
            s.configure("TNotebook.Tab", background=bg, foreground=dim, padding=(16, 8), bordercolor=bg)
            s.map("TNotebook.Tab", background=[("selected", panel)], foreground=[("selected", ac)])
            for w in ("TCheckbutton", "TRadiobutton"):
                s.configure(w, background=panel, foreground=fg, indicatorcolor=bg)
                s.map(w, background=[("active", panel)], indicatorcolor=[("selected", ac), ("active", ac2)])
            s.configure("Horizontal.TProgressbar", troughcolor=bg, background=ac, bordercolor=bg, lightcolor=ac, darkcolor=ac2)
            s.configure("Horizontal.TScale", background=panel, troughcolor=bg)
            s.configure("Vertical.TScrollbar", background=panel, troughcolor=bg, arrowcolor=ac, bordercolor=bg)
            self.option_add("*TCombobox*Listbox.background", bg)
            self.option_add("*TCombobox*Listbox.foreground", fg)
            self.option_add("*TCombobox*Listbox.selectBackground", ac)
            self.option_add("*TCombobox*Listbox.selectForeground", bg)
            for w in (self.msg, self.out_text, self.log_w):
                w.configure(bg=bg, fg=fg, insertbackground=ac, selectbackground=ac2, selectforeground=bg,
                            highlightbackground=panel, highlightcolor=ac)
            for tag in ("ok", "err", "warn", "info"):
                self.log_w.tag_configure(tag, foreground=hx(p[{"info": "accent"}.get(tag, tag)]))
            self._hdr_build()

        def _on_theme(self, *_):
            self.pal = copy.deepcopy(THEMES[self.v_theme.get()])
            self.apply_theme()

        def _pick_color(self, key):
            c = colorchooser.askcolor(color=hexc(self.pal[key]), title=f"Pick {key}")
            if c and c[0]:
                self.pal[key] = tuple(int(x) for x in c[0])
                if key in ("accent", "accent2"):
                    self.pal["stops"] = [self.pal["accent2"], self.pal["accent"]]
                self.apply_theme()

        def _randomize(self):
            h = random.random()
            rgb = lambda hh, s, v: tuple(int(x * 255) for x in colorsys.hsv_to_rgb(hh % 1, s, v))
            self.pal.update(accent=rgb(h, .85, 1), accent2=rgb(h + .5, .85, 1), bg=rgb(h + .55, .5, .08),
                            panel=rgb(h + .55, .45, .17), fg=rgb(h, .08, 1))
            self.pal["stops"] = [self.pal["accent2"], rgb(h + .25, .9, 1), self.pal["accent"]]
            self.apply_theme()

        # ── animated header ──
        def _hdr_resized(self, _e=None):
            if self._hdr_job:
                self.after_cancel(self._hdr_job)
            self._hdr_job = self.after(120, self._hdr_build)

        def _hdr_build(self):
            self._hdr_job = None
            c = self.hdr
            c.delete("all")
            w, h = max(c.winfo_width(), 500), int(c["height"])
            bg, mode = hexc(self.pal["bg"]), self.v_fx.get()
            self.cell = 14
            self.cols, self.rows = w // self.cell + 1, h // self.cell + 1
            self.rain_items, self.stars, self.bcells = [], [], []
            self.hw = w
            if mode == "rain":
                self.rain_items = [[c.create_text(i * self.cell + 7, j * self.cell + 7, text=" ", fill=bg,
                                                  font=("Courier", 10, "bold")) for j in range(self.rows)]
                                   for i in range(self.cols)]
                self.heads = [random.randint(-2 * self.rows, self.rows) for _ in range(self.cols)]
            elif mode == "stars":
                for _ in range(110):
                    x, y, s = random.uniform(0, w), random.uniform(0, h), random.choice((1, 2, 3))
                    self.stars.append([c.create_oval(x, y, x + s, y + s, fill=bg, outline=""), x, y, s])
            rows = banner_matrix()
            px = 7
            x0, y0 = (w - len(rows[0]) * px) // 2, 38
            shadow = hexc(lerp(self.pal["accent2"], self.pal["bg"], .72))
            cells = [(x, r) for r, row in enumerate(rows) for x, ch in enumerate(row) if ch == "#"]
            for x, r in cells:
                X, Y = x0 + x * px, y0 + r * px
                c.create_rectangle(X + 3, Y + 3, X + px + 2, Y + px + 2, fill=shadow, outline="")
            for x, r in cells:
                X, Y = x0 + x * px, y0 + r * px
                self.bcells.append((c.create_rectangle(X, Y, X + px - 1, Y + px - 1, fill=bg, outline=""),
                                    (x + r * 2) / (len(rows[0]) + 8)))
            c.create_text(w // 2, y0 + 5 * px + 26, text="◢◤  " + TAGLINE + "  ◥◣", fill=hexc(self.pal["accent"]),
                          font=(self.v_font.get(), 11, "bold"))
            self._recolor_banner()

        def _recolor_banner(self):
            st = self.pal["stops"]
            for item, u in self.bcells:
                t = abs(((u + self.phase) % 1) * 2 - 1)
                self.hdr.itemconfigure(item, fill=hexc(grad(st, t)))

        def _tick(self):
            sp = self.v_speed.get()
            self.phase = (self.phase + .012 * sp) % 1
            if self.v_shimmer.get():
                self._recolor_banner()
            c, bg, st = self.hdr, self.pal["bg"], self.pal["stops"]
            if self.rain_items:
                for i in range(self.cols):
                    if random.random() < min(1, .45 * sp):
                        self.heads[i] += 1
                    hd = self.heads[i]
                    if hd - 10 > self.rows:
                        if random.random() < .08:
                            self.heads[i] = random.randint(-8, 0)
                        continue
                    base = grad(st, i / max(1, self.cols))
                    for t in range(10):
                        r = hd - t
                        if 0 <= r < self.rows:
                            col = lerp(bg, grad(st, .95), .8) if t == 0 else lerp(bg, base, .62 * (1 - t / 10))
                            if t == 0:
                                c.itemconfigure(self.rain_items[i][r], text=random.choice(RAIN), fill=hexc(col))
                            else:
                                c.itemconfigure(self.rain_items[i][r], fill=hexc(col))
                    r = hd - 10
                    if 0 <= r < self.rows:
                        c.itemconfigure(self.rain_items[i][r], fill=hexc(bg))
            for s in self.stars:
                s[1] -= s[3] * .7 * sp
                if s[1] < -4:
                    s[1], s[2] = self.hw + 2, random.uniform(0, int(c["height"]))
                c.coords(s[0], s[1], s[2], s[1] + s[3], s[2] + s[3])
                c.itemconfigure(s[0], fill=hexc(lerp(bg, self.pal["fg"], s[3] / 3.4)))
            self.after(70, self._tick)

        # ── logging / threads ──
        def say(self, msg, tag="info"):
            w = self.log_w
            w.config(state="normal")
            w.insert("end", f"{ICON[tag]} {msg}\n", tag)
            w.see("end")
            w.config(state="disabled")

        def _warn(self, msg):
            self.say(msg, "warn")
            messagebox.showwarning(APP, msg)

        def run_bg(self, fn, done):
            self.v_status.set("working…")

            def work():
                try:
                    self.q.put(("done", done, fn(lambda f, l="": self.q.put(("prog", f, l)))))
                except StegoError as e:
                    self.q.put(("err", None, str(e)))
                except Exception as e:  # noqa: BLE001
                    self.q.put(("err", None, f"{type(e).__name__}: {e}"))
            threading.Thread(target=work, daemon=True).start()

        def _poll(self):
            try:
                while True:
                    kind, a, b = self.q.get_nowait()
                    if kind == "prog":
                        self.prog["value"] = a * 100
                        self.v_status.set(b)
                    elif kind == "done":
                        self.prog["value"] = 0
                        self.v_status.set("ready")
                        a(b)
                    else:
                        self.prog["value"] = 0
                        self.v_status.set("ready")
                        self.say(b, "err")
                        messagebox.showerror(APP, b)
            except queue.Empty:
                pass
            self.after(50, self._poll)

        # ── actions ──
        def _pick(self, var, title):
            p = filedialog.askopenfilename(title=title)
            if p:
                var.set(p)

        def _pickdir(self):
            p = filedialog.askdirectory(title="Save extracted files to")
            if p:
                self.v_ddir.set(p)

        def _save_as(self):
            p = filedialog.asksaveasfilename(title="Save stego file as", initialfile=os.path.basename(self.v_out.get()))
            if p:
                self.v_out.set(p)

        def _copy(self):
            self.clipboard_clear()
            self.clipboard_append(self.out_text.get("1.0", "end-1c"))

        def _preview(self, path):
            self.pv_img = None
            if path and Image is not None and os.path.splitext(path)[1].lower() in IMG_ANY:
                try:
                    im = Image.open(path)
                    im.thumbnail((230, 170))
                    buf = io.BytesIO()
                    im.convert("RGB").save(buf, "PNG")
                    self.pv_img = tk.PhotoImage(data=base64.b64encode(buf.getvalue()))
                except Exception:  # noqa: BLE001
                    self.pv_img = None
            txt = "" if (not path or self.pv_img) else f"{os.path.splitext(path)[1].upper() or 'FILE'}\n{fmt_size(os.path.getsize(path))}"
            if self.pv_img is not None:
                self.pv.config(image=self.pv_img, text="", compound="top")
            else:
                self.pv.config(image="", text=txt)

        def _cover_changed(self, *_):
            p = self.v_cover.get().strip()
            if not os.path.isfile(p):
                self.cap.config(text="")
                self._preview(None)
                return
            self._preview(p)
            try:
                m = choose_method(p, self.v_method.get())
                auto = default_out(p, m)
                if self.v_out.get() in ("", self._auto_out):
                    self.v_out.set(auto)
                    self._auto_out = auto
                _, cap = capacity(p, self.v_method.get(), int(self.v_bits.get()))
                txt = f"mode: {m}   ·   capacity ≈ {fmt_size(cap)}" if cap is not None else f"mode: {m}   ·   capacity: unlimited (data is appended)"
            except Exception as e:  # noqa: BLE001
                txt = f"⚠ {e}"
            self.cap.config(text=txt)

        def do_encode(self):
            try:
                cover = self.v_cover.get().strip()
                if not os.path.isfile(cover):
                    return self._warn("Choose a carrier file first.")
                if self.v_mode.get() == "text":
                    txt = self.msg.get("1.0", "end-1c")
                    if not txt:
                        return self._warn("Type a message to hide (or switch Payload to File).")
                    data, name, is_text = txt.encode("utf-8"), "message.txt", True
                else:
                    pf = self.v_payload.get().strip()
                    if not os.path.isfile(pf):
                        return self._warn("Choose a payload file first.")
                    data, name, is_text = open(pf, "rb").read(), os.path.basename(pf), False
                out = self.v_out.get().strip() or default_out(cover, choose_method(cover, self.v_method.get()))
                kw = dict(name=name, password=self.v_pw.get(), method=self.v_method.get(), bits=int(self.v_bits.get()),
                          compress=self.v_compress.get(), cipher=self.v_cipher.get(), is_text=is_text)
                self.run_bg(lambda cb: encode(cover, out, data, cb=cb, **kw), self._enc_done)
            except StegoError as e:
                self.say(str(e), "err")
                messagebox.showerror(APP, str(e))

        def _enc_done(self, r):
            self.say(f"hidden {r['size']:,} B via {r['method']}" + (f" ({r['bits']} bit)" if r["bits"] else "")
                     + f"  ·  crypto: {r['cipher']}", "ok")
            self.say(f"saved → {r['out']}", "ok")
            if r["method"] == "append":
                self.say("append mode is easy to find with Scan or a hex editor.", "warn")
            self.v_din.set(r["out"])
            self._preview(r["out"])

        def do_decode(self):
            p = self.v_din.get().strip()
            if not os.path.isfile(p):
                return self._warn("Choose a stego file first.")
            pw = self.v_dpw.get()
            self.run_bg(lambda cb: decode(p, pw, cb=cb), self._dec_done)

        def _dec_done(self, r):
            self.say(f"revealed via {r['method']}" + (f" ({r['bits']} bit)" if r["bits"] else "")
                     + (" · was encrypted" if r["encrypted"] else ""), "ok")
            self.out_text.delete("1.0", "end")
            if r["is_text"]:
                self.out_text.insert("1.0", r["data"].decode("utf-8", "replace"))
                return
            d = self.v_ddir.get().strip() or os.path.dirname(self.v_din.get()) or "."
            os.makedirs(d, exist_ok=True)
            path = unique_path(os.path.join(d, safe_name(r["name"])))
            with open(path, "wb") as f:
                f.write(r["data"])
            self.out_text.insert("1.0", f"File extracted ({len(r['data']):,} bytes):\n{path}")
            self.say(f"saved → {path}", "ok")

        def do_scan(self):
            p = self.v_sin.get().strip()
            if not os.path.isfile(p):
                return self._warn("Choose a file to inspect first.")
            self.run_bg(lambda cb: scan(p), self._scan_done)

        def _scan_done(self, findings):
            self.say("— scan: " + os.path.basename(self.v_sin.get()), "info")
            for kind, msg in findings:
                self.say(msg, kind)

        def do_clean(self):
            p = self.v_sin.get().strip()
            if not os.path.isfile(p):
                return self._warn("Choose a file to clean first.")
            out = filedialog.asksaveasfilename(title="Save cleaned copy as",
                                               initialfile=os.path.basename("_clean".join(os.path.splitext(p))))
            if out:
                self.run_bg(lambda cb: clean(p, out), lambda n: self.say(f"payload stripped → {out}", "ok"))

    App().mainloop()


if __name__ == "__main__":
    sys.exit(main())
