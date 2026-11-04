"""Certificate rendering (Pillow). Logo/seal/signature live in data/assets/*.png so the Red Team's
visual-tampering module can swap them. QR decoding uses OpenCV (no system libs needed)."""
import io, os
import cv2, numpy as np, qrcode
from PIL import Image, ImageDraw, ImageFont
from config import DATA, INSTITUTION
AS = os.path.join(DATA, "assets")

def font(sz, bold=False):
    n = "DejaVuSerif-Bold.ttf" if bold else "DejaVuSerif.ttf"
    for p in (f"/usr/share/fonts/truetype/dejavu/{n}", n, "arial.ttf"):
        try: return ImageFont.truetype(p, sz)
        except OSError: pass
    return ImageFont.load_default(size=sz)

def ensure_assets():
    os.makedirs(AS, exist_ok=True)
    if os.path.exists(f"{AS}/logo.png"): return
    im = Image.new("RGBA", (160, 160)); d = ImageDraw.Draw(im)
    d.ellipse((4, 4, 156, 156), fill=(20, 38, 79, 255)); d.text((80, 80), "SNU", fill="white", font=font(46, True), anchor="mm")
    im.save(f"{AS}/logo.png")
    im = Image.new("RGBA", (200, 200)); d = ImageDraw.Draw(im)
    d.ellipse((4, 4, 196, 196), outline=(184, 137, 43, 255), width=8); d.ellipse((24, 24, 176, 176), outline=(184, 137, 43, 255), width=3)
    d.text((100, 100), "OFFICIAL\nSEAL", fill=(184, 137, 43, 255), font=font(26, True), anchor="mm", align="center")
    im.save(f"{AS}/seal.png")
    im = Image.new("RGBA", (300, 110)); d = ImageDraw.Draw(im)
    d.line([(10, 80), (50, 30), (80, 90), (120, 25), (150, 85), (200, 40), (290, 70)], fill=(20, 38, 79, 255), width=4, joint="curve")
    im.save(f"{AS}/signature.png")

def build_certificate(r, qr_url):
    W, H = 1240, 877
    im = Image.new("RGB", (W, H), (252, 250, 244)); d = ImageDraw.Draw(im)
    d.rectangle((25, 25, W - 25, H - 25), outline=(20, 38, 79), width=6); d.rectangle((45, 45, W - 45, H - 45), outline=(184, 137, 43), width=2)
    logo = Image.open(f"{AS}/logo.png"); im.paste(logo, (W // 2 - 80, 70), logo)
    c = lambda y, t, f, fill=(20, 38, 79): d.text((W // 2, y), t, font=f, fill=fill, anchor="mm")
    c(285, INSTITUTION.upper(), font(34, True)); c(340, "CERTIFICATE OF ACADEMIC ACHIEVEMENT", font(24), (90, 90, 90))
    c(420, "This is to certify that", font(22), (90, 90, 90)); c(490, r["name"], font(52, True))
    c(565, "has successfully completed", font(22), (90, 90, 90)); c(620, r["programme"], font(34, True))
    c(685, f"with Grade  {r['grade']}", font(32)); c(735, f"Issued on {r['issue_date']}", font(22), (90, 90, 90))
    seal = Image.open(f"{AS}/seal.png").resize((150, 150)); im.paste(seal, (110, 680), seal)
    sig = Image.open(f"{AS}/signature.png"); im.paste(sig, (W // 2 - 150, 745), sig)
    d.line((W // 2 - 160, 835, W // 2 + 160, 835), fill=(60, 60, 60), width=2)
    q = qrcode.make(qr_url, box_size=6, border=2).convert("RGB").resize((190, 190), Image.NEAREST); im.paste(q, (W - 300, 650))
    d.text((W - 205, 852), f"ID: {r['cert_id']}", font=font(18), fill=(60, 60, 60), anchor="mm")
    buf = io.BytesIO(); im.save(buf, "PNG"); return buf.getvalue()

def decode_qr(data: bytes):
    try:
        img = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
        det = cv2.QRCodeDetector()
        h, w = img.shape[:2]
        for view in (img, img[h // 2:, w // 2:], img[int(h * .65):, int(w * .7):]):   # full image, then lower-right crops
            txt = det.detectAndDecode(np.ascontiguousarray(view))[0]
            if txt: return txt
    except Exception:
        pass
    return None
