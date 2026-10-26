import io
import re

import pytesseract
import requests
from PIL import Image, ImageFilter, ImageOps

from .config import logger

# whitelist alphanumerique : les captchas de ce TP sont des lettres/chiffres
_OCR_CONFIG = (
    "--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)


class Captcha:
    """Resolution d'un captcha image : capture, pretraitement PIL, OCR pytesseract."""

    def __init__(self, source, session: requests.Session | None = None):
        # source : une URL (str) a telecharger, ou directement des octets d'image
        self.source = source
        self.session = session or requests.Session()
        self.image: Image.Image | None = None
        self.value = ""

    def capture(self) -> Image.Image:
        """Charge l'image du captcha depuis l'URL ou les octets fournis."""
        if isinstance(self.source, (bytes, bytearray)):
            data = bytes(self.source)
        else:
            data = self.session.get(self.source, timeout=10).content
        self.image = Image.open(io.BytesIO(data))
        return self.image

    def preprocess(self, image: Image.Image | None = None) -> Image.Image:
        """Nettoie l'image pour l'OCR : gris, agrandissement, contraste, binarisation, anti-bruit."""
        img = image or self.image
        if img is None:
            raise RuntimeError("aucune image a pretraiter (appeler capture d'abord)")
        img = img.convert("L")
        width, height = img.size
        img = img.resize((width * 3, height * 3), Image.LANCZOS)
        img = ImageOps.autocontrast(img)
        img = img.point(lambda p: 0 if p < 140 else 255)
        img = img.filter(ImageFilter.MedianFilter(3))
        return img

    def solve(self) -> str:
        """Capture si besoin, pretraite, lit le texte et ne garde que l'alphanumerique."""
        if self.image is None:
            self.capture()
        processed = self.preprocess()
        raw = pytesseract.image_to_string(processed, config=_OCR_CONFIG)
        self.value = re.sub(r"[^A-Za-z0-9]", "", raw)
        logger.info(f"captcha lu par OCR : '{self.value}'")
        return self.value

    def get_value(self) -> str:
        """Renvoie la derniere valeur resolue du captcha."""
        return self.value
