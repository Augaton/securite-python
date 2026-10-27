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


def agrandir_img_x3(img: Image.Image) -> Image.Image:
    largeur, hauteur = img.size
    return img.resize((largeur * 3, hauteur * 3), Image.LANCZOS)


def binariser_img(img: Image.Image) -> Image.Image:
    return img.point(lambda p: 0 if p < 140 else 255)


def nettoyer_txt_ocr(raw: str) -> str:
    """Ne garde que l'alphanumerique lu par tesseract."""
    return re.sub(r"[^A-Za-z0-9]", "", raw)


class Captcha:
    """Resolution d'un captcha image : capture, pretraitement PIL, OCR pytesseract."""

    def __init__(self, source, session: requests.Session | None = None):
        # source : une URL (str) a telecharger, ou directement des octets d'image
        self.source = source
        self.session = session or requests.Session()
        self.image: Image.Image | None = None
        self.value = ""

    def _lire_octets_source(self) -> bytes:
        if isinstance(self.source, (bytes, bytearray)):
            return bytes(self.source)
        return self.session.get(self.source, timeout=10).content

    def capture(self) -> Image.Image:
        """Charge l'image du captcha depuis l'URL ou les octets fournis."""
        self.image = Image.open(io.BytesIO(self._lire_octets_source()))
        return self.image

    def pretraiter_img(self, image: Image.Image | None = None) -> Image.Image:
        """Nettoie l'image pour l'OCR : gris, agrandissement, contraste, binarisation, anti-bruit."""
        img = image or self.image
        if img is None:
            raise RuntimeError("aucune image a pretraiter (appeler capture d'abord)")
        img = agrandir_img_x3(img.convert("L"))
        img = ImageOps.autocontrast(img)
        img = binariser_img(img)
        return img.filter(ImageFilter.MedianFilter(3))

    def solve(self) -> str:
        """Capture si besoin, pretraite, lit le texte et ne garde que l'alphanumerique."""
        if self.image is None:
            self.capture()
        raw = pytesseract.image_to_string(self.pretraiter_img(), config=_OCR_CONFIG)
        self.value = nettoyer_txt_ocr(raw)
        logger.info(f"captcha lu par OCR : '{self.value}'")
        return self.value

    def get_value(self) -> str:
        """Renvoie la derniere valeur resolue du captcha."""
        return self.value
