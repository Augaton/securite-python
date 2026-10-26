import io
from unittest.mock import patch

from PIL import Image

from src.tp3.utils.captcha import Captcha


def _png_bytes(text_color=0, size=(60, 20)) -> bytes:
    """Petite image PNG en memoire pour tester capture et pretraitement."""
    img = Image.new("RGB", size, "white")
    img.putpixel((5, 5), (text_color, text_color, text_color))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_init():
    captcha = Captcha("http://example.com/captcha")
    assert captcha.source == "http://example.com/captcha"
    assert captcha.image is None
    assert captcha.value == ""


def test_capture_from_bytes():
    captcha = Captcha(_png_bytes())
    image = captcha.capture()
    assert image.size == (60, 20)
    assert captcha.image is not None


def test_preprocess_returns_binarised_image():
    captcha = Captcha(_png_bytes())
    captcha.capture()
    processed = captcha.preprocess()
    # agrandi x3 et reduit a deux niveaux (noir et blanc)
    assert processed.size == (180, 60)
    assert processed.getextrema() == (0, 255)


@patch("src.tp3.utils.captcha.pytesseract.image_to_string", return_value="  aB 3x!\n")
def test_solve_strips_non_alphanumeric(_mock_ocr):
    captcha = Captcha(_png_bytes())
    value = captcha.solve()
    assert value == "aB3x"
    assert captcha.get_value() == "aB3x"


@patch("src.tp3.utils.captcha.pytesseract.image_to_string", return_value="XYZ789")
def test_solve_captures_when_needed(_mock_ocr):
    captcha = Captcha(_png_bytes())
    assert captcha.image is None
    assert captcha.solve() == "XYZ789"
    assert captcha.image is not None
