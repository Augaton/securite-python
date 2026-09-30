from unittest.mock import MagicMock, patch

from src.tp1.utils.detection import Attack
from src.tp1.utils.graph import save_graph
from src.tp1.utils.report import Report


def test_report_init():
    # Given
    capture = MagicMock()
    filename = "test.pdf"
    summary = "Test summary"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "Rapport de capture réseau"
    assert report.summary == summary
    assert report.array == []
    assert report.graph == ""


def test_concat_report():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.array = [("TCP", 3), ("DNS", 1)]

    # When
    result = report.concat_report()

    # Then
    assert result.page_no() == 1


def test_save(tmp_path):
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.array = [("TCP", 3)]
    filename = tmp_path / "test.pdf"

    # When
    report.save(str(filename))

    # Then
    assert filename.read_bytes().startswith(b"%PDF")


def test_given_graph_when_save_then_pdf_is_created(tmp_path, monkeypatch):
    # Given
    monkeypatch.chdir(tmp_path)
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.array = [("TCP", 3), ("DNS", 1)]
    report.graph = save_graph({"TCP": 3, "DNS": 1})

    # When
    report.save("test.pdf")

    # Then
    assert (tmp_path / "test.pdf").read_bytes().startswith(b"%PDF")


def test_generate_graph():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    with patch("src.tp1.utils.report.save_graph", return_value="graph.png"):
        report.generate("graph")

    # Then
    assert report.graph == "graph.png"


def test_generate_array():
    # Given
    capture = MagicMock()
    capture.protocols = {"TCP": 3, "DNS": 1}
    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array == [("TCP", 3), ("DNS", 1)]


def test_generate_invalid_param():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == ""
    assert report.array == []


def test_when_concat_report_then_array_has_share_of_each_protocol_and_total():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.array = [("TCP", 3), ("DNS", 1)]

    # When
    pdf = report.concat_report()

    # Then
    # sans compression le texte du PDF est lisible directement dans le fichier
    pdf.set_compression(False)
    content = bytes(pdf.output())
    for text in (b"Part du trafic", b"75.0 %", b"25.0 %", b"Total", b"100.0 %"):
        assert text in content


ARP_ATTACK = Attack(
    attack_type="arp_spoofing",
    name="ARP spoofing",
    protocol="ARP",
    attacker_ip="192.168.1.66",
    attacker_mac="aa:bb:cc:dd:ee:ff",
    details="se fait passer pour 192.168.1.1",
)


def make_capture(attacks: list, flag: str | None = None) -> MagicMock:
    """
    Capture analysée de test : 3 paquets ARP et 1 TCP
    """
    capture = MagicMock()
    capture.interface = "eth0"
    capture.protocols = {"ARP": 3, "TCP": 1}
    capture.attacks = attacks
    capture.flag = flag
    return capture


def get_pdf_text(report: Report) -> bytes:
    """
    Contenu du PDF sans compression, pour pouvoir y chercher du texte (encodé en latin-1)
    """
    report.generate("array")
    pdf = report.concat_report()
    pdf.set_compression(False)
    return bytes(pdf.output())


def test_given_attack_when_concat_report_then_traffic_is_illegitimate_and_attacker_is_shown():
    # Given
    report = Report(make_capture([ARP_ATTACK], flag="ESGI{abc}"), "test.pdf", "Test summary")

    # When
    content = get_pdf_text(report)

    # Then
    for text in (
        "Illégitime : ARP spoofing",
        "Légitime",
        "aa:bb:cc:dd:ee:ff",
        "192.168.1.66",
        "Marqueur trouvé : ESGI{abc}",
    ):
        assert text.encode("latin-1") in content


def test_given_no_attack_when_concat_report_then_everything_is_fine():
    # Given
    report = Report(make_capture([]), "test.pdf", "Test summary")

    # When
    content = get_pdf_text(report)

    # Then
    assert "Aucune attaque détectée : tout va bien.".encode("latin-1") in content
    assert "Illégitime".encode("latin-1") not in content


def test_given_non_latin1_text_from_attacker_when_concat_report_then_pdf_is_still_created():
    # Given
    attack = Attack("sql_injection", "Injection SQL", "TCP", "10.0.0.66", "aa:bb:cc:dd:ee:ff", "requête ’😈’")
    report = Report(make_capture([attack]), "test.pdf", "Test summary")

    # When
    content = get_pdf_text(report)

    # Then
    assert "requête ??".encode("latin-1") in content
