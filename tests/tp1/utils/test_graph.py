from src.tp1.utils.graph import create_graph, save_graph


def test_given_protocols_when_create_graph_then_graph_contains_protocols():
    # Given
    protocols = {"TCP": 3, "DNS": 1}

    # When
    graph = create_graph(protocols)

    # Then
    svg = graph.render(is_unicode=True)
    assert "Nombre de paquets par protocole" in svg
    assert "TCP" in svg
    assert "DNS" in svg


def test_given_protocols_when_create_graph_then_most_used_protocol_is_on_top():
    # Given
    protocols = {"DNS": 2, "TCP": 5, "ARP": 1}

    # When
    graph = create_graph(protocols)

    # Then
    # pygal dessine le premier libellé en bas du graphique
    assert graph.x_labels == ["ARP", "DNS", "TCP"]


def test_when_create_graph_then_no_script_is_loaded_from_internet():
    # When
    svg = create_graph({"TCP": 3}).render(is_unicode=True)

    # Then
    # par défaut pygal ajoute <script xlink:href="https://kozea.github.io/..."> pour ses infobulles
    assert "https://" not in svg


def test_given_no_protocol_when_create_graph_then_say_no_packet():
    # When
    svg = create_graph({}).render(is_unicode=True)

    # Then
    assert "Aucun paquet capturé" in svg


def test_given_protocols_when_save_graph_then_only_svg_is_created(tmp_path, monkeypatch):
    # Given
    protocols = {"TCP": 3, "DNS": 1}
    monkeypatch.chdir(tmp_path)

    # When
    result = save_graph(protocols)

    # Then
    assert result == "graph.svg"
    assert (tmp_path / "graph.svg").exists()
    assert not (tmp_path / "graph.png").exists()
