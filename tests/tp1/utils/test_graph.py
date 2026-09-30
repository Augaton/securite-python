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


def test_given_protocols_when_save_graph_then_svg_and_png_are_created(tmp_path, monkeypatch):
    # Given
    protocols = {"TCP": 3, "DNS": 1}
    monkeypatch.chdir(tmp_path)

    # When
    result = save_graph(protocols)

    # Then
    assert result == "graph.png"
    assert (tmp_path / "graph.svg").exists()
    assert (tmp_path / "graph.png").exists()
