from unittest.mock import patch

from src.tp3.main import main


@patch("src.tp3.main.run_network_phase", return_value="ESGI{chain_final}")
@patch("src.tp3.main.WebPhase")
def test_main_prints_both_flags(mock_web, mock_network, capsys):
    mock_web.return_value.run.return_value = {
        "flag1": "ESGI{web_abc}",
        "host": "10.0.0.1",
        "port": 9090,
        "key": "s3cr3t",
    }

    main(["--target", "http://localhost:8080"])

    out = capsys.readouterr().out
    assert "[+] FLAG1: ESGI{web_abc}" in out
    assert "[+] FLAG_FINAL: ESGI{chain_final}" in out
    mock_network.assert_called_once_with("10.0.0.1", 9090, "s3cr3t")
