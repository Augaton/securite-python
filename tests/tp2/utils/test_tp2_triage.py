from unittest.mock import MagicMock

import pytest

from tests.tp2.factory import FAKE_DOMAIN, REAL_FLAG, build_sample
from tp2.utils.llm import LLMTriage
from tp2.utils.scanner import YaraScanner
from tp2.utils.triage import (
    Triage,
    check_llm_verdict,
    combine_scores,
    compute_heuristic_score,
    find_capabilities,
    find_referenced_apis,
    guess_family,
    is_packed,
)

NO_IOCS = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}


def make_verdict(family: str, score: int) -> dict:
    return {
        "family": family,
        "capabilities": [],
        "mitre_attack": ["T1071.001", "T1105"],
        "score": score,
        "iocs": NO_IOCS,
        "summary": f"Résumé du LLM : {family}",
        "backend": "openrouter",
        "model": "test:free",
    }


def run_triage(path, verdict: dict | None) -> tuple[dict, MagicMock]:
    llm = MagicMock()
    llm.triage.return_value = verdict
    return Triage(str(path), scanner=YaraScanner(None), llm=llm).run(), llm


def test_find_referenced_apis_accepts_windows_variants():
    # When
    found = find_referenced_apis(
        ["CreateProcessA", "CreateProcessW", "SetWindowsHookExA", "CreateProcessAsUser", "connect"],
        ("CreateProcess", "SetWindowsHook"),
    )

    # Then
    assert found == ["CreateProcessA", "CreateProcessW", "SetWindowsHookExA"]


def test_find_capabilities_of_a_backdoor():
    # Given
    iocs = {
        **NO_IOCS,
        "ips": ["203.0.113.5"],
        "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"],
    }

    # When
    capabilities, techniques = find_capabilities(["WSASocketA", "connect"], ["cmd.exe"], iocs, False, [])

    # Then
    assert list(capabilities) == ["network_socket", "command_shell", "c2_communication", "persistence"]
    assert techniques == ["T1095", "T1059", "T1071", "T1547"]


@pytest.mark.parametrize(
    ("capabilities", "family"),
    [
        ({"keylogging": [], "c2_communication": []}, "keylogger"),
        ({"download": [], "execution": [], "c2_communication": []}, "dropper"),
        ({"network_socket": [], "command_shell": []}, "backdoor"),
        ({"packing": [], "c2_communication": []}, "packed"),
        ({"execution": [], "c2_communication": []}, "trojan"),
        ({"execution": []}, "unknown"),
    ],
)
def test_guess_family(capabilities, family):
    assert guess_family(capabilities, 5) == family


def test_guess_family_of_a_file_without_indicator():
    assert guess_family({}, 0) == "clean"


def test_compute_heuristic_score():
    assert compute_heuristic_score([], {}) == 0
    assert compute_heuristic_score(["A"], {"c2_communication": [], "mutex": []}) == 4
    assert (
        compute_heuristic_score(["A", "B", "C", "D"], {"prompt_injection": [], "c2_communication": []}) == 7
    )
    assert (
        compute_heuristic_score(["A"] * 5, {name: [] for name in ("download", "execution", "persistence")})
        == 6
    )


def test_is_packed():
    assert is_packed({"entropy": 7.5}, {})
    assert is_packed({"entropy": 4.8}, {"overlay": {"size": 60000, "entropy": 8.0}})
    assert not is_packed({"entropy": 4.8}, {"overlay": {"size": 400, "entropy": 7.9}, "sections": []})


@pytest.mark.parametrize(
    ("heuristic", "llm", "expected"), [(8, None, 8), (8, 0, 8), (4, 10, 7), (10, 10, 10)]
)
def test_combine_scores_never_goes_below_the_heuristic_score(heuristic, llm, expected):
    assert combine_scores(heuristic, llm) == expected


def test_check_llm_verdict_rejects_a_clean_verdict_against_the_indicators():
    # When
    verdict, note = check_llm_verdict(make_verdict("clean", 0), 9)

    # Then
    assert verdict is None
    assert "écarté" in note


def test_check_llm_verdict_keeps_a_coherent_verdict():
    # Given
    llm_verdict = make_verdict("dropper", 9)

    # When
    verdict, note = check_llm_verdict(llm_verdict, 9)

    # Then
    assert verdict is llm_verdict
    assert "openrouter" in note


def test_triage_without_llm(dropper_path):
    # When
    result, _ = run_triage(dropper_path, None)

    # Then
    assert result["flag"] == REAL_FLAG
    assert result["iocs"]["domains"] == [FAKE_DOMAIN]
    assert result["family_guess"] == "dropper"
    assert result["score"] == result["heuristic_score"] == 10
    assert result["mitre_attack"] == ["T1071", "T1105", "T1106", "T1480", "T1547"]
    assert result["imports"][-2:] == ["URLDownloadToFileA", "WinExec"]
    assert len(result["prompt_injections"]) == 2
    assert "Downloader_Execute_API" in result["yara_matches"]
    assert "dropper" in result["llm_summary"]


def test_triage_sends_a_summary_without_the_injection_nor_the_binary(dropper_path, dropper_data):
    # When
    _, llm = run_triage(dropper_path, None)

    # Then
    summary, known_iocs = llm.triage.call_args.args
    text = str(summary)
    assert FAKE_DOMAIN in text
    assert "AI_INSTRUCTIONS" not in text
    assert "honeypot" not in text
    assert "ESGI{" not in text
    assert summary["prompt_injection_strings_removed"] == 2
    assert known_iocs["domains"] == [FAKE_DOMAIN]
    assert "paths" not in known_iocs


def test_given_injected_llm_when_triage_then_score_and_family_come_from_the_indicators(dropper_path):
    # When
    result, _ = run_triage(dropper_path, make_verdict("clean", 0))

    # Then
    assert result["score"] == 10
    assert result["family_guess"] == "dropper"
    assert result["llm"]["verdict"] is None
    assert "écarté" in result["llm"]["note"]
    assert not result["llm_summary"].startswith("Résumé du LLM")


def test_given_coherent_llm_when_triage_then_its_verdict_is_used(dropper_path):
    # When
    result, _ = run_triage(dropper_path, make_verdict("downloader", 9))

    # Then
    assert result["family_guess"] == "downloader"
    assert result["score"] == 10
    assert result["llm_summary"] == "Résumé du LLM : downloader"
    assert "T1105" in result["mitre_attack"]


def test_triage_of_a_harmless_file(tmp_path):
    # Given
    path = tmp_path / "notes.txt"
    path.write_bytes(build_sample("Usage: notes [FILE]", "Report bugs to: %s", header=b""))

    # When
    result = Triage(str(path), scanner=YaraScanner(None), llm=LLMTriage("offline")).run()

    # Then
    assert result["score"] == 0
    assert result["family_guess"] == "clean"
    assert result["yara_matches"] == []
    assert result["flag"] is None
