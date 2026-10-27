from src.tp2.utils.llm import LLMClient, _verif_verdict_llm, triage_llm

VALID = '{"famille":"dropper","capacites":["c2"],"mitre_attack":["T1071"],"score":8,"iocs":["x"]}'


class FakeClient:
    def __init__(self, raw, est_dispo=True):
        self._raw = raw
        self._available = est_dispo
        self.user = None

    def est_dispo(self):
        return self._available

    def envoyer_chat(self, system, user):
        self.user = user
        return self._raw


def test_llm_triage_parses_valid_verdict():
    verdict = triage_llm({"a": 1}, FakeClient(VALID))
    assert verdict["famille"] == "dropper" and verdict["score"] == 8


def test_llm_triage_returns_none_when_unavailable():
    assert triage_llm({"a": 1}, FakeClient(VALID, est_dispo=False)) is None


def test_llm_triage_wraps_untrusted_data_in_delimiters():
    client = FakeClient(VALID)
    triage_llm({"a": 1}, client)
    assert "<<<DATA>>>" in client.user and "<<<END>>>" in client.user


def test_parse_verdict_rejects_non_json():
    assert _verif_verdict_llm("désolé je ne peux pas") is None


def test_parse_verdict_rejects_missing_keys():
    assert _verif_verdict_llm('{"famille":"x"}') is None


def test_parse_verdict_bounds_score():
    verdict = _verif_verdict_llm('{"famille":"x","capacites":[],"mitre_attack":[],"score":99,"iocs":[]}')
    assert verdict["score"] == 10


def test_openrouter_client_needs_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert LLMClient("openrouter").est_dispo() is False


def test_messages_shape():
    from src.tp2.utils.llm import _constr_messages

    messages = _constr_messages("sys", "usr")
    assert messages == [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}]


def test_chat_returns_none_when_backend_unreachable():
    # ollama local absent en test -> la requête échoue, envoyer_chat renvoie None sans lever
    assert LLMClient("ollama").envoyer_chat("sys", "usr") is None
