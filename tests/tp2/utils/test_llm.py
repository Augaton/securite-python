from src.tp2.utils.llm import LLMClient, _parse_verdict, llm_triage

VALID = '{"famille":"dropper","capacites":["c2"],"mitre_attack":["T1071"],"score":8,"iocs":["x"]}'


class FakeClient:
    def __init__(self, raw, available=True):
        self._raw = raw
        self._available = available
        self.user = None

    def available(self):
        return self._available

    def chat(self, system, user):
        self.user = user
        return self._raw


def test_llm_triage_parses_valid_verdict():
    verdict = llm_triage({"a": 1}, FakeClient(VALID))
    assert verdict["famille"] == "dropper" and verdict["score"] == 8


def test_llm_triage_returns_none_when_unavailable():
    assert llm_triage({"a": 1}, FakeClient(VALID, available=False)) is None


def test_llm_triage_wraps_untrusted_data_in_delimiters():
    client = FakeClient(VALID)
    llm_triage({"a": 1}, client)
    assert "<<<DATA>>>" in client.user and "<<<END>>>" in client.user


def test_parse_verdict_rejects_non_json():
    assert _parse_verdict("désolé je ne peux pas") is None


def test_parse_verdict_rejects_missing_keys():
    assert _parse_verdict('{"famille":"x"}') is None


def test_parse_verdict_bounds_score():
    verdict = _parse_verdict('{"famille":"x","capacites":[],"mitre_attack":[],"score":99,"iocs":[]}')
    assert verdict["score"] == 10


def test_openrouter_client_needs_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert LLMClient("openrouter").available() is False


def test_messages_shape():
    from src.tp2.utils.llm import _messages

    messages = _messages("sys", "usr")
    assert messages == [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}]


def test_chat_returns_none_when_backend_unreachable():
    # ollama local absent en test -> la requête échoue, chat renvoie None sans lever
    assert LLMClient("ollama").chat("sys", "usr") is None
