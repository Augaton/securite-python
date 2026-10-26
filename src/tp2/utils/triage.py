import json
from pathlib import Path

from src.tp2.utils.config import logger
from src.tp2.utils.llm import LLMTriage
from src.tp2.utils.sample import Sample
from src.tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path: str, backend: str = "openrouter") -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner()
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        matches = self.scanner.scan(sample.data)
        result = {
            "file": Path(self.path).name,
            "meta": meta,
            "iocs": iocs,
            "yara": matches,
            "bin": bininfo,
            "flag": sample.find_flag(),
        }

        summary = json.dumps({"meta": meta, "iocs": iocs, "yara": matches, "bin": bininfo})
        verdict = self.llm.triage(summary)
        if verdict is not None:
            result["verdict"] = verdict
        return result
