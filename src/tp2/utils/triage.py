import re

from tp2.utils.config import logger
from tp2.utils.iocs import FLAG, IOC_CATEGORIES, extract_strings, get_trusted_strings
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import DEFAULT_RULES_PATH, YaraScanner, get_scanner

# API importées ou citées dans les chaînes (résolues à l'exécution avec GetProcAddress / dlsym) qui
# trahissent une capacité, avec ses techniques MITRE ATT&CK
API_CAPABILITIES = {
    "download": (
        ("URLDownloadToFile", "InternetOpenUrl", "InternetReadFile", "WinHttpReadData", "HttpSendRequest"),
        ("T1105",),
    ),
    "execution": (
        ("WinExec", "ShellExecute", "CreateProcess", "execve", "execvp", "system", "popen"),
        ("T1106",),
    ),
    "network_socket": (("WSASocket", "WSAStartup", "socket", "connect"), ("T1095",)),
    "keylogging": (("SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "GetKeyState"), ("T1056",)),
    "process_injection": (
        (
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtUnmapViewOfSection",
            "QueueUserAPC",
        ),
        ("T1055",),
    ),
    "anti_debug": (("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "ptrace"), ("T1622",)),
}
SHELL_MARKERS = ("cmd.exe", "powershell", "/bin/sh", "/bin/bash")
PERSISTENCE_KEY = re.compile(r"\\(?:CurrentVersion\\Run(?:Once|Services)?|Winlogon)\\", re.IGNORECASE)
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,63}")
PACKED_ENTROPY = 7.0
PACKED_REGION_ENTROPY = 7.2
PACKED_REGION_MIN_SIZE = 4096
# famille devinée : la première dont toutes les capacités sont présentes
FAMILY_RULES = (
    ("keylogger", {"keylogging"}),
    ("dropper", {"download", "execution"}),
    ("backdoor", {"network_socket", "command_shell"}),
    ("injector", {"process_injection"}),
    ("packed", {"packing"}),
    ("trojan", {"c2_communication"}),
)
BENIGN_FAMILIES = ("clean", "benign", "sain", "safe", "legit", "legitimate", "none", "goodware")
# au-delà, un verdict « sain » du LLM contredit les indicateurs : sûrement une injection qui a marché
SUSPICIOUS_SCORE = 6
MAX_LLM_STRINGS = 40
MAX_LLM_STRING_LENGTH = 120
MAX_LLM_IMPORTS = 80


def get_api_symbols(imports: list[str], strings: list[str]) -> list[str]:
    """
    Noms de fonctions : imports et chaînes qui ressemblent à un nom d'API
    """
    return list(dict.fromkeys([*imports, *(text for text in strings if IDENTIFIER.fullmatch(text))]))


def find_referenced_apis(symbols: list[str], apis: tuple[str, ...]) -> list[str]:
    """
    Symboles qui sont une des API, avec ses variantes Windows (CreateProcessA, SetWindowsHookExW...)
    """
    pattern = re.compile(rf"(?:{'|'.join(map(re.escape, apis))})(?:Ex)?[AW]?")
    return [symbol for symbol in symbols if pattern.fullmatch(symbol)]


def is_packed(metadata: dict, binary: dict) -> bool:
    """
    Indique si le fichier ou une de ses parties (section, overlay) est compressé ou chiffré
    """
    regions = [*binary.get("sections", []), binary.get("overlay") or {}]
    return metadata["entropy"] >= PACKED_ENTROPY or any(
        region.get("size", 0) >= PACKED_REGION_MIN_SIZE and region.get("entropy", 0) >= PACKED_REGION_ENTROPY
        for region in regions
    )


def find_capabilities(
    symbols: list[str], strings: list[str], iocs: dict, packed: bool, injections: list[str]
) -> tuple[dict, list[str]]:
    """
    Capacités de l'échantillon et techniques MITRE ATT&CK, d'après ses API, ses chaînes et ses IOC

    :return: capacités (nom -> preuves) et techniques
    """
    capabilities = {}
    techniques = []
    for name, (apis, capability_techniques) in API_CAPABILITIES.items():
        found = find_referenced_apis(symbols, apis)
        if found:
            capabilities[name] = found
            techniques += capability_techniques
    shells = [text for text in strings if any(marker in text.lower() for marker in SHELL_MARKERS)]
    if shells:
        capabilities["command_shell"] = shells[:3]
        techniques.append("T1059")
    network_iocs = iocs["domains"] + iocs["ips"] + iocs["urls"]
    if network_iocs:
        capabilities["c2_communication"] = network_iocs
        techniques.append("T1071")
    persistence_keys = [key for key in iocs["registry"] if PERSISTENCE_KEY.search(key + "\\")]
    if persistence_keys:
        capabilities["persistence"] = persistence_keys
        techniques.append("T1547")
    if iocs["mutex"]:
        capabilities["mutex"] = iocs["mutex"]
        techniques.append("T1480")
    if packed:
        capabilities["packing"] = ["entropie élevée"]
        techniques.append("T1027")
    if injections:
        capabilities["prompt_injection"] = [f"{len(injections)} chaîne(s)"]
    return capabilities, list(dict.fromkeys(techniques))


def compute_heuristic_score(yara_matches: list[str], capabilities: dict) -> int:
    """
    Score de 0 à 10 sans LLM : règles YARA, IOC réseau, persistance, mutex, API suspectes, packer et
    tentative d'injection (un fichier qui essaie de tromper l'analyse n'est pas innocent)
    """
    api_capabilities = [name for name in capabilities if name in API_CAPABILITIES or name == "command_shell"]
    weights = {"c2_communication": 2, "persistence": 1, "mutex": 1, "packing": 1, "prompt_injection": 2}
    score = min(len(yara_matches), 3) + min(len(api_capabilities), 3)
    score += sum(weight for name, weight in weights.items() if name in capabilities)
    return min(score, 10)


def guess_family(capabilities: dict, score: int) -> str:
    """
    Famille du malware d'après ses capacités
    """
    for family, needed in FAMILY_RULES:
        if needed <= capabilities.keys():
            return family
    return "unknown" if score > 0 else "clean"


def combine_scores(heuristic_score: int, llm_score: int | None) -> int:
    """
    Score final : le LLM peut l'augmenter (moyenne avec l'heuristique) mais jamais le faire passer sous le
    score heuristique, qu'une injection ne peut pas changer
    """
    if llm_score is None:
        return heuristic_score
    return max(heuristic_score, int((heuristic_score + llm_score) / 2 + 0.5))


def check_llm_verdict(verdict: dict | None, heuristic_score: int) -> tuple[dict | None, str]:
    """
    Écarte un verdict du LLM qui contredit les indicateurs (« sain » alors que YARA et les IOC disent le
    contraire)

    :return: verdict gardé (None s'il est écarté) et explication pour le rapport
    """
    if verdict is None:
        return None, "LLM indisponible ou réponse non conforme : verdict déterministe (YARA, IOC, API)"
    says_benign = verdict["family"] in BENIGN_FAMILIES or verdict["score"] <= 2
    if says_benign and heuristic_score >= SUSPICIOUS_SCORE:
        return None, (
            f"Verdict du LLM écarté : « {verdict['family']} », score {verdict['score']}/10, contredit les "
            f"indicateurs (score heuristique {heuristic_score}/10), probable effet d'une injection de prompt"
        )
    return verdict, f"Verdict du LLM ({verdict['backend']}, {verdict['model']}) recoupé avec YARA et les IOC"


def shorten(text: str, max_length: int = MAX_LLM_STRING_LENGTH) -> str:
    return text if len(text) <= max_length else text[: max_length - 3] + "..."


def select_strings(
    data: bytes, binary: dict, trusted: list[str], iocs: dict, symbols: list[str]
) -> list[str]:
    """
    Chaînes utiles au LLM : celles de l'overlay (la charge utile) puis celles qui contiennent un IOC ou une
    API suspecte, sans les tentatives d'injection ni le marqueur (inutile au LLM, il ne sort pas de la machine)
    """
    overlay_offset = (binary.get("overlay") or {}).get("offset")
    overlay_strings = extract_strings(data[overlay_offset:]) if overlay_offset is not None else []
    ioc_values = [value for category in IOC_CATEGORIES for value in iocs[category]]
    interesting = [text for text in trusted if text in symbols or any(value in text for value in ioc_values)]
    selected = [
        text
        for text in dict.fromkeys(overlay_strings + interesting)
        if text in trusted and not FLAG.search(text)
    ]
    return [shorten(text) for text in selected[:MAX_LLM_STRINGS]]


def build_deterministic_summary(result: dict) -> str:
    """
    Résumé lisible du triage quand le LLM n'a pas donné de verdict utilisable
    """
    iocs = result["iocs"]
    counts = ", ".join(f"{len(iocs[category])} {category}" for category in IOC_CATEGORIES if iocs[category])
    sentences = [
        f"Échantillon classé {result['heuristic_family']} avec un score de {result['heuristic_score']}/10.",
        f"Règles YARA déclenchées : {', '.join(result['yara_matches']) or 'aucune'}.",
        f"Capacités : {', '.join(result['capabilities']) or 'aucune'}.",
        f"IOC : {counts or 'aucun'}.",
    ]
    if result["prompt_injections"]:
        sentences.append(
            f"{len(result['prompt_injections'])} tentative(s) d'injection de prompt dans le fichier, ignorée(s)."
        )
    return " ".join(sentences)


class Triage:
    def __init__(
        self,
        path: str,
        backend: str = "auto",
        rules_path: str | None = DEFAULT_RULES_PATH,
        scanner: YaraScanner | None = None,
        llm: LLMTriage | None = None,
    ) -> None:
        self.path = path
        self.backend = backend
        self.scanner = scanner or get_scanner(rules_path)
        self.llm = llm or LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        yara_details = self.scanner.scan_details(sample.data, self.path)
        matches = [detail["rule"] for detail in yara_details]
        injections = sample.get_prompt_injections()
        trusted = get_trusted_strings(sample.strings)
        symbols = get_api_symbols(bininfo["imports"], trusted)
        capabilities, techniques = find_capabilities(
            symbols, trusted, iocs, is_packed(meta, bininfo), injections
        )
        referenced_apis = [api for name in API_CAPABILITIES for api in capabilities.get(name, [])]
        heuristic_score = compute_heuristic_score(matches, capabilities)
        result = {
            "file_name": sample.name,
            **meta,
            "iocs": {category: iocs[category] for category in IOC_CATEGORIES},
            "paths": iocs["paths"],
            "imports": list(dict.fromkeys(bininfo["imports"] + referenced_apis)),
            "binary": bininfo,
            "yara_matches": matches,
            "yara_details": yara_details,
            "capabilities": capabilities,
            "heuristic_score": heuristic_score,
            "heuristic_family": guess_family(capabilities, heuristic_score),
            "heuristic_mitre_attack": techniques,
            "prompt_injections": injections,
            "flag": sample.get_flag(),
        }

        summary = {
            "file": {key: meta[key] for key in ("sha256", "md5", "size", "entropy", "file_type")},
            "binary": {
                "format": bininfo["format"],
                "imports": result["imports"][:MAX_LLM_IMPORTS],
                "exports": bininfo["exports"][:20],
                "libraries": bininfo["libraries"],
                "sections": bininfo["sections"][:30],
                "overlay": bininfo["overlay"],
            },
            "iocs": result["iocs"],
            "yara_matches": matches,
            "capabilities": {name: evidence[:5] for name, evidence in capabilities.items()},
            "heuristic_score": heuristic_score,
            "strings": select_strings(sample.data, bininfo, trusted, iocs, symbols),
            "prompt_injection_strings_removed": len(injections),
        }
        verdict, verdict_note = check_llm_verdict(self.llm.triage(summary, result["iocs"]), heuristic_score)
        result["llm"] = {"verdict": verdict, "note": verdict_note}
        result["family_guess"] = verdict["family"] if verdict and verdict["family"] != "unknown" else None
        result["family_guess"] = result["family_guess"] or result["heuristic_family"]
        llm_techniques = verdict["mitre_attack"] if verdict else []
        # techniques de base, comme dans l'exemple de l'énoncé : T1547.001 et T1547 donnent T1547
        result["mitre_attack"] = sorted(
            {technique.split(".")[0] for technique in techniques + llm_techniques}
        )
        result["score"] = combine_scores(heuristic_score, verdict["score"] if verdict else None)
        result["llm_summary"] = (verdict or {}).get("summary") or build_deterministic_summary(result)
        logger.info(
            f"{sample.name} : {result['family_guess']}, score {result['score']}/10, "
            f"{len(matches)} règle(s) YARA, marqueur {result['flag']}"
        )
        return result
