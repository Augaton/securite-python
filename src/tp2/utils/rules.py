"""
Nos règles YARA, en plus de celles du cours (dossier --rules). Elles sont dans le code et pas dans un .yar
parce que l'archive rendue ne garde que les .py, .toml, .txt... Elles décrivent des comportements, pas des
valeurs d'un échantillon précis (aucun domaine, IP ou hash en dur)
"""

CUSTOM_RULES = r"""
import "math"

rule Persistence_Run_Key
{
    meta:
        author = "Augaton"
        description = "Clé Run du registre : le programme est relancé à chaque ouverture de session"
        mitre_attack = "T1547.001"
    strings:
        $run = /\\CurrentVersion\\Run(Once|Services)?\\/ nocase ascii wide
    condition:
        $run
}

rule C2_Http_Gate
{
    meta:
        author = "Augaton"
        description = "URL d'un panneau de commande et contrôle (gate.php, panel.php...)"
        mitre_attack = "T1071.001"
    strings:
        $gate = /https?:\/\/[a-z0-9.\-]{1,253}(:[0-9]{1,5})?\/[a-z0-9_\/\-]{0,64}(gate|panel|admin|beacon|task|tasks|connect|bot|cmd|command)\.(php|aspx?|jsp|cgi)/ nocase ascii wide
    condition:
        $gate
}

rule Named_Mutex
{
    meta:
        author = "Augaton"
        description = "Mutex nommé Global\\ ou Local\\ : le malware ne tourne qu'une fois par machine"
        mitre_attack = "T1480.002"
    strings:
        $mutex = /(Global|Local)\\[A-Za-z0-9_.{}\-]{4,64}/ ascii wide
    condition:
        $mutex
}

rule Downloader_Execute_API
{
    meta:
        author = "Augaton"
        description = "Télécharge un fichier puis l'exécute (dropper / downloader)"
        mitre_attack = "T1105"
    strings:
        $download1 = "URLDownloadToFile" ascii wide
        $download2 = "InternetReadFile" ascii wide
        $download3 = "WinHttpReadData" ascii wide
        $execute1 = "WinExec" ascii wide
        $execute2 = "ShellExecute" ascii wide
        $execute3 = "CreateProcess" ascii wide
    condition:
        any of ($download*) and any of ($execute*)
}

rule Keylogger_API
{
    meta:
        author = "Augaton"
        description = "Hook clavier ou lecture de l'état des touches (keylogger)"
        mitre_attack = "T1056.001"
    strings:
        $hook = "SetWindowsHookEx" ascii wide
        $key1 = "GetAsyncKeyState" ascii wide
        $key2 = "GetKeyboardState" ascii wide
        $key3 = "GetKeyState" fullword ascii wide
    condition:
        ($hook and any of ($key*)) or 2 of ($key*)
}

rule Reverse_Shell_API
{
    meta:
        author = "Augaton"
        description = "Socket vers l'extérieur et interpréteur de commandes (backdoor / reverse shell)"
        mitre_attack = "T1059.003"
    strings:
        $socket1 = "WSASocket" ascii wide
        $socket2 = "WSAStartup" ascii wide
        $socket3 = "connect" fullword ascii wide
        $shell1 = "cmd.exe" nocase ascii wide
        $shell2 = "powershell" nocase ascii wide
        $shell3 = "/bin/sh" ascii
        $shell4 = "/bin/bash" ascii
    condition:
        2 of ($socket*) and any of ($shell*)
}

rule Prompt_Injection_LLM
{
    meta:
        author = "Augaton"
        description = "Texte qui s'adresse à un LLM ou à l'analyste pour fausser le verdict (injection de prompt)"
    strings:
        $en1 = /ignore (all |any |the |your )*(previous|prior|above|earlier) (instructions|prompts?|rules)/ nocase ascii wide
        $en2 = /(AI|LLM|GPT|ASSISTANT)_?(INSTRUCTIONS?|PROMPT)/ nocase ascii wide
        $en3 = /NOTE_?TO_?(AI|LLM|ASSISTANT|MODEL)/ nocase ascii wide
        $en4 = /(mark|declare|report|classify) (the |this )?(sample|file|binary) (as )?(clean|benign|safe)/ nocase ascii wide
        $fr1 = /ignore[rsz]? (toutes )?(les |tes |vos )?(instructions|consignes)/ nocase ascii wide
        $fr2 = /d.{1,2}clare[rsz]? (ce|le|cet) (fichier|binaire|.{1,2}chantillon) (comme )?(sain|propre|b.{1,2}nin)/ nocase ascii wide
    condition:
        any of them
}

rule Packed_High_Entropy
{
    meta:
        author = "Augaton"
        description = "Exécutable compressé ou chiffré (packer) : marqueur UPX ou entropie très élevée"
        mitre_attack = "T1027.002"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
    condition:
        (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and (
            any of ($upx*)
            or math.entropy(0, filesize) >= 7.0
            or (filesize > 32768 and math.entropy(filesize - 16384, 16384) >= 7.5)
        )
}
"""
