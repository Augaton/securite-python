import "math"

rule ESGI_C2_HTTP_Beacon
{
    meta:
        description = "Balise C2 HTTP vers un endpoint /gate.php"
        author = "binome ESGI"
    strings:
        $gate = "/gate.php"
        $c2 = "c2-"
        $host = ".example.test"
    condition:
        $gate and ($c2 or $host)
}

rule ESGI_Keylogger_Behavior
{
    meta:
        description = "Capture de frappes (keylogger)"
        author = "binome ESGI"
    strings:
        $a = "GetAsyncKeyState"
        $b = "keylog" nocase
        $c = "/dev/input/event"
    condition:
        any of them
}

rule ESGI_Reverse_Shell_Backdoor
{
    meta:
        description = "Porte dérobée / reverse shell"
        author = "binome ESGI"
    strings:
        $a = "backdoor" nocase
        $b = "reverse shell" nocase
        $c = "/bin/sh"
    condition:
        any of them
}

rule ESGI_High_Entropy_Payload
{
    meta:
        description = "Fichier à forte entropie (packé ou chiffré)"
        author = "binome ESGI"
    condition:
        math.entropy(0, filesize) >= 7.0
}
