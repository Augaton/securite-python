import "math"

rule suspicious_c2_http
{
    meta:
        description = "Balise C2 HTTP vers un endpoint /gate.php"
    strings:
        $gate = "/gate.php"
        $c2 = "c2-"
        $host = ".example.test"
    condition:
        $gate and ($c2 or $host)
}

rule keylogger_behavior
{
    strings:
        $a = "GetAsyncKeyState"
        $b = "keylog" nocase
    condition:
        any of them
}

rule backdoor_behavior
{
    strings:
        $a = "backdoor" nocase
        $b = "reverse shell" nocase
    condition:
        any of them
}

rule dropper_behavior
{
    strings:
        $a = "dropper" nocase
    condition:
        $a
}

rule high_entropy_packed
{
    meta:
        description = "Entropie du fichier typique d'une charge packée ou chiffrée"
    condition:
        math.entropy(0, filesize) >= 7.0
}

rule embedded_esgi_flag
{
    strings:
        $f = /ESGI\{[ -~]{1,100}\}/
    condition:
        $f
}
