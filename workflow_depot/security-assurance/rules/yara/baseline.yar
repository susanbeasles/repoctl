// Baseline YARA-X rules. Deliberately small and high-precision; extend with
// vetted community rules (e.g. YARA-Forge curated set) via a reviewed PR.
// Rule names prefixed MAL_ are treated as critical by normalize.py; others high.

rule MAL_EICAR_Test_File {
  meta:
    description = "EICAR antivirus test string"
    severity = "critical"
  strings:
    $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
  condition:
    $e
}

rule MAL_Webshell_PHP_Eval_Request {
  meta:
    description = "PHP webshell: eval/system over request parameters"
    reference = "generic"
  strings:
    $a = /(eval|assert|system|passthru|shell_exec)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)|base64_decode\s*\()/ nocase
  condition:
    filesize < 2MB and $a
}

rule MAL_Node_Reverse_Shell {
  meta:
    description = "Node.js reverse shell pattern (net.connect + child_process spawn with stdio piping)"
  strings:
    $net = "net.connect" ascii
    $sock = "net.Socket" ascii
    $spawn = /child_process.{0,40}spawn\s*\(\s*["'](\/bin\/)?(ba)?sh["']/
    $pipe = ".pipe(" ascii
  condition:
    filesize < 5MB and ($net or $sock) and $spawn and $pipe
}

rule MAL_Python_Download_And_Exec {
  meta:
    description = "Python fetch-then-exec of remote code"
  strings:
    $u1 = "urlopen(" ascii
    $u2 = "requests.get(" ascii
    $e1 = /\bexec\s*\(/
    $e2 = /\beval\s*\(/
    $b = "base64.b64decode(" ascii
  condition:
    filesize < 5MB and ($u1 or $u2) and ($e1 or $e2) and $b
}

rule SUSP_Shell_Curl_Pipe_Sh {
  meta:
    description = "curl/wget piped directly into a shell"
  strings:
    $a = /(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
  condition:
    filesize < 5MB and $a
}

rule SUSP_Install_Script_Postinstall_Network {
  meta:
    description = "package.json lifecycle script that reaches the network or evals"
  strings:
    $k = /"(pre|post)?install"\s*:\s*"[^"]*(curl|wget|node -e|eval|bash -c|powershell)[^"]*"/
  condition:
    filesize < 1MB and $k
}

rule SUSP_Trojan_Source_Bidi {
  meta:
    description = "Unicode bidi override characters in a text file (CVE-2021-42574 class)"
  strings:
    $rlo = { E2 80 AE }
    $lro = { E2 80 AD }
    $rli = { E2 81 A7 }
    $lri = { E2 81 A6 }
  condition:
    filesize < 5MB and any of them
}

rule SUSP_Embedded_ELF_In_Text {
  meta:
    description = "ELF header appearing inside a file that is not at offset 0"
  strings:
    $elf = { 7F 45 4C 46 }
  condition:
    filesize < 20MB and $elf and not ($elf at 0)
}
