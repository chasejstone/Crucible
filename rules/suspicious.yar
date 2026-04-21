/*
 * Baseline YARA ruleset for Crucible.
 *
 * These rules are intentionally broad. They are meant to flag common
 * patterns seen in droppers, shell stagers, and packed binaries, not
 * to identify specific malware families. Tune or replace for real use.
 */

rule suspicious_shell_oneliner
{
    meta:
        description = "Shell one-liner patterns common in malicious scripts"
        author = "crucible"
        severity = "medium"

    strings:
        $bash_i = "bash -i"
        $sh_c = "/bin/sh -c"
        $dev_tcp = "/dev/tcp/"
        $nc_e = "nc -e"
        $curl_pipe = /curl\s+[^\n|]+\|\s*(ba)?sh/
        $wget_pipe = /wget\s+[^\n|]+\|\s*(ba)?sh/

    condition:
        any of them
}

rule suspicious_windows_apis
{
    meta:
        description = "Win32 API names commonly abused by malware"
        author = "crucible"
        severity = "medium"

    strings:
        $a1 = "VirtualAllocEx" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "CreateRemoteThread" ascii wide
        $a4 = "SetWindowsHookEx" ascii wide
        $a5 = "URLDownloadToFile" ascii wide
        $a6 = "WinExec" ascii wide
        $a7 = "ShellExecute" ascii wide

    condition:
        3 of them
}

rule upx_packed
{
    meta:
        description = "UPX packer signature"
        author = "crucible"
        severity = "low"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upxsig = "UPX!"

    condition:
        any of them
}

rule base64_encoded_powershell
{
    meta:
        description = "Base64-encoded PowerShell launcher"
        author = "crucible"
        severity = "high"

    strings:
        $enc1 = /powershell(\.exe)?\s+-e(nc(odedcommand)?)?\s+/ nocase
        $enc2 = /FromBase64String\(/

    condition:
        any of them
}

rule xor_key_strings
{
    meta:
        description = "Obvious XOR keys or decoder strings"
        author = "crucible"
        severity = "low"

    strings:
        $x1 = "xor eax, eax" ascii
        $x2 = { 48 31 C0 48 31 DB }  // xor rax, rax; xor rbx, rbx
        $x3 = "decrypt" ascii nocase

    condition:
        any of them
}
