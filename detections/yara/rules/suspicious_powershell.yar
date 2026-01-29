/*
    YARA Rules for Suspicious PowerShell Content
    Detection Lab - Detection Engineering
*/

rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detects PowerShell download cradles in files or memory"
        author = "Detection Lab"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "medium"
        mitre_attack = "T1059.001, T1105"

    strings:
        $download1 = "DownloadString" ascii wide nocase
        $download2 = "DownloadFile" ascii wide nocase
        $download3 = "DownloadData" ascii wide nocase
        $download4 = "Invoke-WebRequest" ascii wide nocase
        $download5 = "Net.WebClient" ascii wide nocase
        $download6 = "Start-BitsTransfer" ascii wide nocase

        $invoke1 = "Invoke-Expression" ascii wide nocase
        $invoke2 = "IEX" ascii wide
        $invoke3 = "iex(" ascii wide nocase
        $invoke4 = "iex " ascii wide nocase

        $obfuscation1 = "-enc" ascii wide nocase
        $obfuscation2 = "-encodedcommand" ascii wide nocase
        $obfuscation3 = "FromBase64String" ascii wide nocase
        $obfuscation4 = "[Convert]::" ascii wide

    condition:
        (any of ($download*) and any of ($invoke*)) or
        (any of ($download*) and any of ($obfuscation*))
}

rule Suspicious_PowerShell_Execution_Policy_Bypass
{
    meta:
        description = "Detects PowerShell execution policy bypass attempts"
        author = "Detection Lab"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        severity = "medium"
        mitre_attack = "T1059.001"

    strings:
        $bypass1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $bypass2 = "-ep bypass" ascii wide nocase
        $bypass3 = "-exec bypass" ascii wide nocase
        $bypass4 = "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" ascii wide nocase
        $bypass5 = "-ExecutionPolicy Unrestricted" ascii wide nocase

        $hidden1 = "-WindowStyle Hidden" ascii wide nocase
        $hidden2 = "-w hidden" ascii wide nocase
        $hidden3 = "-window hidden" ascii wide nocase

        $noprofile = "-NoProfile" ascii wide nocase

    condition:
        any of ($bypass*) or
        (any of ($hidden*) and $noprofile)
}

rule Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz or similar credential dumping tools"
        author = "Detection Lab"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1003/"
        severity = "critical"
        mitre_attack = "T1003.001"

    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "gentilkiwi" ascii wide nocase
        $mimi3 = "sekurlsa::" ascii wide nocase
        $mimi4 = "kerberos::" ascii wide nocase
        $mimi5 = "lsadump::" ascii wide nocase

        $cmd1 = "sekurlsa::logonpasswords" ascii wide nocase
        $cmd2 = "sekurlsa::wdigest" ascii wide nocase
        $cmd3 = "lsadump::sam" ascii wide nocase
        $cmd4 = "lsadump::dcsync" ascii wide nocase

        $priv1 = "privilege::debug" ascii wide nocase
        $priv2 = "token::elevate" ascii wide nocase

    condition:
        any of ($mimi*) or any of ($cmd*) or all of ($priv*)
}

rule Base64_Encoded_PowerShell
{
    meta:
        description = "Detects base64-encoded PowerShell commands"
        author = "Detection Lab"
        date = "2024-01-15"
        reference = "https://attack.mitre.org/techniques/T1027/"
        severity = "medium"
        mitre_attack = "T1027, T1059.001"

    strings:
        // Common base64 patterns for PowerShell
        // These are base64 for common strings like "powershell", "IEX", etc.
        $b64_ps1 = "cG93ZXJzaGVsbA" ascii wide  // powershell
        $b64_ps2 = "UG93ZXJTaGVsbA" ascii wide  // PowerShell
        $b64_iex = "SUVYICgo" ascii wide        // IEX ((
        $b64_download = "RG93bmxvYWRTdHJpbmc" ascii wide  // DownloadString
        $b64_webclient = "V2ViQ2xpZW50" ascii wide  // WebClient

        // Pattern for PowerShell with -enc flag
        $enc_pattern = /powershell[^\n]{0,50}-enc[^\n]{20,}/ nocase

    condition:
        any of ($b64*) or $enc_pattern
}
