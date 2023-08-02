<# Decode-SafeLinks.ps1 v0.2 SystenInsecure
--== May 17, 2023 ==--

This script aims to make deciphering Safelinks easier on analysts. Not only does it strip the padded text that Exchange Online protection adds,
it will also decode the pieces in links that use hex encoding, and will detect urls containing non-latin characters (for domain lookalike/spoofing/dnstwisting attacks).

See Errata section at bottom for prerequisites, restrictions, and the changelog.

#>

$encodedCharacters = [regex]::Matches($string, "%[0-9a-fA-F]{2}")
Add-Type -AssemblyName System.Web
$l = Read-Host -Prompt "Input Safelinks URL"
$u = New-Object -TypeName System.Uri -ArgumentList $l
$qs = [System.Web.HttpUtility]::ParseQueryString($u.Query)

if ($encodedCharacters.Count -gt 0) {
    write-host ("Decoded URL: $([System.Web.HttpUtility]::UrlDecode($qs["url"]))") -ForegroundColor DarkYellow
} else {
    write-host ("Safelink removed: $($qs["url"])") -ForegroundColor Yellow
}

if ($($qs["url"])-match "http"){
    $domain = ($($qs["url"]) -split("/"))[2]
    if ($Domain -match "[^\x00-\x7F]+"){
        write-host("WARNING!!!! The domain in this URL contains non-latin letters") -ForegroundColor Red
    }
}

<# --== Errata ==--

Prerequisites needed before launching:
- Powershell 5.1 or better

Restrictions
- None

To do in later versions:
- Nothing planned

Changelog:
- 0.1 Initial version for interactive use.
- 0.2 Add detection for encoded characters and print decoded result if found
#>
