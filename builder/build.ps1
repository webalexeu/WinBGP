[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [String] $Version,
    [Parameter(Mandatory = $false)]
    [ValidateSet("amd64", "arm64")]
    [String] $Arch = "amd64",
    [Parameter(ParameterSetName='Signing', Mandatory = $false)]
    [Switch] $Sign = $false,
    [Parameter(ParameterSetName='Signing', Mandatory = $false)]
    [String] $CertificateThumbprint
)
$ErrorActionPreference = "Stop"

# The MSI version is not semver compliant, so just take the numerical parts
$MsiVersion = $Version -replace '^v?([0-9\.]+).*$','$1'

# Set working dir to this directory, reset previous on exit
Push-Location $PSScriptRoot
Trap {
    # Reset working dir on error
    Pop-Location
}

$cert=Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
Get-ChildItem -Path '..\src' | Where-Object {$_.Extension -eq '.ps1'} |  ForEach-Object {
    Copy-Item -Path $_.FullName  -Destination "..\engine" -Force
    if ($Sign) {
        Set-AuthenticodeSignature -FilePath "..\engine\$($_.Name)" -TimestampServer 'http://time.certum.pl' -Certificate $cert 
    }
}

Write-Verbose "Creating winbgp-${Version}-${Arch}.msi"
$wixArch = @{"amd64" = "x64"; "arm64" = "arm64"}[$Arch]

Invoke-Expression "wix build -arch $wixArch -o .\WinBGP-$($Version)-$($Arch).msi .\files.wxs .\main.wxs -d ProductName=WinBGP -d Version=$($MsiVersion) -ext WixToolset.Firewall.wixext -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext"

Write-Verbose "Done!"
Pop-Location

Copy-Item -Path "WinBGP-$($Version)-$($Arch).msi" -Destination "..\release" -Force
if ($Sign) {
    & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /sha1 $CertificateThumbprint /tr http://time.certum.pl/ /td sha256 /fd sha256 /v "..\release\WinBGP-$($Version)-$($Arch).msi"
}

