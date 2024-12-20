[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [String] $Version,
    [Parameter(Mandatory = $false)]
    [ValidateSet("amd64", "arm64")]
    [String] $Arch = "amd64"
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


Write-Verbose "Creating winbgp-${Version}-${Arch}.msi"
$wixArch = @{"amd64" = "x64"; "arm64" = "arm64"}[$Arch]

Invoke-Expression "wix build -arch $wixArch -o .\WinBGP-$($Version)-$($Arch).msi .\files.wxs .\main.wxs -d ProductName=WinBGP -d Version=$($MsiVersion) -ext WixToolset.Firewall.wixext -ext WixToolset.UI.wixext -ext WixToolset.Util.wixext"

Write-Verbose "Done!"
Pop-Location
