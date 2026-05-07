# AvD session-host configuration script (v2).
#
# Entra-Kerberos-only successor to AvDDeploy.ps1. Runs as a Custom Script
# Extension on a freshly provisioned AVD session host. The FSLogix MSI
# itself is installed at image-build time; this script writes the registry
# values FSLogix reads at service start.
#
# This script is a *bridge* — most of what it sets should eventually move
# into an Intune Settings Catalog profile assigned to the AVD device group.
# It exists because the disk/SKU rollout it supports is happening before
# the Intune profile work.
#
# Differences vs AvDDeploy.ps1
#   - VHDLocations (direct SMB attach) instead of CCDLocations (Cloud Cache).
#     Cloud Cache is positioned by Microsoft as a multi-region HA feature;
#     KAHL has a single Premium_LRS share in one region.
#   - **Profile Container only — no ODFC.** Modern Microsoft / FSLogix
#     guidance: only use a separate Office Container when an existing
#     non-FSLogix profile solution is already in place (Citrix UPM, VMware
#     DEM, etc.). The Profile Container already captures Outlook OST,
#     Teams cache, OneDrive cache, and all other Office data. Running
#     both doubles the VHDX mount surface for no benefit and historically
#     caused New-Teams sign-out bugs.
#   - No D:\ / temp-disk dependency. Works on D8as_v6, D8as_v7, D8s_v5, etc.
#   - No `cmdkey` / storage-account-key planting. With Entra Kerberos the
#     user's own ticket authenticates them.
#   - No `AccessNetworkAsComputerObject` (storage-key-only workaround).
#   - No `HealthyProvidersRequiredForRegister` (CCD-only).
#   - No `frxccd*\Parameters` block (CCD-only).
#   - Adds Microsoft-recommended retry / re-attach values that v1 was
#     missing: LockedRetryCount, LockedRetryInterval, ReAttachIntervalSeconds,
#     ReAttachRetryCount. These matter for concurrent morning login storms.
#   - Pre-flight check: fails immediately if the FSLogix MSI isn't installed
#     in the image (rather than silently writing dead registry keys).
#   - Tailscale removed (not used at KAHL).
#
# Prerequisites
#   1. Storage account is configured for AADKERB
#      (`Set-AzStorageAccount -EnableAzureActiveDirectoryKerberosForFile $true`).
#   2. Storage-account enterprise app has admin consent for openid /
#      profile / User.Read.
#   3. Storage-account enterprise app is excluded from any Conditional
#      Access policy that enforces MFA.
#   4. Entra group(s) representing AVD users are granted "Storage File
#      Data SMB Share Contributor" on the share. (For cloud-only identities
#      the only supported share-level permission is the default share-level
#      permission; configure it to that role.)
#   5. Session host is Entra-joined with `CloudKerberosTicketRetrievalEnabled
#      = 1` set via Intune Settings Catalog (NOT OMA-URI; OMA-URI doesn't
#      apply on multi-session devices).
#
# Migration path (target end state)
#   - All values written here move into a single Intune Settings Catalog
#     profile assigned to the AVD device group. Custom Script Extension
#     and this script disappear.
#   - Local-group memberships and Defender process exclusions move into
#     the AIB image build.
#   - Defender path exclusion for the share UNC moves to Intune
#     (Endpoint Security → Antivirus → Exclusions).
#
# Parameters
#   -fileServer    storage account FQDN, e.g.
#                  stvdkahlprod101.privatelink.file.core.windows.net
#                  (used only for the Defender path exclusion)
#   -profileShare  full UNC of the profile share, e.g.
#                  \\stvdkahlprod101.privatelink.file.core.windows.net\share-profiles
#   -sharename     share name only, e.g. share-profiles
#                  (used for the Defender path exclusion)

param(
    [Parameter(Mandatory = $true)] [string] $fileServer,
    [Parameter(Mandatory = $true)] [string] $profileShare,
    [Parameter(Mandatory = $true)] [string] $sharename
)

$ErrorActionPreference = 'Stop'

if (-not $fileServer)   { Write-Error "fileServer parameter is missing.";   Exit 1 }
if (-not $profileShare) { Write-Error "profileShare parameter is missing."; Exit 1 }
if (-not $sharename)    { Write-Error "sharename parameter is missing.";    Exit 1 }

# Fail fast if FSLogix MSI isn't already installed in the image. Without
# frx.exe present, the registry writes below are silently no-ops and the
# misconfiguration only surfaces as temp profiles at first user login.
$frxPath = Join-Path $env:ProgramFiles 'FSLogix\Apps\frx.exe'
if (-not (Test-Path $frxPath)) {
    Write-Error "FSLogix MSI not installed at '$frxPath'. The MSI is meant to be baked into the AIB image (see Install-FSLogix.ps1)."
    Exit 1
}

Write-Host "=== AvDDeployV2: configuring FSLogix Profile Container (VHDLocations, Entra Kerberos) ==="
Write-Host "  share: $profileShare"
Write-Host "  frx:   $((Get-Item $frxPath).VersionInfo.FileVersion)"

# --- FSLogix Profile Container ----------------------------------------------
# Single container per user. Captures profile + Outlook OST + Teams cache +
# OneDrive cache + Office settings. No ODFC — see header.
#
# Target: move all of these into Intune Settings Catalog → "FSLogix > Profile
# Containers" once the Intune profile is set up.
New-Item -Path "HKLM:\SOFTWARE"          -Name "FSLogix"  -ErrorAction Ignore | Out-Null
New-Item -Path "HKLM:\SOFTWARE\FSLogix"  -Name "Profiles" -ErrorAction Ignore | Out-Null

$profilesKey = "HKLM:\SOFTWARE\FSLogix\Profiles"

# Where the per-user VHDX lives.
New-ItemProperty -Path $profilesKey -Name "VHDLocations"                          -Value $profileShare -PropertyType MultiString -Force | Out-Null

# Core profile-container settings (Microsoft-recommended for AVD multi-session).
New-ItemProperty -Path $profilesKey -Name "Enabled"                              -Value 1      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "DeleteLocalProfileWhenVHDShouldApply" -Value 1      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "FlipFlopProfileDirectoryName"        -Value 1      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "IsDynamic"                            -Value 1      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "KeepLocalDir"                         -Value 0      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "SizeInMBs"                            -Value 30000  -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "VolumeType"                           -Value "VHDX" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "PreventLoginWithFailure"              -Value 1      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "PreventLoginWithTempProfile"          -Value 1      -PropertyType DWord  -Force | Out-Null

# Resilience under concurrent login storms (Microsoft-recommended values).
New-ItemProperty -Path $profilesKey -Name "LockedRetryCount"                     -Value 3      -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "LockedRetryInterval"                  -Value 15     -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "ReAttachIntervalSeconds"              -Value 15     -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $profilesKey -Name "ReAttachRetryCount"                   -Value 3      -PropertyType DWord  -Force | Out-Null

# --- Credential Guard / LSA tweak -------------------------------------------
# TODO: move into AIB image build (env-agnostic). Setting LsaCfgFlags=0
# disables Windows Defender Credential Guard.
#
# With Entra-Kerberos auth (no storage key in Credential Manager) the
# original "Credential Guard wipes the storage key on dealloc" failure mode
# doesn't apply, but most production FSLogix-on-AVD guides still set this
# defensively on Win 11 22H2+ to avoid edge cases with Kerberos delegation
# paths under VBS. The marketplace 25H2 image ships with Credential Guard
# enabled by default; we leave this here until the image build does it.
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -PropertyType DWord -Force | Out-Null

# --- Local accounts that should NOT get an FSLogix profile ------------------
# TODO: move into AIB image build. These groups are created by the FSLogix
# MSI; the local user names are fixed across deployments, so this is
# env-agnostic. Lives here only because the AIB pipeline hasn't picked
# it up yet.
foreach ($principal in @('azure', 'defaultuser100000')) {
    try {
        Add-LocalGroupMember -Group 'FSLogix Profile Exclude List' -Member $principal -ErrorAction Stop
    } catch [Microsoft.PowerShell.Commands.MemberExistsException] {
        # Already a member — fine.
    } catch {
        Write-Warning "Could not add ${principal} to 'FSLogix Profile Exclude List': $($_.Exception.Message)"
    }
}

# --- Defender exclusion for the FSLogix share path --------------------------
# TODO: move into Intune (Endpoint Security → Antivirus → Exclusions).
# Process exclusions for FSLogix binaries are env-agnostic and belong in
# the AIB image build, NOT here.
Add-MpPreference -ExclusionPath "\\$fileServer\$sharename\*.VHD"  -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "\\$fileServer\$sharename\*.VHDX" -ErrorAction SilentlyContinue

Write-Host "=== AvDDeployV2: done. Restarting to apply settings. ==="
shutdown -r -t 0
