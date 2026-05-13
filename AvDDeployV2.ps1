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
#     deployments with a single share in a single region don't get value
#     from Cloud Cache and pay its operational tax (local cache management,
#     sequence sync, hydration).
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
#   - Tailscale removed (call InstallTailscale.ps1 separately if a deployment
#     needs it).
#
# Prerequisites (storage-/identity-side, not session-host-side)
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
#   5. Session host is Entra-joined.
#      (CloudKerberosTicketRetrievalEnabled is set by this script — see
#      "Cloud Kerberos Ticket Retrieval" section below. An equivalent Intune
#      Settings Catalog policy is idempotent and can be added later for
#      centralized management; if both are in place, both write the same
#      registry value.)
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
#                  <storage-account>.privatelink.file.core.windows.net
#                  (used only for the Defender path exclusion)
#   -profileShare  full UNC of the profile share, e.g.
#                  \\<storage-account>.privatelink.file.core.windows.net\<share-name>
#   -sharename     share name only, e.g. share-profiles
#                  (used for the Defender path exclusion)
#   -hostPoolRegistrationToken
#                  AVD host-pool registration token. When supplied, this script
#                  also registers the session host with the host pool — replacing
#                  the brittle Microsoft.PowerShell.DSC extension that fails on
#                  the Win 11 25H2 marketplace image with "Access is denied" at
#                  RunMsiWithRetry. The marketplace 25H2 multisession image
#                  ships RDAgentBootLoader pre-installed; this script plants the
#                  token in the registry and bounces the bootloader, the same
#                  pattern as Azure/avdaccelerator's Set-SessionHostConfiguration.
#                  When omitted, registration is skipped (legacy/AIB-image path).

param(
    [Parameter(Mandatory = $true)] [string] $fileServer,
    [Parameter(Mandatory = $true)] [string] $profileShare,
    [Parameter(Mandatory = $true)] [string] $sharename,
    [Parameter(Mandatory = $false)][string] $hostPoolRegistrationToken = ''
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

Write-Host "=== AvDDeployV2: starting ==="
Write-Host "  share: $profileShare"
Write-Host "  frx:   $((Get-Item $frxPath).VersionInfo.FileVersion)"

# Order of operations:
#   1. Network category + RDP firewall — gets Bastion reachable immediately,
#      so if a later step fails the host is still debuggable mid-CSE.
#   2. AVD agent registration — long-running, network-dependent, the most
#      likely step to fail. Fail fast; don't waste time on registry writes
#      that won't matter if the broker handshake is broken.
#   3. FSLogix + Cloud Kerberos + Defender exclusions — deterministic
#      registry writes, no external dependencies.
#   4. Reboot.
# This matches avdaccelerator's Set-SessionHostConfiguration.ps1 sequence.

# --- 1. Network category: Public -> Private + RDP firewall ------------------
# Win 11 25H2 marketplace images categorize the Azure NIC as "Public", which
# silently suppresses inbound firewall Allow rules for cross-subnet traffic
# (including Bastion -> 3389) even when those rules are Enabled with
# Profile=Any. Setting the profile to Private at provisioning time makes the
# Allow rules effective. See win11_25h2_network_category memory note.
Write-Host '--- (1/3) network category + RDP firewall'
Get-NetConnectionProfile |
    Where-Object { $_.IPv4Connectivity -ne 'NoTraffic' } |
    Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue

# Make sure the built-in RDP rules are enabled. The 25H2 marketplace image
# ships them disabled by default; AIB images had them on.
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

# --- 2. AVD agent registration ----------------------------------------------
# Replaces the Microsoft.PowerShell.DSC extension. The DSC `AddSessionHost`
# configuration's RunMsiWithRetry / InstallRDAgents step fails on the Win 11
# 25H2 marketplace image with "Access is denied" — the DSC handler can't
# spawn msiexec from its non-interactive SYSTEM session on this image even
# though the same MSI installs cleanly when invoked directly.
#
# Two MSIs are installed:
#   - Microsoft.RDInfra.RDAgent.Installer-x64        (the agent; takes the
#                                                     REGISTRATIONTOKEN MSI
#                                                     property and plants
#                                                     it in HKLM:\SOFTWARE\
#                                                     Microsoft\RDInfraAgent)
#   - Microsoft.RDInfra.RDAgentBootLoader.Installer  (the bootloader service
#                                                     that starts the agent)
#
# Microsoft FWLinks always resolve to the latest GA versions of both MSIs:
#   2310011 -> Microsoft.RDInfra.RDAgent.Installer-x64-<latest>.msi
#   2311028 -> Microsoft.RDInfra.RDAgentBootLoader.Installer-x64.msi
# These are documented at
# https://learn.microsoft.com/en-us/azure/virtual-desktop/agent-overview
# (Azure/avdaccelerator's Set-SessionHostConfiguration uses the same FWLinks).
#
# Idempotent: re-running the MSIs upgrades in place; the REGISTRATIONTOKEN
# property re-plants the token each time. Run before FSLogix config so a
# broken broker handshake fails fast.
if ($hostPoolRegistrationToken) {
    Write-Host '--- (2/3) registering session host with AVD host pool'

    $agentMsi      = Join-Path $env:TEMP 'RDInfraAgent.msi'
    $bootloaderMsi = Join-Path $env:TEMP 'RDInfraAgentBootloader.msi'

    Write-Host '  downloading bootloader + agent MSIs (Microsoft FWLinks)'
    Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2311028' -OutFile $bootloaderMsi -UseBasicParsing
    Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2310011' -OutFile $agentMsi      -UseBasicParsing

    # Install order matters — BootLoader must be installed before the Agent.
    # avdaccelerator's Set-SessionHostConfiguration.ps1 follows this order
    # because the Agent install is what actually triggers the broker
    # registration; doing it first leaves a window where the Agent service
    # has no BootLoader to start it on next boot. The 5s gap between
    # installers is also from avdaccelerator (gives MSI's rollback / log
    # writer time to release file handles before the next msiexec runs).
    Write-Host '  installing RDAgentBootLoader (no token; runs first)'
    $blInstall = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', "`"$bootloaderMsi`"", '/quiet', '/qn', '/norestart', '/passive'
    )
    if ($blInstall.ExitCode -ne 0) {
        Write-Error "RDAgentBootLoader install failed: msiexec exit $($blInstall.ExitCode)"
        Exit 2
    }
    Start-Sleep -Seconds 5

    Write-Host '  installing RDInfraAgent (REGISTRATIONTOKEN passed as MSI property)'
    $agentInstall = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', "`"$agentMsi`"", '/quiet', '/qn', '/norestart', '/passive',
        "REGISTRATIONTOKEN=$hostPoolRegistrationToken"
    )
    if ($agentInstall.ExitCode -ne 0) {
        Write-Error "RDInfraAgent install failed: msiexec exit $($agentInstall.ExitCode)"
        Exit 2
    }
    Start-Sleep -Seconds 5

    # Poll for registration. The agent reads the token, contacts the AVD
    # broker, and flips IsRegistered to 1. Normal time is 30-90 seconds;
    # cap at 10 minutes so a broken broker doesn't hang the deploy.
    Write-Host '  polling HKLM:\SOFTWARE\Microsoft\RDInfraAgent\IsRegistered (10 min)'
    $deadline = (Get-Date).AddMinutes(10)
    $isRegistered = 0
    while ((Get-Date) -lt $deadline) {
        $isRegistered = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\RDInfraAgent' -Name 'IsRegistered' -ErrorAction SilentlyContinue).IsRegistered
        if ($isRegistered -eq 1) {
            Write-Host '  IsRegistered=1 — session host registered with host pool'
            break
        }
        Start-Sleep -Seconds 10
    }
    if ($isRegistered -ne 1) {
        Write-Error 'AVD agent failed to register within 10 minutes (IsRegistered != 1).'
        Exit 2
    }

    # --- 2b. SxS Network Stack install verification + retry -----------------
    # RDInfraAgent.msi bundles SxSStack-<version>.msi as a payload and
    # installs it transitively. That nested install sometimes returns
    # status 1603 (FATAL) on Win 11 25H2 marketplace images even though
    # the outer agent MSI returns 0 and IsRegistered flips to 1.
    #
    # When that happens the agent registers and heartbeats, but the SxS
    # listener service never starts -- the session host shows "Available"
    # briefly, then the bootloader's automatic version-management routine
    # notices the broken SxS, uninstalls it cleanly, and tries to reinstall.
    # The reinstall hits the same 1603 (same DLL-init race underneath the
    # MSI custom action) -- and now SxS is just gone, host stays Unavailable.
    #
    # Manual retry of the same MSI ~30s later succeeds (system has settled),
    # so wrap with up to 4 retries before failing the deploy. The script-side
    # IsRegistered=1 check above isn't sufficient because it only reflects
    # broker handshake, not listener health.
    $sxsLog = Get-ChildItem 'C:\Program Files\Microsoft RDInfra\SXSStackInstall*.txt' -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $sxsMsi = Get-ChildItem 'C:\Program Files\Microsoft RDInfra\SxSStack-*.msi' -EA SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    $sxsFailed = $false
    if ($sxsLog) {
        $logContent = Get-Content $sxsLog.FullName -Raw -EA SilentlyContinue
        # English: "Installation success or error status: 1603"
        # German : "Erfolg- bzw. Fehlerstatus der Installation: 1603"
        if ($logContent -match 'status:\s*1603' -or
            $logContent -match 'Fehlerstatus der Installation:\s*1603') {
            $sxsFailed = $true
        }
    }

    if ($sxsFailed -and $sxsMsi) {
        Write-Host "  SxS install reported 1603 in $($sxsLog.Name) -- retrying"
        $maxAttempts = 4
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            Start-Sleep -Seconds 30  # give DLL-init race time to settle
            $retryLog = Join-Path $env:TEMP "SxSRetry-$attempt.log"
            $r = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
                '/i', "`"$($sxsMsi.FullName)`"",
                '/qn', '/norestart',
                '/l*v', "`"$retryLog`""
            )
            Write-Host "  SxS retry $attempt of ${maxAttempts}: msiexec exit=$($r.ExitCode)"
            if ($r.ExitCode -in 0, 3010) {
                Write-Host '  SxS reinstall succeeded'
                # Restart bootloader so the new SxS becomes the active stack
                # immediately rather than on next maintenance cycle.
                Restart-Service RDAgentBootLoader -Force -EA SilentlyContinue
                break
            }
            if ($attempt -eq $maxAttempts) {
                Write-Error "SxS Network Stack install failed after $maxAttempts retries (last exit=$($r.ExitCode))"
                Exit 2
            }
        }
    }
    elseif ($sxsFailed -and -not $sxsMsi) {
        Write-Error 'SxS install reported 1603 but no SxSStack-*.msi found to retry'
        Exit 2
    }
    else {
        Write-Host '  SxS install OK (no 1603 in log)'
    }
}

# --- 3. FSLogix Profile Container -------------------------------------------
# Single container per user. Captures profile + Outlook OST + Teams cache +
# OneDrive cache + Office settings. No ODFC — see header.
#
# Target: move all of these into Intune Settings Catalog → "FSLogix > Profile
# Containers" once the Intune profile is set up.
Write-Host '--- (3/3) FSLogix + Cloud Kerberos + Defender exclusions'
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

# --- Cloud Kerberos Ticket Retrieval (Entra Kerberos client switch) ---------
# This single REG_DWORD is what enables Win 11 / Server 2025 to request
# Kerberos tickets from Entra ID for SMB authentication to Azure Files.
# Without it, FSLogix can't mount the AADKERB-configured share even when
# everything else is in place — the user's Kerberos ticket simply isn't
# requested.
#
# Microsoft documents an Intune Settings Catalog policy as the "supported
# way" to set this on multi-session AVD; the underlying mechanism is
# identical to the registry write below. Setting it here means the session
# host is fully self-configuring on first boot — no Intune profile sync
# timing dependency. If an Intune profile is later added for centralized
# management, both layers write the same value (idempotent).
#
# See Microsoft Learn (note the registry-key tab):
# https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable
New-Item        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Force -ErrorAction Ignore | Out-Null
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "CloudKerberosTicketRetrievalEnabled" -Value 1 -PropertyType DWord -Force | Out-Null

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
