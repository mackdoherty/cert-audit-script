#Requires -Version 7
#Requires -Modules DnsServer

<#
.SYNOPSIS
    Parallel TLS server certificate audit using raw SslStream.
    Built for mixed Windows/Linux environments during CA migrations.

    Features:
    - IPv4 + IPv6 discovery with hostname deduplication
    - Precise issuer matching (thumbprint > DN > name fallback)
    - Optional revocation checking
    - Conditional handshake bypass (real validation when root trusted)
    - Rich output: protocol, cipher, SANs, chain status, days left
    - Live progress, colored summary, migration-focused warnings

.PARAMETER RequireTrustedChain
    When specified: perform real TLS validation (no bypass callback).
    Use once new root is trusted locally.

.PARAMETER CheckRevocation
    Enable online revocation checking (adds latency, use sparingly).

.EXAMPLE
    .\newca-cert-audit.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
        -NewCA_Name "MegaCorp Enterprise CA 2025" -WhatIf

.EXAMPLE
    .\newca-cert-audit.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
        -NewCA_Name "MegaCorp Enterprise CA 2025" -PortsToCheck 443,636,8443 `
        -NewCA_IssuerThumbprint "A1B2C3D4E5F67890..." -CheckRevocation

.EXAMPLE
    .\newca-cert-audit.ps1 -DnsServer dc01.megacorp.corp -DnsZone megacorp.corp `
        -NewCA_Name "MegaCorp Enterprise CA 2025" -RequireTrustedChain
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [string]$DnsServer,

    [Parameter(Mandatory)]
    [string]$DnsZone,

    [Parameter(Mandatory)]
    [string]$NewCA_Name,

    [string]$NewCA_IssuerThumbprint,
    [string]$NewCA_IssuerDN,

    [int[]]$PortsToCheck = @(443, 8443),

    # If not provided, defaults to Desktop when available, otherwise %TEMP%.
    [string]$ExportPath,

    [ValidateRange(5, 50)]
    [int]$Concurrency = 20,

    [ValidateRange(1000, 30000)]
    [int]$ConnectTimeoutMs = 4000,

    [ValidateRange(2000, 60000)]
    [int]$HandshakeTimeoutMs = 6000,

    [ValidateRange(0, 5)]
    [int]$MaxRetries = 2,

    [string]$HostnameFilter = '^(?!.*(pc|laptop|workstation|test|dev-|backup)).*$',

    [System.Security.Authentication.SslProtocols]$SslProtocols = [System.Security.Authentication.SslProtocols]::None,

    [Alias("TrustNewCA")]
    [switch]$RequireTrustedChain,

    [switch]$CheckRevocation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Export Path fallback ─────────────────────────────────────────────────────
if (-not $ExportPath) {
    $desktop = if ($env:USERPROFILE) { Join-Path $env:USERPROFILE 'Desktop' } else { $null }
    $basePath = if ($desktop -and (Test-Path $desktop)) { $desktop } else { $env:TEMP }
    $ExportPath = Join-Path $basePath ("CertAudit_NewCA_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd_HHmm'))
}

# ── Pre-flight: local trust check ───────────────────────────────────────────
Write-Host "Pre-flight check: new CA root in local trust store?" -ForegroundColor Gray
$cleanThumb = ($NewCA_IssuerThumbprint -replace '\s','').ToUpperInvariant()
$localRoots = Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -EA SilentlyContinue |
    Where-Object { $_.Subject -like "*$NewCA_Name*" -or ($cleanThumb -and $_.Thumbprint -eq $cleanThumb) }

if (-not $localRoots) {
    Write-Warning "→ New CA root NOT trusted locally → ChainValid may be False for updated certs (or trust-mode handshakes may fail)."
} else {
    Write-Host "✓ Root candidate found (thumbprint: $($localRoots[0].Thumbprint))" -ForegroundColor Green
}

# ── Discover targets (IPv4 + IPv6 deduplicated) ─────────────────────────────
Write-Host "`nDiscovering hosts from DNS zone $DnsZone..." -ForegroundColor Yellow

$records = @()
$records += Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $DnsZone -RRType A -EA Stop |
    Where-Object { $_.HostName -and $_.HostName -ne '@' -and $_.HostName -match $HostnameFilter }
$records += Get-DnsServerResourceRecord -ComputerName $DnsServer -ZoneName $DnsZone -RRType AAAA -EA SilentlyContinue |
    Where-Object { $_.HostName -and $_.HostName -ne '@' -and $_.HostName -match $HostnameFilter }

$servers = $records | Group-Object HostName | ForEach-Object {
    $fqdn = if ($_.Name -match '\.') { $_.Name } else { "$($_.Name).$DnsZone" }
    [PSCustomObject]@{ Hostname = $fqdn }
} | Sort-Object Hostname

Write-Host "→ $($servers.Count) unique hosts found (IPv4 + IPv6 after dedup)" -ForegroundColor Green
if ($servers.Count -eq 0) { throw "No hosts after filtering." }

$targetCount = $servers.Count * $PortsToCheck.Count

# ── Native WhatIf handling ──────────────────────────────────────────────────
if (-not $PSCmdlet.ShouldProcess("Audit $targetCount host:port pairs")) { return }

if ($WhatIfPreference) {
    Write-Host "`nWhatIf mode — would audit these targets:" -ForegroundColor Magenta
    $servers.Hostname | ForEach-Object {
        $h = $_
        $PortsToCheck | ForEach-Object { "  $h : $_" }
    }
    return
}

# ── Parallel audit ──────────────────────────────────────────────────────────
Write-Host "`nStarting parallel audit..." -ForegroundColor Cyan
Write-Host "  Concurrency : $Concurrency"
Write-Host "  Timeouts    : Connect $ConnectTimeoutMs ms | Handshake $HandshakeTimeoutMs ms"
Write-Host "  Protocols   : $(if ($SslProtocols -eq 'None') {'OS default'} else {$SslProtocols})"
Write-Host "  Validation  : $(if ($RequireTrustedChain) {'Real chain check'} else {'Bypass handshake'})"
Write-Host "  Revocation  : $(if ($CheckRevocation) { 'Enabled (online)' } else { 'Disabled' })`n"

$sync = [hashtable]::Synchronized(@{})
$progress = [hashtable]::Synchronized(@{ Done = 0; Total = $targetCount })

$results = $servers | ForEach-Object -Parallel {
    # ── Runspace-local helpers ──────────────────────────────────────────────
    function Get-LocalDeepestError ([Exception]$ex) {
        while ($ex.InnerException) { $ex = $ex.InnerException }
        return $ex.Message -replace '\r?\n',' ' -replace '\s+',' '
    }

    function ConvertTo-LocalNormalizedDN ([string]$DN) {
        if (-not $DN) { return "" }
        return ($DN -replace '\s*=\s*','=' -replace '\s*,\s*',',').ToUpperInvariant()
    }

    $target    = $_.Hostname
    $caName    = $using:NewCA_Name
    $caThumb   = ($using:NewCA_IssuerThumbprint -replace '\s','').ToUpperInvariant()
    $caDN_norm = ConvertTo-LocalNormalizedDN $using:NewCA_IssuerDN
    $ports     = $using:PortsToCheck
    $connTO    = $using:ConnectTimeoutMs
    $handTO    = $using:HandshakeTimeoutMs
    $retries   = $using:MaxRetries
    $prot      = $using:SslProtocols
    $trustMode = $using:RequireTrustedChain
    $revoke    = $using:CheckRevocation

    $local = @()

    foreach ($port in $ports) {
        $row = [ordered]@{
            Hostname     = $target
            Port         = $port
            Status       = "Unknown"
            Issuer       = "N/A"
            Subject      = "N/A"
            SANs         = "N/A"
            Thumbprint   = "N/A"
            ExpiryDate   = "N/A"
            DaysLeft     = "N/A"
            TlsVersion   = "N/A"
            Cipher       = "N/A"
            ChainValid   = $false
            ChainStatus  = "N/A"
            Error        = $null
        }

        $retry = 0
        do {
            $tcp = $null; $ssl = $null
            try {
                $tcp = [Net.Sockets.TcpClient]::new()
                $connTask = $tcp.ConnectAsync($target, $port)
                if (-not $connTask.Wait($connTO)) { throw "TCP connect timeout ($connTO ms)" }

                $stream = $tcp.GetStream()

                # Correct delegate signature: bypass only when NOT requiring trust
                $callback = if ($trustMode) { $null } else {
                    [System.Net.Security.RemoteCertificateValidationCallback]{
                        param($_sender,$cert,$chain,$errors)
                        $true
                    }
                }

                $ssl = [Net.Security.SslStream]::new($stream, $false, $callback)

                $handTask = $ssl.AuthenticateAsClientAsync($target, $null, $prot, $false)
                if (-not $handTask.Wait($handTO)) { throw "TLS handshake timeout ($handTO ms)" }

                $row.TlsVersion = $ssl.SslProtocol
                $row.Cipher     = "$($ssl.CipherAlgorithm) ($($ssl.CipherStrength) bits)"

                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
                if (-not $cert) { throw "No certificate presented" }

                $row.Subject    = $cert.Subject
                $row.Issuer     = $cert.Issuer
                $row.Thumbprint = $cert.Thumbprint
                $row.ExpiryDate = $cert.NotAfter.ToString("yyyy-MM-dd")
                $row.DaysLeft   = [math]::Round(($cert.NotAfter - (Get-Date)).TotalDays, 0)

                $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
                $row.SANs = if ($san) { $san.Format(0) -replace '\s*,\s*', ', ' -replace '\s*\r?\n\s*', '; ' } else { "None" }

                # Chain
                $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.ChainPolicy.RevocationMode = if ($revoke) {
                    [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                } else {
                    [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                }
                $chain.ChainPolicy.RevocationFlag = [Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
                $chain.ChainPolicy.VerificationTime = Get-Date
                $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(5)

                $row.ChainValid = $chain.Build($cert)
                $row.ChainStatus = if ($chain.ChainStatus -and $chain.ChainStatus.Count -gt 0) {
                    ($chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation.Trim())" }) -join ' | '
                } else { "OK" }

                # Issuer match (strongest first)
                $match = $false
                if ($caThumb -and ($chain.ChainElements.Certificate.Thumbprint -contains $caThumb)) {
                    $match = $true
                } elseif ($caDN_norm -and ((ConvertTo-LocalNormalizedDN $cert.Issuer) -eq $caDN_norm)) {
                    $match = $true
                } elseif ((ConvertTo-LocalNormalizedDN $cert.Issuer) -match [regex]::Escape($caName)) {
                    $match = $true
                }

                $row.Status = if ($match) {
                    if ($trustMode -and -not $row.ChainValid) { "Updated (New CA) - Chain Invalid" }
                    else { "Updated (New CA)" }
                } else {
                    "OLD / Other CA"
                }

                break
            }
            catch {
                $row.Error = Get-LocalDeepestError $_.Exception
                $row.Status = "Error"
                if ($retry -lt $retries) {
                    Start-Sleep -Milliseconds (300 * ($retry + 1))
                    $retry++
                }
            }
            finally {
                if ($ssl) { try { $ssl.Dispose() } catch {} }
                if ($tcp) { try { $tcp.Dispose() } catch {} }
            }
        } while ($retry -le $retries)

        $local += [PSCustomObject]$row

        # Progress
        [System.Threading.Monitor]::Enter($using:sync)
        try {
            $p = $using:progress
            $p['Done'] = $p['Done'] + 1
            $pct = [math]::Round(($p['Done'] / [double]$p['Total']) * 100, 1)
            Write-Progress -Activity "TLS Certificate Audit" -Status "$($p['Done'])/$($p['Total']) ($pct%)" -PercentComplete $pct
        } finally {
            [System.Threading.Monitor]::Exit($using:sync)
        }
    }

    $local
} -ThrottleLimit $Concurrency

Write-Progress -Activity "TLS Certificate Audit" -Completed

# ── Summary & Export ────────────────────────────────────────────────────────
Write-Host "`nAudit complete." -ForegroundColor Cyan

$summary = $results | Group-Object Status | Sort-Object Count -Descending

Write-Host "Summary:" -ForegroundColor Cyan
foreach ($g in $summary) {
    $c = switch -Wildcard ($g.Name) {
        "*Updated*" { "Green" }
        "*OLD*"     { "Yellow" }
        "Error"     { "Red" }
        default     { "White" }
    }
    Write-Host ("  {0,-35} {1,6}" -f $g.Name, $g.Count) -ForegroundColor $c
}

$updated = ($results | Where-Object Status -like "*Updated*").Count
$total   = $results.Count
$percent = if ($total) { [math]::Round($updated / $total * 100, 1) } else { 0 }

Write-Host "`n  New CA adoption : $updated / $total   ($percent%)" -ForegroundColor Green

$badChain = $results | Where-Object { $_.Status -like "*Updated*" -and $_.ChainValid -eq $false }
if ($badChain.Count -gt 0 -and $updated -gt 0) {
    $pctBad = [math]::Round(($badChain.Count / [double]$updated) * 100, 1)
    Write-Warning "→ $($badChain.Count) updated certs have invalid chain locally ($pctBad%)"
    Write-Warning "  (likely new root not yet trusted on this machine)"
}

Write-Host "`nExport → " -NoNewline
Write-Host $ExportPath -ForegroundColor Green

$results | Sort-Object Status, Hostname, Port |
    Select-Object Hostname, Port, Status, Issuer, Subject, SANs, Thumbprint,
                  ExpiryDate, DaysLeft, TlsVersion, Cipher, ChainValid, ChainStatus, Error |
    Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8 -UseQuotes Always

Write-Host "Done." -ForegroundColor Green
